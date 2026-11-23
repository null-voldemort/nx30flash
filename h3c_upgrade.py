#!/usr/bin/env python3
import argparse
import csv
import datetime
import getpass
import hashlib
import http.server
import json
import os
import re
import shlex
import shutil
import socket
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

try:
    from h3c_probe import connect as _connect, load_env, redact
except ImportError:
    sys.exit("h3c_probe.py not found next to this script")

RDIR = "/tmp/ftproot/version"
RNAME = "fw_h3c.bin"
HALT = {"FAILED_NO_REBOOT", "NOT_UPGRADED", "LOST", "UNVERIFIED", "DOWNLOAD_FAILED", "ERROR"}
HEX = "hexdump -v -e '1/1 \"%02x\"'"
BEG = re.compile(r"__B1__\s*\n?")
PLOCK = threading.RLock()
STAT, ORDER, UI = {}, [], {"on": False, "drawn": 0}
STAGES, BAR = 8, 24


def connect(*args, **kw):
    conn = _connect(*args, **kw)
    raw = conn.run

    def run(cmd, timeout=20):
        code, out = raw(f"printf '__B%s__\\n' 1; {cmd}", timeout=timeout)
        parts = BEG.split(out)
        return code, (parts[-1] if len(parts) > 1 else out).strip()

    conn.run = run
    return conn


def _line(h):
    idx, text, frac, t0 = STAT[h]
    p = min(1.0, (idx + frac) / STAGES)
    n = int(p * BAR)
    el = int(time.time() - t0)
    return f"{h:<15} [{'#' * n}{'-' * (BAR - n)}] {int(p * 100):3d}%  {text}  ({el // 60}:{el % 60:02d})"


def _draw():
    if not UI["on"]:
        return
    w = shutil.get_terminal_size((100, 20)).columns - 1
    if UI["drawn"]:
        sys.stdout.write(f"\033[{UI['drawn']}A")
    for h in ORDER:
        sys.stdout.write("\r\033[K" + _line(h)[:w] + "\n")
    UI["drawn"] = len(ORDER)
    sys.stdout.flush()


def say(host, msg):
    with PLOCK:
        if UI["on"] and UI["drawn"]:
            sys.stdout.write(f"\033[{UI['drawn']}A\033[J")
            UI["drawn"] = 0
        print(f"[{datetime.datetime.now():%H:%M:%S}] {host:<15} {msg}", flush=True)
        _draw()


def stat(host, idx, text, frac=0.0):
    with PLOCK:
        prev = STAT.get(host)
        STAT[host] = (idx, text, frac, prev[3] if prev and prev[0] == idx else time.time())


def load_image(path):
    with open(path, "rb") as f:
        data = f.read()
    fit = data.find(b"\xd0\x0d\xfe\xed", 0, 4096)
    if fit < 0:
        sys.exit("no FIT image in the first 4 KiB, wrong file format")
    if fit > 0 and data[:4] != b"H3C_":
        sys.exit("header before the FIT image is not an H3C header")
    m = re.search(rb"(NX30-[A-Z]+)(V\d+R\d+)", data[:8 << 20])
    return {"path": path, "name": os.path.basename(path), "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "skip": fit,
            "product": m.group(1).decode() if m else None,
            "version": m.group(2).decode() if m else "?"}


def make_server(path, port):
    name = os.path.basename(path)

    class H(http.server.SimpleHTTPRequestHandler):
        def translate_path(self, p):
            return path

        def _ok(self):
            return urllib.parse.unquote(self.path.split("?", 1)[0]) == "/" + name

        def do_GET(self):
            super().do_GET() if self._ok() else self.send_error(404)

        def do_HEAD(self):
            super().do_HEAD() if self._ok() else self.send_error(404)

        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def local_ip_for(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    finally:
        s.close()


def num(pattern, text):
    m = re.search(pattern, text or "")
    return int(m.group(1)) if m else None


def snapshot(conn):
    def g(c):
        return conn.run(c, timeout=15)[1].strip()

    def first(pat, text):
        m = re.search(pat, text)
        return m.group(0) if m else text[:30]

    return {"boot": first(r"^[01]$", g("cat /proc/boot_info/rootfs/primaryboot 2>&1")),
            "other": first(r"rootfs\w*", g("cat /proc/boot_info/rootfs/upgradepartition 2>&1")),
            "uname": g("uname -v"),
            "ver": g("cat /etc/openwrt_version 2>&1"),
            "up": g("cut -d. -f1 /proc/uptime")}


def preflight(conn, img, a, url):
    prob = []

    def rd(cmd, t=15):
        return conn.run(cmd, timeout=t)[1]

    model = rd("cat /proc/device-tree/model 2>/dev/null | tr -d '\\0'")
    if "IPQ5018" not in model:
        prob.append(f"not an IPQ5018 board ({model[:50]!r})")

    m = re.search(r"productname=(\S+)", rd("fw_printenv productname 2>/dev/null"))
    prod = m.group(1) if m else None
    if not prod:
        prob.append("cannot read productname")
    elif img["product"]:
        if prod != img["product"]:
            prob.append(f"image is {img['product']}, router is {prod}")
    elif not a.force_model:
        prob.append("no product string in image, use --force-model")

    tools = dict(re.findall(r"(\S+)=(yes|NO)", rd(
        'for t in curl wget sha256sum dumpimage hexdump dd sysupgrade; do command -v $t >/dev/null 2>&1 && echo "$t=yes" || echo "$t=NO"; done; '
        '[ -x /bin/upgrade.sh ] && echo upgrade.sh=yes || echo upgrade.sh=NO')))
    missing = [t for t in ("sha256sum", "dumpimage", "hexdump", "dd", "sysupgrade", "upgrade.sh") if tools.get(t) != "yes"]
    if missing:
        prob.append("missing on router: " + ", ".join(missing))
    if tools.get("curl") != "yes" and tools.get("wget") != "yes":
        prob.append("no curl or wget on router")

    snap = snapshot(conn)
    if snap["boot"] not in ("0", "1") or not snap["other"].startswith("rootfs"):
        prob.append(f"cannot read boot slot (primaryboot={snap['boot'][:20]!r}, other={snap['other'][:20]!r})")
    up = num(r"^(\d+)$", snap["up"])
    if up is not None and up < 180:
        prob.append(f"booted {up}s ago")

    need_kb = img["size"] // 1024
    avail = num(r"MemAvailable:\s+(\d+)", rd("grep MemAvailable /proc/meminfo"))
    t = re.search(r"(\d+)\s+(\d+)\s+(\d+)\s+\d+%", rd("df -k /tmp | tail -n 1"))
    tmp_free = int(t.group(3)) if t else None
    if avail is None or avail < need_kb + 12 * 1024:
        prob.append(f"low RAM ({(avail or 0) // 1024} MiB available, need {need_kb // 1024 + 12})")
    if tmp_free is None or tmp_free < need_kb + 2048:
        prob.append(f"/tmp too small ({(tmp_free or 0) // 1024} MiB free)")

    if url:
        u = shlex.quote(url)
        out = rd(f"if command -v curl >/dev/null 2>&1; then curl -sS -I -m 10 {u} 2>&1 | head -n 3; "
                 f"else wget --spider -S -T 10 {u} 2>&1 | head -n 6; fi", 25)
        if not re.search(r"HTTP/\S+\s+200", out):
            prob.append(f"cannot fetch firmware url ({redact(out)[:80]!r})")

    notes = f"{prod} slot={snap['boot']} RAM={(avail or 0) // 1024}MiB tmp={(tmp_free or 0) // 1024}MiB up={snap['up']}s"
    return snap, prob, notes


def wait_port(host, port, want_open, timeout, need=2, cb=None):
    start = time.time()
    end, streak = start + timeout, 0
    while time.time() < end:
        if cb:
            cb(time.time() - start)
        is_open = False
        for pt in (port if isinstance(port, (list, tuple)) else [port]):
            try:
                socket.create_connection((host, pt), 3).close()
                is_open = True
                break
            except OSError:
                pass
        streak = streak + 1 if is_open == want_open else 0
        if streak >= need:
            return True
        time.sleep(3)
    return False


def relogin(host, a, creds, tries=12):
    err = None
    for _ in range(tries):
        try:
            return connect(host, a.port, creds[0], creds[1], a.protocol, a.timeout), None
        except PermissionError as e:
            return None, f"login rejected ({e})"
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            time.sleep(10)
    return None, err


def upgrade_one(host, a, img, url_for, creds, ctl):
    t0 = time.time()
    rec = {"host": host, "status": "", "detail": "", "before_boot": "", "after_boot": "", "seconds": 0}

    def finish(status, detail=""):
        rec.update(status=status, detail=detail, seconds=int(time.time() - t0))
        prev = STAT.get(host)
        ok = status in ("UPGRADED", "READY", "SKIPPED")
        stat(host, STAGES if ok else (prev[0] if prev else 0), status if ok else "STOPPED: " + status, 0)
        say(host, status + (": " + detail if detail else ""))
        if status in HALT and not a.keep_going:
            ctl["abort"].set()
        return rec

    if ctl["abort"].is_set():
        return finish("NOT_STARTED", "earlier router failed")
    if not a.redo and ctl["state"].get(host) == "UPGRADED":
        return finish("SKIPPED", "already upgraded")

    url = url_for(host)
    stat(host, 0, "connecting")
    try:
        conn = connect(host, a.port, creds[0], creds[1], a.protocol, a.timeout)
    except Exception as e:
        return finish("UNREACHABLE", f"{type(e).__name__}: {e}")

    try:
        stat(host, 1, "preflight")
        before, prob, notes = preflight(conn, img, a, url)
        rec["before_boot"] = before["boot"]
        if prob:
            return finish("BLOCKED", "; ".join(prob))
        if not a.go:
            return finish("READY", notes)
        say(host, f"preflight ok ({notes})")

        f = f"{RDIR}/{RNAME}"
        u = shlex.quote(url)
        dl = (f"if command -v curl >/dev/null 2>&1; then curl -sS -f -m {a.download_timeout} -o {f} {u}; "
              f"else wget -q -T 30 -O {f} {u}; fi")
        stat(host, 2, "downloading 0%", 0)
        conn.run(f"mkdir -p {RDIR}; rm -f {f} /tmp/{RNAME} /tmp/upgradefile.img /tmp/upgrade_run.log /tmp/dl.rc /tmp/dl.log; "
                 f"( trap '' HUP; ( {dl}; echo $? > /tmp/dl.rc ) >/tmp/dl.log 2>&1 </dev/null & ); echo started", timeout=20)
        rc, dl_end = None, time.time() + a.download_timeout + 30
        while time.time() < dl_end:
            time.sleep(2)
            _, o = conn.run(f"wc -c < {f} 2>/dev/null; echo RC=$(cat /tmp/dl.rc 2>/dev/null)", timeout=20)
            m = re.match(r"\s*(\d+)", o)
            size = int(m.group(1)) if m else 0
            frac = min(1.0, size / img["size"])
            stat(host, 2, f"downloading {int(frac * 100)}%  {size / 1048576:.1f}/{img['size'] / 1048576:.1f} MiB", frac)
            r = re.search(r"RC=(\d+)", o)
            if r:
                rc = int(r.group(1))
                break
        if rc != 0:
            _, lg = conn.run("cat /tmp/dl.log 2>&1 | tail -n 3", timeout=15)
            conn.run(f"killall curl wget 2>/dev/null; rm -f {f}", timeout=15)
            return finish("DOWNLOAD_FAILED", f"{'timed out' if rc is None else 'exit ' + str(rc)}: {redact(lg)[-120:]}")

        stat(host, 3, "verifying image")
        _, out = conn.run(f"sha256sum {f}; wc -c < {f}; dd if={f} bs=1 skip={img['skip']} count=4 2>/dev/null | {HEX}", timeout=120)
        sha = re.search(r"\b([0-9a-f]{64})\b", out)
        sizes = [int(x) for x in re.findall(r"^\s*(\d+)\s*$", out, re.M)]
        if not sha or sha.group(1) != img["sha256"] or img["size"] not in sizes:
            conn.run(f"rm -f {f}", timeout=15)
            return finish("DOWNLOAD_FAILED", "sha256 or size mismatch, file removed")
        if "d00dfeed" not in out:
            conn.run(f"rm -f {f}", timeout=15)
            return finish("DOWNLOAD_FAILED", f"no FIT magic at byte {img['skip']}, file removed")
        say(host, "image verified, starting upgrade")
        stat(host, 4, "starting upgrade")

        try:
            _, lo = conn.run(f"( trap '' HUP; /bin/upgrade.sh {RNAME} {img['skip']} >/tmp/upgrade_run.log 2>&1 </dev/null & ); "
                             f"sleep 2; ps w | grep -c '[u]pgrade.sh'", timeout=20)
            say(host, f"upgrade.sh processes: {lo.strip()[-3:].strip() or '?'}")
        except Exception:
            pass
    except Exception as e:
        return finish("ERROR", f"{type(e).__name__}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    stat(host, 5, "waiting for router to go down")
    if not wait_port(host, a.port, False, 180, cb=lambda s: stat(host, 5, "waiting for router to go down", min(s / 150, 0.95))):
        c2, err = relogin(host, a, creds, tries=3)
        tail = ""
        if c2:
            try:
                tail = redact(c2.run("tail -n 12 /tmp/upgrade_run.log 2>&1", timeout=15)[1])
                if not a.no_reboot_on_fail:
                    c2.run("(sleep 2; reboot) >/dev/null 2>&1 &", timeout=10)
                    tail += " | reboot issued"
                c2.close()
            except Exception:
                pass
        return finish("FAILED_NO_REBOOT", f"router did not start flashing, old firmware still active. {tail[-300:] or err or ''}")
    say(host, "router went down")
    stat(host, 6, "flashing and booting")
    if not wait_port(host, [a.port, 80, 23, 443], True, a.boot_timeout,
                     cb=lambda s: stat(host, 6, "flashing and booting", min(s / 240, 0.95))):
        return finish("LOST", f"no answer on ports {a.port}/80/23/443 after {a.boot_timeout}s")
    stat(host, 7, "logging in, checking slot")
    time.sleep(25)
    c3, err = relogin(host, a, creds, tries=18)
    if not c3:
        return finish("UNVERIFIED", f"router is online but login on port {a.port} failed ({err}), check the version in the web UI")
    try:
        after = snapshot(c3)
        c3.close()
    except Exception as e:
        return finish("LOST", f"online but could not read state: {e}")
    rec["after_boot"] = after["boot"]
    changed = ", kernel build changed" if after["uname"] != before["uname"] else ""
    if after["boot"] != before["boot"]:
        return finish("UPGRADED", f"slot {before['boot']} -> {after['boot']}{changed}, uptime {after['up']}s")
    return finish("NOT_UPGRADED", f"still on slot {after['boot']}{changed}")


def main():
    load_env()
    p = argparse.ArgumentParser(description="H3C NX30 firmware upgrade")
    p.add_argument("--image", required=True)
    p.add_argument("--host", action="append", default=[])
    p.add_argument("--hosts-file")
    p.add_argument("--url")
    p.add_argument("--serve-port", type=int, default=8080)
    p.add_argument("--serve-ip")
    p.add_argument("--port", type=int, default=99)
    p.add_argument("--user", default=os.environ.get("H3C_SSH_USER"))
    p.add_argument("--password", default=os.environ.get("H3C_SSH_PASS"))
    p.add_argument("--protocol", choices=["auto", "ssh", "telnet"], default="auto")
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--go", action="store_true")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--boot-timeout", type=int, default=600)
    p.add_argument("--download-timeout", type=int, default=900)
    p.add_argument("--keep-going", action="store_true")
    p.add_argument("--no-reboot-on-fail", action="store_true")
    p.add_argument("--force-model", action="store_true")
    p.add_argument("--redo", action="store_true")
    p.add_argument("--out", default=".")
    a = p.parse_args()

    hosts = list(a.host)
    if a.hosts_file:
        with open(a.hosts_file, encoding="utf-8-sig") as f:
            hosts += [ln.split("#")[0].strip() for ln in f if ln.split("#")[0].strip()]
    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        p.error("give --host or --hosts-file")

    img = load_image(a.image)
    print(f"image   : {img['name']}  {img['size']:,} bytes  sha256 {img['sha256'][:16]}")
    print(f"          product {img['product']}  version {img['version']}  header {img['skip']} bytes")
    print(f"routers : {len(hosts)}  mode: {'flash' if a.go else 'preflight'}")

    user = a.user or input("router username: ").strip()
    pw = a.password if a.password is not None else getpass.getpass(f"router password for {user}: ")

    srv = None
    if a.url:
        def url_for(h):
            return a.url
    else:
        srv = make_server(a.image, a.serve_port)
        quoted = urllib.parse.quote(img["name"])

        def url_for(h):
            return f"http://{a.serve_ip or local_ip_for(h, a.port)}:{a.serve_port}/{quoted}"
        print(f"serving : {img['name']} on port {a.serve_port}")

    if a.go and not a.yes:
        if input(f"\nFlash {len(hosts)} router(s)? Type UPGRADE: ").strip() != "UPGRADE":
            print("cancelled")
            return 1

    state_path = os.path.join(a.out, "upgrade_state.json")
    try:
        with open(state_path, encoding="utf-8") as f:
            all_state = json.load(f)
    except (OSError, ValueError):
        all_state = {}
    ctl = {"abort": threading.Event(), "state": all_state.setdefault(img["sha256"], {})}
    results, rlock = [], threading.Lock()

    def run(h):
        r = upgrade_one(h, a, img, url_for, (user, pw), ctl)
        with rlock:
            results.append(r)
            if r["status"] == "UPGRADED":
                ctl["state"][h] = "UPGRADED"
                with open(state_path, "w", encoding="utf-8") as f:
                    json.dump(all_state, f, indent=1)
        return r

    ORDER[:] = hosts
    for h in hosts:
        stat(h, 0, "waiting")
    ui_stop = threading.Event()
    if sys.stdout.isatty():
        if os.name == "nt":
            os.system("")
        UI["on"] = True

        def refresher():
            while not ui_stop.wait(0.5):
                with PLOCK:
                    _draw()
        threading.Thread(target=refresher, daemon=True).start()
        with PLOCK:
            _draw()
    try:
        rest = hosts
        if a.go and len(hosts) > 1:
            run(hosts[0])
            rest = hosts[1:]
        with ThreadPoolExecutor(max_workers=max(1, a.workers)) as ex:
            list(ex.map(run, rest))
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        ui_stop.set()
        with PLOCK:
            _draw()
            UI["on"] = False
        if srv:
            srv.shutdown()

    path = os.path.join(a.out, f"upgrade_results_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["host", "status", "detail", "before_boot", "after_boot", "seconds"])
        w.writeheader()
        w.writerows(results)
    print("\nsummary")
    for r in results:
        print(f"  {r['host']:<15} {r['status']:<18} {r['detail'][:90]}")
    print(f"saved: {path}")
    bad = [r for r in results if r["status"] in HALT or r["status"] == "NOT_STARTED"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
