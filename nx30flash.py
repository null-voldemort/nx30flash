#!/usr/bin/env python3
"""
nx30flash — interactive H3C NX30 probe & upgrade.

Runs with no arguments:

    python3 nx30flash.py
    ./nx30flash                # chmod +x

Sits on top of the existing engine files:

    h3c_probe.py    image analysis, raw connection, deep-probe sections
    h3c_upgrade.py  preflight + flash driver (upgrade_one)

This file replaces the engine's plain-text UI hooks with a full-screen
TUI and adds an interactive menu. The engine files are untouched, so
automation / CI can still call `h3c_upgrade.py --go --yes ...` and
`h3c_probe.py --host ...` directly.

Only external dep: paramiko (and only if a router speaks SSH).
"""

import argparse
import csv
import datetime
import getpass
import io
import json
import os
import re
import shutil
import sys
import threading
import time
import urllib.parse
from collections import deque

try:
    from h3c_probe import (
        SECTIONS, analyze_image, image_lines, findings, redact, load_env,
        connect as probe_connect,
    )
    import h3c_upgrade as eng
except ImportError as e:
    sys.exit(f"nx30flash: missing module ({e}). "
             "h3c_probe.py and h3c_upgrade.py must sit next to this script.")


# ───────────────────────────── ANSI / colours ─────────────────────────────
CSI = "\033["
RESET = f"{CSI}0m"
BOLD = f"{CSI}1m"
DIM = f"{CSI}2m"
C_TITLE = BOLD + f"{CSI}96m"
C_HEAD = BOLD + f"{CSI}96m"
C_LABEL = f"{CSI}90m"
C_OK = f"{CSI}92m"
C_WARN = f"{CSI}93m"
C_BAD = f"{CSI}91m"
C_RUN = f"{CSI}93m"
C_DIM = f"{CSI}90m"
C_ACCENT = f"{CSI}94m"
C_BORDER = f"{CSI}90m"

ALT_ON = f"{CSI}?1049h"
ALT_OFF = f"{CSI}?1049l"
CUR_HIDE = f"{CSI}?25l"
CUR_SHOW = f"{CSI}?25h"
CLEAR = f"{CSI}2J{CSI}H"

ANSI_RE = re.compile(r"\033\[[0-9;?]*[A-Za-z]")


def _vlen(s):
    return len(ANSI_RE.sub("", s))


def _fit(s, width):
    """Pad / truncate a (possibly coloured) string to exactly `width` visible chars."""
    v = _vlen(s)
    if v <= width:
        return s + " " * (width - v)
    out, vis, i = [], 0, 0
    while i < len(s) and vis < width - 1:
        if s[i] == "\033":
            m = ANSI_RE.match(s, i)
            if m:
                out.append(m.group())
                i = m.end()
                continue
        out.append(s[i])
        vis += 1
        i += 1
    return "".join(out) + "…" + RESET


def box(title, lines, width=None):
    if width is None:
        width = min(shutil.get_terminal_size((100, 30)).columns - 4, 100)
    pad = max(0, width - _vlen(title) - 4)
    out = [f"{C_BORDER}╭─ {C_TITLE}{title}{C_BORDER} {'─' * pad}╮{RESET}"]
    for ln in lines:
        out.append(f"{C_BORDER}│{RESET} {_fit(ln, width - 2)} {C_BORDER}│{RESET}")
    out.append(f"{C_BORDER}╰{'─' * width}╯{RESET}")
    return "\n".join(out)


# ───────────────────────────── input helpers ─────────────────────────────
def ask(prompt, default=None, validate=None):
    while True:
        tail = f" [{default}]" if default is not None else ""
        try:
            raw = input(f"{C_ACCENT}?{RESET} {prompt}{tail}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not raw and default is not None:
            return default
        if not raw:
            continue
        if validate:
            ok, err = validate(raw)
            if not ok:
                print(f"  {C_BAD}✗ {err}{RESET}")
                continue
        return raw


def confirm(prompt, default=False):
    suffix = " [Y/n]" if default else " [y/N]"
    while True:
        try:
            raw = input(f"{C_WARN}?{RESET} {prompt}{suffix}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False


def pause(msg="Press Enter to continue"):
    try:
        input(f"\n{C_DIM}{msg} …{RESET}")
    except (EOFError, KeyboardInterrupt):
        print()


# ───────────────────────────── live UI ─────────────────────────────
class LiveUI:
    BAR_W = 20

    def __init__(self, title, image=None, hosts=None, mode="upgrade",
                 stages=8, workers=1):
        self.title = title
        self.image = image
        self.hosts = list(hosts or [])
        self.mode = mode
        self.stages = max(1, stages)
        self.workers = workers
        self.lock = threading.RLock()
        self.stat_dict = {}                      # host -> (idx, text, frac, t0)
        self.log = deque(maxlen=64)
        self.start_ts = time.time()
        self.tty = sys.stdout.isatty()
        self.stop_evt = threading.Event()
        self.thread = None

    # -- shared with the engine ----------------------------------------
    def stat(self, host, idx, text, frac=0.0):
        with self.lock:
            prev = self.stat_dict.get(host)
            t0 = prev[3] if prev and prev[0] == idx else time.time()
            self.stat_dict[host] = (idx, text, frac, t0)
            if not self.tty and (not prev or prev[0] != idx or prev[1] != text):
                pct = int(min(1.0, (idx + frac) / self.stages) * 100)
                print(f"[{datetime.datetime.now():%H:%M:%S}] {host:<15} {pct:3d}%  {text}")

    def say(self, host, msg):
        with self.lock:
            stamp = f"{datetime.datetime.now():%H:%M:%S}"
            if self.tty:
                self.log.append((stamp, host, msg))
            else:
                print(f"[{stamp}] {host:<15} {msg}")

    # -- rendering ------------------------------------------------------
    def _status(self, host):
        s = self.stat_dict.get(host)
        if not s:
            return "waiting", 0.0, 0, None
        idx, text, frac, t0 = s
        pct = min(1.0, (idx + frac) / self.stages)
        failed = text.startswith("STOPPED:") or text in eng.HALT
        done = pct >= 1.0 and text in ("UPGRADED", "READY", "SKIPPED")
        if failed:
            return "failed", pct, idx, text
        if done:
            return "done", pct, idx, text
        return "running" if idx > 0 else "waiting", pct, idx, text

    def _host_row(self, host):
        st, pct, idx, text = self._status(host)
        s = self.stat_dict.get(host)
        t0 = s[3] if s else time.time()
        n = int(pct * self.BAR_W)
        bar = "█" * n + "░" * (self.BAR_W - n)
        el = int(time.time() - t0)
        timestr = f"{el // 60:>2}:{el % 60:02d}"
        color = {"failed": C_BAD, "done": C_OK,
                 "running": C_RUN, "waiting": C_DIM}[st]
        phase = _fit(text or "waiting", 28)
        return f"{color}{host:<15} {phase} {bar} {int(pct * 100):3d}%  {timestr}{RESET}"

    def _frame(self, cols, rows):
        inner = cols - 2
        out = []

        # top border
        bar = max(0, inner - _vlen(self.title) - 3)
        out.append(f"{C_BORDER}╭─ {C_TITLE}{self.title}{C_BORDER} {'─' * bar}╮{RESET}")

        # image line
        if self.image:
            img = self.image
            line = (f"{C_LABEL}image{RESET}    {img['name']}  "
                    f"{img['size'] / 1048576:.1f} MiB  "
                    f"{img.get('product') or '?'} {img.get('version', '?')}  "
                    f"sha256 {img['sha256'][:12]}")
        else:
            line = f"{C_DIM}(no image selected){RESET}"
        out.append(f"{C_BORDER}│{RESET} {_fit(line, inner - 2)} {C_BORDER}│{RESET}")

        # meta
        meta = (f"{C_LABEL}routers{RESET}  {len(self.hosts)}   "
                f"{C_LABEL}workers{RESET}  {self.workers}   "
                f"{C_LABEL}mode{RESET}  {self.mode}")
        out.append(f"{C_BORDER}│{RESET} {_fit(meta, inner - 2)} {C_BORDER}│{RESET}")
        out.append(f"{C_BORDER}├{'─' * inner}┤{RESET}")

        # host table (capped so it never eats the log)
        hdr = f"{'HOST':<15} {'PHASE':<28} {'PROGRESS':<20} {'PCT':>4}  {'TIME':>5}"
        out.append(f"{C_BORDER}│{RESET} {_fit(C_HEAD + hdr + RESET, inner - 2)} {C_BORDER}│{RESET}")
        max_hosts = max(1, rows - 16)
        shown = self.hosts[:max_hosts]
        for h in shown:
            out.append(f"{C_BORDER}│{RESET} {_fit(self._host_row(h), inner - 2)} {C_BORDER}│{RESET}")
        if len(self.hosts) > max_hosts:
            more = f"{C_DIM}… and {len(self.hosts) - max_hosts} more{RESET}"
            out.append(f"{C_BORDER}│{RESET} {_fit(more, inner - 2)} {C_BORDER}│{RESET}")
        out.append(f"{C_BORDER}├{'─' * inner}┤{RESET}")

        # log header
        out.append(f"{C_BORDER}│{RESET} {_fit(C_HEAD + 'LOG' + RESET, inner - 2)} {C_BORDER}│{RESET}")

        # fill remaining height with log lines
        log_space = max(1, rows - len(out) - 3)
        entries = list(self.log)[-log_space:]
        for stamp, host, msg in entries:
            line = f"{C_DIM}{stamp}{RESET}  {C_ACCENT}{host:<15}{RESET}  {msg}"
            out.append(f"{C_BORDER}│{RESET} {_fit(line, inner - 2)} {C_BORDER}│{RESET}")
        for _ in range(log_space - len(entries)):
            out.append(f"{C_BORDER}│{RESET} {' ' * (inner - 2)} {C_BORDER}│{RESET}")

        # footer
        out.append(f"{C_BORDER}├{'─' * inner}┤{RESET}")
        done = sum(1 for h in self.hosts if self._status(h)[0] == "done")
        failed = sum(1 for h in self.hosts if self._status(h)[0] == "failed")
        el = int(time.time() - self.start_ts)
        foot = (f"{C_DIM}done {done}/{len(self.hosts)}   failed {failed}   "
                f"elapsed {el // 60}:{el % 60:02d}   ·   Ctrl-C interrupts{RESET}")
        out.append(f"{C_BORDER}│{RESET} {_fit(foot, inner - 2)} {C_BORDER}│{RESET}")
        out.append(f"{C_BORDER}╰{'─' * inner}╯{RESET}")
        return out

    def _render(self):
        cols, rows = shutil.get_terminal_size((100, 30))
        frame = self._frame(cols, rows)[:rows]
        with self.lock:
            sys.stdout.write(CLEAR + "\n".join(frame) + "\n")
            sys.stdout.flush()

    def _loop(self):
        while not self.stop_evt.wait(0.15):
            try:
                self._render()
            except Exception:
                pass

    def start(self):
        if not self.tty:
            return
        sys.stdout.write(ALT_ON + CUR_HIDE)
        sys.stdout.flush()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop_ui(self):
        if not self.tty:
            return
        self.stop_evt.set()
        if self.thread:
            self.thread.join(timeout=2)
        sys.stdout.write(CUR_SHOW + ALT_OFF)
        sys.stdout.flush()


# ───────────────────────────── pickers ─────────────────────────────
def pick_image():
    while True:
        path = ask("firmware image (.bin)")
        if not path:
            return None
        if not os.path.isfile(path):
            print(f"  {C_BAD}✗ {path}: not a file{RESET}")
            continue
        try:
            info = analyze_image(path)
        except Exception as e:
            print(f"  {C_BAD}✗ {type(e).__name__}: {e}{RESET}")
            continue
        if not info["fit_offsets"]:
            print(f"  {C_BAD}✗ no FIT image in the first 8 MiB — wrong file?{RESET}")
            continue
        try:
            img = eng.load_image(path)
        except SystemExit as e:
            print(f"  {C_BAD}✗ {e.code}{RESET}")
            continue
        except Exception as e:
            print(f"  {C_BAD}✗ {type(e).__name__}: {e}{RESET}")
            continue
        print()
        for ln in image_lines(info):
            print("  " + ln)
        print()
        if confirm("use this image?", default=True):
            return img


def pick_hosts():
    print(f"\n{C_HEAD}Routers{RESET}")
    print("  One or more IPs (space or comma separated), or a path to a hosts file.")
    while True:
        raw = ask("host(s)")
        if not raw:
            return []
        if os.path.isfile(raw):
            try:
                with open(raw, encoding="utf-8-sig") as f:
                    hosts = [ln.split("#")[0].strip()
                             for ln in f if ln.split("#")[0].strip()]
            except OSError as e:
                print(f"  {C_BAD}✗ {e}{RESET}")
                continue
        else:
            hosts = [h.strip() for h in raw.replace(",", " ").split() if h.strip()]
        hosts = list(dict.fromkeys(hosts))
        if not hosts:
            print(f"  {C_BAD}✗ no hosts entered{RESET}")
            continue
        preview = ", ".join(hosts[:5]) + (" …" if len(hosts) > 5 else "")
        print(f"  {C_OK}✓{RESET} {len(hosts)} host(s): {preview}")
        if confirm("use these hosts?", default=True):
            return hosts


def pick_creds():
    user = os.environ.get("H3C_SSH_USER") or ask("router username", default="root")
    pw = os.environ.get("H3C_SSH_PASS")
    if pw is None:
        try:
            pw = getpass.getpass(f"  password for {user}: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
    return user, pw


def default_settings():
    return {
        "port": int(os.environ.get("H3C_SSH_PORT", "99")),
        "protocol": os.environ.get("H3C_SSH_PROTO", "auto"),
        "timeout": 8,
        "workers": 1,
        "boot_timeout": 600,
        "download_timeout": 900,
        "keep_going": False,
        "no_reboot_on_fail": False,
        "force_model": False,
        "redo": False,
        "url": os.environ.get("H3C_URL") or None,
        "serve_port": 8080,
        "serve_ip": None,
        "out": ".",
    }


def settings_menu(s):
    while True:
        print(f"\n{C_HEAD}Settings{RESET}")
        for k in sorted(s):
            print(f"  {C_LABEL}{k:<20}{RESET} = {s[k]}")
        raw = ask("key=value  (blank back, 'reset' defaults)")
        if not raw:
            return
        if raw == "reset":
            s.update(default_settings())
            continue
        if "=" not in raw:
            print(f"  {C_BAD}✗ expected key=value{RESET}")
            continue
        k, v = (x.strip() for x in raw.split("=", 1))
        if k not in s:
            print(f"  {C_BAD}✗ unknown key {k!r}{RESET}")
            continue
        orig = s[k]
        try:
            if isinstance(orig, bool):
                s[k] = v.lower() in ("1", "true", "yes", "on")
            elif isinstance(orig, int):
                s[k] = int(v)
            else:
                s[k] = v or None
        except ValueError:
            print(f"  {C_BAD}✗ not a valid value for {k}{RESET}")
            continue
        print(f"  {C_OK}✓ {k} = {s[k]}{RESET}")


# ───────────────────────────── actions ─────────────────────────────
def do_analyze():
    path = ask("firmware image (.bin)")
    if not path:
        return
    if not os.path.isfile(path):
        print(f"  {C_BAD}✗ {path}: not a file{RESET}")
        return
    try:
        info = analyze_image(path)
    except Exception as e:
        print(f"  {C_BAD}✗ {type(e).__name__}: {e}{RESET}")
        return
    print()
    print(box("image", image_lines(info)))
    pause()


def do_deep_probe(s):
    image = pick_image()
    if not image:
        return
    hosts = pick_hosts()
    if not hosts:
        return
    creds = pick_creds()
    if not creds:
        return
    user, pw = creds
    for h in hosts:
        probe_one(h, s, user, pw, image)


def probe_one(host, s, user, pw, image):
    print(f"\n  connecting to {host}:{s['port']} …")
    buf = io.StringIO()
    real = sys.stdout
    sys.stdout = buf
    try:
        conn = probe_connect(host, s["port"], user, pw, s["protocol"], s["timeout"])
    except Exception as e:
        sys.stdout = real
        print(f"  {C_BAD}✗ cannot log in: {type(e).__name__}: {e}{RESET}")
        return
    finally:
        sys.stdout = real
    speak = buf.getvalue().strip()
    if speak:
        print(f"  {speak}")

    sections = list(SECTIONS)
    if s["url"]:
        import shlex
        u = shlex.quote(s["url"])
        sections.append(("reach-url",
            f"if command -v curl >/dev/null 2>&1; then curl -sS -I -m 10 {u} 2>&1 | head -15; "
            f"else wget --spider -S -T 10 {u} 2>&1 | head -15; fi"))

    ui = LiveUI(title="nx30flash · deep probe", image=image,
                hosts=[host], mode="probe", stages=len(sections), workers=1)
    ui.start()
    results = {}
    report = [f"nx30flash deep probe  {datetime.datetime.now():%Y-%m-%d %H:%M:%S}  "
              f"host={host}  (read-only)"]
    if image:
        report += ["", "=== firmware image (local) ==="] + image_lines(image)
    try:
        ui.say(host, f"connected ({s['protocol']})")
        for i, (name, cmd) in enumerate(sections):
            ui.stat(host, i, name)
            code, out = conn.run(cmd, timeout=25)
            results[name] = redact(out)
            report += ["", f"=== {name} ===", results[name] or "(empty)"]
            ui.stat(host, i + 1, name)
            ui.say(host, f"{name} {'timed out' if code == 124 else 'ok'}")
        ui.stat(host, len(sections), "done")
    except Exception as e:
        ui.say(host, f"error: {type(e).__name__}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        ui.stop_ui()

    try:
        fl = findings(results, image)
    except Exception:
        fl = []
    if fl:
        print(f"\n{C_HEAD}Findings{RESET}")
        for ln in fl:
            print("  " + ln)
        report = report[:1] + ["", "=== findings ==="] + fl + report[1:]

    try:
        os.makedirs(s["out"], exist_ok=True)
    except OSError:
        pass
    path = os.path.join(s["out"], f"probe_{host}_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(report) + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        print(f"\n  {C_OK}✓ report saved{RESET} {path}")
    except OSError as e:
        print(f"\n  {C_BAD}✗ could not save report: {e}{RESET}")

    pause()


def do_upgrade(s, go):
    image = pick_image()
    if not image:
        return
    hosts = pick_hosts()
    if not hosts:
        return
    creds = pick_creds()
    if not creds:
        return
    user, pw = creds

    s = dict(s)  # local copy so we don't mutate the user's menu settings

    print()
    print(box("plan", [
        f"{C_LABEL}image{RESET}    {image['name']}  {image['size'] / 1048576:.1f} MiB  "
        f"{image['product'] or '?'} {image['version']}",
        f"{C_LABEL}sha256{RESET}   {image['sha256']}",
        f"{C_LABEL}routers{RESET}  {len(hosts)}  "
        f"({', '.join(hosts[:4])}{' …' if len(hosts) > 4 else ''})",
        f"{C_LABEL}workers{RESET}  {s['workers']}",
        f"{C_LABEL}mode{RESET}     {'UPGRADE (flashes routers)' if go else 'QUICK CHECK (read-only)'}",
    ]))

    if not image.get("product"):
        if confirm("image has no product string — force anyway?", default=False):
            s["force_model"] = True

    try:
        with open(os.path.join(s["out"], "upgrade_state.json"), encoding="utf-8") as f:
            prev = json.load(f).get(image["sha256"], {})
    except (OSError, ValueError):
        prev = {}
    already = [h for h in hosts if prev.get(h) == "UPGRADED"]
    if already and not s["redo"]:
        if confirm(f"{len(already)} host(s) already upgraded — redo?", default=False):
            s["redo"] = True

    if go:
        print()
        print(f"  {C_WARN}This will FLASH {len(hosts)} router(s). Do not power off.{RESET}")
        raw = input(f"  {C_WARN}Type UPGRADE to confirm, or anything else to cancel: {RESET}").strip()
        if raw != "UPGRADE":
            print(f"  {C_DIM}cancelled{RESET}")
            return
    else:
        if not confirm(f"Run quick check on {len(hosts)} host(s)?", default=True):
            return

    run_fleet(s, image, hosts, (user, pw), go)


def run_fleet(s, img, hosts, creds, go):
    srv = None
    if s["url"]:
        def url_for(_h):
            return s["url"]
    else:
        srv = eng.make_server(img["path"], s["serve_port"])
        quoted = urllib.parse.quote(img["name"])

        def url_for(h):
            ip = s["serve_ip"] or eng.local_ip_for(h, s["port"])
            return f"http://{ip}:{s['serve_port']}/{quoted}"

    state_path = os.path.join(s["out"], "upgrade_state.json")
    try:
        with open(state_path, encoding="utf-8") as f:
            all_state = json.load(f)
    except (OSError, ValueError):
        all_state = {}
    ctl = {"abort": threading.Event(),
           "state": all_state.setdefault(img["sha256"], {})}

    a = argparse.Namespace(
        port=s["port"], user=creds[0], password=creds[1],
        protocol=s["protocol"], timeout=s["timeout"],
        go=go, yes=True, workers=s["workers"],
        boot_timeout=s["boot_timeout"], download_timeout=s["download_timeout"],
        keep_going=s["keep_going"], no_reboot_on_fail=s["no_reboot_on_fail"],
        force_model=s["force_model"], redo=s["redo"], out=s["out"],
    )

    ui = LiveUI(title=f"nx30flash · {'upgrade' if go else 'quick check'}",
                image=img, hosts=hosts,
                mode="upgrade" if go else "check",
                stages=eng.STAGES, workers=s["workers"])

    # wire the engine's UI hooks to this LiveUI
    eng.STAT = ui.stat_dict
    eng.stat = ui.stat
    eng.say = ui.say

    for h in hosts:
        ui.stat(h, 0, "waiting")
    ui.start()

    results, rlock = [], threading.Lock()

    def run(h):
        try:
            r = eng.upgrade_one(h, a, img, url_for, creds, ctl)
        except Exception as e:
            r = {"host": h, "status": "ERROR",
                 "detail": f"{type(e).__name__}: {e}",
                 "before_boot": "", "after_boot": "", "seconds": 0}
            ui.say(h, f"ERROR: {e}")
        with rlock:
            results.append(r)
            if r["status"] == "UPGRADED":
                ctl["state"][h] = "UPGRADED"
                try:
                    with open(state_path, "w", encoding="utf-8") as f:
                        json.dump(all_state, f, indent=1)
                except OSError:
                    pass
        return r

    try:
        from concurrent.futures import ThreadPoolExecutor
        if go and len(hosts) > 1:
            run(hosts[0])
            rest = hosts[1:]
            if rest and not ctl["abort"].is_set():
                with ThreadPoolExecutor(max_workers=max(1, s["workers"])) as ex:
                    list(ex.map(run, rest))
        else:
            with ThreadPoolExecutor(max_workers=max(1, s["workers"])) as ex:
                list(ex.map(run, hosts))
    except KeyboardInterrupt:
        ctl["abort"].set()
        print(f"\n{C_WARN}interrupted — waiting for in-flight operations{RESET}")
    finally:
        ui.stop_ui()
        if srv:
            try:
                srv.shutdown()
            except Exception:
                pass

    try:
        os.makedirs(s["out"], exist_ok=True)
    except OSError:
        pass
    path = os.path.join(
        s["out"],
        f"{'upgrade' if go else 'check'}_results_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv",
    )
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["host", "status", "detail",
                                          "before_boot", "after_boot", "seconds"])
        w.writeheader()
        w.writerows(results)

    bad_set = eng.HALT | {"BLOCKED", "UNREACHABLE", "NOT_STARTED"}
    print(f"\n{C_HEAD}Summary{RESET}")
    for r in results:
        st = r["status"]
        if st in ("UPGRADED", "READY", "SKIPPED"):
            color = C_OK
        elif st in bad_set:
            color = C_BAD
        else:
            color = C_WARN
        print(f"  {color}{st:<18}{RESET} {r['host']:<15} {r['detail'][:80]}")
    print(f"\n  {C_DIM}saved:{RESET} {path}")
    pause()


# ───────────────────────────── main ─────────────────────────────
def main():
    load_env()
    if os.name == "nt":
        os.system("")  # enable VT processing on Windows 10+
    s = default_settings()

    banner = box("nx30flash", ["  H3C NX30 firmware probe & upgrade"], width=70)
    while True:
        print()
        print(banner)
        print()
        print(f"  {C_ACCENT}[1]{RESET}  Analyze image     inspect a .bin locally")
        print(f"  {C_ACCENT}[2]{RESET}  Deep probe        read-only device inspection (saves report)")
        print(f"  {C_ACCENT}[3]{RESET}  Quick check       preflight only, no flashing")
        print(f"  {C_ACCENT}[4]{RESET}  Upgrade           preflight + flash, live progress")
        print(f"  {C_ACCENT}[5]{RESET}  Settings")
        print(f"  {C_ACCENT}[6]{RESET}  Quit")
        print(f"\n  {C_DIM}tip: probe a lab unit first; the tool will refuse to flash a mismatched image{RESET}")
        print()
        try:
            choice = input(f"  {C_ACCENT}>{RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice in ("1", "a", "analyze"):
            do_analyze()
        elif choice in ("2", "p", "probe"):
            do_deep_probe(s)
        elif choice in ("3", "c", "check"):
            do_upgrade(s, go=False)
        elif choice in ("4", "u", "upgrade"):
            do_upgrade(s, go=True)
        elif choice in ("5", "s", "settings"):
            settings_menu(s)
        elif choice in ("6", "q", "quit", "exit"):
            return 0
        else:
            print(f"  {C_BAD}✗ unknown choice{RESET}")
            time.sleep(0.4)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)