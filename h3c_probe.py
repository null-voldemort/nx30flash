#!/usr/bin/env python3
import argparse
import datetime
import getpass
import hashlib
import os
import re
import shlex
import socket
import sys
import tarfile
import time

try:
    import paramiko
except ImportError:
    paramiko = None

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
MARK = re.compile(r"__END_(\d+)_MARK")
REJECTED = re.compile(r"login\s+(incorrect|failed)|authentication\s+fail|(incorrect|invalid|wrong|bad)\s+password")

class Ssh:
    def __init__(self, host, port, user, pw, timeout):
        if paramiko is None:
            raise RuntimeError("router speaks SSH but paramiko is not installed (pip install paramiko)")
        self.c = paramiko.SSHClient()
        self.c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.c.connect(host, port=port, username=user, password=pw, timeout=timeout,
                       banner_timeout=timeout, auth_timeout=timeout, look_for_keys=False, allow_agent=False)

    def run(self, cmd, timeout=20):
        _, o, e = self.c.exec_command(cmd, timeout=timeout)
        out = o.read().decode(errors="replace") + e.read().decode(errors="replace")
        return o.channel.recv_exit_status(), out.strip()

    def close(self):
        self.c.close()

class Telnet:
    def __init__(self, host, port, user, pw, timeout, sock=None):
        self.user, self.pw, self.timeout, self._pend = user, pw, timeout, b""
        self.s = sock or socket.create_connection((host, port), timeout)
        try:
            self._login()

            self.run("stty -echo 2>/dev/null; true", timeout=8)
        except BaseException:
            self.s.close()
            raise

    def close(self):
        try:
            self._line("exit")
        except OSError:
            pass
        self.s.close()

    def _line(self, text):
        self.s.sendall(text.encode() + b"\r\n")

    def _read(self, wait):
        self.s.settimeout(wait)
        try:
            data = self.s.recv(4096)
        except socket.timeout:
            return ""
        if not data:
            raise ConnectionError("connection closed by the router")
        return self._strip_iac(data)

    def _drain(self, wait=0.3):
        while self._read(wait):
            pass

    def _strip_iac(self, data):
        data, self._pend = self._pend + data, b""
        out, i, n = bytearray(), 0, len(data)
        while i < n:
            b = data[i]
            if b != IAC:
                out.append(b)
                i += 1
            elif i + 1 >= n:
                self._pend = data[i:]
                break
            elif data[i + 1] == IAC:
                out.append(IAC)
                i += 2
            elif data[i + 1] in (DO, DONT, WILL, WONT):
                if i + 2 >= n:
                    self._pend = data[i:]
                    break
                cmd, opt = data[i + 1], data[i + 2]
                if cmd == DO:
                    self.s.sendall(bytes([IAC, WONT, opt]))
                elif cmd == WILL:
                    self.s.sendall(bytes([IAC, DO if opt in (1, 3) else DONT, opt]))
                i += 3
            elif data[i + 1] == SB:
                end = data.find(bytes([IAC, SE]), i + 2)
                if end < 0:
                    self._pend = data[i:]
                    break
                i = end + 2
            else:
                i += 2
        return ANSI.sub("", out.decode("utf-8", "replace"))

    def _login(self):
        buf, sent_user, sent_pass = "", False, False
        deadline = time.time() + self.timeout * 2
        while time.time() < deadline:
            buf += self._read(0.5)
            low = buf.lower().replace("\r", "")
            if not sent_user and re.search(r"(login|user ?name)\s*:\s*$", low):
                self._line(self.user)
                sent_user, buf = True, ""
            elif not sent_pass and re.search(r"pass(word|code)?\s*:\s*$", low):
                self._line(self.pw)
                sent_pass, buf = True, ""
            elif sent_pass and (REJECTED.search(low) or re.search(r"(login|user ?name)\s*:\s*$", low)):
                raise PermissionError("telnet login rejected (wrong username/password)")
            elif (sent_pass or not sent_user) and re.search(r"[#$>]\s*$", low):
                break
        self._drain(0.5)
        code, _ = self.run("true", timeout=8)
        if code != 0:
            raise RuntimeError("logged in over Telnet, but no Linux shell answered (restricted CLI?)")

    def run(self, cmd, timeout=20):
        self._drain(0.2)
        self._line(f'{cmd}; echo "__END_$?_MARK"')
        buf, end = "", time.time() + timeout
        while time.time() < end:
            buf += self._read(0.5)
            m = MARK.search(buf)
            if m:
                out = buf[:m.start()]
                echo = out.find("__END_$?_MARK")
                if echo >= 0:
                    nl = out.find("\n", echo)
                    out = out[nl + 1:] if nl >= 0 else ""
                return int(m.group(1)), out.replace("\r", "").strip()
        return 124, buf.replace("\r", "").strip()

def connect(host, port, user, pw, protocol, timeout):
    sock = None
    if protocol == "auto":
        sock = socket.create_connection((host, port), timeout)
        sock.settimeout(3)
        try:
            first = sock.recv(8, socket.MSG_PEEK)
        except socket.timeout:
            first = b""
        if first.startswith(b"SSH-"):
            protocol = "ssh"
            sock.close()
            sock = None
        else:
            protocol = "telnet"
    print(f"  {host}:{port} speaks {protocol.upper()}")
    if protocol == "ssh":
        return Ssh(host, port, user, pw, timeout)
    return Telnet(host, port, user, pw, timeout, sock)

TOOLS = ("sysupgrade curl wget fw_printenv fw_setenv mtd nandwrite ubiattach ubiformat flash_erase "
         "md5sum sha256sum sha1sum tar gzip zcat nc tftp ftpget opkg uhttpd busybox")

SECTIONS = [
    ("identity", "id; uname -a; cat /proc/cmdline; uptime"),
    ("release", "cat /etc/openwrt_release /etc/os-release /etc/banner 2>&1 | head -40"),
    ("version-files", 'for f in /etc/*version* /etc/*release*; do [ -f "$f" ] && { echo "== $f"; head -n 5 "$f"; }; done 2>&1 | head -40'),
    ("board", "ubus call system board 2>&1 | head -30; cat /tmp/sysinfo/model /tmp/sysinfo/board_name 2>&1; "
              "cat /proc/device-tree/model 2>/dev/null; echo; cat /proc/device-tree/compatible 2>/dev/null | tr '\\0' ' '"),
    ("cpu", "grep -m4 -iE 'model|system type|machine|hardware|cpu' /proc/cpuinfo"),
    ("mtd", "cat /proc/mtd 2>&1; echo ---; cat /proc/partitions 2>&1; echo ---; ls -l /dev/mtd* /dev/ubi* 2>&1 | head -40"),
    ("memory", "grep -E 'MemTotal|MemFree|MemAvailable' /proc/meminfo"),
    ("tmp-space", "df -k /tmp 2>&1 | tail -n 1"),
    ("disk", "df -h 2>&1 | head -20; mount | grep -E 'overlay|ubi|jffs|squashfs|/tmp' | head -10"),
    ("tools", f'for t in {TOOLS}; do p=$(command -v $t 2>/dev/null); echo "$t: ${{p:-MISSING}}"; done'),
    ("download", 'curl -V 2>&1 | head -3; echo "CA certs: $(ls /etc/ssl/certs 2>/dev/null | wc -l)"; wget --help 2>&1 | head -2'),
    ("upgrade-files", "ls -l /sbin/sysupgrade /usr/sbin/sysupgrade 2>&1; ls -l /lib/upgrade 2>&1 | head -30; "
                      "ls /sbin /usr/sbin /bin /usr/bin /etc /lib /usr/lib 2>/dev/null | grep -iE 'upgrade|firmware|flash|fwup|ota|cwmp|tr069' | sort -u | head -40"),
    ("sysupgrade-script", 'for f in /sbin/sysupgrade /usr/sbin/sysupgrade; do [ -f $f ] && { if head -c 4 $f | grep -q ELF; then echo "($f is a binary)"; '
                          'else echo "== $f (first 80 lines)"; head -n 80 $f; fi; }; done; true'),
    ("platform.sh", "[ -f /lib/upgrade/platform.sh ] && head -n 150 /lib/upgrade/platform.sh; true"),
    ("sysupgrade.conf", "cat /etc/sysupgrade.conf 2>&1 | head -30"),
    ("bootloader-env", "fw_printenv 2>&1 | head -60; echo ---; cat /etc/fw_env.config 2>&1 | head -10"),

    ("sysupgrade-rest", "sed -n '81,220p' /sbin/sysupgrade 2>&1"),
    ("platform.sh-rest", "[ -f /lib/upgrade/platform.sh ] && sed -n '151,600p' /lib/upgrade/platform.sh; true"),
    ("nand.sh", "head -n 300 /lib/upgrade/nand.sh 2>&1"),
    ("vendor-upgrade-scripts",
     'for f in $(find /sbin /usr/sbin /bin /usr/bin /etc /lib -maxdepth 2 -type f \\( -name firmwarecheck -o -name upgrade.sh -o -name upgrade -o -name upgraded -o -name firmware \\) 2>/dev/null); do '
     'if head -c 4 $f | grep -q ELF; then echo "== $f (binary)"; else echo "== $f"; head -n 60 $f; fi; done 2>&1 | head -300'),
    ("boot-slots", 'ls -R /proc/boot_info 2>&1 | head -40; for f in /proc/boot_info/rootfs/*; do [ -f "$f" ] && echo "$f: $(head -c 100 $f)"; done 2>&1 | head -20'),
    ("onlineupdate", "cat /etc/config/onlineupdate 2>&1 | head -30"),
    ("config-persist", "ls -la /mnt/config /mnt/backup 2>&1 | head -40; ls /lib/upgrade/keep.d 2>&1; cat /lib/upgrade/keep.d/* 2>&1 | head -30"),
    ("mnt-config-names", "echo /mnt/config:; ls /mnt/config 2>&1 | tr '\\n' ' '; echo; echo /mnt/backup/config:; ls /mnt/backup/config 2>&1 | tr '\\n' ' '"),

    ("upgrade.sh-rest", "sed -n '61,220p' /bin/upgrade.sh 2>&1"),
    ("firmwarecheck-strings", "strings /usr/bin/firmwarecheck 2>&1 | head -80"),
    ("upgraded-strings", "strings /sbin/upgraded 2>&1 | head -80"),
    ("onlineupdate-init", "head -n 120 /etc/init.d/onlineupdate 2>&1"),
    ("tr069", "ps w 2>/dev/null | grep -iE 'cwmp|tr069' | grep -v grep; ls /etc/config 2>&1; "
              'for c in cwmp easycwmp icwmp cwmpd tr069; do [ -f /etc/config/$c ] && { echo "== /etc/config/$c"; cat /etc/config/$c; }; done; true'),
]

def redact(text):
    out = []
    for ln in text.splitlines():
        ln = re.sub(r"(-u\s+)\S+", r"\1<redacted>", ln)
        ln = re.sub(r"(?i)(\b\w*(?:pass|psk|secret|token|username|key)\w*\b['\"]?\s*[=:]?\s*['\"]?)[^\s'\"]+",
                    r"\1<redacted>", ln)
        out.append(ln)
    return "\n".join(out)

MAGICS = [
    (b"\x27\x05\x19\x56", 0, "U-Boot legacy uImage"),
    (b"\xd0\x0d\xfe\xed", 0, "device-tree / FIT image (kernel+dtb)"),
    (b"hsqs", 0, "SquashFS (root filesystem)"),
    (b"UBI#", 0, "UBI image (raw NAND volume)"),
    (b"UBI!", 0, "UBI volume table"),
    (b"HDR0", 0, "TRX firmware container"),
    (b"\x1f\x8b", 0, "gzip-compressed"),
    (b"\xfd7zXZ\x00", 0, "xz-compressed"),
    (b"BZh", 0, "bzip2-compressed"),
    (b"PK\x03\x04", 0, "ZIP archive (needs unpacking first)"),
    (b"\x7fELF", 0, "ELF executable"),
    (b"ustar", 257, "tar archive (OpenWrt sysupgrade-style image)"),
]
KEYWORDS = re.compile(rb"NX30|H3C|supported_devices|board_name|DISTRIB_|OpenWrt|sysupgrade|cwmp|tr069|version", re.I)

def analyze_image(path):
    info = {"path": path}
    st = os.stat(path)
    info["size"] = st.st_size
    sha, md5 = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as f:
        head = f.read(8 * 1024 * 1024)
        sha.update(head)
        md5.update(head)
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            sha.update(chunk)
            md5.update(chunk)
    info["sha256"], info["md5"] = sha.hexdigest(), md5.hexdigest()
    info["head_hex"] = head[:16].hex(" ")
    info["magic"] = next((name for sig, off, name in MAGICS if head[off:off + len(sig)] == sig),
                         "unknown (raw/vendor format - check the vendor's upgrade notes)")
    seen, hits = set(), []
    for m in re.finditer(rb"[\x20-\x7e]{6,120}", head):
        if KEYWORDS.search(m.group()):
            s = m.group().decode("ascii", "replace")
            if s not in seen:
                seen.add(s)
                hits.append(s)
        if len(hits) >= 15:
            break
    info["strings"] = hits

    info["fit_offsets"] = [m.start() for m in re.finditer(re.escape(b"\xd0\x0d\xfe\xed"), head)][:4]
    info["fit_check"] = ""
    if info["fit_offsets"]:
        off = info["fit_offsets"][0]
        if len(head) >= off + 8:
            total = int.from_bytes(head[off + 4:off + 8], "big")
            rest = info["size"] - off
            info["fit_check"] = (f"FIT header at byte {off} says its size is {total:,}; bytes left in the file from there: {rest:,} "
                                 f"-> {'MATCH (looks like vendor header + one FIT image)' if total == rest else 'differ (FIT may use external data or have a trailer)'}")
    info["tar_members"] = []
    try:
        with tarfile.open(path) as t:
            info["tar_members"] = [m.name for m in t.getmembers()[:12]]
    except Exception:
        pass
    return info

def image_lines(info):
    L = [f"file     : {info['path']}",
         f"size     : {info['size']:,} bytes ({info['size'] / 1048576:.1f} MiB)",
         f"sha256   : {info['sha256']}",
         f"md5      : {info['md5']}",
         f"first 16 : {info['head_hex']}",
         f"format   : {info['magic']}"]
    if info.get("fit_offsets"):
        L.append("FIT magic at byte offset(s): " + ", ".join(str(o) for o in info["fit_offsets"]))
        if info.get("fit_check"):
            L.append("   " + info["fit_check"])
    if info["tar_members"]:
        L.append("tar holds: " + ", ".join(info["tar_members"]))
    if info["strings"]:
        L.append("strings that mention board/version (first 8 MiB):")
        L += [f"   {s}" for s in info["strings"]]
    return L

def tools_found(results):
    found = {}
    for ln in results.get("tools", "").splitlines():
        m = re.match(r"(\S+): (\S+)$", ln.strip())
        if m:
            found[m.group(1)] = None if m.group(2) == "MISSING" else m.group(2)
    return found

def kb(pattern, text):
    m = re.search(pattern, text or "")
    return int(m.group(1)) if m else None

def findings(results, image):
    tools = tools_found(results)
    lines = []

    def add(flag, text):
        lines.append(f"  [{flag}] {text}")

    rel = results.get("release", "") + "\n" + results.get("board", "")
    ver = re.search(r"DISTRIB_DESCRIPTION='?([^'\n]+)", rel) or re.search(r'"release":\s*\{[^}]*"description":\s*"([^"]+)"', rel, re.S)
    model = re.search(r'"model":\s*"([^"]+)"', rel) or re.search(r"DISTRIB_TARGET='?([^'\n]+)", rel)
    add("..", f"firmware: {ver.group(1).strip() if ver else 'not recognised - read the release/version-files sections'}")
    add("..", f"board/model: {model.group(1).strip() if model else 'not recognised - read the board section'}")

    su = tools.get("sysupgrade")
    add("OK" if su else "NO", f"sysupgrade: {su or 'not found - need the vendor tool or raw mtd/ubi writes (read upgrade-files)'}")
    dl = [t for t in ("curl", "wget") if tools.get(t)]
    add("OK" if dl else "NO", f"can download on the router: {', '.join(dl) if dl else 'neither curl nor wget - would have to push the file in'}")
    sums = [t for t in ("sha256sum", "md5sum") if tools.get(t)]
    add("OK" if sums else "NO", f"checksum tool: {', '.join(sums) if sums else 'none - cannot verify the image on the router'}")

    dl_out = results.get("download", "")
    tls = bool(re.search(r"OpenSSL|mbed ?TLS|wolfSSL|GnuTLS", dl_out, re.I)) and "https" in dl_out.lower()
    certs = kb(r"CA certs: (\d+)", dl_out) or 0
    add("OK" if tls and certs else "??", f"HTTPS from the router: {'curl has TLS' if tls else 'no TLS in curl'}, {certs} CA certs "
        f"-> {'ok' if tls and certs else 'use plain http on your management network instead'}")

    layout = (results.get("mtd", "") + "\n" + results.get("bootloader-env", "")).lower()
    dual = re.search(r"kernel[_-]?[0-9]|rootfs[_-]?[0-9]|firmware[12]|image[_-]?[ab]\b|bootbank|bootnum|boot_part|flag_boot|bootside|upgrade_available|active_slot|slot[_-]?[ab]", layout)
    add("OK" if dual else "??", f"dual-partition (A/B) hint: {'yes - matched ' + repr(dual.group()) if dual else 'not obvious. A single-image device has no fallback if a flash fails'}")
    add("OK" if tools.get("fw_printenv") else "??", f"bootloader env readable: {'yes' if tools.get('fw_printenv') else 'fw_printenv missing'}")

    avail = kb(r"MemAvailable:\s+(\d+)", results.get("memory", "")) or kb(r"MemFree:\s+(\d+)", results.get("memory", ""))
    total = kb(r"MemTotal:\s+(\d+)", results.get("memory", ""))
    tmpm = re.search(r"(\d+)\s+(\d+)\s+(\d+)\s+\d+%", results.get("tmp-space", ""))
    tmp_free = int(tmpm.group(3)) if tmpm else None
    add("..", f"RAM: {total // 1024 if total else '?'} MiB total, {avail // 1024 if avail else '?'} MiB available; "
              f"/tmp free: {tmp_free // 1024 if tmp_free else '?'} MiB")
    if image:
        need = image["size"] / 1024
        margin = 8 * 1024
        ok_ram = avail is not None and avail >= need * 2 + margin
        fits_once = avail is not None and avail >= need + margin
        ok_tmp = tmp_free is not None and tmp_free >= need + 1024
        flag = "OK" if ok_ram and ok_tmp else ("??" if fits_once and ok_tmp else "NO")
        add(flag,
            f"image {image['size'] / 1048576:.1f} MiB vs router: holds it once={'yes' if fits_once else 'NO'}, "
            f"/tmp {'fits' if ok_tmp else 'TOO SMALL/unknown'}; comfortable (2x image + 8 MiB) = {'yes' if ok_ram else 'NO'}. "
            f"Flashing can need extra RAM copies of the image (read the platform.sh sections) - confirm with a bench test")

    cw = results.get("tr069", "")
    add("..", f"your easycwmpd shim running: {'yes (a firmware upgrade or reboot will stop it)' if 'easycwmpd' in cw else 'no'}")
    native = re.search(r"== /etc/config/(cwmp|easycwmp|icwmp|cwmpd|tr069)\b", cw)
    add("..", f"native TR-069 client config in /etc/config: {'present (' + native.group(1) + ') - see tr069 section' if native else 'none found'}")

    url = results.get("reach-url")
    if url is not None:
        ok = bool(re.search(r"HTTP/\S+\s+(200|206|301|302)", url))
        add("OK" if ok else "NO", f"router can reach your firmware URL: {'yes' if ok else 'no - see reach-url section'}")
    return lines

def load_env(path=".env"):
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass

def main():
    load_env()
    p = argparse.ArgumentParser(description="Read-only firmware-upgrade capability probe for one router.")
    p.add_argument("--host", help="router IP (omit to only analyse --image)")
    p.add_argument("--port", type=int, default=99, help="telnet/SSH port (default 99, like fleet.py)")
    p.add_argument("--user", default=os.environ.get("H3C_SSH_USER"))
    p.add_argument("--password", default=os.environ.get("H3C_SSH_PASS"))
    p.add_argument("--protocol", choices=["auto", "ssh", "telnet"], default="auto")
    p.add_argument("--image", help="local firmware .bin to analyse (size, sha256, format, board strings)")
    p.add_argument("--url", help="URL the router should download the image from; checked with a HEAD request only")
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--out", default=".", help="folder for the saved report")
    a = p.parse_args()
    if not a.host and not a.image:
        p.error("give --host and/or --image")

    report = [f"h3c_probe report  {datetime.datetime.now():%Y-%m-%d %H:%M:%S}  host={a.host or '-'}  (read-only, secrets masked)"]
    image = None
    if a.image:
        print(f"Analysing {a.image} ...")
        image = analyze_image(a.image)
        report += ["", "=== firmware image (local) ==="] + image_lines(image)
        print("\n".join("  " + l for l in image_lines(image)))

    results = {}
    if a.host:
        user = a.user or input("router username: ").strip()
        pw = a.password if a.password is not None else getpass.getpass(f"password for {user}@{a.host}: ")
        print(f"\nConnecting to {a.host} (READ-ONLY probe) ...")
        try:
            conn = connect(a.host, a.port, user, pw, a.protocol, a.timeout)
        except Exception as e:
            print(f"  cannot log in: {type(e).__name__}: {e}")
            return 2
        sections = list(SECTIONS)
        if a.url:
            u = shlex.quote(a.url)
            sections.append(("reach-url", f"if command -v curl >/dev/null 2>&1; then curl -sS -I -m 10 {u} 2>&1 | head -15; "
                                          f"else wget --spider -S -T 10 {u} 2>&1 | head -15; fi"))
        try:
            for name, cmd in sections:
                print(f"  reading {name} ...", end="", flush=True)
                code, out = conn.run(cmd, timeout=25)
                results[name] = redact(out)
                print(" timed out" if code == 124 else " ok")
                report += ["", f"=== {name} ===", results[name] or "(empty)"]
        finally:
            conn.close()

        print("\nWhat this tells us:")
        fl = findings(results, image)
        print("\n".join(fl))
        report = report[:1] + ["", "=== findings ==="] + fl + report[1:]

        path = os.path.join(a.out, f"probe_{a.host}_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(report) + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        print(f"\nFull report saved: {path}")
        print("Secrets are masked, but the report still has the MAC/serial and firmware details - share it with care.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
