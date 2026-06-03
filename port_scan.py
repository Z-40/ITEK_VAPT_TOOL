#!/usr/bin/env python3
"""
PortScan Pro — Pure Python, zero dependencies.
Hardened Edition with Protocol & Version Fingerprinting Engine.
Usage: python portscanner.py <target> [options]
"""

import socket
import argparse
import sys
import time
import ipaddress
import concurrent.futures
import threading
import os
import json
import re
from datetime import datetime

# ── ANSI colours (auto-disabled on Windows if no ANSI support) ────────────────
def _supports_ansi():
    if os.name == "nt":
        try:
            import ctypes
            kernel = ctypes.windll.kernel32
            kernel.SetConsoleMode(kernel.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = _supports_ansi()

def _c(code): return code if USE_COLOR else ""

R      = _c("\033[0m")
B      = _c("\033[1m")
DIM    = _c("\033[2m")
IT     = _c("\033[3m")
TEAL   = _c("\033[38;5;38m")
GREEN  = _c("\033[38;5;82m")
RED    = _c("\033[38;5;196m")
ORANGE = _c("\033[38;5;214m")
BLUE   = _c("\033[38;5;75m")
PURPLE = _c("\033[38;5;177m")
GREY   = _c("\033[38;5;242m")
WHITE  = _c("\033[38;5;255m")
YELLOW = _c("\033[38;5;226m")
CYAN   = _c("\033[38;5;51m")

# ── Service database ───────────────────────────────────────────────────────────
SERVICES = {
    21:    ("FTP",          RED,    "⚠  Plaintext credentials",    b""),
    22:    ("SSH",          GREEN,  "✔  Encrypted shell",          b""),
    23:    ("Telnet",       RED,    "⚠  Plaintext — retire this",   b"\r\n"),
    25:    ("SMTP",         ORANGE, "ℹ  Mail relay",                b"EHLO probe\r\n"),
    53:    ("DNS",          BLUE,   "ℹ  Name resolution",          None),
    80:    ("HTTP",         ORANGE, "ℹ  Plaintext web",             b"HEAD / HTTP/1.0\r\n\r\n"),
    110:   ("POP3",         ORANGE, "ℹ  Mail retrieval",            b""),
    111:   ("RPCBind",      RED,    "⚠  RPC exposure",              b""),
    135:   ("MSRPC",        RED,    "⚠  Windows RPC",               b""),
    139:   ("NetBIOS",      RED,    "⚠  Legacy SMB",                b""),
    143:   ("IMAP",         ORANGE, "ℹ  Mail access",               b""),
    161:   ("SNMP",         RED,    "⚠  Often misconfigured",       None),
    389:   ("LDAP",         ORANGE, "ℹ  Directory service",         b""),
    443:   ("HTTPS",        GREEN,  "✔  Encrypted web",             b""),
    445:   ("SMB",          RED,    "⚠  High attack surface",       b""),
    465:   ("SMTPS",        GREEN,  "✔  Secure mail",               b""),
    587:   ("SMTP/TLS",     GREEN,  "✔  Mail submission",           b""),
    636:   ("LDAPS",        GREEN,  "✔  Secure directory",          b""),
    993:   ("IMAPS",        GREEN,  "✔  Secure mail",               b""),
    995:   ("POP3S",        GREEN,  "✔  Secure mail",               b""),
    1433:  ("MSSQL",        RED,    "⚠  DB — restrict access",      b""),
    1521:  ("Oracle DB",    RED,    "⚠  DB — restrict access",      b""),
    2222:  ("SSH-alt",      ORANGE, "ℹ  Non-standard SSH",          b""),
    3000:  ("Dev Server",   ORANGE, "ℹ  App dev port",              b""),
    3306:  ("MySQL",        RED,    "⚠  DB — restrict access",      b""),
    3389:  ("RDP",          RED,    "⚠  Remote Desktop exposed",    b""),
    4444:  ("Metasploit",   RED,    "🚨 Known backdoor port",        b""),
    5432:  ("PostgreSQL",   RED,    "⚠  DB — restrict access",      b""),
    5900:  ("VNC",          RED,    "⚠  Remote desktop",            b""),
    6379:  ("Redis",        RED,    "⚠  Often unauth exposed",      b"PING\r\n"),
    7070:  ("Dev/Alt",      ORANGE, "ℹ  App alt port",              b""),
    8080:  ("HTTP-alt",     ORANGE, "ℹ  Proxy / web alt",           b"HEAD / HTTP/1.0\r\n\r\n"),
    8443:  ("HTTPS-alt",    GREEN,  "✔  Alt secure web",            b""),
    8888:  ("Jupyter",      ORANGE, "ℹ  Notebook server",           b"HEAD / HTTP/1.0\r\n\r\n"),
    9200:  ("Elasticsearch", RED,   "⚠  Often unauth exposed",      b"GET / HTTP/1.0\r\n\r\n"),
    27017: ("MongoDB",      RED,    "⚠  DB — restrict access",      b""),
}

# ── Nmap-style Protocol Fingerprints ───────────────────────────────────────────
FINGERPRINTS = [
    {
        "name": "SSH",
        "regex": re.compile(r"SSH-([\d\.]+)-OpenSSH_([^ \r\n_-]+)(?:[-_]([^\r\n]+))?"),
        "format": lambda m: f"OpenSSH {m.group(2)}" + (f" ({m.group(3)})" if m.group(3) else "")
    },
    {
        "name": "HTTP",
        "regex": re.compile(r"Server:\s*([A-Za-z0-9\-_\.]+)/?([\d\.]+)?(?:\s*\(([^\)]+)\))?"),
        "format": lambda m: f"{m.group(1)}" + (f" {m.group(2)}" if m.group(2) else "") + (f" ({m.group(3)})" if m.group(3) else "")
    },
    {
        "name": "FTP",
        "regex": re.compile(r"220[- ](?:.*)(vsFTPd|ProFTPD|Pure-FTPd)[- ]([\d\.]+)?", re.IGNORECASE),
        "format": lambda m: f"{m.group(1)}" + (f" {m.group(2)}" if m.group(2) else "")
    },
    {
        "name": "MySQL",
        "regex": re.compile(r"([58]\.[\d\.]+-[a-zA-Z0-9\-~]+)"),
        "format": lambda m: f"MySQL {m.group(1)}"
    }
]

TOP_100 = [
    21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,514,
    587,631,636,993,995,1080,1194,1433,1521,1723,2049,2222,2375,3000,
    3306,3389,3690,4444,5000,5432,5900,5985,6379,7070,7777,8000,8080,
    8081,8443,8888,9000,9200,9300,27017
]

TOP_1000 = sorted(set(TOP_100 + list(range(1, 1025)) + [
    1080,1194,1433,1521,1723,2049,2082,2083,2086,2087,2095,2096,
    2222,2375,2376,3000,3128,3268,3269,3306,3389,3690,4443,4444,4848,
    5000,5001,5432,5555,5601,5900,5985,5986,6379,6443,7001,7070,7443,
    7777,8000,8008,8080,8081,8082,8083,8084,8085,8086,8088,8090,8180,
    8181,8443,8444,8500,8787,8888,8983,9000,9001,9042,9090,9091,9092,
    9200,9300,9418,9443,9999,10000,10001,11211,15672,16379,27017,27018,
    28017,50000,50070,50075,61616
]))

SCAN_PROFILES = {
    "quick":    (TOP_100,    1.0, "Top 50 ports   │  Fast sweep"),
    "standard": (TOP_1000,   1.5, "Top 1000 ports │  Service detection"),
    "deep":     (TOP_1000,   2.0, "Top 1000 ports │  Fingerprinting & Grab"),
    "full":     (list(range(1, 65536)), 2.0, "All 65535 ports │  Full range (slow)"),
    "custom":   ([],         1.5, "Custom ports   │  User-defined"),
}

# ── Progress tracker ───────────────────────────────────────────────────────────
class Progress:
    def __init__(self, total):
        self.total   = total
        self.done    = 0
        self.found   = 0
        self._lock   = threading.Lock()
        self._active = True
        self._thread = threading.Thread(target=self._render, daemon=True)
        self._thread.start()

    def tick(self, found=False):
        with self._lock:
            self.done += 1
            if found:
                self.found += 1

    def _render(self):
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        i = 0
        while self._active:
            with self._lock:
                d, t, f = self.done, self.total, self.found
            pct  = int(d / t * 100) if t else 0
            bar_w = 30
            filled = int(bar_w * d / t) if t else 0
            bar  = f"{GREEN}{'█' * filled}{GREY}{'░' * (bar_w - filled)}{R}"
            spin = chars[i % len(chars)]
            line = (f"  {TEAL}{spin}{R} Scanning  {bar}  "
                    f"{CYAN}{B}{pct:3d}%{R}  "
                    f"{GREY}{d}/{t} ports{R}  "
                    f"{GREEN}{B}{f} open{R}   ")
            print(f"\r{line}", end="", flush=True)
            i += 1
            time.sleep(0.08)

    def stop(self):
        self._active = False
        self._thread.join()
        print("\r" + " " * 80 + "\r", end="", flush=True)


# ── Core scanning engine ───────────────────────────────────────────────────────

def tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except (socket.timeout, OSError, ConnectionRefusedError):
        return False


def grab_banner(ip: str, port: int, timeout: float) -> str:
    meta  = SERVICES.get(port)
    probe = meta[3] if meta and meta[3] is not None else b""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if probe:
                s.sendall(probe)
            s.settimeout(2.0)
            data = b""
            try:
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 512:
                        break
            except (socket.timeout, OSError):
                pass
            banner = data.decode("utf-8", errors="replace").strip()
            return banner
    except (socket.timeout, OSError, ConnectionRefusedError):
        return ""


def match_fingerprint(banner: str, port: int) -> tuple[str, str]:
    """Matches the raw banner against our signature database."""
    if not banner:
        meta = SERVICES.get(port)
        return (meta[0] if meta else "unknown"), ""

    # Check database signatures
    for fp in FINGERPRINTS:
        match = fp["regex"].search(banner)
        if match:
            try:
                formatted_version = fp["format"](match)
                return fp["name"], formatted_version
            except Exception:
                pass

    # Fallback to defaults if no match
    meta = SERVICES.get(port)
    name = meta[0] if meta else socket.getservbyport(port, "tcp") if _safe_getserv(port) else "unknown"
    
    # Process basic readable string for unknown banners
    clean_banner = banner.strip().splitlines()[0][:50] if banner else ""
    return name, clean_banner


def scan_port(ip: str, port: int, timeout: float, grab: bool) -> dict | None:
    if not tcp_connect(ip, port, timeout):
        return None
    
    raw_banner = grab_banner(ip, port, timeout) if grab else ""
    service_name, identification = match_fingerprint(raw_banner, port)
    
    return {
        "port": port, 
        "proto": "tcp", 
        "service": service_name, 
        "banner": identification if identification else raw_banner.replace("\r\n", " ").strip()[:50]
    }


def _safe_getserv(port: int) -> bool:
    try:
        socket.getservbyport(port, "tcp")
        return True
    except (exclude := (OSError, socket.error)):
        return False


def run_scan_engine(ip: str, ports: list, timeout: float,
                    workers: int, grab_banners: bool) -> list:
    results = []
    prog    = Progress(len(ports))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout, grab_banners): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            prog.tick(found=res is not None)
            if res:
                results.append(res)

    prog.stop()
    return sorted(results, key=lambda x: x["port"])


# ── Host info ──────────────────────────────────────────────────────────────────

def resolve_target(target: str):
    try:
        ipaddress.ip_address(target)
        try:    hostname = socket.gethostbyaddr(target)[0]
        except (exclude := Exception): hostname  = target
        return target, hostname
    except ValueError:
        try:
            ip = socket.gethostbyname(target)
            return ip, target
        except socket.gaierror:
            fatal(f"Cannot resolve host: {target}")


def check_host_up(ip: str, timeout: float = 2.0) -> bool:
    for p in [80, 443, 22, 8080, 21, 25]:
        if tcp_connect(ip, p, timeout):
            return True
    return False


# ── Rendering ──────────────────────────────────────────────────────────────────

def banner_art():
    print(f"""
{TEAL}{B}╔══════════════════════════════════════════════════════════════╗
║  ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗  ██╗ ║
║  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗ ██║ ║
║  ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗██║ ║
║  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚████║ ║
║  ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚███║ ║
║  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝ ║
╠══════════════════════════════════════════════════════════════╣
║    P R O  v2  —  Pure Python  ·  Zero Dependencies  ·  CLI     ║
╚══════════════════════════════════════════════════════════════╝{R}
""")

def divider(char="─", width=72, color=GREY):
    print(f"{color}{char * width}{R}")

def section(title: str):
    w   = 72
    pad = (w - len(title) - 2) // 2
    r   = w - pad - len(title) - 2
    print(f"\n{TEAL}{B}{'─'*pad}  {title}  {'─'*r}{R}")

def elapsed(start: float) -> str:
    s = time.time() - start
    m, s = divmod(int(s), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"

def fatal(msg: str):
    print(f"\n{RED}{B}[FATAL]{R} {msg}\n")
    sys.exit(1)

def render_results(ip, hostname, open_ports, profile, timeout, duration, grab, json_path=None):
    section("HOST INFORMATION")
    print(f"  {GREY}IP Address  :{R}  {B}{WHITE}{ip}{R}")
    print(f"  {GREY}Hostname    :{R}  {B}{hostname}{R}")
    print(f"  {GREY}Status      :{R}  {GREEN}{B}UP{R}")

    section(f"OPEN PORTS  ({len(open_ports)} found)")

    if not open_ports:
        print(f"  {ORANGE}{B}[!]{R} No open ports found in scanned range.")
        print(f"  {GREY}Tip: The host may be firewalled. Try --timeout 3 for slower hosts.{R}")
    else:
        col_p  = 10
        col_pr = 7
        col_st = 11
        col_sv = 18
        print(f"  {TEAL}{B}{'PORT':<{col_p}}{'PROTO':<{col_pr}}{'STATE':<{col_st}}{'SERVICE':<{col_sv}}{'BANNER / VERSION'}{R}")
        divider("·", 72, GREY)

        for r in open_ports:
            port    = r["port"]
            proto   = r["proto"]
            service = r["service"]
            bnr     = r["banner"]

            meta       = SERVICES.get(port)
            svc_color  = meta[1] if meta else WHITE
            risk_note  = meta[2] if meta else ""

            port_col  = f"{YELLOW}{B}{str(port)+'/'+proto:<{col_p}}{R}"
            proto_col = f"{GREY}{proto.upper():<{col_pr}}{R}"
            state_col = f"{GREEN}{B}{'OPEN':<{col_st}}{R}"
            svc_col   = f"{svc_color}{B}{service:<{col_sv}}{R}"
            bnr_col   = f"{WHITE}{bnr[:45]}{R}" if bnr else f"{GREY}—{R}"

            print(f"  {port_col}{proto_col}{state_col}{svc_col}{bnr_col}")

            if risk_note:
                indent = " " * (col_p + col_pr + col_st + 2)
                print(f"  {indent}{svc_color}{risk_note}{R}")

        divider("·", 72, GREY)

    # ── Summary ────────────────────────────────────────────────────────────────
    section("SUMMARY")
    risky = [r["port"] for r in open_ports
             if r["port"] in SERVICES and SERVICES[r["port"]][1] == RED]
    safe  = [r["port"] for r in open_ports
             if r["port"] in SERVICES and SERVICES[r["port"]][1] == GREEN]

    print(f"  {GREY}Total open  :{R}  {B}{GREEN}{len(open_ports)}{R}")
    if risky:
        print(f"  {GREY}High risk   :{R}  {B}{RED}{len(risky)}{R}  {RED}{', '.join(str(p) for p in risky)}{R}")
    if safe:
        print(f"  {GREY}Encrypted   :{R}  {GREEN}{', '.join(str(p) for p in safe)}{R}")
    print(f"  {GREY}Scan time   :{R}  {B}{duration}{R}")
    print(f"  {GREY}Completed   :{R}  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
    
    if json_path:
        print(f"  {GREY}Report File :{R}  {DIM}Saved to {json_path}{R}")

    if risky:
        section("SECURITY ADVISORIES")
        for p in risky:
            svc, color, note = SERVICES[p][:3]
            print(f"  {color}{B}Port {str(p):<7}{R}  {B}{svc:<16}{R}  {color}{note}{R}")

    divider("═", 72, TEAL)
    print(f"{GREY}{IT}  PortScan Pro v2  ·  Pure Python  ·  Authorised use only{R}\n")


# ── Entry point ────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="portscanner",
        description="PortScan Pro v2 — Hardened Version Fingerprinter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
PROFILES:
  quick     — ~50 well-known ports, very fast
  standard  — Top 1000 ports + service detection  (default)
  deep      — Top 1000 ports + fingerprint grabbing
  full      — All 65535 ports (can be slow)
        """
    )
    p.add_argument("target",   help="Target IP or hostname")
    p.add_argument("--profile", choices=SCAN_PROFILES.keys(), default="standard",
                   help="Scan profile (default: standard)")
    p.add_argument("--ports",  metavar="PORTS",
                   help="Custom ports: 22,80,443  or  1-1024")
    p.add_argument("--workers", type=int, default=200, metavar="N",
                   help="Concurrent threads (default: 200)")
    p.add_argument("--timeout", type=float, default=None, metavar="SEC",
                   help="Per-port TCP timeout in seconds (default: profile-based)")
    p.add_argument("--no-banner", action="store_true",
                   help="Skip the ASCII banner")
    p.add_argument("--skip-up-check", action="store_true",
                   help="Skip host-up probe and scan anyway")
    p.add_argument("--json", metavar="FILE", help="Save results to a JSON file")
    return p


def parse_ports(spec: str) -> list:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    parser = build_parser()
    if len(sys.argv) == 1:
        banner_art()
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if not args.no_banner:
        banner_art()

    ip, hostname = resolve_target(args.target)

    if args.ports:
        ports = parse_ports(args.ports)
        desc  = f"Custom {len(ports)} ports"
    else:
        profile_ports, _, desc = SCAN_PROFILES[args.profile]
        ports = profile_ports
        if args.profile == "custom":
            fatal("--profile custom requires --ports to be specified.")

    timeout = args.timeout or SCAN_PROFILES[args.profile][1]

    section("SCAN CONFIGURATION")
    print(f"  {GREY}Target    :{R}  {B}{WHITE}{args.target}{R}  {GREY}({ip}){R}")
    print(f"  {GREY}Hostname  :{R}  {B}{hostname}{R}")
    print(f"  {GREY}Profile   :{R}  {B}{CYAN}{args.profile.upper()}{R}  {GREY}│{R}  {desc}")
    print(f"  {GREY}Ports     :{R}  {B}{len(ports):,}{R} total")
    print(f"  {GREY}Threads   :{R}  {B}{args.workers}{R}")
    print(f"  {GREY}Timeout   :{R}  {B}{timeout}s{R}  per port")
    print(f"  {GREY}Engine    :{R}  {B}{GREEN}Pure Python TCP Connect{R}  {GREY}(no Nmap){R}")
    print(f"  {GREY}Started   :{R}  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
    divider()

    if not args.skip_up_check:
        print(f"  {BLUE}{B}[*]{R} Checking host reachability…", end=" ", flush=True)
        up = check_host_up(ip, timeout=min(timeout, 2.0))
        if up:
            print(f"{GREEN}{B}UP{R}")
        else:
            print(f"{ORANGE}{B}?{R}  {GREY}(no common port responded — scanning anyway){R}")
    print()

    # Always grab banners on deep or custom specified scans
    grab = args.profile in ("deep", "standard") or (args.ports is not None)
    start = time.time()

    open_ports = run_scan_engine(ip, ports, timeout, args.workers, grab_banners=grab)
    duration   = elapsed(start)

    if args.json:
        export_data = {
            "metadata": {
                "target": args.target,
                "ip": ip,
                "hostname": hostname,
                "profile": args.profile,
                "total_ports_scanned": len(ports),
                "duration": duration,
                "timestamp": datetime.now().isoformat()
            },
            "open_ports": open_ports
        }
        try:
            with open(args.json, "w") as f:
                json.dump(export_data, f, indent=4)
        except Exception:
            pass

    render_results(ip, hostname, open_ports, args.profile, timeout, duration, grab, json_path=args.json)


if __name__ == "__main__":
    main()
