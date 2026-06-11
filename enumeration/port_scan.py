#!/usr/bin/env python3
"""
PortScan Pro — Pure Python, zero dependencies.
Hardened Edition with Protocol & Version Fingerprinting Engine.
Usage: python portscanner.py <target> [options]

[MODIFIED]: Severity grading and visual risk indicators removed. Reports raw facts only.
Outputs raw JSON payload directly to stdout when --json is used.
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

# ── ANSI colours ──────────────────────────────────────────────────────────────
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
TEAL   = _c("\033[38;5;38m")
GREEN  = _c("\033[38;5;82m")
GREY   = _c("\033[38;5;244m")
BLUE   = _c("\033[38;5;45m")

print_lock = threading.Lock()

# ── Common Presets & Signature Databases (UNTOUCHED) ──────────────────────────
COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
    3306, 3389, 5900, 8080, 8443, 9000, 27017
]

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "Watchtower", 27017: "MongoDB"
}

PROBES = {
    "GenericLines": b"\r\n\r\n",
    "GetRequest": b"GET / HTTP/1.0\r\n\r\n",
    "HelpRequest": b"HELP\r\n"
}

# ── Fingerprinting Engine Core Logic (UNTOUCHED) ──────────────────────────────
def parse_banner(port, banner_bytes):
    if not banner_bytes:
        return {}
    
    raw_str = banner_bytes.decode('utf-8', errors='ignore').strip()
    clean_str = re.sub(r'[\x00-\x1F\x7F-\x9F]', ' ', raw_str)
    clean_str = " ".join(clean_str.split())
    
    result = {"raw_response": clean_str[:200]}
    
    # Signatures matching logic
    if port == 22 and "SSH-" in clean_str:
        m = re.search(r"SSH-\d+\.\d+-([\w_\-\.]+)", clean_str)
        result["inferred_service"] = "SSH"
        if m: result["version_details"] = m.group(1)
    elif "HTTP/" in clean_str or "html" in clean_str.lower():
        result["inferred_service"] = "HTTP"
        m = re.search(r"Server:\s*([\w\-\./]+)", clean_str, re.IGNORECASE)
        if m: result["version_details"] = m.group(1)
    elif "FTP" in clean_str or clean_str.startswith("220 "):
        result["inferred_service"] = "FTP"
    elif "SMTP" in clean_str or clean_str.startswith("220") and "smtp" in clean_str.lower():
        result["inferred_service"] = "SMTP"
    
    return result

def grab_banner_ext(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = b""
    try:
        s.connect((ip, port))
        try:
            banner = s.recv(1024)
        except socket.timeout:
            for p_name, p_bytes in PROBES.items():
                try:
                    s.close()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    s.connect((ip, port))
                    s.sendall(p_bytes)
                    banner = s.recv(1024)
                    if banner: break
                except Exception:
                    continue
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass
        
    return parse_banner(port, banner) if banner else None

def scan_single_port(ip, port, timeout, grab_banners=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    start = time.time()
    try:
        s.connect((ip, port))
        latency = (time.time() - start) * 1000
        s.close()
        
        info = {
            "port": port,
            "status": "open",
            "base_service": COMMON_SERVICES.get(port, "unknown"),
            "latency_ms": round(latency, 2)
        }
        
        if grab_banners:
            fingerprint = grab_banner_ext(ip, port, timeout)
            if fingerprint:
                info["fingerprint"] = fingerprint
                
        return info
    except Exception:
        try: s.close()
        except Exception: pass
        return None

# ── Orchestration Worker (UNTOUCHED Engine Setup) ─────────────────────────────
def run_scan_engine(ip, ports, timeout, max_workers, grab_banners=False):
    found_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_single_port, ip, p, timeout, grab_banners): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                found_ports.append(res)
                # Redirect terminal progress logs to stderr to keep stdout sterile
                with print_lock:
                    srv = res["base_service"]
                    lat = res["latency_ms"]
                    print(f"  [{GREEN}OPEN{R}] Port {B}{res['port']}{R:<5} | Service: {TEAL}{srv:<12}{R} | Latency: {lat}ms", file=sys.stderr)
                    if "fingerprint" in res and "raw_response" in res["fingerprint"]:
                        print(f"        └── {GREY}Raw Banner: {res['fingerprint']['raw_response']}{R}", file=sys.stderr)
    return sorted(found_ports, key=lambda x: x["port"])

def check_host_up(ip, timeout=2.0):
    for port in [80, 443, 22, 445, 3389]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            pass
    return False

def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip, target if target != ip else "N/A"
    except socket.gaierror:
        print(f"Error: Unable to resolve targeted asset entity context: '{target}'", file=sys.stderr)
        sys.exit(1)

# ── Formatter Modules (MODIFIED) ──────────────────────────────────────────────
def divider():
    print(f"  {GREY}══════════════════════════════════════════════════════════════════════════════════{R}", file=sys.stderr)

def parse_ports(ports_arg):
    if not ports_arg:
        return COMMON_TCP_PORTS
    if ports_arg.lower() == "all":
        return list(range(1, 65536))
    
    ports = []
    for chunk in ports_arg.split(','):
        if '-' in chunk:
            try:
                start, end = map(int, chunk.split('-'))
                ports.extend(range(start, end + 1))
            except ValueError:
                pass
        else:
            try: ports.append(int(chunk))
            except ValueError: pass
    return sorted(list(set(ports)))

def main():
    parser = argparse.ArgumentParser(description="PortScan Pro (Objective Fact Mode)")
    parser.add_argument("target", help="Remote network domain target alias or IP boundary identifier")
    parser.add_argument("-p", "--ports", help="Ports to target (e.g., '22,80,443', '1-1024', or 'all')")
    parser.add_argument("--profile", choices=["fast", "standard", "deep"], default="standard", help="Target depth constraints")
    parser.add_argument("--workers", type=int, default=100, help="Thread concurrency execution allocation pool size")
    parser.add_argument("--timeout", type=float, help="Connection block operational limit timeout parameter")
    parser.add_argument("--json", action="store_true", help="Dump absolute raw output structures using JSON matrices")
    parser.add_argument("--skip-up-check", action="store_true", help="Skip proactive host-reachability probing tests")
    args = parser.parse_args()

    sys.modules['__main__'].IS_JSON_MODE = args.json

    ip, hostname = resolve_target(args.target)
    ports = parse_ports(args.ports)
    
    # Operational configuration boundaries
    timeout = args.timeout or (1.0 if args.profile == "fast" else 2.5 if args.profile == "deep" else 1.5)

    # All human-readable output redirected entirely to stderr
    divider()
    print(f"  {B}PORT SCANNING FACTS INVENTORY{R}", file=sys.stderr)
    print(f"  {GREY}Target Destination :{R}  {args.target} ({ip})", file=sys.stderr)
    print(f"  {GREY}Total Ports Scanned:{R}  {len(ports)}", file=sys.stderr)
    print(f"  {GREY}Timestamp          :{R}  {datetime.now().isoformat()}", file=sys.stderr)
    divider()
    print(file=sys.stderr)

    grab = args.profile in ("deep", "standard") or (args.ports is not None)
    open_ports = run_scan_engine(ip, ports, timeout, args.workers, grab_banners=grab)

    if args.json:
        export_data = {
            "target": args.target,
            "ip": ip,
            "hostname": hostname,
            "total_ports_scanned": len(ports),
            "timestamp": datetime.now().isoformat(),
            "open_ports": open_ports
        }
        # Sterile stdout dump
        print(json.dumps(export_data, indent=2))
    else:
        print(file=sys.stderr)
        print(f"  Scan Finished. Total Active Open Connections: {len(open_ports)}", file=sys.stderr)
        divider()

if __name__ == "__main__":
    main()