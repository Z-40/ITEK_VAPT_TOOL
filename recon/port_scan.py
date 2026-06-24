import socket
import sys
import time
import ipaddress
import concurrent.futures
import threading
import os
import json
import re
from datetime import datetime
from typing import Dict, Any, List

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & PROTOCOL MAPPING SIGNATURES
# ─────────────────────────────────────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443
]

HTTP_GET = b"GET / HTTP/1.0\r\nUser-Agent: PortScanPro/2.1\r\nConnection: close\r\n\r\n"
SSH_REQ  = b"\r\n"

BANNER_GRAB_TIMEOUT = 2.0

BANNER_SIGNATURES = [
    (re.compile(r"SSH-\d+\.\d+-(.*)", re.IGNORECASE), "SSH"),
    (re.compile(r"FTP", re.IGNORECASE), "FTP"),
    (re.compile(r"SMTP", re.IGNORECASE), "SMTP"),
    (re.compile(r"HTTP/\d+\.\d+\s+(\d+)", re.IGNORECASE), "HTTP Gateway"),
]

# ── Thread-safe reporting coordination ──
_print_lock = threading.Lock()

def _safe_print(msg: str):
    with _print_lock:
        print(msg, file=sys.stderr, flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PROTOCOL FINGERPRINTING MOTOR ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def probe_service_details(ip: str, port: int) -> tuple[str, str]:
    """Probes the open port to extract the protocol and banner details."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(BANNER_GRAB_TIMEOUT)
    banner = ""
    protocol = "Unknown"

    try:
        sock.connect((ip, port))
        
        # ── Port Specific Application Probing Trigger ──
        if port in [80, 443, 8080, 8443]:
            sock.sendall(HTTP_GET)
        elif port == 22:
            sock.sendall(SSH_REQ)
        else:
            try:
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            except socket.timeout:
                pass

        if not banner:
            try:
                banner = sock.recv(2048).decode("utf-8", errors="replace").strip()
            except socket.timeout:
                pass

    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if banner:
        clean_banner = " ".join(banner.splitlines())
        if len(clean_banner) > 120:
            clean_banner = clean_banner[:117] + "..."
        
        for regex, proto_lbl in BANNER_SIGNATURES:
            if regex.search(clean_banner):
                protocol = proto_lbl
                break
        return protocol, clean_banner

    # Default common port assignments fallback if no banner responds
    port_map = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        8080: "HTTP-Alt"
    }
    return port_map.get(port, "Unknown"), "No banner response captured"

# ─────────────────────────────────────────────────────────────────────────────
# CORE SCANNING WORKER THREAD
# ─────────────────────────────────────────────────────────────────────────────
def scan_single_port(ip: str, port: int, timeout: float) -> Dict[str, Any] | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.close()
        
        # Port is open; execute deep configuration fingerprinting sweep
        proto, banner = probe_service_details(ip, port)
        return {
            "port": port,
            "status": "open",
            "protocol": proto,
            "banner": banner
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass

def scan_target_host(ip: str, ports: List[int], concurrency: int, timeout: float) -> Dict[str, Any]:
    _safe_print(f"[*] Starting port validation scan against host: {ip}")
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_map = {executor.submit(scan_single_port, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(future_map):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    return {
        "ip": ip,
        "scan_timestamp": datetime.now().isoformat(),
        "total_open_ports": len(open_ports),
        "open_ports": open_ports
    }

# ─────────────────────────────────────────────────────────────────────────────
# TARGET RESOLUTION AND EXPANSION HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def resolve_and_expand(target_str: str) -> List[str]:
    """Expands strings into single IP strings."""
    target_str = target_str.strip()
    if not target_str:
        return []

    # Check for CIDR block structures
    if "/" in target_str:
        try:
            return [str(ip) for ip in ipaddress.ip_network(target_str, strict=False).hosts()]
        except ValueError:
            pass

    # Check for Range expressions (e.g., 192.168.1.1-10)
    range_match = re.match(r"^([\d.]+)-(\d+)$", target_str)
    if range_match:
        base_ip = range_match.group(1)
        end_bound = int(range_match.group(2))
        if "." in base_ip:
            parts = base_ip.split(".")
            if len(parts) == 4 and 0 <= end_bound <= 255:
                start_bound = int(parts[3])
                prefix = ".".join(parts[:3])
                return [f"{prefix}.{i}" for i in range(start_bound, end_bound + 1)]

    # Standalone Host IP Resolution
    try:
        resolved_ip = socket.gethostbyname(target_str)
        return [resolved_ip]
    except socket.gaierror:
        return []

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SYNCHRONOUS IN-MEMORY INTERFACE
# ─────────────────────────────────────────────────────────────────────────────
def scan_ports(input_json_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts a structured payload dictionary containing targeting rules,
    executes multi-threaded connection-state and fingerprinting sweeps,
    and returns the resulting findings directly back as a dictionary tree.
    """
    # Extract scanning constraints and custom ports maps
    ports_input = input_json_data.get("ports")
    if ports_input:
        if isinstance(ports_input, list):
            ports_to_scan = [int(p) for p in ports_input]
        else:
            # Parse comma-separated string fields
            ports_to_scan = []
            for p in str(ports_input).split(","):
                p_clean = p.strip()
                if "-" in p_clean:
                    start, end = p_clean.split("-")
                    ports_to_scan.extend(range(int(start), int(end) + 1))
                elif p_clean:
                    ports_to_scan.append(int(p_clean))
    else:
        ports_to_scan = COMMON_PORTS

    # Sort and filter unique port inputs
    ports_to_scan = sorted(list(set(ports_to_scan)))

    # Pull tuneable connection variables
    concurrency = int(input_json_data.get("concurrency", 100))
    timeout = float(input_json_data.get("timeout", 1.5))

    # Determine input type tracking mode (Direct Targets vs Subdomain Enumerate JSON maps)
    scan_results = []
    
    if "subdomains" in input_json_data:
        # Ingestion Mode A: Processing output from enumerate.py pipeline directly
        subdomains_map = input_json_data.get("subdomains", {})
        for sub_name, resolved_ip in subdomains_map.items():
            if resolved_ip:
                host_report = scan_target_host(resolved_ip, ports_to_scan, concurrency, timeout)
                host_report["subdomain_alias"] = sub_name
                scan_results.append(host_report)
        
        return {
            "source_manifest": input_json_data.get("target", "pipeline_buffer"),
            "timestamp": datetime.now().isoformat(),
            "total_targets_processed": len(scan_results),
            "hosts": scan_results
        }
        
    else:
        # Ingestion Mode B: Standard raw scope targeting string array/field
        target_field = input_json_data.get("target")
        if not target_field:
            raise ValueError("Input JSON dataset must contain either a 'target' or a 'subdomains' map layer.")

        targets_list = [target_field] if isinstance(target_field, str) else list(target_field)
        all_resolved_ips = []
        for t in targets_list:
            all_resolved_ips.extend(resolve_and_expand(t))

        unique_ips = sorted(list(set(all_resolved_ips)), key=lambda ip: ipaddress.ip_address(ip))
        
        for target_ip in unique_ips:
            scan_results.append(scan_target_host(target_ip, ports_to_scan, concurrency, timeout))

        # Return backward-compatible object for single target, otherwise bulk payload manifest array
        if len(unique_ips) == 1 and isinstance(target_field, str) and not ("/" in target_field or "-" in target_field):
            return scan_results[0] if scan_results else {}
        else:
            return {
                "source_manifest": str(target_field),
                "timestamp": datetime.now().isoformat(),
                "total_targets_processed": len(scan_results),
                "hosts": scan_results
            }