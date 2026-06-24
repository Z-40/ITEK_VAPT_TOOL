#!/usr/bin/env python3
"""
aggregator.py  —  VAPT Forensic Graph Ingestion Engine (Hardened Edition)
═══════════════════════════════════════════════════════════════════════════════
Principal Security Automation | Production Grade | File-Agnostic Schema Routing

Ingests every *.json artifact produced by the offensive pipeline (enumerate,
dns_scan, fingerprinting, port_scan, rdap_scan) and compiles them into a
single, deduplicated, richly-annotated Forensic Graph (default: recon.json).

Hardened Against:
  - Target Overwrite Corruptions (IPs masquerading as Root Apex Domains)
  - Network Layer Topology Deserialization Anomalies (IP Subdomain Nodes)
  - Structural Key Mismatches ("web_probes" vs "probes", "open_ports" vs "ports")
  - Network Fingerprint Log Accumulation Bloat
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────────────
# Logging (All diagnostic telemetry targets stderr; stdout stays stream-clean)
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stderr,
)
log = logging.getLogger("aggregator")

# Regex to detect fast structural components
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")
_IPv4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# ═══════════════════════════════════════════════════════════════════════════════
# Subdomain Normalisation & Guard Filters
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_subdomain(raw: str) -> str:
    """
    Sanitise a raw target token into a clean, lowercase FQDN.
    Handles schemes, trailing DNS dots, paths, and trailing ports.
    Returns "" for anything that cannot be reduced to a valid host token.
    """
    if not raw or not isinstance(raw, str):
        return ""

    s = raw.strip()

    # Inject temporary scheme to allow urlparse to process cleanly
    if not _SCHEME_RE.match(s):
        s = "http://" + s

    try:
        hostname: str = urlparse(s).hostname or ""
    except Exception:
        hostname = s.removeprefix("http://").split("/")[0].split(":")[0]

    return hostname.rstrip(".").lower()


def is_raw_ip(token: str) -> bool:
    """Verify if a normalized host string is a raw IP configuration."""
    return bool(_IPv4_RE.match(token) or ":" in token)


# ═══════════════════════════════════════════════════════════════════════════════
# Cryptographic & Behavioral Deduplication
# ═══════════════════════════════════════════════════════════════════════════════
_hash_registry: dict[str, set[str]] = defaultdict(set)


def compute_finding_hash(finding: dict[str, Any]) -> str:
    """Produce a stable SHA-256 fingerprint boundary for a security finding."""
    title = str(finding.get("title", ""))
    detail = str(finding.get("detail", ""))
    evidence = finding.get("evidence", "")

    if not isinstance(evidence, str):
        evidence = json.dumps(evidence, sort_keys=True, ensure_ascii=False)

    canonical = f"{title}\x00{detail}\x00{evidence}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_duplicate_finding(fqdn: str, finding: dict[str, Any]) -> bool:
    """Evaluate or register structural duplicate vulnerabilities per host."""
    digest = compute_finding_hash(finding)
    if digest in _hash_registry[fqdn]:
        return True
    _hash_registry[fqdn].add(digest)
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Graph Node Factory & Pipeline Synthesizers
# ═══════════════════════════════════════════════════════════════════════════════

def _make_node(fqdn: str) -> dict[str, Any]:
    """Initialise a blank structured node obeying the master system schema."""
    return {
        "subdomain": fqdn,
        "ips_by_file": {},
        "dns_posture": {
            "finding_count": 0,
            "findings": [],
        },
        "web_fingerprint": {
            "waf_vendor": None,
            "probes": [],
        },
        "network_infrastructure": {
            "open_ports": [],
            "fingerprints": [],
        },
    }


def _get_node(graph: dict, fqdn: str) -> dict[str, Any]:
    """Extract node target. Bypasses injection of raw IP nodes into the tree."""
    if not fqdn or is_raw_ip(fqdn):
        return {}
    if fqdn not in graph["subdomains"]:
        graph["subdomains"][fqdn] = _make_node(fqdn)
    return graph["subdomains"][fqdn]


def _try_set_target(graph: dict, candidate: str) -> None:
    """Safely updates or targets shortest FQDN while blocking IP injections."""
    norm = normalize_subdomain(candidate)
    if not norm or is_raw_ip(norm):
        return
    if not graph["target"] or len(norm) < len(graph["target"]):
        graph["target"] = norm


def _record_ip(node: dict, filename: str, value: Any) -> None:
    """Store raw mapped IP metrics tracking back to original filename source."""
    if node and value and isinstance(value, str) and value.strip() and value.strip() not in ("N/A", "Unknown"):
        node["ips_by_file"][filename] = value.strip()


def _extract_ip(d: dict) -> str:
    """Scan uniform network patterns to yield real IP structures."""
    for key in ("ip", "address", "resolved_ip", "ipv4", "a_record"):
        val = d.get(key)
        if val and isinstance(val, str) and val not in ("N/A", "Unknown"):
            return val
    return ""


def _add_open_port(node: dict, port_num: Any) -> None:
    """Safely register integer entry records inside open port configurations."""
    if not node or port_num is None:
        return
    try:
        p_int = int(port_num)
        if p_int not in node["network_infrastructure"]["open_ports"]:
            node["network_infrastructure"]["open_ports"].append(p_int)
    except (ValueError, TypeError):
        pass


def _add_network_fingerprint(node: dict, fingerprint: dict[str, Any]) -> bool:
    """Adds open port banner telemetry, preventing duplicate asset logs."""
    if not node:
        return False
    
    port_val = fingerprint.get("port")
    service_val = fingerprint.get("service")
    banner_val = fingerprint.get("banner")

    # Evaluate unique signature criteria across already stored metrics
    for existing in node["network_infrastructure"]["fingerprints"]:
        if (existing.get("port") == port_val and 
                existing.get("service") == service_val and 
                existing.get("banner") == banner_val):
            return False  # Structural duplicate detected
            
    node["network_infrastructure"]["fingerprints"].append(fingerprint)
    return True


def _find_parent_node_by_ip(graph: dict, ip_address: str) -> dict[str, Any] | None:
    """Trace structural IP tracking states backward to identify owner FQDN."""
    if not ip_address:
        return None
    for node in graph["subdomains"].values():
        if ip_address in node["ips_by_file"].values():
            return node
    return None


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively synchronize master schemas in-place."""
    for key, val in override.items():
        if key in base:
            if isinstance(base[key], dict) and isinstance(val, dict):
                _deep_merge(base[key], val)
            elif isinstance(base[key], list) and isinstance(val, list):
                base[key].extend(val)
            else:
                base[key] = val
        else:
            base[key] = val


# ═══════════════════════════════════════════════════════════════════════════════
# Structural Schema Dispatches (File-Agnostic Engine)
# ═══════════════════════════════════════════════════════════════════════════════

def _handle_root_governance(graph: dict, payload: dict, fname: str) -> None:
    """Absorb registry definitions without losing domain markers."""
    gov = payload.get("root_domain_governance")
    if not isinstance(gov, dict):
        return

    for candidate_key in ("domain", "root_domain", "name", "fqdn", "registrant_domain"):
        val = gov.get(candidate_key)
        if val and isinstance(val, str):
            _try_set_target(graph, val)
            break

    _deep_merge(graph["root_domain_governance"], gov)
    log.info("  ├─ [governance]  merged root_domain_governance ← %s", fname)


def _handle_subdomains_block(graph: dict, subdomains: Any, fname: str) -> None:
    """Process top-level subdomain metrics across flat maps and structural configurations."""
    if not isinstance(subdomains, dict):
        return

    flat_count = 0
    nested_count = 0

    for raw_key, value in subdomains.items():
        fqdn = normalize_subdomain(raw_key)
        if not fqdn or is_raw_ip(fqdn):
            continue

        _try_set_target(graph, fqdn)
        node = _get_node(graph, fqdn)

        # Flat Mapping Variant (enumerate.py standard)
        if isinstance(value, str):
            _record_ip(node, fname, value)
            flat_count += 1
            continue

        # Nested Structure Variant (fingerprinting.py / rdap_scan.py structural standard)
        if isinstance(value, dict):
            _record_ip(node, fname, _extract_ip(value))

            waf = value.get("waf_vendor") or value.get("waf")
            if waf:
                node["web_fingerprint"]["waf_vendor"] = waf

            # Unified Schema Extraction (Bridges "probes" vs "web_probes" field anomalies)
            probes = value.get("probes") or value.get("web_probes") or []
            if isinstance(probes, list):
                for probe in probes:
                    if isinstance(probe, dict):
                        probe.setdefault("source_log_file", fname)
                        node["web_fingerprint"]["probes"].append(probe)

            for finding in value.get("findings", []):
                if isinstance(finding, dict) and not _is_duplicate_finding(fqdn, finding):
                    node["dns_posture"]["findings"].append(finding)
                    node["dns_posture"]["finding_count"] += 1

            nested_count += 1

    log.info(
        "  ├─ [subdomains]  %d flat + %d nested entries ← %s",
        flat_count, nested_count, fname,
    )


def _handle_results_array(graph: dict, results: list, fname: str) -> None:
    """Extract standard properties from structural analytical output logs."""
    dns_count = web_count = 0

    for item in results:
        if not isinstance(item, dict):
            continue

        raw_target = (
            item.get("subdomain") or item.get("target") or 
            item.get("host") or item.get("domain") or ""
        )
        fqdn = normalize_subdomain(raw_target)
        if not fqdn or is_raw_ip(fqdn):
            continue

        _try_set_target(graph, fqdn)
        node = _get_node(graph, fqdn)

        _record_ip(node, fname, _extract_ip(item))

        findings = item.get("findings")
        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict) and not _is_duplicate_finding(fqdn, finding):
                    node["dns_posture"]["findings"].append(finding)
                    node["dns_posture"]["finding_count"] += 1
                    dns_count += 1

        waf = item.get("waf_vendor") or item.get("waf")
        probes = item.get("probes") or item.get("web_probes") or []

        if waf or probes:
            if waf:
                node["web_fingerprint"]["waf_vendor"] = waf
            if isinstance(probes, list):
                for probe in probes:
                    if isinstance(probe, dict):
                        probe.setdefault("source_log_file", fname)
                        node["web_fingerprint"]["probes"].append(probe)
                        web_count += 1

    log.info(
        "  ├─ [results]     %d DNS findings, %d web probes ← %s",
        dns_count, web_count, fname,
    )


def _handle_network_layer(graph: dict, payload: dict, fname: str) -> None:
    """Maps port metrics back into host trees while rejecting rogue IP nodes."""
    # Expanded structural schema support for portscan_results.json
    if "hosts" in payload and isinstance(payload["hosts"], list):
        host_records: list[dict] = payload["hosts"]
    elif ("host" in payload or "hostname" in payload) and (isinstance(payload.get("ports"), list) or isinstance(payload.get("open_ports"), list)):
        host_records = [payload]
    elif isinstance(payload.get("ports"), list):
        host_records = [{"host": "", "ports": payload["ports"]}]
    elif isinstance(payload.get("open_ports"), list):
        host_records = [{"host": "", "ports": payload["open_ports"]}]
    else:
        return

    total_fingerprints = 0

    for record in host_records:
        if not isinstance(record, dict):
            continue

        raw_host = (
            record.get("hostname") or record.get("host") or 
            record.get("target") or record.get("ip") or 
            record.get("fqdn") or ""
        )
        token = normalize_subdomain(raw_host)
        if not token:
            continue

        node = None
        # Topology Routing Guard: Trace parents if token evaluates to an IP address representation
        if is_raw_ip(token):
            node = _find_parent_node_by_ip(graph, token)
            if not node:
                log.debug("  │  [network] Orphaned tracking context resolved on %s — dumping entry", token)
                continue
        else:
            _try_set_target(graph, token)
            node = _get_node(graph, token)

        # Pull from either "ports" or "open_ports" depending on the tool's schema
        ports = record.get("ports") or record.get("open_ports") or []
        for port_entry in ports:
            if not isinstance(port_entry, dict):
                continue

            port_num = port_entry.get("port") or port_entry.get("number")
            _add_open_port(node, port_num)

            fingerprint: dict[str, Any] = {
                "port": port_num,
                "protocol": port_entry.get("protocol") or port_entry.get("proto"),
                "service": port_entry.get("service") or port_entry.get("base_service") or port_entry.get("service_name"),
                "banner": port_entry.get("banner") or port_entry.get("version") or port_entry.get("raw_response"),
                "state": port_entry.get("status") or port_entry.get("state", "open"),
                "source_log_file": fname,
            }
            
            # Unpack nested fingerprint objects cleanly if present
            nested_fp = port_entry.get("fingerprint")
            if isinstance(nested_fp, dict):
                fingerprint["service"] = nested_fp.get("inferred_service", fingerprint["service"])
                fingerprint["banner"] = nested_fp.get("version_details") or nested_fp.get("raw_response", fingerprint["banner"])

            # Remove empty key objects cleanly
            fingerprint = {k: v for k, v in fingerprint.items() if v is not None}
            
            if _add_network_fingerprint(node, fingerprint):
                total_fingerprints += 1

    log.info(
        "  ├─ [network]     %d port fingerprints ← %s",
        total_fingerprints, fname,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Master Core Dispatch Control Center
# ═══════════════════════════════════════════════════════════════════════════════

def route_payload(graph: dict, payload: Any, fname: str) -> None:
    """Inspect top-level signatures to direct parsed schemas to their handlers."""
    if not isinstance(payload, dict):
        log.warning("  ! [%s]  top-level JSON object missing structural keys — skipped", fname)
        return

    dispatched: list[str] = []

    # Target processing loops must observe a strict hierarchy sequence 
    # to preserve parental IP associations before mapping port data
    if "root_domain_governance" in payload:
        _handle_root_governance(graph, payload, fname)
        dispatched.append("governance")

    if "subdomains" in payload:
        _handle_subdomains_block(graph, payload["subdomains"], fname)
        dispatched.append("subdomains")

    if "results" in payload and isinstance(payload["results"], list):
        _handle_results_array(graph, payload["results"], fname)
        dispatched.append("results")

    # Upgraded routing triggers to catch multiple network layer schema variations
    if any(k in payload for k in ("hosts", "host", "hostname", "ports", "open_ports")):
        _handle_network_layer(graph, payload, fname)
        dispatched.append("network")

    if dispatched:
        log.debug("  └─ routes fired: %s", "  →  ".join(dispatched))
    else:
        log.warning("  ! [%s]  unregistered payload structures — yielded no data elements", fname)


def _compile_metrics(graph: dict) -> None:
    """Refresh complete statistical calculations upon compiling active data inputs."""
    nodes = graph["subdomains"]
    graph["pipeline_summary"]["total_unique_subdomains"] = len(nodes)
    graph["pipeline_summary"]["data_density_metrics"] = {
        "subdomains_with_dns_findings": sum(
            1 for n in nodes.values() if n["dns_posture"]["finding_count"] > 0
        ),
        "subdomains_with_web_presence": sum(
            1 for n in nodes.values() if n["web_fingerprint"]["waf_vendor"] or n["web_fingerprint"]["probes"]
        ),
        "subdomains_with_open_ports": sum(
            1 for n in nodes.values() if n["network_infrastructure"]["open_ports"]
        ),
    }


def build_graph(input_dir: Path, output_file: Path) -> dict[str, Any]:
    """Execute sequence pipelines over directory targets while excluding recurrent artifacts."""
    graph: dict[str, Any] = {
        "target": "",
        "compiled_at": "",
        "pipeline_summary": {
            "total_unique_subdomains": 0,
            "processed_files_inventory": [],
            "data_density_metrics": {
                "subdomains_with_dns_findings": 0,
                "subdomains_with_web_presence": 0,
                "subdomains_with_open_ports": 0,
            },
        },
        "root_domain_governance": {},
        "subdomains": {},
    }

    blocked_basename: str = output_file.name
    candidates: list[Path] = sorted(input_dir.glob("*.json"))
    if not candidates:
        log.warning("Empty source matrix inside: %s", input_dir)
        return graph

    log.info("Discovered %d JSON file(s) in: %s", len(candidates), input_dir)

    # First Pass: Establish clean subdomain mappings and IP indices
    for jpath in candidates:
        if jpath.name == blocked_basename:
            continue
        try:
            payload = json.loads(jpath.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and "subdomains" in payload:
                _handle_subdomains_block(graph, payload["subdomains"], jpath.name)
        except Exception:
            continue

    # Second Pass: Extract multi-tier analytical findings and network port details
    for jpath in candidates:
        if jpath.name == blocked_basename:
            log.info("[SKIP] %-36s  ← anti-recursion guard configuration active", jpath.name)
            continue

        log.info("[READ] %s", jpath.name)

        try:
            raw_text = jpath.read_text(encoding="utf-8")
            payload = json.loads(raw_text)
        except Exception as exc:
            log.error("  ! Failure deserializing JSON targets inside %s — %s", jpath.name, exc)
            continue

        route_payload(graph, payload, jpath.name)
        if jpath.name not in graph["pipeline_summary"]["processed_files_inventory"]:
            graph["pipeline_summary"]["processed_files_inventory"].append(jpath.name)

    graph["compiled_at"] = datetime.now(timezone.utc).isoformat()
    _compile_metrics(graph)
    return graph


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Entry Control Module
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aggregator.py",
        description="Hardened VAPT Forensic Graph Aggregator — Stable Pipeline Consolidation Engine.",
    )
    parser.add_argument("-i", "--input-dir", required=True, metavar="DIR", help="Input logs folder track.")
    parser.add_argument("-o", "--output", default="recon.json", metavar="FILE", help="Graph storage path.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose tracing logs.")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    input_dir = Path(args.input_dir).resolve()
    output_file = Path(args.output).resolve()

    if not input_dir.exists() or not input_dir.is_dir():
        log.error("Invalid source parameter path target directory: %s", input_dir)
        sys.exit(1)

    log.info("═" * 62)
    log.info("  VAPT Forensic Graph Aggregator  —  aggregator.py (Hardened)")
    log.info("═" * 62)
    log.info("  input  : %s", input_dir)
    log.info("  output : %s", output_file)
    log.info("─" * 62)

    graph = build_graph(input_dir, output_file)

    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        log.error("Master IO error tracking graph serialisation failures — %s", exc)
        sys.exit(1)

    ps = graph["pipeline_summary"]
    dm = ps["data_density_metrics"]

    log.info("─" * 62)
    log.info("  ✓  Forensic Graph compiled  →  %s", output_file)
    log.info("  ┌─ Target             : %s", graph["target"] or "<undetermined>")
    log.info("  ├─ Ingested Files     : %d", len(ps["processed_files_inventory"]))
    log.info("  ├─ Unique Host FQDNs  : %d", ps["total_unique_subdomains"])
    log.info("  ├─ DNS Vulnerabilities: %d host(s)", dm["subdomains_with_dns_findings"])
    log.info("  ├─ App Web Footprints : %d host(s)", dm["subdomains_with_web_presence"])
    log.info("  └─ Infrastructure Ports: %d host(s)", dm["subdomains_with_open_ports"])
    log.info("═" * 62)


if __name__ == "__main__":
    main()