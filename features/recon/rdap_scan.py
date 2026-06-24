#!/usr/bin/env python3
"""
pipeline_aggregator.py
~~~~~~~~~~~~~~~~~~~~~~
Master brain stage for the VAPT pipeline. 
Ingests DNS scan results, Master Recon fingerprints, and RDAP registration metrics,
stitches them per domain tree, evaluates risk profiles, and generates final analysis reports.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any

_BAD_FNAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

# ─────────────────────────────────────────────────────────────────────────────
# RISK EVALUATION ENGINE (INTEGRATED TELEMETRY)
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_subdomain_risks(dns_info: dict[str, Any], recon_info: dict[str, Any]) -> list[dict[str, str]]:
    """Evaluates security findings from the dynamic network and application data."""
    findings: list[dict[str, str]] = []
    
    # 1. DNS Layer
    dns_vulns = dns_info.get("vulns", []) or dns_info.get("vulnerabilities", [])
    for v in dns_vulns:
        findings.append({
            "title": v.get("title", "DNS Finding"),
            "severity": v.get("severity", "Medium"),
            "source": "DNS Module",
            "detail": v.get("detail", "Identified anomaly during record resolution lookup."),
            "remediation": v.get("remediation", "Review authoritative zone configuration files.")
        })
        
    if dns_info.get("dnssec_enabled") is False:
        findings.append({
            "title": "DNSSEC Deployment Missing",
            "severity": "Low",
            "source": "DNS Module",
            "detail": "Zone fails to serve signed DNSKEY/DS validation pairs, exposing clients to cache poisoning.",
            "remediation": "Enable DNSSEC signing policies at the primary authoritative domain registrar."
        })

    # 2. Web Application Layer
    waf = recon_info.get("waf_vendor", "Unknown")
    if waf in ("None Detected", "Unknown"):
        findings.append({
            "title": "Web Application Firewall (WAF) Missing",
            "severity": "Low",
            "source": "Recon Module",
            "detail": "The application host is serving traffic bare to the public internet without intercepting proxy layers.",
            "remediation": "Deploy a cloud proxy layer or reverse WAF topology (e.g., Cloudflare, CloudFront, Akamai) to filter bad actors."
        })

    for p in recon_info.get("probes", []):
        server = p.get("server")
        techs = p.get("technologies") or []
        
        if server:
            findings.append({
                "title": f"Information Disclosure: Exposed Server Banner ({server})",
                "severity": "Info",
                "source": "Recon Module",
                "detail": f"Web server natively leaks active signature infrastructure version via 'Server: {server}' header responses.",
                "remediation": "Configure defensive runtime directives (e.g., 'server_tokens off' in Nginx)."
            })
            
        for tech in techs:
            if any(old in tech.lower() for old in ["php/5.", "jquery/1.", "iis/7."]):
                findings.append({
                    "title": f"Legacy Software Detection: {tech}",
                    "severity": "High",
                    "source": "Recon Module",
                    "detail": f"Target environment is operating an unpatched runtime asset platform tracking known active CVE targets.",
                    "remediation": "Migrate system binaries and public modules to the current stable LTS baseline tree."
                })

    return findings


def evaluate_rdap_governance_risks(rdap_info: dict[str, Any]) -> list[dict[str, str]]:
    """Evaluates administrative risk indicators found inside domain ownership metrics."""
    findings: list[dict[str, str]] = []
    if not rdap_info:
        return findings

    statuses = rdap_info.get("epp_statuses", [])
    
    # Check for Domain Hijack/Tamper Vulnerability (Missing Registrar Anti-Deletion/Transfer Lock)
    lock_statuses = ["clienttransferprohibited", "clientdeleteprohibited", "clientupdateprohibited"]
    has_locks = any(l in statuses for l in lock_statuses)
    
    if not has_locks and "ok" in statuses:
        findings.append({
            "title": "Missing EPP Anti-Hijacking Security Status Locks",
            "severity": "Medium",
            "source": "RDAP Corporate Module",
            "detail": "The root domain registration status is set to raw 'ok' without active client transfer/deletion restrictions enabled at the registrar level. This exposes the asset to unauthenticated social engineering porting or deletion attacks.",
            "remediation": "Log into your domain registry portal and enable 'Transfer Lock', 'Update Lock', and 'Delete Lock' protective attributes."
        })

    # Information Leak via WHOIS/RDAP arrays
    emails = rdap_info.get("extracted_emails", [])
    corporate_emails = [e for e in emails if not any(prov in e for prov in ["privacy", "proxy", "protection", "blackhole"])]
    if corporate_emails:
        findings.append({
            "title": "Corporate Contact Email Exposure in Ownership Registry",
            "severity": "Info",
            "source": "RDAP Corporate Module",
            "detail": f"Internal team email communications vectors are exposed publicly on the authoritative registry: {', '.join(corporate_emails)}. This provides actionable vectors for spear-phishing and social engineering orchestration.",
            "remediation": "Enable standard privacy proxy protection masking profiles with your registrar to terminate plain text exposure."
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# MARKDOWN REPORT COMPILER
# ─────────────────────────────────────────────────────────────────────────────

def compile_markdown_report(report_data: dict[str, Any]) -> str:
    meta = report_data["scan_metadata"]
    sum_data = report_data["summary"]
    rdap = report_data.get("root_domain_governance", {})
    
    md = []
    md.append(f"# Executive Security Assessment Report")
    md.append(f"**Target Host Scope:** `{meta['target']}`  ")
    md.append(f"**Assessment Window:** `{meta['compiled_at']}`  ")
    md.append(f"**Discovered Footprint:** {sum_data['total_subdomains']} Tracked Assets  \n")
    
    if rdap:
        md.append("### Authoritative Registrar Dossier")
        md.append(f"* **Registrar Identity:** `{rdap.get('registrar_name')}` (IANA: `{rdap.get('canonical_iana_id')}`)")
        md.append(f"* **Creation Timeline:** `{rdap.get('created_date')}`")
        md.append(f"* **Expiration Timeline:** `{rdap.get('expiration_date')}`")
        md.append(f"* **DNSSEC Root Sync State:** `{rdap.get('dnssec_state')}`\n")

    md.append("## 1. Severity Distribution Matrix")
    md.append("| Critical | High | Medium | Low | Info |")
    md.append("| :---: | :---: | :---: | :---: | :---: |")
    md.append(f"| **{sum_data['metrics']['Critical']}** | **{sum_data['metrics']['High']}** | **{sum_data['metrics']['Medium']}** | **{sum_data['metrics']['Low']}** | **{sum_data['metrics']['Info']}** |\n")
    
    md.append("## 2. Vulnerability Ledger Matrix")
    
    # Print root governance issues first if they exist
    gov_findings = rdap.get("findings", [])
    if gov_findings:
        md.append(f"### 🛡️ Core Infrastructure & Domain Governance Vulnerabilities")
        md.append("| Finding Title | Severity | Source Module |")
        md.append("| :--- | :---: | :--- |")
        for f in gov_findings:
            md.append(f"| {f['title']} | **{f['severity']}** | {f['source']} |")
        md.append("\n#### Administrative Resolution Vectors")
        for idx, f in enumerate(gov_findings, 1):
            md.append(f"**G-{idx}. {f['title']}** ")
            md.append(f"   * **Severity:** `{f['severity']}` | **Origin:** `{f['source']}`  ")
            md.append(f"   * **Technical Detail:** {f['detail']}  ")
            md.append(f"   * **Actionable Remediation:** {f['remediation']}\n")

    # Map out the subdomain matrix
    for sub, profile in sorted(report_data["subdomains"].items(), key=lambda x: len(x[1]["findings"]), reverse=True):
        md.append(f"### Target Endpoint Profile: `{sub}`")
        md.append(f"* **Resolved Network Endpoint:** `{profile['ip']}`")
        md.append(f"* **Web Protection Context:** `{profile['waf_vendor']}`\n")
        
        if not profile["findings"]:
            md.append("> ✨ **Observation Summary:** No active deployment misconfigurations or operational flaws identified within this target zone.\n")
            continue
            
        md.append("| Finding Title | Severity | Source Module |")
        md.append("| :--- | :---: | :--- |")
        for f in profile["findings"]:
            md.append(f"| {f['title']} | **{f['severity']}** | {f['source']} |")
        md.append("\n#### Finding Breakdowns & Remediation Guidance")
        
        for idx, f in enumerate(profile["findings"], 1):
            md.append(f"**{idx}. {f['title']}** ")
            md.append(f"   * **Severity:** `{f['severity']}` | **Origin:** `{f['source']}`  ")
            md.append(f"   * **Technical Detail:** {f['detail']}  ")
            md.append(f"   * **Actionable Remediation:** {f['remediation']}\n")
            
    return "\n".join(md)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Master VAPT Aggregator Script")
    parser.add_argument("--target", "-t", required=True, help="Base target scope (e.g., infoteksoftware.com)")
    args = parser.parse_args()
    
    safe_target = _BAD_FNAME_RE.sub('_', args.target.strip())
    
    dns_file = Path(f"{safe_target}_dns_scan.json")
    recon_file = Path(f"{safe_target}_master_recon.json")
    rdap_file = Path(f"{safe_target}_rdap_scan.json")
    
    print(f"[*] Aggregator checking tracking data streams...", file=sys.stderr)
    
    severity_metrics = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    # ── INGEST STREAM 1: DNS ──────────────────────────────────────────────────
    dns_data: dict[str, Any] = {}
    if dns_file.exists():
        with open(dns_file, encoding="utf-8") as fh: dns_data = json.load(fh)
        print(f"[+] Loaded DNS data: {dns_file.name}", file=sys.stderr)
        
    # ── INGEST STREAM 2: RECON/FINGERPRINT ────────────────────────────────────
    recon_data: dict[str, Any] = {}
    if recon_file.exists():
        with open(recon_file, encoding="utf-8") as fh: recon_data = json.load(fh)
        print(f"[+] Loaded Recon data: {recon_file.name}", file=sys.stderr)

    # ── INGEST STREAM 3: RDAP GOVERNANCE METRICS ──────────────────────────────
    rdap_raw_list: list[dict[str, Any]] = []
    rdap_governance: dict[str, Any] = {}
    if rdap_file.exists():
        with open(rdap_file, encoding="utf-8") as fh: rdap_raw_list = json.load(fh)
        print(f"[+] Loaded RDAP governance records: {rdap_file.name}", file=sys.stderr)
        
        # Pull records that match the root target domain precisely
        for item in rdap_raw_list:
            if item.get("target") == args.target:
                rdap_governance = item
                gov_vulnerabilities = evaluate_rdap_governance_risks(rdap_governance)
                rdap_governance["findings"] = gov_vulnerabilities
                for f in gov_vulnerabilities:
                    severity_metrics[f["severity"]] += 1
                break

    # ── STITCH SUBDOMAINS ─────────────────────────────────────────────────────
    all_subs: set[str] = set()
    dns_subs_map: dict[str, dict[str, Any]] = {}
    if "results" in dns_data:
        for entry in dns_data["results"]:
            s = entry.get("subdomain")
            if s: dns_subs_map[s] = entry; all_subs.add(s)
                
    recon_subs_map: dict[str, dict[str, Any]] = {}
    if "results" in recon_data:
        for entry in recon_data["results"]:
            s = entry.get("subdomain")
            if s: recon_subs_map[s] = entry; all_subs.add(s)

    stitched_subdomains: dict[str, dict[str, Any]] = {}
    for sub in sorted(all_subs):
        d_info = dns_subs_map.get(sub, {})
        r_info = recon_subs_map.get(sub, {})
        
        ip_addr = r_info.get("ip") or d_info.get("ip") or "N/A"
        waf_vendor = r_info.get("waf_vendor") or "Unknown"
        web_probes = r_info.get("probes") or []
        
        sub_findings = evaluate_subdomain_risks(d_info, r_info)
        for f in sub_findings:
            severity_metrics[f["severity"]] += 1
                
        stitched_subdomains[sub] = {
            "ip": ip_addr,
            "waf_vendor": waf_vendor,
            "web_probes": web_probes,
            "findings": sub_findings
        }

    # Consolidated JSON Payload Structure
    final_report = {
        "scan_metadata": {
            "target": args.target,
            "compiled_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "summary": {
            "total_subdomains": len(stitched_subdomains),
            "metrics": severity_metrics
        },
        "root_domain_governance": rdap_governance,
        "subdomains": stitched_subdomains
    }
    
    # Save Output Assets
    json_out = Path(f"{safe_target}_final_bakery.json")
    with open(json_out, "w", encoding="utf-8") as fj:
        json.dump(final_report, fj, indent=2, default=str)
        
    md_out = Path(f"{safe_target}_security_report.md")
    with open(md_out, "w", encoding="utf-8") as fm:
        fm.write(compile_markdown_report(final_report))
        
    print(f"\n[+] Master Ingestion Sequence Finalized.", file=sys.stderr)
    print(f"[+] Consolidated Data Saved  → {json_out.resolve()}", file=sys.stderr)
    print(f"[+] Markdown Executive Report → {md_out.resolve()}", file=sys.stderr)


if __name__ == "__main__":
    main()