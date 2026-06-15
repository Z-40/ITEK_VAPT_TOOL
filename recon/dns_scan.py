#!/usr/bin/env python3
"""
dns_scanner.py  ─  DNS Security Posture Scanner  |  Pipeline Edition
────────────────────────────────────────────────────────────────────────────────
Stage input  : <domain>_alive_subdomains.json   (via -i / --input)
Stage output : <target>_dns_scan.json

Runs 13 DNS / mail posture checks sequentially against every subdomain in the
input file's "subdomains" object.

Anti-False-Positive Engine (Apex Fallback)
──────────────────────────────────────────
Email-policy checks — SPF, DMARC, MTA-STS, TLS-RPT — include an
organisational-apex fallback.  If a subdomain carries no policy record of its
own the scanner re-queries the apex domain (from the "target" key) before
logging a finding.  Inherited corporate policies therefore do NOT generate
false-positive findings.

Output contract
───────────────
Raw findings only.  No severity scoring, risk matrices, or weighted grades.
"""

import argparse
import datetime
import json
import os
import socket
import sys
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Tuple

import dns.query
import dns.resolver
import dns.zone


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single raw DNS / mail posture finding — no severity weighting."""
    title:       str
    category:    str
    detail:      str
    evidence:    str
    remediation: str


@dataclass
class SubdomainResult:
    """Aggregated scan output for one subdomain entry."""
    subdomain:      str
    ip:             str
    scan_timestamp: str
    finding_count:  int
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ScanReport:
    """Top-level container written to <target>_dns_scan.json."""
    target:          str
    generated:       str
    source_file:     str
    subdomain_count: int
    results: List[SubdomainResult] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# CORE PROBE FUNCTIONS   (logic ported verbatim from original)
# ─────────────────────────────────────────────────────────────────────────────

def check_zone_transfer(domain: str, ns_ips: List[str]) -> List[str]:
    """Return list of nameserver IPs that permit unrestricted AXFR transfers."""
    vulnerable: List[str] = []
    for ip in ns_ips:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=2.0))
            if z:
                vulnerable.append(ip)
        except Exception:
            continue
    return vulnerable


def check_subdomain_takeover(domain: str) -> Tuple[bool, str, str]:
    """Detect dangling CNAMEs pointing at known claimable provider namespaces."""
    providers = {
        "github.io":         "GitHub Pages",
        "heroku.com":        "Heroku",
        "agilecrm.com":      "Agile CRM",
        "anvil.app":         "Anvil",
        "wpengine.com":      "WPEngine",
        "cloudfront.net":    "AWS CloudFront",
        "s3.amazonaws.com":  "AWS S3 Bucket",
        "bitbucket.io":      "Bitbucket",
        "squarespace.com":   "Squarespace",
        "shopify.com":       "Shopify",
        "azurewebsites.net": "Azure App Service",
    }
    try:
        for rdata in dns.resolver.resolve(domain, "CNAME"):
            cname = str(rdata.target).lower()
            for key, name in providers.items():
                if key in cname:
                    return True, cname, name
    except Exception:
        pass
    return False, "", ""


def probe_dkim_selectors(domain: str) -> List[str]:
    """
    Heuristic DKIM probe — checks a list of common enterprise selectors.
    Returns the subset of selectors that resolved successfully.
    """
    selectors = [
        "default", "google", "mail", "dkim", "k1", "k2", "smtp",
        "email", "mta", "selector1", "selector2", "mandrill",
        "sendgrid", "mailchimp", "amazonses",
    ]
    found: List[str] = []
    for sel in selectors:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            found.append(sel)
        except Exception:
            continue
    return found


def get_ns_records(domain: str) -> Tuple[List[str], List[str]]:
    """Resolve NS hostnames for *domain* and return (nameservers, ns_ips)."""
    nameservers: List[str] = []
    ns_ips:      List[str] = []
    try:
        for rdata in dns.resolver.resolve(domain, "NS"):
            ns = str(rdata).rstrip(".")
            nameservers.append(ns)
            try:
                for item in socket.getaddrinfo(ns, None, socket.AF_INET):
                    ns_ips.append(item[4][0])
            except Exception:
                continue
    except Exception:
        pass
    return nameservers, list(set(ns_ips))


# ─────────────────────────────────────────────────────────────────────────────
# APEX-AWARE EMAIL POLICY HELPERS   (anti-false-positive engine)
# ─────────────────────────────────────────────────────────────────────────────

def _txt_has_prefix(fqdn: str, prefix: str) -> bool:
    """
    Return True when any TXT record at *fqdn* begins with *prefix*.
    All DNS errors and decode failures are silently absorbed.
    """
    try:
        for rdata in dns.resolver.resolve(fqdn, "TXT"):
            txt = "".join(
                chunk.decode("utf-8", errors="replace") for chunk in rdata.strings
            )
            if txt.startswith(prefix):
                return True
    except Exception:
        pass
    return False


def apex_aware_check(
    subdomain:       str,
    apex:            str,
    query_fqdn_tmpl: str,
    prefix:          str,
    label:           str,
) -> Tuple[bool, str]:
    """
    Generic apex-fallback checker for TXT-based email policies.

    Parameters
    ----------
    subdomain        : Subdomain currently under audit.
    apex             : Organisational root domain (from the 'target' JSON key).
    query_fqdn_tmpl  : FQDN template containing the literal ``{domain}`` token.
                       e.g.  "_dmarc.{domain}"  →  "_dmarc.qa.example.com"
                             "{domain}"          →  "qa.example.com"         (SPF)
    prefix           : TXT value prefix to match, e.g. "v=DMARC1".
    label            : Human-readable record name used in evidence strings.

    Returns
    -------
    (policy_found : bool, evidence_string : str)
      policy_found == True   → record exists; no finding should be emitted.
      policy_found == False  → neither subdomain nor apex carry the policy.
    """
    sub_fqdn  = query_fqdn_tmpl.format(domain=subdomain)
    apex_fqdn = query_fqdn_tmpl.format(domain=apex)

    # Primary check — subdomain itself
    if _txt_has_prefix(sub_fqdn, prefix):
        return True, f"{label} present at {sub_fqdn}"

    # Apex fallback — only meaningful when subdomain ≠ apex
    if subdomain != apex:
        if _txt_has_prefix(apex_fqdn, prefix):
            return (
                True,
                f"{label} absent at {sub_fqdn}; "
                f"policy inherited from organisational apex ({apex_fqdn})",
            )
        return False, f"{sub_fqdn} (absent), {apex_fqdn} (absent)"

    # subdomain IS the apex and has no record
    return False, f"{sub_fqdn} (absent)"


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def run(domain: str, apex: str) -> SubdomainResult:
    """
    Execute all 13 posture checks against *domain*.

    *apex* is the organisational root domain sourced from the 'target' key of
    the input JSON file.  It is used exclusively by the apex fallback logic for
    email-policy checks (checks 6, 7, 9, 10).
    """
    result = SubdomainResult(
        subdomain=domain,
        ip="",           # populated by the caller from the input JSON
        scan_timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        finding_count=0,
    )
    findings: List[Finding] = []

    # ── 1. Base Resolution & NS  (setup step; generates no finding) ───────────
    _, ns_ips = get_ns_records(domain)

    # ── 2. Zone Transfer ──────────────────────────────────────────────────────
    if ns_ips:
        vuln_ns = check_zone_transfer(domain, ns_ips)
        if vuln_ns:
            findings.append(Finding(
                title="DNS Zone Transfer Allowed",
                category="DNS Security",
                detail=(
                    "One or more nameservers permit unrestricted AXFR zone transfers, "
                    "exposing the complete internal DNS record set to any requestor."
                ),
                evidence=f"Vulnerable NS IPs: {', '.join(vuln_ns)}",
                remediation=(
                    "Restrict AXFR transfers to authorised secondary nameserver IPs "
                    "only, via ACLs in your DNS server configuration."
                ),
            ))

    # ── 3. Subdomain Takeover ─────────────────────────────────────────────────
    is_takeover, target_cname, provider_name = check_subdomain_takeover(domain)
    if is_takeover:
        findings.append(Finding(
            title="Dangling CNAME / Potential Subdomain Takeover",
            category="Infrastructure",
            detail=(
                f"A CNAME record points to {provider_name}, which appears "
                "unconfigured or unclaimed by the current organisation."
            ),
            evidence=f"CNAME target: {target_cname}",
            remediation=(
                "Remove the dangling CNAME record or immediately reclaim "
                "the resource in the provider's management console."
            ),
        ))

    # ── 4. DNSSEC ─────────────────────────────────────────────────────────────
    has_dnskey = False
    has_ds     = False
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        has_dnskey = True
    except Exception:
        pass
    try:
        dns.resolver.resolve(domain, "DS")
        has_ds = True
    except Exception:
        pass

    if not has_dnskey and not has_ds:
        findings.append(Finding(
            title="DNSSEC Not Deployed",
            category="DNS Security",
            detail=(
                "No DNSKEY or DS records present; resolvers cannot cryptographically "
                "verify the authenticity of DNS responses for this domain."
            ),
            evidence="DNSKEY: absent | DS at parent zone: absent",
            remediation=(
                "Enable DNSSEC at your DNS provider and publish the resulting "
                "DS record at your domain registrar."
            ),
        ))

    # ── 5. MX Records ─────────────────────────────────────────────────────────
    has_mx = False
    try:
        dns.resolver.resolve(domain, "MX")
        has_mx = True
    except Exception:
        pass

    if not has_mx:
        findings.append(Finding(
            title="No MX Records Found",
            category="Mail",
            detail="Domain has no MX records and is incapable of receiving inbound email.",
            evidence="MX query returned zero records",
            remediation=(
                "Add MX records pointing to your mail gateway if "
                "inbound email delivery is required for this domain."
            ),
        ))

    # ── 6. SPF  [apex fallback active] ───────────────────────────────────────
    spf_ok, spf_evidence = apex_aware_check(
        subdomain=domain,
        apex=apex,
        query_fqdn_tmpl="{domain}",   # SPF lives directly on the domain's TXT records
        prefix="v=spf1",
        label="SPF",
    )
    if not spf_ok:
        findings.append(Finding(
            title="SPF Record Missing",
            category="Email Security",
            detail=(
                "No SPF policy was found on this subdomain or its organisational apex; "
                "email spoofing from this domain is unmitigated."
            ),
            evidence=spf_evidence,
            remediation=(
                "Publish a valid SPF TXT record at the apex domain "
                "enumerating all authorised sending sources."
            ),
        ))

    # ── 7. DMARC  [apex fallback active] ─────────────────────────────────────
    dmarc_ok, dmarc_evidence = apex_aware_check(
        subdomain=domain,
        apex=apex,
        query_fqdn_tmpl="_dmarc.{domain}",
        prefix="v=DMARC1",
        label="DMARC",
    )
    if not dmarc_ok:
        findings.append(Finding(
            title="DMARC Record Missing",
            category="Email Security",
            detail=(
                "No DMARC policy was found on this subdomain or its apex; "
                "spoofing compliance enforcement and aggregate reporting are absent."
            ),
            evidence=dmarc_evidence,
            remediation=(
                "Publish a DMARC TXT record at _dmarc.<apex> with "
                "at minimum a monitoring policy (p=none) to begin collecting reports."
            ),
        ))

    # ── 8. DKIM  (heuristic — subdomain only, no apex fallback) ──────────────
    dkim_found = probe_dkim_selectors(domain)
    if not dkim_found:
        findings.append(Finding(
            title="DKIM Not Detected (Heuristic)",
            category="Email Security",
            detail=(
                "No DKIM selector TXT records were found across the standard set of "
                "common enterprise selectors for this subdomain."
            ),
            evidence=(
                "Selectors probed: default, google, mail, dkim, k1, k2, smtp, "
                "email, mta, selector1, selector2, mandrill, sendgrid, mailchimp, amazonses"
            ),
            remediation=(
                "Configure DKIM signing on your mail platform and publish "
                "the public key as a TXT record at <selector>._domainkey.<domain>."
            ),
        ))

    # ── 9. MTA-STS  [apex fallback active] ───────────────────────────────────
    sts_ok, sts_evidence = apex_aware_check(
        subdomain=domain,
        apex=apex,
        query_fqdn_tmpl="_mta-sts.{domain}",
        prefix="v=STSv1",
        label="MTA-STS",
    )
    if not sts_ok:
        findings.append(Finding(
            title="MTA-STS Not Configured",
            category="Email Security",
            detail=(
                "No MTA-STS TXT record was found on this subdomain or its apex; "
                "opportunistic TLS for inbound SMTP is not enforced."
            ),
            evidence=sts_evidence,
            remediation=(
                "Publish an MTA-STS policy file at "
                "https://mta-sts.<apex>/.well-known/mta-sts.txt and "
                "reference it with a _mta-sts TXT record."
            ),
        ))

    # ── 10. TLS-RPT  [apex fallback active] ──────────────────────────────────
    rpt_ok, rpt_evidence = apex_aware_check(
        subdomain=domain,
        apex=apex,
        query_fqdn_tmpl="_smtp._tls.{domain}",
        prefix="v=TLSRPTv1",
        label="TLS-RPT",
    )
    if not rpt_ok:
        findings.append(Finding(
            title="TLS-RPT Not Configured",
            category="Email Security",
            detail=(
                "No SMTP TLS Reporting record was found on this subdomain or its apex; "
                "TLS delivery failures will remain unmonitored."
            ),
            evidence=rpt_evidence,
            remediation=(
                "Publish a TLS-RPT TXT record at _smtp._tls.<domain> "
                "specifying a mailto: reporting destination."
            ),
        ))

    # ── 11. CAA Records ───────────────────────────────────────────────────────
    has_caa = False
    try:
        dns.resolver.resolve(domain, "CAA")
        has_caa = True
    except Exception:
        pass

    if not has_caa:
        findings.append(Finding(
            title="CAA Records Missing",
            category="PKI",
            detail=(
                "No CAA records restrict which Certificate Authorities may "
                "issue TLS certificates for this domain."
            ),
            evidence="CAA record query returned no results",
            remediation=(
                "Add CAA records naming only your approved certificate authority "
                "partners to prevent unauthorised certificate issuance."
            ),
        ))

    # ── 12. TLSA / DANE ───────────────────────────────────────────────────────
    has_tlsa = False
    try:
        dns.resolver.resolve(f"_443._tcp.{domain}", "TLSA")
        has_tlsa = True
    except Exception:
        pass

    if not has_tlsa:
        findings.append(Finding(
            title="TLSA / DANE Not Configured",
            category="PKI",
            detail=(
                "No TLSA record for port 443; DNS-Based Authentication of Named Entities "
                "(DANE) certificate pinning is not enforced for HTTPS."
            ),
            evidence=f"No TLSA record at _443._tcp.{domain}",
            remediation=(
                "Publish a TLSA record to anchor your TLS certificate fingerprint "
                "in DNS via the DANE protocol."
            ),
        ))

    # ── 13. BIMI ──────────────────────────────────────────────────────────────
    has_bimi = False
    try:
        for rdata in dns.resolver.resolve(f"default._bimi.{domain}", "TXT"):
            txt = "".join(
                chunk.decode("utf-8", errors="replace") for chunk in rdata.strings
            )
            if txt.startswith("v=BIMI1"):
                has_bimi = True
                break
    except Exception:
        pass

    if not has_bimi:
        findings.append(Finding(
            title="BIMI Not Configured",
            category="Brand Trust",
            detail=(
                "No BIMI record found; brand logo display in BIMI-capable "
                "mail clients is unavailable for this domain."
            ),
            evidence=f"No matching TXT record at default._bimi.{domain}",
            remediation=(
                "Publish a BIMI TXT record at default._bimi.<domain> pointing "
                "to a Tiny P/S SVG brand logo, and optionally include a VMC certificate."
            ),
        ))

    result.findings      = findings
    result.finding_count = len(findings)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# I/O  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def load_input(path: str) -> Dict:
    """Load and return the parsed alive-subdomains JSON file."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def serialise_report(report: ScanReport) -> Dict:
    """Convert the ScanReport dataclass tree into a plain dict for JSON export."""
    return {
        "target":          report.target,
        "generated":       report.generated,
        "source_file":     report.source_file,
        "subdomain_count": report.subdomain_count,
        "results": [
            {
                "subdomain":      r.subdomain,
                "ip":             r.ip,
                "scan_timestamp": r.scan_timestamp,
                "finding_count":  r.finding_count,
                "findings":       [asdict(f) for f in r.findings],
            }
            for r in report.results
        ],
    }


def write_json(data: Dict, path: str) -> None:
    """Write *data* as pretty-printed JSON to *path*."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNS Security Posture Scanner — Pipeline Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            "  python dns_scanner.py -i infoteksoftware.com_alive_subdomains.json\n"
        ),
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        metavar="FILE",
        help=(
            "Path to <domain>_alive_subdomains.json produced by the "
            "subdomain-enumeration stage."
        ),
    )
    args = parser.parse_args()

    # ── Validate input path ──────────────────────────────────────────────────
    if not os.path.isfile(args.input):
        print(f"[ERROR] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # ── Parse input JSON ─────────────────────────────────────────────────────
    try:
        data = load_input(args.input)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[ERROR] Failed to parse input file: {exc}", file=sys.stderr)
        sys.exit(1)

    target:     str  = data.get("target", "").strip()
    subdomains: Dict = data.get("subdomains", {})

    if not target:
        print(
            "[ERROR] Input JSON is missing the required 'target' field.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not subdomains:
        print(
            "[ERROR] Input JSON 'subdomains' object is empty or absent.",
            file=sys.stderr,
        )
        sys.exit(1)

    output_path = f"{target}_dns_scan.json"

    # ── Initialise top-level report ──────────────────────────────────────────
    report = ScanReport(
        target=target,
        generated=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        source_file=os.path.basename(args.input),
        subdomain_count=len(subdomains),
    )

    # ── Banner ───────────────────────────────────────────────────────────────
    print(f"[*] Target         : {target}")
    print(f"[*] Subdomains     : {len(subdomains)}")
    print(f"[*] Output file    : {output_path}")
    print(f"[*] Apex fallback  : SPF, DMARC, MTA-STS, TLS-RPT")
    print()

    # ── Sequential subdomain scan ─────────────────────────────────────────────
    total = len(subdomains)
    for idx, (subdomain, ip) in enumerate(subdomains.items(), start=1):
        print(
            f"  [{idx:>{len(str(total))}}/{total}]  {subdomain}  ({ip})",
            end="  ...",
            flush=True,
        )
        result    = run(subdomain, apex=target)
        result.ip = ip
        report.results.append(result)
        print(f"  {result.finding_count} finding(s)")

    # ── Write output ─────────────────────────────────────────────────────────
    write_json(serialise_report(report), output_path)

    total_findings = sum(r.finding_count for r in report.results)
    print()
    print(f"[+] Scan complete.")
    print(f"[+] Total findings : {total_findings} across {total} subdomain(s)")
    print(f"[+] Report written : {output_path}")


if __name__ == "__main__":
    main()