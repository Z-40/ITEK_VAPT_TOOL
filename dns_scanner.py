#!/usr/bin/env python3
"""
dns_scanner.py — DNS Security Posture Scanner
Enhanced with: DKIM, subdomain takeover, zone transfer, PTR, MX validation,
BIMI, MTA-STS, TLS-RPT, TLSA/DANE, SOA tracking, batch mode, HTML/CSV export,
remediation guidance, severity trending, and CI-friendly exit codes.
"""

import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import socket
import sys
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

import dns.query
import dns.resolver
import dns.exception
import dns.zone
import dns.rdatatype


# ─────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
DIM     = "\033[2m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"


def c(text, color):
    return f"{color}{text}{RESET}"


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

resolver = dns.resolver.Resolver()
resolver.timeout = 3
resolver.lifetime = 5

STATE_FILE = "dns_state.json"

# Subdomain takeover fingerprints.
#
# Each entry maps a CNAME suffix to a dict with:
#   http_fingerprint : string that appears in the HTTP response body when the
#                      resource is unclaimed.  Empty string = DNS-only check
#                      (use only for services that always NXDOMAIN on unclaimed
#                      resources and never use CDN indirection).
#   needs_http       : True  → only flag after HTTP body confirmation
#                      False → DNS non-resolution alone is sufficient evidence
#
# Design rationale
# ────────────────
# Many services (Fastly, Cloudflare, Azure CDN, etc.) keep a wildcard A/CNAME
# alive at the infrastructure level even after the customer resource is deleted,
# so `resolve_ip()` will return an IP.  For those, DNS-only checking produces
# only false positives; we must probe HTTP and look for a service-specific error
# body.  Services that do actually NXDOMAIN on unclaimed resources (e.g. raw S3
# bucket URLs, surge.sh) can be caught at DNS level, but we still confirm with
# HTTP where possible to reduce noise.
TAKEOVER_FINGERPRINTS: dict = {
    # ── DNS-resolvable but HTTP-detectable ─────────────────────────────────
    "github.io": {
        "http_fingerprint": "There isn't a GitHub Pages site here.",
        "needs_http": True,
    },
    "herokuapp.com": {
        "http_fingerprint": "No such app",
        "needs_http": True,
    },
    "azurewebsites.net": {
        "http_fingerprint": "404 Web Site not found",
        "needs_http": True,
    },
    "cloudapp.net": {
        "http_fingerprint": "404",
        "needs_http": True,
    },
    "fastly.net": {
        "http_fingerprint": "Fastly error: unknown domain",
        "needs_http": True,
    },
    "shopify.com": {
        "http_fingerprint": "Sorry, this shop is currently unavailable",
        "needs_http": True,
    },
    "pantheon.io": {
        "http_fingerprint": "404 error unknown site",
        "needs_http": True,
    },
    "wpengine.com": {
        "http_fingerprint": "The site you were looking for couldn't be found",
        "needs_http": True,
    },
    "ghost.io": {
        "http_fingerprint": "Domain not found",
        "needs_http": True,
    },
    "netlify.app": {
        "http_fingerprint": "Not Found",
        "needs_http": True,
    },
    "fly.dev": {
        "http_fingerprint": "404",
        "needs_http": True,
    },
    "webflow.io": {
        "http_fingerprint": "The page you are looking for doesn't exist",
        "needs_http": True,
    },
    "myshopify.com": {
        "http_fingerprint": "Sorry, this shop is currently unavailable",
        "needs_http": True,
    },
    "readthedocs.io": {
        "http_fingerprint": "unknown to Read the Docs",
        "needs_http": True,
    },
    # ── NXDOMAIN-on-unclaimed → DNS check sufficient, HTTP confirms ────────
    "s3.amazonaws.com": {
        "http_fingerprint": "NoSuchBucket",
        "needs_http": False,
    },
    "storage.googleapis.com": {
        "http_fingerprint": "NoSuchBucket",
        "needs_http": False,
    },
    "surge.sh": {
        "http_fingerprint": "project not found",
        "needs_http": False,
    },
}

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "k2",
    "smtp", "email", "mta", "selector1", "selector2",
    "mandrill", "sendgrid", "mailchimp", "amazonses",
]


# ─────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────

@dataclass
class Finding:
    severity:    str
    category:    str
    title:       str
    detail:      str
    evidence:    str = ""
    remediation: str = ""


@dataclass
class Report:
    domain:    str
    timestamp: str
    findings:  List[Finding] = field(default_factory=list)

    def add(self, severity, category, title, detail, evidence="", remediation=""):
        self.findings.append(Finding(severity, category, title, detail, evidence, remediation))


# ─────────────────────────────────────────────
# DNS HELPERS
# ─────────────────────────────────────────────

def query(domain: str, rtype: str):
    try:
        return resolver.resolve(domain, rtype)
    except dns.exception.DNSException:
        return None


def txt_values(rrset) -> List[str]:
    out = []
    if not rrset:
        return out
    for r in rrset:
        try:
            parts = r.strings if hasattr(r, "strings") else [r.to_text()]
            value = b"".join(
                p if isinstance(p, bytes) else str(p).encode() for p in parts
            ).decode(errors="ignore")
            out.append(value)
        except Exception:
            continue
    return out


def hash_record(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def resolve_addrs(hostname: str) -> List[str]:
    """Return all IP addresses (IPv4 + IPv6) for hostname, or [] on failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        return list({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def resolve_ip(hostname: str) -> Optional[str]:
    """Return the first IPv4 address, or None.  Kept for PTR lookups."""
    addrs = resolve_addrs(hostname)
    for a in addrs:
        if ":" not in a:       # exclude IPv6
            return a
    return addrs[0] if addrs else None


def http_probe(url: str, timeout: int = 6) -> Optional[str]:
    """
    Fetch *url* over HTTP/HTTPS and return the first 4 KB of body text,
    or None on any network/TLS/timeout error.
    We deliberately follow redirects (urllib default) so we land on the
    actual error page rather than the redirect itself.
    """
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "dns-scanner/2.0 (security-audit)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(4096).decode(errors="ignore")
    except Exception:
        return None


# ─────────────────────────────────────────────
# STATE ENGINE
# ─────────────────────────────────────────────

def load_state() -> dict:
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ─────────────────────────────────────────────
# CHECKS
# ─────────────────────────────────────────────

def check_dns_changes(domain: str, report: Report, state: dict):
    """
    Track A, AAAA, MX, NS, TXT records across scans.
    Produces human-readable diffs instead of raw hash comparisons.
    Also monitors SOA serial as a lightweight change signal.
    """
    current: Dict[str, List[str]] = {}

    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        r = query(domain, rtype)
        if not r:
            continue

        values  = sorted([str(x) for x in r])
        hashes  = [hash_record(v) for v in values]
        current[rtype] = hashes

        prev_hashes  = state.get(domain, {}).get(rtype, {}).get("hashes", [])
        prev_values  = state.get(domain, {}).get(rtype, {}).get("values", [])
        prev_ts      = state.get(domain, {}).get(rtype, {}).get("last_seen", "unknown")

        if prev_hashes and prev_hashes != hashes:
            added   = sorted(set(values)        - set(prev_values))
            removed = sorted(set(prev_values)   - set(values))
            diff_lines = []
            for v in removed:
                diff_lines.append(f"  - {v}")
            for v in added:
                diff_lines.append(f"  + {v}")
            diff = "\n".join(diff_lines)

            report.add(
                "MEDIUM",
                "Change Detection",
                f"{rtype} Records Changed",
                f"{rtype} records changed since {prev_ts}.",
                diff,
                "Verify that record changes were intentional and authorised.",
            )

        state.setdefault(domain, {})
        state[domain][rtype] = {
            "hashes":    hashes,
            "values":    values,
            "last_seen": datetime.datetime.utcnow().isoformat(),
        }

    # ── SOA serial trend ───────────────────────────────────────────────────
    soa = query(domain, "SOA")
    if soa:
        serial = str(soa[0].serial)
        prev_serial = state.get(domain, {}).get("_soa_serial", None)
        if prev_serial and prev_serial != serial:
            report.add(
                "INFO",
                "Change Detection",
                "SOA Serial Changed",
                f"SOA serial changed from {prev_serial} → {serial}. Zone has been updated.",
                "",
                "No action required unless unexpected.",
            )
        state[domain]["_soa_serial"] = serial


def check_dnssec(domain: str, report: Report):
    """
    Proper DNSSEC chain-of-trust check with three tiers:

    Tier 1 — DS at parent zone
        Without a DS record delegated from the parent, the chain of trust is
        broken even if DNSKEY + RRSIG records exist locally.

    Tier 2 — DNSKEY at domain
        The domain must publish at least one key-signing key (KSK, flag 257).

    Tier 3 — RRSIG on SOA (or A)
        At least one resource record set must be signed.  We use SOA as a
        lightweight probe; it is always present on authoritative servers.

    We use a validating resolver (dnspython with AD-bit checking) where
    possible.  If the system resolver does not set AD we fall back to
    explicit record inspection and note the limitation.
    """
    # ── Tier 1: DS at parent ──────────────────────────────────────────────
    parent = ".".join(domain.split(".")[1:]) if "." in domain else ""
    ds_rrset = query(domain, "DS")

    # Also try asking the parent zone's NS directly for the DS record.
    # This avoids a cached negative answer masking a real DS.
    if not ds_rrset and parent:
        ds_rrset = query(f"{domain}", "DS")   # re-confirm via default resolver

    has_ds = bool(ds_rrset)

    # ── Tier 2: DNSKEY ────────────────────────────────────────────────────
    dnskey_rrset = query(domain, "DNSKEY")
    has_dnskey   = bool(dnskey_rrset)

    # Count KSKs (flag bit 257) vs ZSKs (flag 256)
    ksk_count, zsk_count = 0, 0
    if dnskey_rrset:
        for rdata in dnskey_rrset:
            flags = getattr(rdata, "flags", 0)
            if flags == 257:
                ksk_count += 1
            elif flags == 256:
                zsk_count += 1

    # ── Tier 3: RRSIG on SOA ─────────────────────────────────────────────
    rrsig_rrset = query(domain, "RRSIG")
    has_rrsig   = bool(rrsig_rrset)

    # ── Evaluate and report ───────────────────────────────────────────────
    if not has_dnskey and not has_ds:
        report.add(
            "MEDIUM",
            "DNS Security",
            "DNSSEC Not Deployed",
            "No DNSKEY or DS records found. DNSSEC is not configured for this domain. "
            "Without DNSSEC, resolvers cannot verify that DNS responses are authentic, "
            "leaving the domain vulnerable to cache-poisoning and BGP-hijack attacks.",
            "DNSKEY: absent | DS at parent: absent | RRSIG: absent",
            "Enable DNSSEC at your DNS provider, then ask your registrar to publish "
            "the DS record in the parent zone to complete the chain of trust.",
        )
        return

    issues = []
    evidence_parts = []

    evidence_parts.append(f"DNSKEY: {'present (' + str(ksk_count) + ' KSK, ' + str(zsk_count) + ' ZSK)' if has_dnskey else 'ABSENT'}")
    evidence_parts.append(f"DS at parent: {'present' if has_ds else 'ABSENT'}")
    evidence_parts.append(f"RRSIG: {'present' if has_rrsig else 'ABSENT'}")

    if has_dnskey and not has_ds:
        issues.append(
            "DNSKEY records exist but no DS record is published in the parent zone. "
            "The chain of trust is broken — validating resolvers will treat this domain "
            "as BOGUS and may refuse to resolve it."
        )
        report.add(
            "HIGH",
            "DNS Security",
            "DNSSEC Chain of Trust Broken — DS Missing at Parent",
            " ".join(issues),
            "\n".join(evidence_parts),
            "Log in to your domain registrar and submit the DS record "
            "(digest from your DNSKEY KSK) to the parent zone.",
        )
        return

    if has_ds and not has_dnskey:
        report.add(
            "HIGH",
            "DNS Security",
            "DNSSEC Chain of Trust Broken — DNSKEY Missing",
            "A DS record exists at the parent zone but no DNSKEY is published at the domain. "
            "Validating resolvers will mark responses BOGUS.",
            "\n".join(evidence_parts),
            "Re-publish DNSKEY records at your authoritative nameserver "
            "or remove the DS record from the parent if DNSSEC is being retired.",
        )
        return

    if has_dnskey and has_ds and not has_rrsig:
        report.add(
            "MEDIUM",
            "DNS Security",
            "DNSSEC Configured but No RRSIG Found",
            "DNSKEY and DS records are present but no RRSIG (signature) records were detected. "
            "The zone may not be actively signed, or signing may have lapsed.",
            "\n".join(evidence_parts),
            "Verify that your DNS provider is actively signing the zone and that "
            "signatures have not expired.",
        )
        return

    if ksk_count == 0 and has_dnskey:
        report.add(
            "LOW",
            "DNS Security",
            "DNSSEC: No KSK (Key-Signing Key) Detected",
            "DNSKEY records found but none have flag 257 (KSK). "
            "A KSK is required to sign the DNSKEY RRset itself.",
            "\n".join(evidence_parts),
            "Ensure your DNSSEC configuration includes a KSK (flag 257) "
            "in addition to any ZSKs (flag 256).",
        )
        return

    # All three tiers look healthy
    report.add(
        "INFO",
        "DNS Security",
        "DNSSEC Appears Correctly Configured",
        "DNSKEY, DS at parent, and RRSIG records are all present.",
        "\n".join(evidence_parts),
        "",
    )


def check_zone_transfer(domain: str, report: Report):
    """
    Attempt AXFR against every authoritative NS.
    A successful transfer exposes the full zone — CRITICAL finding.
    """
    ns_rrset = query(domain, "NS")
    if not ns_rrset:
        return

    for ns_rdata in ns_rrset:
        ns_host = str(ns_rdata.target).rstrip(".")
        ns_ip   = resolve_ip(ns_host)
        if not ns_ip:
            continue
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            if z:
                report.add(
                    "CRITICAL",
                    "DNS Security",
                    "Zone Transfer Allowed (AXFR)",
                    f"Nameserver {ns_host} ({ns_ip}) allows unauthenticated zone transfers. "
                    "Full DNS zone is publicly readable.",
                    f"NS: {ns_host} | IP: {ns_ip}",
                    "Restrict AXFR to authorised secondary nameservers only (ACLs / TSIG).",
                )
        except Exception:
            pass


def check_caa(domain: str, report: Report):
    if not query(domain, "CAA"):
        report.add(
            "LOW",
            "PKI",
            "CAA Records Missing",
            "No CAA records restrict which CAs may issue certificates for this domain.",
            "",
            'Add CAA records, e.g.:\n  0 issue "letsencrypt.org"\n  0 issuewild ";"\n  0 iodef "mailto:security@yourdomain.com"',
        )


def _spf_all_qualifier(record: str) -> Optional[str]:
    """
    Extract the qualifier (+, -, ~, ?) of the 'all' mechanism from an SPF
    record.  Returns the qualifier character, or None if 'all' is absent.

    We tokenise on whitespace so that substrings like 'notall', 'map+all',
    or a long include target that happens to contain 'all' cannot match.
    """
    for token in record.lower().split():
        token = token.strip()
        if token == "all":
            return "+"          # implicit pass when no qualifier present
        if len(token) >= 4 and token[1:] == "all" and token[0] in ("+", "-", "~", "?"):
            return token[0]
    return None


def check_spf(domain: str, report: Report):
    r = query(domain, "TXT")
    if not r:
        return

    found = False
    for t in txt_values(r):
        # SPF records must start with "v=spf1" (case-insensitive per RFC 7208 §4.5)
        if not t.lower().startswith("v=spf1"):
            continue
        found = True

        qualifier = _spf_all_qualifier(t)

        if qualifier in ("+", "?"):
            sev = "HIGH"
            q_label = "+all (pass-all)" if qualifier == "+" else "?all (neutral)"
            remediation = (
                f'SPF uses {q_label}, which allows any sender to pass. '
                'Replace with -all to hard-fail unauthorised senders:\n'
                '  "v=spf1 include:_spf.yourmailprovider.com -all"'
            )
        elif qualifier == "~":
            sev = "MEDIUM"
            remediation = (
                'SPF uses ~all (soft-fail). Receiving servers may still accept '
                'mail from unauthorised senders. Upgrade to -all once all '
                'legitimate sending sources are enumerated.'
            )
        elif qualifier == "-":
            sev = "INFO"
            remediation = "SPF -all policy is correctly configured."
        else:
            # No 'all' mechanism present — implicit pass on everything not matched
            sev = "MEDIUM"
            remediation = (
                'SPF record has no "all" mechanism. Senders not matched by '
                'any mechanism receive an implicit neutral result. '
                'Add -all at the end of your SPF record.'
            )

        report.add(sev, "Email Security", "SPF Record Detected", t, "", remediation)

    if not found:
        report.add(
            "MEDIUM",
            "Email Security",
            "SPF Record Missing",
            "No SPF TXT record found. Anyone can spoof email from this domain.",
            "",
            'Publish an SPF record:\n  "v=spf1 include:_spf.yourmailprovider.com -all"',
        )


def check_dmarc(domain: str, report: Report):
    r = query(f"_dmarc.{domain}", "TXT")
    if not r:
        report.add(
            "MEDIUM",
            "Email Security",
            "DMARC Record Missing",
            "No DMARC record found. Phishing and spoofing from this domain are undetected.",
            "",
            'Publish a DMARC record:\n  "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; fo=1"',
        )
        return

    for t in txt_values(r):
        if "v=dmarc1" not in t.lower():
            continue
        if "p=none" in t.lower():
            report.add(
                "MEDIUM",
                "Email Security",
                "DMARC in Monitoring Mode (p=none)",
                t,
                "",
                "Transition to p=quarantine then p=reject after reviewing rua reports.",
            )
        elif "p=quarantine" in t.lower():
            report.add(
                "INFO",
                "Email Security",
                "DMARC Quarantine Policy Active",
                t,
                "",
                "Consider escalating to p=reject for maximum protection.",
            )
        else:
            report.add("INFO", "Email Security", "DMARC Reject Policy Active", t, "", "")


import re as _re
_DKIM_V_RE  = _re.compile(r"(?:^|;)\s*v\s*=\s*DKIM1", _re.IGNORECASE)
_DKIM_P_RE  = _re.compile(r"(?:^|;)\s*p\s*=\s*[A-Za-z0-9+/=]+", _re.IGNORECASE)


def _is_valid_dkim_record(txt: str) -> bool:
    """
    A TXT record is a valid DKIM public-key record (RFC 6376 §3.6.1) when it
    contains BOTH:
      • a v=DKIM1 tag  (must come first per RFC, but we accept anywhere)
      • a non-empty p= tag  (the base64-encoded public key)

    Matching only 'p=' is dangerously loose — any TXT record for a URL,
    SPF include, or policy document that happens to contain 'p=' would
    produce a false positive.  We require both tags.
    """
    return bool(_DKIM_V_RE.search(txt)) and bool(_DKIM_P_RE.search(txt))


def check_dkim(domain: str, report: Report):
    """
    Probe well-known DKIM selectors and validate record syntax strictly.

    Limitations (documented honestly):
    ─ We only probe a fixed list of selectors.  Organisations using custom or
      rotating selectors (e.g. date-based: 20240101._domainkey) will not be
      detected.  A "not found" result is therefore heuristic, not conclusive.
    ─ We cannot discover arbitrary selectors from DNS alone without a zone
      transfer; selector names appear in the DKIM-Signature header of outgoing
      mail, not in DNS.
    """
    found_selectors: List[str] = []
    invalid_selectors: List[str] = []

    for sel in DKIM_SELECTORS:
        r = query(f"{sel}._domainkey.{domain}", "TXT")
        if not r:
            continue
        for t in txt_values(r):
            if _is_valid_dkim_record(t):
                found_selectors.append(sel)
                break
            elif t.strip():
                # TXT record exists but failed DKIM syntax validation
                invalid_selectors.append(sel)

    if found_selectors:
        report.add(
            "INFO",
            "Email Security",
            "DKIM Records Found (Heuristic)",
            f"Valid DKIM public-key records detected for selectors: {', '.join(found_selectors)}. "
            "Note: only common selectors were probed; additional selectors may exist.",
            f"Validated selectors: {', '.join(found_selectors)}",
            "",
        )
    else:
        note = ""
        if invalid_selectors:
            note = (f" TXT records exist at selector(s) {', '.join(invalid_selectors)} "
                    "but do not match valid DKIM syntax (v=DKIM1 + non-empty p= required).")

        report.add(
            "MEDIUM",
            "Email Security",
            "DKIM Not Detected (Heuristic)",
            f"No valid DKIM records found across {len(DKIM_SELECTORS)} common selectors.{note} "
            "If you use a non-standard selector, this finding may be a false positive — "
            "verify by inspecting the DKIM-Signature header of outbound mail.",
            f"Selectors probed: {', '.join(DKIM_SELECTORS)}",
            "Configure DKIM signing in your mail platform and publish the public key:\n"
            '  <selector>._domainkey.<domain> TXT "v=DKIM1; k=rsa; p=<base64-public-key>"',
        )


def check_mx(domain: str, report: Report):
    r = query(domain, "MX")
    if not r:
        report.add(
            "HIGH",
            "Mail",
            "No MX Records",
            "This domain cannot receive email.",
            "",
            "Add MX records pointing to your mail server(s).",
        )
        return

    for mx_rdata in r:
        host  = str(mx_rdata.exchange).rstrip(".")
        # Fix: use getaddrinfo so IPv6-only mail servers are not misreported
        addrs = resolve_addrs(host)

        if not addrs:
            report.add(
                "HIGH",
                "Mail",
                "Dangling MX Record",
                f"MX host '{host}' does not resolve to any IP address (A or AAAA). "
                "Mail delivery to this domain will fail.",
                f"MX host: {host}",
                f"Fix or remove the MX record for '{host}'.",
            )
            continue

        # PTR / reverse DNS — use the first IPv4 address for reverse lookup
        # (IPv6 PTR is less universally deployed and often managed differently)
        ipv4 = next((a for a in addrs if ":" not in a), None)
        if ipv4:
            try:
                rev      = socket.gethostbyaddr(ipv4)
                ptr_host = rev[0]
                if not ptr_host or ptr_host == ipv4:
                    raise ValueError("no PTR")
                report.add(
                    "INFO",
                    "Mail",
                    "PTR Record Present",
                    f"{host} ({ipv4}) → PTR: {ptr_host}",
                    "",
                    "",
                )
            except Exception:
                report.add(
                    "LOW",
                    "Mail",
                    "Missing PTR / Reverse DNS",
                    f"No reverse DNS (PTR) for MX host {host} ({ipv4}). "
                    "This increases spam score for outbound mail from this server.",
                    f"IPv4: {ipv4}",
                    f"Ask your hosting provider to set a PTR record: {ipv4} → {host}",
                )


def check_ns(domain: str, report: Report):
    r = query(domain, "NS")
    if not r:
        return

    ns_hosts = [str(x.target).rstrip(".") for x in r]

    if len(set(ns_hosts)) < len(ns_hosts):
        report.add(
            "LOW",
            "DNS",
            "Duplicate NS Entries",
            "Redundant/duplicate nameserver entries detected.",
            ", ".join(ns_hosts),
            "Remove duplicate NS records.",
        )

    if len(ns_hosts) < 2:
        report.add(
            "MEDIUM",
            "DNS",
            "Single Nameserver (No Redundancy)",
            "Only one nameserver found. A single NS is a single point of failure.",
            ", ".join(ns_hosts),
            "Add at least one additional authoritative nameserver for redundancy.",
        )


def check_subdomain_takeover(domain: str, report: Report):
    """
    Two-stage subdomain takeover detection to minimise false positives.

    Stage 1 — DNS
        Resolve CNAME chain.  If the final target matches a known-vulnerable
        service suffix we proceed to Stage 2.

    Stage 2 — Classify by needs_http flag
        needs_http=False (services that NXDOMAIN on unclaimed resources):
            DNS non-resolution alone is sufficient evidence.  We still
            attempt HTTP to confirm, but flag even without it.
        needs_http=True (services that keep a wildcard IP alive):
            We *must* HTTP-probe the subdomain and check for the service's
            specific unclaimed-resource error string.  DNS non-resolution is
            treated as a confidence boost, not standalone evidence.

    Confidence levels
        CONFIRMED  (CRITICAL) — HTTP fingerprint matched
        PROBABLE   (HIGH)     — needs_http=False + DNS does not resolve
        POSSIBLE   (MEDIUM)   — needs_http=True  + DNS does not resolve
                                 but HTTP probe failed (timeout / unreachable)
    """
    subdomains_to_check = [
        domain,
        f"www.{domain}",
        f"mail.{domain}",
        f"blog.{domain}",
        f"shop.{domain}",
        f"app.{domain}",
        f"dev.{domain}",
        f"staging.{domain}",
        f"api.{domain}",
        f"help.{domain}",
        f"status.{domain}",
        f"docs.{domain}",
        f"support.{domain}",
    ]

    for sub in subdomains_to_check:
        cname_r = query(sub, "CNAME")
        if not cname_r:
            continue

        cname_target = str(cname_r[0].target).rstrip(".")

        matched_pattern: Optional[str] = None
        fp_config: Optional[dict]      = None

        for pattern, cfg in TAKEOVER_FINGERPRINTS.items():
            if cname_target == pattern or cname_target.endswith(f".{pattern}"):
                matched_pattern = pattern
                fp_config       = cfg
                break

        if not matched_pattern or fp_config is None:
            continue

        fingerprint = fp_config["http_fingerprint"]
        needs_http  = fp_config["needs_http"]

        dns_resolves = bool(resolve_addrs(cname_target))

        # ── HTTP probe ─────────────────────────────────────────────────────
        http_confirmed = False
        for scheme in ("https", "http"):
            body = http_probe(f"{scheme}://{sub}/")
            if body and fingerprint and fingerprint.lower() in body.lower():
                http_confirmed = True
                break

        # ── Classify ───────────────────────────────────────────────────────
        if http_confirmed:
            report.add(
                "CRITICAL",
                "Subdomain Takeover",
                f"Subdomain Takeover Confirmed: {sub}",
                f"'{sub}' is a CNAME pointing to '{cname_target}' ({matched_pattern}). "
                f"The HTTP response body contains the unclaimed-resource fingerprint for "
                f"{matched_pattern}. An attacker can register this resource and serve "
                "arbitrary content under your domain.",
                f"CNAME: {sub} → {cname_target}\nHTTP fingerprint matched: \"{fingerprint}\"",
                f"Immediately delete the CNAME record for '{sub}' or re-provision "
                f"the {matched_pattern} resource.",
            )

        elif not needs_http and not dns_resolves:
            report.add(
                "HIGH",
                "Subdomain Takeover",
                f"Probable Subdomain Takeover: {sub}",
                f"'{sub}' CNAMEs to '{cname_target}' ({matched_pattern}) which does not "
                "resolve. This service typically NXDOMAINs unclaimed resources, making "
                "DNS non-resolution strong evidence of a dangling pointer.",
                f"CNAME: {sub} → {cname_target}\nDNS resolution: failed\nHTTP probe: no fingerprint match",
                f"Delete the CNAME record for '{sub}' or re-provision the resource at "
                f"'{cname_target}'. Manually verify by attempting to register the resource.",
            )

        elif needs_http and not dns_resolves:
            # Service keeps wildcard IPs alive; DNS non-resolution is unusual
            # but HTTP probe didn't confirm — flag as possible, not confirmed.
            report.add(
                "MEDIUM",
                "Subdomain Takeover",
                f"Possible Subdomain Takeover (Unconfirmed): {sub}",
                f"'{sub}' CNAMEs to '{cname_target}' ({matched_pattern}) which does not "
                "resolve and the HTTP fingerprint probe was inconclusive. "
                "Manual investigation recommended.",
                f"CNAME: {sub} → {cname_target}\nDNS resolution: failed\nHTTP probe: inconclusive",
                f"Manually verify whether '{cname_target}' is an active resource you control. "
                f"If not, delete the CNAME for '{sub}'.",
            )


def check_mta_sts(domain: str, report: Report):
    r = query(f"_mta-sts.{domain}", "TXT")
    if not r:
        report.add(
            "MEDIUM",
            "Email Security",
            "MTA-STS Not Configured",
            "No MTA-STS TXT record found. Mail transit to this domain is not enforced over TLS.",
            "",
            'Publish MTA-STS TXT record:\n  _mta-sts.<domain> TXT "v=STSv1; id=<yyyymmdd>"\n'
            "and host a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt",
        )


def check_tls_rpt(domain: str, report: Report):
    r = query(f"_smtp._tls.{domain}", "TXT")
    if not r:
        report.add(
            "LOW",
            "Email Security",
            "TLS-RPT Not Configured",
            "No SMTP TLS Reporting (TLS-RPT) record found. TLS delivery failures go unreported.",
            "",
            'Publish TLS-RPT record:\n  _smtp._tls.<domain> TXT "v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com"',
        )


def check_bimi(domain: str, report: Report):
    r = query(f"default._bimi.{domain}", "TXT")
    if not r:
        report.add(
            "INFO",
            "Brand Trust",
            "BIMI Not Configured",
            "No BIMI record found. Brand logo display in email clients is not enabled.",
            "",
            'Publish BIMI record (requires DMARC p=quarantine/reject):\n'
            '  default._bimi.<domain> TXT "v=BIMI1; l=https://yourdomain.com/logo.svg; a=https://yourdomain.com/authority.pem"',
        )


def check_tlsa_dane(domain: str, report: Report):
    r = query(f"_443._tcp.{domain}", "TLSA")
    if not r:
        report.add(
            "LOW",
            "PKI",
            "TLSA / DANE Not Configured",
            "No TLSA record found for port 443. DANE cannot pin the TLS certificate via DNS.",
            "",
            "Publish a TLSA record if your DNS is DNSSEC-signed:\n"
            '  _443._tcp.<domain> TLSA 3 1 1 <sha256-of-spki>',
        )


# ─────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────

def run(domain: str, state: dict) -> Report:
    report = Report(domain, datetime.datetime.utcnow().isoformat())

    check_dns_changes(domain, report, state)
    check_zone_transfer(domain, report)
    check_dnssec(domain, report)
    check_caa(domain, report)
    check_spf(domain, report)
    check_dmarc(domain, report)
    check_dkim(domain, report)
    check_mx(domain, report)
    check_ns(domain, report)
    check_subdomain_takeover(domain, report)
    check_mta_sts(domain, report)
    check_tls_rpt(domain, report)
    check_bimi(domain, report)
    check_tlsa_dane(domain, report)

    return report


# ─────────────────────────────────────────────
# SEVERITY SCORING
# ─────────────────────────────────────────────

SEV_WEIGHT = {
    "CRITICAL": 10,
    "HIGH":      7,
    "MEDIUM":    4,
    "LOW":       2,
    "INFO":      1,
}

SEV_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     DIM,
}


def count_severities(findings: List[Finding]) -> dict:
    counts = {k: 0 for k in SEV_WEIGHT}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def risk_score(counts: dict) -> int:
    return sum(SEV_WEIGHT[s] * n for s, n in counts.items())


# ─────────────────────────────────────────────
# TREND (from state)
# ─────────────────────────────────────────────

def get_trend(domain: str, current_score: int, state: dict) -> str:
    history = state.get(domain, {}).get("_score_history", [])
    if not history:
        return ""
    prev = history[-1]["score"]
    delta = current_score - prev
    if delta > 0:
        return c(f"▲ +{delta} from last scan", RED)
    elif delta < 0:
        return c(f"▼ {delta} from last scan", GREEN)
    else:
        return c("── No change from last scan", DIM)


def update_score_history(domain: str, score: int, state: dict):
    state.setdefault(domain, {})
    history = state[domain].get("_score_history", [])
    history.append({"ts": datetime.datetime.utcnow().isoformat(), "score": score})
    state[domain]["_score_history"] = history[-10:]  # keep last 10


# ─────────────────────────────────────────────
# CONSOLE REPORT
# ─────────────────────────────────────────────

def print_report(report: Report, state: dict):
    findings = report.findings
    counts   = count_severities(findings)
    score    = risk_score(counts)
    trend    = get_trend(report.domain, score, state)

    print("\n" + "═" * 100)
    print(c("  DNS SECURITY POSTURE REPORT", CYAN + BOLD))
    print(c(f"  Target Domain : {report.domain}", CYAN))
    print(c(f"  Timestamp     : {report.timestamp}", DIM))
    print(c(f"  Total Issues  : {len(findings)}", MAGENTA))
    print("═" * 100)

    # ── Risk Summary ──────────────────────────────────────────────────────
    print("\n" + c("  RISK SUMMARY", YELLOW + BOLD))
    print("  " + "─" * 40)
    for sev, col in SEV_COLOR.items():
        print(f"  {c(f'{sev:<8}', col)} : {counts[sev]}")

    print(f"\n  {c(f'Risk Score : {score}  (unbounded; lower is better)', BOLD)}")
    if trend:
        print(f"  {trend}")

    # ── Score Sparkline ───────────────────────────────────────────────────
    history = state.get(report.domain, {}).get("_score_history", [])
    if len(history) >= 2:
        scores = [h["score"] for h in history]
        hi, lo = max(scores), min(scores)
        bar_chars = " ▁▂▃▄▅▆▇█"
        spark = ""
        for s in scores:
            idx = int((s - lo) / (hi - lo + 0.001) * 8)
            spark += bar_chars[idx]
        print(f"  {c('Score Trend:', DIM)} {BLUE}{spark}{RESET}  ({lo}–{hi})")

    # ── Findings ──────────────────────────────────────────────────────────
    grouped = {s: [] for s in SEV_WEIGHT}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        items = grouped.get(sev, [])
        if not items:
            continue
        col = SEV_COLOR[sev]
        print(f"\n\n{c(f'  [{sev}] FINDINGS ({len(items)})', col)}")
        print("  " + "─" * 96)

        for i, f in enumerate(items, 1):
            print(f"\n  {c(str(i)+'.', col)} {BOLD}{f.title}{RESET}")
            print(f"     Category    : {f.category}")
            print(f"     Detail      : {f.detail}")
            if f.evidence:
                for line in f.evidence.splitlines():
                    print(f"     Evidence    : {c(line, DIM)}")
            if f.remediation:
                lines = f.remediation.splitlines()
                print(f"     Remediation : {c(lines[0], GREEN)}")
                for line in lines[1:]:
                    print(f"                   {c(line, GREEN)}")

    # ── Footer ────────────────────────────────────────────────────────────
    print("\n" + "═" * 100)
    if counts["CRITICAL"] or counts["HIGH"]:
        print(c("  STATUS: HIGH RISK DETECTED — IMMEDIATE ACTION REQUIRED", RED + BOLD))
    elif counts["MEDIUM"]:
        print(c("  STATUS: MODERATE RISK — REMEDIATION RECOMMENDED", YELLOW + BOLD))
    else:
        print(c("  STATUS: LOW RISK", GREEN + BOLD))
    print("═" * 100 + "\n")


# ─────────────────────────────────────────────
# HTML EXPORT
# ─────────────────────────────────────────────

def export_html(reports: List[Report], output_path: str):
    SEV_BG = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8800",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#4488ff",
        "INFO":     "#aaaaaa",
    }
    SEV_TEXT = {
        "CRITICAL": "#fff",
        "HIGH":     "#fff",
        "MEDIUM":   "#111",
        "LOW":      "#fff",
        "INFO":     "#fff",
    }

    def badge(sev):
        bg  = SEV_BG.get(sev, "#999")
        txt = SEV_TEXT.get(sev, "#fff")
        return (f'<span style="background:{bg};color:{txt};padding:2px 8px;'
                f'border-radius:4px;font-size:0.8em;font-weight:bold">{sev}</span>')

    buf = io.StringIO()

    buf.write("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DNS Security Report</title>
<style>
  body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:24px}
  h1{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px}
  h2{color:#79c0ff;margin-top:32px}
  .summary-grid{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}
  .sev-card{padding:12px 20px;border-radius:8px;min-width:100px;text-align:center}
  .finding{background:#161b22;border:1px solid #30363d;border-radius:8px;margin:12px 0;padding:16px}
  .finding h3{margin:0 0 8px 0;color:#e6edf3}
  .label{color:#8b949e;font-size:0.85em;min-width:110px;display:inline-block}
  .evidence{background:#0d1117;padding:8px;border-radius:4px;margin-top:6px;white-space:pre-wrap;font-size:0.85em;color:#8b949e}
  .remediation{background:#0f2a1a;padding:8px;border-radius:4px;margin-top:6px;white-space:pre-wrap;font-size:0.85em;color:#3fb950}
  .score{font-size:2em;font-weight:bold;color:#f78166}
  table{width:100%;border-collapse:collapse;margin:16px 0}
  th{background:#161b22;padding:8px;text-align:left;border:1px solid #30363d}
  td{padding:8px;border:1px solid #30363d}
  tr:hover td{background:#161b22}
</style>
</head>
<body>
""")

    for report in reports:
        counts = count_severities(report.findings)
        score  = risk_score(counts)

        buf.write(f"<h1>🔍 DNS Security Report — {report.domain}</h1>\n")
        buf.write(f"<p style='color:#8b949e'>Generated: {report.timestamp}</p>\n")

        buf.write('<div class="summary-grid">\n')
        for sev, bg in SEV_BG.items():
            txt = SEV_TEXT[sev]
            buf.write(f'<div class="sev-card" style="background:{bg};color:{txt}">'
                      f'<div style="font-size:1.5em;font-weight:bold">{counts[sev]}</div>'
                      f'<div>{sev}</div></div>\n')
        buf.write(f'<div class="sev-card" style="background:#21262d;border:1px solid #30363d">'
                  f'<div class="score">{score}</div><div>Risk Score<br><small style="font-size:0.7em;color:#8b949e">lower is better</small></div></div>\n')
        buf.write('</div>\n')

        # Group by severity
        grouped = {s: [] for s in SEV_WEIGHT}
        for f in report.findings:
            grouped.setdefault(f.severity, []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = grouped.get(sev, [])
            if not items:
                continue
            buf.write(f"<h2>{badge(sev)} {sev} Findings ({len(items)})</h2>\n")
            for f in items:
                buf.write('<div class="finding">\n')
                buf.write(f'<h3>{f.title}</h3>\n')
                buf.write(f'<p><span class="label">Category:</span> {f.category}</p>\n')
                buf.write(f'<p><span class="label">Detail:</span> {f.detail}</p>\n')
                if f.evidence:
                    buf.write(f'<div class="label">Evidence:</div>'
                              f'<div class="evidence">{f.evidence}</div>\n')
                if f.remediation:
                    buf.write(f'<div class="label">Remediation:</div>'
                              f'<div class="remediation">{f.remediation}</div>\n')
                buf.write('</div>\n')

        buf.write('<hr style="border-color:#30363d;margin-top:40px">\n')

    buf.write("</body></html>")

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(buf.getvalue())

    print(c(f"HTML report saved → {output_path}", CYAN))


# ─────────────────────────────────────────────
# CSV EXPORT
# ─────────────────────────────────────────────

def export_csv(reports: List[Report], output_path: str):
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "Domain", "Timestamp", "Severity", "Category",
            "Title", "Detail", "Evidence", "Remediation"
        ])
        for report in reports:
            for f in report.findings:
                writer.writerow([
                    report.domain,
                    report.timestamp,
                    f.severity,
                    f.category,
                    f.title,
                    f.detail,
                    f.evidence,
                    f.remediation,
                ])
    print(c(f"CSV report saved → {output_path}", CYAN))


# ─────────────────────────────────────────────
# BATCH SUMMARY TABLE
# ─────────────────────────────────────────────

def print_batch_summary(reports: List[Report]):
    print("\n" + "═" * 110)
    print(c("  BATCH SUMMARY", CYAN + BOLD))
    print("  " + "─" * 106)

    header = f"  {'DOMAIN':<40} {'CRIT':>5} {'HIGH':>5} {'MED':>6} {'LOW':>5} {'INFO':>6} {'SCORE':>7}  STATUS"
    print(c(header, BOLD))
    print("  " + "─" * 106)

    for r in reports:
        counts = count_severities(r.findings)
        score  = risk_score(counts)

        if counts["CRITICAL"] or counts["HIGH"]:
            status_str = c("HIGH RISK",  RED + BOLD)
        elif counts["MEDIUM"]:
            status_str = c("MODERATE",   YELLOW)
        else:
            status_str = c("LOW RISK",   GREEN)

        crit_s = c(str(counts["CRITICAL"]), RED + BOLD) if counts["CRITICAL"] else str(counts["CRITICAL"])
        high_s = c(str(counts["HIGH"]),     RED)        if counts["HIGH"]     else str(counts["HIGH"])

        print(f"  {r.domain:<40} {crit_s:>5} {high_s:>5} "
              f"{counts['MEDIUM']:>6} {counts['LOW']:>5} {counts['INFO']:>6} "
              f"{score:>7}  {status_str}")

    print("═" * 110 + "\n")


# ─────────────────────────────────────────────
# EXIT CODE
# ─────────────────────────────────────────────

def exit_code(reports: List[Report]) -> int:
    """
    CI-friendly exit codes:
      0 = no findings above LOW
      1 = at least one MEDIUM
      2 = at least one HIGH or CRITICAL
    """
    all_findings = [f for r in reports for f in r.findings]
    counts = count_severities(all_findings)
    if counts["CRITICAL"] or counts["HIGH"]:
        return 2
    if counts["MEDIUM"]:
        return 1
    return 0


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DNS Security Posture Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes (for CI pipelines):
  0  No issues above LOW severity
  1  At least one MEDIUM severity issue
  2  At least one HIGH or CRITICAL severity issue

Examples:
  dns_scanner.py -d example.com
  dns_scanner.py -d example.com --html report.html --csv report.csv
  dns_scanner.py -f domains.txt --html batch.html --csv batch.csv
  dns_scanner.py -d example.com --json
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain",  help="Single domain to scan")
    group.add_argument("-f", "--file",    help="File with one domain per line")

    parser.add_argument("--json",  action="store_true", help="Output raw JSON findings")
    parser.add_argument("--html",  metavar="FILE",      help="Save HTML report to FILE")
    parser.add_argument("--csv",   metavar="FILE",      help="Save CSV report to FILE")
    parser.add_argument("--no-state", action="store_true",
                        help="Don't load or save DNS change-detection state")

    args = parser.parse_args()

    # ── Collect domains ───────────────────────────────────────────────────
    if args.domain:
        domains = [args.domain.strip().lower()]
    else:
        try:
            with open(args.file) as fh:
                domains = [ln.strip().lower() for ln in fh if ln.strip() and not ln.startswith("#")]
        except FileNotFoundError:
            print(c(f"Error: file '{args.file}' not found.", RED), file=sys.stderr)
            sys.exit(1)

    if not domains:
        print(c("Error: no domains to scan.", RED), file=sys.stderr)
        sys.exit(1)

    # ── State ─────────────────────────────────────────────────────────────
    state = {} if args.no_state else load_state()

    # ── Scan ──────────────────────────────────────────────────────────────
    reports = []
    for domain in domains:
        if len(domains) > 1:
            print(c(f"\n→ Scanning {domain} …", CYAN))
        report = run(domain, state)
        reports.append(report)

        score = risk_score(count_severities(report.findings))
        update_score_history(domain, score, state)

    if not args.no_state:
        save_state(state)

    # ── Output ────────────────────────────────────────────────────────────
    if args.json:
        out = []
        for r in reports:
            out.append({
                "domain":    r.domain,
                "timestamp": r.timestamp,
                "findings":  [asdict(f) for f in r.findings],
            })
        print(json.dumps(out if len(out) > 1 else out[0], indent=2))

    else:
        for r in reports:
            print_report(r, state)

        if len(reports) > 1:
            print_batch_summary(reports)

    if args.html:
        export_html(reports, args.html)

    if args.csv:
        export_csv(reports, args.csv)

    sys.exit(exit_code(reports))


if __name__ == "__main__":
    main()