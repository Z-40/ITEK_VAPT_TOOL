from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import http.client
import json
import re
import socket
import ssl
import sys
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Mute OpenSSL legacy TLS 1.0/1.1 context deprecation warnings from python runtime noise
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ─── Dependency Gate ──────────────────────────────────────────────────────────
_MISSING: List[str] = []

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:
    _MISSING.append("rich")

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:
    _MISSING.append("cryptography")

if _MISSING:
    print(f"[!] Install missing packages first:\n    pip install {' '.join(_MISSING)}")
    sys.exit(1)

console = Console(highlight=False)

# ─── Constants ────────────────────────────────────────────────────────────────
VERSION = "3.2"

SEVERITY: Dict[str, Tuple[str, str]] = {
    "CRITICAL": ("bold red",     "💀"),
    "HIGH":     ("red",          "🔴"),
    "MEDIUM":   ("dark_orange",  "🟠"),
    "LOW":      ("yellow",       "🟡"),
    "INFO":     ("cyan",         "ℹ️ "),
    "PASS":     ("green",        "✅"),
}

WEAK_CIPHER_TESTS: Dict[str, Tuple[str, str]] = {
    "NULL":   ("CRITICAL", "NULL cipher — zero encryption, data sent in plaintext"),
    "EXPORT": ("CRITICAL", "EXPORT-grade cipher — FREAK / LOGJAM vulnerable"),
    "RC4":    ("HIGH",     "RC4 stream cipher — cryptographically broken"),
    "DES":    ("HIGH",     "DES cipher — 56-bit key, trivially brute-forceable"),
    "3DES":   ("MEDIUM",   "Triple-DES — SWEET32 birthday attack (CVE-2016-2183)"),
    "aNULL":  ("CRITICAL", "Anonymous auth — server identity unverified, MITM trivial"),
    "ADH":    ("CRITICAL", "Anonymous DH — no authentication, MITM trivial"),
    "AECDH":  ("CRITICAL", "Anonymous ECDH — no authentication, MITM trivial"),
    "RC2":    ("HIGH",     "RC2 cipher — broken, effective key < 128-bit"),
    "IDEA":   ("MEDIUM",   "IDEA cipher — legacy, limited modern support"),
    "SEED":   ("LOW",      "SEED cipher — non-standard Korean algorithm"),
}

PROTO_RISK: Dict[str, Tuple[str, str, Optional[str]]] = {
    "SSL 2.0": ("CRITICAL", "DROWN attack — completely broken",       "CVE-2015-3197"),
    "SSL 3.0": ("CRITICAL", "POODLE attack — padding oracle",         "CVE-2014-3566"),
    "TLS 1.0": ("HIGH",     "Deprecated RFC 8996 / BEAST risk",       None),
    "TLS 1.1": ("MEDIUM",   "Deprecated by RFC 8996",                 None),
    "TLS 1.2": ("PASS",     "Acceptable — ensure strong ciphers",     None),
    "TLS 1.3": ("PASS",     "Recommended — best available",           None),
}

SIG_ALGO_NAMES: Dict[str, str] = {
    "1.2.840.113549.1.1.4":  "MD5withRSA",
    "1.2.840.113549.1.1.5":  "SHA1withRSA",
    "1.2.840.113549.1.1.11": "SHA256withRSA",
    "1.2.840.113549.1.1.12": "SHA384withRSA",
    "1.2.840.113549.1.1.13": "SHA512withRSA",
    "1.2.840.10045.4.3.1":   "SHA224withECDSA",
    "1.2.840.10045.4.3.2":   "SHA256withECDSA",
    "1.2.840.10045.4.3.3":   "SHA384withECDSA",
    "1.2.840.10045.4.3.4":   "SHA512withECDSA",
}

@dataclass
class Finding:
    title: str
    severity: str       
    detail: str
    cve: Optional[str] = None
    fix: Optional[str] = None

@dataclass
class ScanResult:
    host: str
    port: int
    ip: str = ""
    scan_time: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_valid_from: Optional[datetime.datetime] = None
    cert_valid_to: Optional[datetime.datetime] = None
    cert_days_remaining: int = 0
    cert_expired: bool = False
    cert_sans: List[str] = field(default_factory=list)
    cert_key_type: str = ""
    cert_key_size: int = 0
    cert_key_curve: str = ""
    cert_sig_algo: str = ""
    cert_sha256: str = ""
    cert_serial: str = ""
    cert_is_self_signed: bool = False
    cert_is_wildcard: bool = False
    cert_ocsp_url: str = ""
    trust_verified: bool = False
    trust_error_message: str = ""
    protocols: Dict[str, Optional[bool]] = field(default_factory=dict)
    negotiated_cipher: str = ""
    negotiated_proto: str = ""
    negotiated_bits: int = 0
    negotiated_alpn: str = "None"
    has_forward_secrecy: bool = False
    compression_enabled: bool = False
    weak_ciphers: List[Tuple[str, str, str]] = field(default_factory=list)
    http_redirect: bool = False
    hsts: bool = False
    hsts_max_age: int = 0
    hsts_subdomains: bool = False
    hsts_preload: bool = False
    findings: List[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A+"
    errors: List[str] = field(default_factory=list)

# ─── Scanner Core ──────────────────────────────────────────────────────────────

def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        return f"? ({exc})"

def is_ip_address(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))

def _make_ctx(
    min_ver: Optional[ssl.TLSVersion] = None,
    max_ver: Optional[ssl.TLSVersion] = None,
    ciphers: Optional[str] = None,
    verify: bool = False
) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
    for attr, val in [("minimum_version", min_ver), ("maximum_version", max_ver)]:
        if val is not None:
            try:
                setattr(ctx, attr, val)
            except (AttributeError, ssl.SSLError):
                pass
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            pass
    return ctx

def verify_trust_chain(host: str, port: int, timeout: float) -> Tuple[bool, str]:
    try:
        ctx = _make_ctx(verify=True)
        sni = None if is_ip_address(host) else host
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni):
                return True, "Verified Secure Chain"
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message
    except Exception as exc:
        return False, str(exc)

def fetch_certificate(host: str, port: int, timeout: float) -> Optional[bytes]:
    try:
        ctx = _make_ctx()
        sni = None if is_ip_address(host) else host
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as ssock:
                return ssock.getpeercert(binary_form=True)
    except Exception:
        return None

def parse_certificate(der: bytes, host: str) -> Tuple[Dict[str, Any], List[Finding]]:
    findings: List[Finding] = []
    meta: Dict[str, Any] = {}
    cert = x509.load_der_x509_certificate(der, default_backend())

    def _cn(name: x509.Name) -> str:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else name.rfc4514_string()

    meta["subject"] = _cn(cert.subject)
    meta["issuer"]  = _cn(cert.issuer)
    meta["serial"]  = format(cert.serial_number, "X")

    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        vf = cert.not_valid_before_utc
        vt = cert.not_valid_after_utc
    except AttributeError:
        vf = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        vt = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        
    meta["valid_from"] = vf
    meta["valid_to"]   = vt
    days = (vt - now).days
    meta["days_remaining"] = days
    meta["expired"] = days < 0

    if days < 0:
        findings.append(Finding("Certificate Expired", "CRITICAL", f"Expired {abs(days)} day(s) ago.", fix="Renew immediately."))
    elif days < 14:
        findings.append(Finding("Certificate Expiring Very Soon", "HIGH", f"Expires in {days} days.", fix="Renew now."))
    elif days < 30:
        findings.append(Finding("Certificate Expiring Soon", "MEDIUM", f"Expires in {days} days.", fix="Schedule renewal."))
    else:
        findings.append(Finding("Certificate Valid", "PASS", f"Valid until {vt.strftime('%Y-%m-%d')}."))

    meta["is_self_signed"] = cert.issuer == cert.subject
    if meta["is_self_signed"]:
        findings.append(Finding("Self-Signed Certificate", "HIGH", "Identity unverified via third-party anchors.", fix="Replace with standard CA leaf."))

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans: List[str] = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        sans = []
    meta["sans"] = sans
    meta["is_wildcard"] = any(s.startswith("*.") for s in sans)

    host_matched = False
    if not is_ip_address(host):
        for san in sans:
            if san.startswith("*."):
                parts = host.split(".")
                san_parts = san.split(".")
                if len(parts) == len(san_parts) and parts[1:] == san_parts[1:]:
                    host_matched = True
                    break
            elif san == host:
                host_matched = True
                break
        if not host_matched and meta["subject"] == host:
            host_matched = True
    else:
        host_matched = (meta["subject"] == host)

    if not host_matched:
        findings.append(Finding("Hostname Mismatch", "HIGH", f"Target host string '{host}' outside certificate valid identity boundaries.", fix="Reissue certificate for this domain."))

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        sz = pub.key_size
        meta.update(key_type="RSA", key_size=sz, key_curve="")
        if sz < 2048:
            findings.append(Finding("Weak RSA Key", "CRITICAL", f"RSA block size ({sz}-bit) vulnerable.", fix="Upgrade parameters to RSA 3072 / ECC."))
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        sz    = pub.key_size
        curve = pub.curve.name
        meta.update(key_type="EC", key_size=sz, key_curve=curve)
        if sz < 256:
            findings.append(Finding("Weak EC Key", "HIGH", f"Suboptimal security bit density curve: {curve}", fix="Migrate to P-256 or stronger curves."))
    else:
        meta.update(key_type=type(pub).__name__, key_size=0, key_curve="")

    oid_str  = cert.signature_algorithm_oid.dotted_string
    sig_algo = SIG_ALGO_NAMES.get(oid_str, oid_str)
    meta["sig_algo"] = sig_algo

    if "md5" in sig_algo.lower():
        findings.append(Finding("MD5 Signature Algorithm", "CRITICAL", "Collision vector active.", cve="CVE-2008-0166", fix="Upgrade to SHA-256 signatures."))
    elif "sha1" in sig_algo.lower():
        findings.append(Finding("SHA-1 Signature Algorithm", "HIGH", "Broken digest scheme.", fix="Upgrade to SHA-256."))

    meta["sha256"] = hashlib.sha256(der).hexdigest().upper()
    meta["ocsp_url"] = ""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for access in aia.value:
            if access.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
                meta["ocsp_url"] = access.access_location.value
                break
    except Exception:
        pass

    return meta, findings

def test_protocol_version(host: str, port: int, ver: ssl.TLSVersion, timeout: float) -> Optional[bool]:
    try:
        ctx = _make_ctx(min_ver=ver, max_ver=ver)
        sni = None if is_ip_address(host) else host
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni):
                return True
    except ssl.SSLError:
        return False
    except (OSError, socket.timeout, ConnectionRefusedError):
        return None

def probe_protocols(host: str, port: int, timeout: float) -> Dict[str, Optional[bool]]:
    results: Dict[str, Optional[bool]] = {"SSL 2.0": None, "SSL 3.0": None}
    for name, attr in [("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1"), ("TLS 1.2", "TLSv1_2"), ("TLS 1.3", "TLSv1_3")]:
        ver_enum = getattr(ssl.TLSVersion, attr, None)
        results[name] = None if ver_enum is None else test_protocol_version(host, port, ver_enum, timeout)
    return results

def get_session_info(host: str, port: int, timeout: float) -> Tuple[str, str, int, str, bool]:
    try:
        ctx = _make_ctx()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        sni = None if is_ip_address(host) else host
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as ssock:
                c = ssock.cipher() or ("", "", 0)
                alpn = ssock.selected_alpn_protocol() or "None"
                return c[0] or "", c[1] or "", c[2] or 0, alpn, ssock.compression() is not None
    except Exception:
        return "", "", 0, "None", False

def scan_weak_ciphers(host: str, port: int, timeout: float) -> List[Tuple[str, str, str]]:
    found: List[Tuple[str, str, str]] = []
    sni = None if is_ip_address(host) else host
    for cipher_str, (severity, detail) in WEAK_CIPHER_TESTS.items():
        try:
            ctx = _make_ctx(min_ver=ssl.TLSVersion.TLSv1, max_ver=ssl.TLSVersion.TLSv1_2)
            ctx.set_ciphers(cipher_str)
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as ssock:
                    neg = ssock.cipher()[0] or cipher_str
                    found.append((neg, severity, detail))
        except (ssl.SSLError, OSError):
            continue
    return found

def check_hsts_and_redirect(host: str, port: int, timeout: float, errors: List[str]) -> Tuple[Dict[str, Any], bool]:
    """Evaluates HTTP to HTTPS upgrade strategies and HSTS fields across redirection paths."""
    hsts_res = {"enabled": False, "max_age": 0, "subdomains": False, "preload": False}
    redirects_to_https = False
    
    # Part A: Audit cleartext upgrade path (Port 80)
    try:
        import urllib.request
        import urllib.error
        
        # Use GET instead of HEAD. WAFs and CDNs frequently drop HEAD requests 
        # or fail to apply routing/redirect rules to them.
        http_url = f"http://{host}/"
        req = urllib.request.Request(http_url, headers={"User-Agent": f"ssl-scan/{VERSION}"}, method="GET")
        
        # Use our unverified context. If the redirect lands on an HTTPS site with a broken cert, 
        # we still want to successfully acknowledge that the redirect mechanism itself works.
        ctx = _make_ctx()
        
        try:
            # urlopen automatically handles multi-hop redirects 
            # (e.g., http://domain.com -> http://www.domain.com -> https://www.domain.com)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.url.startswith("https://"):
                    redirects_to_https = True
        except urllib.error.HTTPError as e:
            # If the final destination returns a 4xx/5xx (e.g., 403 Forbidden on the HTTPS side)
            if hasattr(e, 'url') and getattr(e, 'url', '').startswith("https://"):
                redirects_to_https = True
            # Fallback check for unhandled redirects (e.g., HTTP 308 on older Python versions)
            elif e.headers.get("Location", "").startswith("https://") or e.headers.get("Location", "").startswith("//"):
                redirects_to_https = True
    except Exception:
        pass

    # Part B: Audit HTTPS headers following redirect structures safely
    try:
        import urllib.request
        url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
        
        class RedirectionHeaderTracker(urllib.request.HTTPRedirectHandler):
            def __init__(self):
                self.saved_headers = []
            def handle_redirect(self, headers):
                if headers:
                    self.saved_headers.append(headers)
            def http_error_302(self, req, fp, code, msg, headers):
                self.handle_redirect(headers)
                return super().http_error_302(req, fp, code, msg, headers)
            def http_error_301(self, req, fp, code, msg, headers):
                self.handle_redirect(headers)
                return super().http_error_301(req, fp, code, msg, headers)
            def http_error_307(self, req, fp, code, msg, headers):
                self.handle_redirect(headers)
                return super().http_error_307(req, fp, code, msg, headers)

        tracker = RedirectionHeaderTracker()
        opener = urllib.request.build_opener(tracker, urllib.request.HTTPSHandler(context=_make_ctx()))
        req = urllib.request.Request(url, headers={"User-Agent": f"ssl-scan/{VERSION}"})
        
        with opener.open(req, timeout=timeout) as resp:
            all_header_layers = tracker.saved_headers + [resp.headers]
            hsts = None
            for headers in all_header_layers:
                if "Strict-Transport-Security" in headers:
                    hsts = headers.get("Strict-Transport-Security")
                    break

        if hsts:
            hsts_res["enabled"] = True
            for part in hsts.split(";"):
                p = part.strip().lower()
                if p.startswith("max-age="):
                    try:
                        hsts_res["max_age"] = int(p.split("=", 1)[1])
                    except ValueError:
                        pass
                elif p == "includesubdomains":
                    hsts_res["subdomains"] = True
                elif p == "preload":
                    hsts_res["preload"] = True
    except Exception as exc:
        errors.append(f"HTTP security header mapping analysis limited: {exc}")
        
    return hsts_res, redirects_to_https

# ─── Scoring Engine ───────────────────────────────────────────────────────────

_DEDUCTIONS = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 3}

def score_result(result: ScanResult) -> Tuple[int, str]:
    score = 100
    for f in result.findings:
        score -= _DEDUCTIONS.get(f.severity, 0)
    if not result.trust_verified:
        score = min(score, 65)
    score = max(0, score)
    grade = ("A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 35 else "F")
    if not result.trust_verified and grade in ("A+", "A", "B"):
        grade = "T"
    return score, grade

def _grade_color(grade: str) -> str:
    return {"A+": "bold green", "A": "green", "B": "yellow", "C": "dark_orange", "D": "red", "F": "bold red", "T": "bold magenta"}.get(grade, "white")

# ─── Report Renderer ──────────────────────────────────────────────────────────

def _sev(severity: str) -> Tuple[str, str]:
    return SEVERITY.get(severity, ("white", "●"))

def _section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold white] {title} ", style="cyan", align="left"))
    console.print()

def print_banner() -> None:
    console.print()
    txt = Text.assemble(
        ("   ⚡   SSL / TLS   SECURITY  ANALYSER\n", "bold white"),
        (f"   v{VERSION}  ·  trust engine · validation · ciphersuites · headers", "dim"),
    )
    console.print(Panel(txt, border_style="cyan", expand=False, padding=(0, 2)))
    console.print()

def render_target(r: ScanResult) -> None:
    g = Table.grid(padding=(0, 2))
    g.add_column(style="dim", min_width=12)
    g.add_column(style="bold")
    g.add_row("Host",    f"{r.host}:{r.port}")
    g.add_row("IP",      r.ip)
    g.add_row("Scanned", r.scan_time)
    console.print(Panel(g, title="[bold cyan]Scan Target[/bold cyan]", border_style="cyan", expand=False))

def render_certificate(r: ScanResult) -> None:
    _section("CERTIFICATE AUTHORITY & VALIDATION")
    g = Table.grid(padding=(0, 2))
    g.add_column(style="dim", min_width=22)
    g.add_column()
    days = r.cert_days_remaining
    dc = "bold red" if days < 0 else "red" if days < 14 else "yellow" if days < 30 else "green"
    label = "EXPIRED" if days < 0 else "days remaining"
    exp_str = r.cert_valid_to.strftime("%Y-%m-%d") if r.cert_valid_to else "?"
    exp_txt = Text(f"{exp_str}  ({abs(days)} {label})", style=dc)
    key_str = f"{r.cert_key_type} {r.cert_key_size}-bit"
    if r.cert_key_curve: key_str += f" ({r.cert_key_curve})"
    trust_style = "bold green" if r.trust_verified else "bold red"
    trust_status = "VERIFIED SECURE" if r.trust_verified else f"FAILED: {r.trust_error_message}"
    g.add_row("Chain Validation", Text(trust_status, style=trust_style))
    g.add_row("Subject CN",      r.cert_subject or "—")
    g.add_row("Issuer",          r.cert_issuer  or "—")
    g.add_row("Valid From",      r.cert_valid_from.strftime("%Y-%m-%d") if r.cert_valid_from else "—")
    g.add_row("Expires",         exp_txt)
    san_display = r.cert_sans[:6]
    if len(r.cert_sans) > 6: san_display.append(f"… (+{len(r.cert_sans)-6} more)")
    g.add_row("SANs",            ", ".join(san_display) or "—")
    g.add_row("Key Params",      key_str or "—")
    g.add_row("Signature Algo",  r.cert_sig_algo or "—")
    g.add_row("Serial ID",       r.cert_serial or "—")
    g.add_row("Self-Signed Status", Text("YES ⚠️", style="bold red") if r.cert_is_self_signed else Text("No", style="green"))
    if r.cert_ocsp_url: g.add_row("OCSP Endpoint", r.cert_ocsp_url)
    if r.cert_sha256:
        fp = ":".join(r.cert_sha256[i:i+2] for i in range(0, min(len(r.cert_sha256), 32), 2)) + "…"
        g.add_row("SHA-256 Fingerprint", fp)
    console.print(Panel(g, title="[bold]Certificate Identity Details[/bold]", border_style="blue"))

def render_protocols(r: ScanResult) -> None:
    _section("PROTOCOL SUPPORT ANALYSIS")
    tbl = Table(box=box.ROUNDED, border_style="blue", show_lines=True, expand=False)
    tbl.add_column("Protocol",  style="bold", width=12)
    tbl.add_column("Supported", justify="center", width=14)
    tbl.add_column("Risk Level", width=12)
    tbl.add_column("Vulnerability Context", width=46)
    for name, supported in r.protocols.items():
        sev, note, _ = PROTO_RISK.get(name, ("INFO", "", None))
        color, icon  = _sev(sev)
        is_bad = sev in ("CRITICAL", "HIGH", "MEDIUM")
        if supported is None: sup = Text("N/A", style="dim")
        elif supported: sup = Text("YES ⚠️" if is_bad else "YES ✅", style="bold red" if is_bad else "bold green")
        else: sup = Text("NO  ✅" if is_bad else "NO ", style="green" if is_bad else "dim")
        tbl.add_row(name, sup, Text(f"{icon} {sev}", style=color), note)
    console.print(tbl)

def render_ciphers(r: ScanResult) -> None:
    _section("CIPHER METRICS & ENVELOPE SELECTION")
    g = Table.grid(padding=(0, 2))
    g.add_column(style="dim", min_width=22)
    g.add_column()
    g.add_row("Selected Suite", Text(r.negotiated_cipher or "—", style="bold"))
    g.add_row("Protocol In Use",  Text(r.negotiated_proto  or "—", style="bold"))
    g.add_row("Effective Key Bits", Text(str(r.negotiated_bits) if r.negotiated_bits else "—", style="bold"))
    g.add_row("Negotiated ALPN", Text(r.negotiated_alpn, style="bold cyan"))
    
    if r.has_forward_secrecy:
        fs_txt = Text("✅ Active (Mandatory Ephemeral Channels)", style="green") if "1.3" in r.negotiated_proto else Text("✅ Active (ECDHE/DHE)", style="green")
    else:
        fs_txt = Text("❌ Deficient — Static Key Exchange Structure", style="red")
        
    comp_txt = Text("⚠️  Enabled — CRIME Attack Risk Context", style="red") if r.compression_enabled else Text("Disabled ✅", style="green")
    g.add_row("Forward Secrecy",   fs_txt)
    g.add_row("TLS Compression",   comp_txt)
    console.print(Panel(g, title="[bold]Negotiated Session Parameter Verification[/bold]", border_style="blue"))

    console.print()
    if r.weak_ciphers:
        wt = Table(title="[bold red]⚠️  Weak Ciphers Accepted by Target Engine[/bold red]", box=box.ROUNDED, border_style="red", show_lines=True)
        wt.add_column("Cipher Sequence Identification", style="bold", min_width=28)
        wt.add_column("Severity", justify="center", width=12)
        wt.add_column("Risk Threat Vector Matrix")
        for name, sev, detail in r.weak_ciphers:
            c, icon = _sev(sev)
            wt.add_row(name, Text(f"{icon} {sev}", style=c), detail)
        console.print(wt)
    else:
        console.print(Text("  ✅  Server strictly rejects all evaluated legacy weak ciphersuites.", style="green"))

def render_features(r: ScanResult) -> None:
    _section("HTTP SECURITY HEADERS")
    tbl = Table(box=box.ROUNDED, border_style="blue", show_lines=True, expand=False)
    tbl.add_column("Header Directive Parameter", style="bold", width=30)
    tbl.add_column("Status", justify="center", width=14)
    tbl.add_column("Detail Validation Output", width=40)

    def yn(val: bool) -> Text:
        return Text("✅ YES", style="green") if val else Text("❌ NO", style="red")

    tbl.add_row("HTTP → HTTPS Redirect",     yn(r.http_redirect), "Cleartext requests upgraded to secure layer" if r.http_redirect else "Port 80 left open or drop rule enforced")
    tbl.add_row("HSTS Enabled",              yn(r.hsts), f"max-age={r.hsts_max_age:,}s" if r.hsts else "Directive absent")
    tbl.add_row("HSTS includeSubDomains",    yn(r.hsts_subdomains) if r.hsts else Text("—", style="dim"), "Policy covers downward zones" if r.hsts_subdomains else "—")
    tbl.add_row("HSTS Preload",              yn(r.hsts_preload) if r.hsts else Text("—", style="dim"), "Configured for global runtime inclusion lists" if r.hsts_preload else "—")
    console.print(tbl)

def render_findings(r: ScanResult) -> None:
    _section("FINDINGS SUMMARY")
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
    sorted_f = sorted(r.findings, key=lambda f: order.index(f.severity) if f.severity in order else 99)
    issues = [f for f in sorted_f if f.severity not in ("PASS", "INFO")]
    passes = [f for f in sorted_f if f.severity == "PASS"]

    if not issues:
        console.print(Text("  🎉  Zero vulnerabilities detected — policy profile rules satisfied.", style="bold green"))
    else:
        for f in issues:
            c, icon = _sev(f.severity)
            hdr = Text.assemble((f"{icon} [{f.severity}]  ", c), (f.title, f"bold {c}"))
            body_parts: List[Any] = [Text(f"\n  {f.detail}")]
            if f.cve:   body_parts.append(Text.assemble(("\n  ⚑ Identifier Mapping: ", "dim"), (f.cve, "bold yellow")))
            if f.fix:   body_parts.append(Text.assemble(("\n  ↳ Correction Action: ", "dim green"), (f.fix, "green")))
            console.print(Panel(Text.assemble(hdr, *body_parts), border_style=c, expand=True, padding=(0, 1)))
    console.print(f"\n  [dim]✅ {len(passes)} elements evaluated clean  ·  ⚠️  {len(issues)} structural issues discovered[/dim]")

def render_summary(r: ScanResult) -> None:
    _section("EXECUTIVE POSTURE ANALYSIS")
    gc = _grade_color(r.grade)
    bar_w  = 38
    filled = int(r.score / 100 * bar_w)
    bc     = "green" if r.score >= 85 else "yellow" if r.score >= 70 else "red"
    bar    = Text("█" * filled + "░" * (bar_w - filled), style=bc)
    bar.append(f"  {r.score}/100", style=f"bold {bc}")

    crits = sum(1 for f in r.findings if f.severity == "CRITICAL")
    highs = sum(1 for f in r.findings if f.severity == "HIGH")
    meds  = sum(1 for f in r.findings if f.severity == "MEDIUM")

    g = Table.grid(padding=(0, 2))
    g.add_column(style="dim", min_width=18)
    g.add_column()
    g.add_row("Security Score",  bar)
    g.add_row("Assigned Grade",  Text("T - UNTRUSTED LAYER" if r.grade == "T" else r.grade, style=f"bold {gc}"))
    g.add_row("Target Context", Text(f"{r.host}:{r.port}", style="bold"))
    
    if not r.trust_verified: g.add_row("⚠️ Trust Failure", Text("Local trust validation chains broken.", style="bold magenta"))
    if crits: g.add_row("💀 Critical Severity", Text(f"{crits} critical flaws found", style="bold red"))
    if highs: g.add_row("🔴 High Severity",     Text(f"{highs} risk conditions found", style="red"))
    if meds:  g.add_row("🟠 Medium Severity",   Text(f"{meds} remediation targets noted", style="dark_orange"))
    if not crits and not highs and not meds and r.trust_verified:
        g.add_row("", Text("Zero significant configuration vulnerabilities identified. 🎉", style="bold green"))

    console.print(Panel(g, title=f"[{gc}] Evaluation Metric Output Grade: {r.grade} [/{gc}]", border_style=gc, padding=(0, 1)))
    console.print()

# ─── Orchestrator Execution Context ───────────────────────────────────────────

def run_scan(host: str, port: int, timeout: float, skip_ciphers: bool = False) -> ScanResult:
    r = ScanResult(host=host, port=port)
    r.scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = 8 if skip_ciphers else 9

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description:<46}"), BarColumn(bar_width=22), TextColumn("[dim]{task.completed}/{task.total}"), console=console, transient=True) as prog:
        task = prog.add_task("Initializing Target Session…", total=total)

        # ── 1. DNS Resolution
        prog.update(task, description="Resolving namespace records via dns lookup…")
        r.ip = resolve_host(host)
        prog.advance(task)

        # ── 2. Trust Chain Validation
        prog.update(task, description="Evaluating root-anchor CA validation chains…")
        r.trust_verified, r.trust_error_message = verify_trust_chain(host, port, timeout)
        if not r.trust_verified:
            r.findings.append(Finding("Broken Authority Trust Chain", "HIGH", f"Validation failed: {r.trust_error_message}", fix="Deploy missing intermediate path certificates."))
        prog.advance(task)

        # ── 3. Transport Verification
        prog.update(task, description="Extracting binary payload from target context…")
        der = fetch_certificate(host, port, timeout)
        prog.advance(task)

        # ── 4. ASN.1 X.509 Parsing
        prog.update(task, description="Parsing X.509 ASN.1 metadata records…")
        if der:
            meta, cert_findings = parse_certificate(der, host)
            r.cert_subject, r.cert_issuer = meta["subject"], meta["issuer"]
            r.cert_valid_from, r.cert_valid_to = meta["valid_from"], meta["valid_to"]
            r.cert_days_remaining, r.cert_expired = meta["days_remaining"], meta["expired"]
            r.cert_sans, r.cert_sig_algo, r.cert_sha256 = meta["sans"], meta["sig_algo"], meta["sha256"]
            r.cert_key_type, r.cert_key_size, r.cert_key_curve = meta["key_type"], meta["key_size"], meta["key_curve"]
            r.cert_serial, r.cert_is_self_signed, r.cert_is_wildcard = meta["serial"], meta["is_self_signed"], meta["is_wildcard"]
            r.cert_ocsp_url = meta.get("ocsp_url", "")
            r.findings.extend(cert_findings)
        else:
            r.errors.append("Target certificate data generation error.")
            r.findings.append(Finding("Handshake Protocol Negation Error", "CRITICAL", "Could not establish an SSL handshake context.", fix="Verify network route or target state."))
        prog.advance(task)

        # ── 5. Protocol Probing
        prog.update(task, description="Probing explicit configuration protocol spaces…")
        r.protocols = probe_protocols(host, port, timeout)
        for pname, risk_meta in PROTO_RISK.items():
            if pname in ("TLS 1.2", "TLS 1.3"): continue
            if r.protocols.get(pname) is True:
                r.findings.append(Finding(f"{pname} Enabled", risk_meta[0], f"Obsolete transport architecture variant accepted.", risk_meta[1], f"Disable {pname} protocol support."))
        if r.protocols.get("TLS 1.2") is True: r.findings.append(Finding("TLS 1.2 Capability", "PASS", "TLS 1.2 active."))
        if r.protocols.get("TLS 1.3") is True: r.findings.append(Finding("TLS 1.3 Capability", "PASS", "TLS 1.3 optimized."))
        prog.advance(task)

        # ── 6. Session Parameters Mapping
        prog.update(task, description="Evaluating context handshake metadata states…")
        r.negotiated_cipher, r.negotiated_proto, r.negotiated_bits, r.negotiated_alpn, r.compression_enabled = get_session_info(host, port, timeout)
        
        if "1.3" in r.negotiated_proto:
            r.has_forward_secrecy = True
        else:
            r.has_forward_secrecy = any(x in r.negotiated_cipher.upper() for x in ["ECDHE", "DHE", "CHACHA20"])
        prog.advance(task)

        # ── 7. Cipher Suite Audit
        if not skip_ciphers:
            prog.update(task, description="Mapping weak ciphersuites configurations…")
            r.weak_ciphers = scan_weak_ciphers(host, port, timeout)
            for name, sev, detail in r.weak_ciphers:
                r.findings.append(Finding(f"Weak Cipher Accepted ({name})", sev, detail, fix="Update system configuration to deny legacy ciphersuites."))
            prog.advance(task)

        # ── 8 & 9. HSTS & Cleartext Redirection Validation Hooks
        prog.update(task, description="Auditing transit header controls and HSTS rules…")
        hsts_meta, redirects = check_hsts_and_redirect(host, port, timeout, r.errors)
        r.hsts, r.http_redirect = hsts_meta["enabled"], redirects
        r.hsts_max_age, r.hsts_subdomains, r.hsts_preload = hsts_meta["max_age"], hsts_meta["subdomains"], hsts_meta["preload"]
        
        if not r.hsts:
            r.findings.append(Finding("Missing HSTS Header Strategy", "MEDIUM", "HTTP Strict-Transport-Security rules missing.", fix="Implement standard HSTS headers immediately."))
        if not r.http_redirect and port == 443:
            r.findings.append(Finding("Missing Inbound Cleartext Upgrades", "LOW", "Port 80 left open without cleartext upgrade handling.", fix="Configure a permanent redirect from port 80 to 443."))

        prog.advance(task)
        if skip_ciphers: prog.advance(task)

        # Compute Metrics
        r.score, r.grade = score_result(r)
        
    return r

def main() -> None:
    parser = argparse.ArgumentParser(description="ssl_scan.py — Production-Grade SSL/TLS Security Analyzer Engine")
    parser.add_argument("host", help="Target evaluation hostname.")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port pathway (Default target: 443)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Socket baseline duration limit (Default: 5s)")
    parser.add_argument("--json", help="Saves report metric structures as JSON data.")
    parser.add_argument("--no-cipher-scan", action="store_true", help="Disables deep legacy cipher verification loops.")
    args = parser.parse_args()

    print_banner()
    try:
        res = run_scan(args.host, args.port, args.timeout, skip_ciphers=args.no_cipher_scan)
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Evaluation session closed by user execution signal.[/bold red]")
        sys.exit(130)

    render_target(res)
    if res.cert_subject: render_certificate(res)
    render_protocols(res)
    render_ciphers(res)
    render_features(res)
    render_findings(res)
    render_summary(res)

    if res.errors:
        console.print(Panel("\n".join(f"· {e}" for e in res.errors), title="[bold yellow]Scan Trace Errors[/bold yellow]", border_style="yellow", expand=False))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(res), f, indent=4, default=str)

if __name__ == "__main__":
    main()