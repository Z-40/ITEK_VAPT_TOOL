from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Mute OpenSSL legacy TLS 1.0/1.1 context deprecation warnings from python runtime noise
warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:
    print("[!] Missing required dependency: cryptography. Run 'pip install cryptography' first.")
    sys.exit(1)

# ─── Constants ────────────────────────────────────────────────────────────────
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

# ──────────────────────────────────────────────────────────────────────────────
# CORE UTILITIES
# ──────────────────────────────────────────────────────────────────────────────
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
    hsts_res = {"enabled": False, "max_age": 0, "subdomains": False, "preload": False}
    redirects_to_https = False
    
    try:
        import urllib.request
        import urllib.error
        
        http_url = f"http://{host}/"
        req = urllib.request.Request(http_url, headers={"User-Agent": "ssl-scan/3.2"}, method="GET")
        ctx = _make_ctx()
        
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.url.startswith("https://"):
                    redirects_to_https = True
        except urllib.error.HTTPError as e:
            if hasattr(e, 'url') and getattr(e, 'url', '').startswith("https://"):
                redirects_to_https = True
            elif e.headers.get("Location", "").startswith("https://") or e.headers.get("Location", "").startswith("//"):
                redirects_to_https = True
    except Exception:
        pass

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
        req = urllib.request.Request(url, headers={"User-Agent": "ssl-scan/3.2"})
        
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

# ──────────────────────────────────────────────────────────────────────────────
# SCORING ENGINE
# ──────────────────────────────────────────────────────────────────────────────
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

# ──────────────────────────────────────────────────────────────────────────────
# SCANNING ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────
def run_scan(host: str, port: int, timeout: float, skip_ciphers: bool = False) -> ScanResult:
    r = ScanResult(host=host, port=port)
    r.scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. DNS Resolution
    r.ip = resolve_host(host)

    # 2. Trust Chain Validation
    r.trust_verified, r.trust_error_message = verify_trust_chain(host, port, timeout)
    if not r.trust_verified:
        r.findings.append(Finding("Broken Authority Trust Chain", "HIGH", f"Validation failed: {r.trust_error_message}", fix="Deploy missing intermediate path certificates."))

    # 3. Transport Verification
    der = fetch_certificate(host, port, timeout)

    # 4. ASN.1 X.509 Parsing
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

    # 5. Protocol Probing
    r.protocols = probe_protocols(host, port, timeout)
    for pname, risk_meta in PROTO_RISK.items():
        if pname in ("TLS 1.2", "TLS 1.3"): continue
        if r.protocols.get(pname) is True:
            r.findings.append(Finding(f"{pname} Enabled", risk_meta[0], f"Obsolete transport architecture variant accepted.", risk_meta[1], f"Disable {pname} protocol support."))
    if r.protocols.get("TLS 1.2") is True: r.findings.append(Finding("TLS 1.2 Capability", "PASS", "TLS 1.2 active."))
    if r.protocols.get("TLS 1.3") is True: r.findings.append(Finding("TLS 1.3 Capability", "PASS", "TLS 1.3 optimized."))

    # 6. Session Parameters Mapping
    r.negotiated_cipher, r.negotiated_proto, r.negotiated_bits, r.negotiated_alpn, r.compression_enabled = get_session_info(host, port, timeout)
    
    if "1.3" in r.negotiated_proto:
        r.has_forward_secrecy = True
    else:
        r.has_forward_secrecy = any(x in r.negotiated_cipher.upper() for x in ["ECDHE", "DHE", "CHACHA20"])

    # 7. Cipher Suite Audit
    if not skip_ciphers:
        r.weak_ciphers = scan_weak_ciphers(host, port, timeout)
        for name, sev, detail in r.weak_ciphers:
            r.findings.append(Finding(f"Weak Cipher Accepted ({name})", sev, detail, fix="Update system configuration to deny legacy ciphersuites."))

    # 8. HSTS & Cleartext Redirection Validation Hooks
    hsts_meta, redirects = check_hsts_and_redirect(host, port, timeout, r.errors)
    r.hsts, r.http_redirect = hsts_meta["enabled"], redirects
    r.hsts_max_age, r.hsts_subdomains, r.hsts_preload = hsts_meta["max_age"], hsts_meta["subdomains"], hsts_meta["preload"]
    
    if not r.hsts:
        r.findings.append(Finding("Missing HSTS Header Strategy", "MEDIUM", "HTTP Strict-Transport-Security rules missing.", fix="Implement standard HSTS headers immediately."))
    if not r.http_redirect and port == 443:
        r.findings.append(Finding("Missing Inbound Cleartext Upgrades", "LOW", "Port 80 left open without cleartext upgrade handling.", fix="Configure a permanent redirect from port 80 to 443."))

    # Compute Metrics
    r.score, r.grade = score_result(r)
    return r

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SYNCHRONOUS IN-MEMORY INTERFACE
# ─────────────────────────────────────────────────────────────────────────────
def scan_tls(input_json_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts a structured payload dictionary containing baseline evaluation metrics,
    executes SSL/TLS validation and network handshake analyses,
    and returns a structured payload metadata dictionary entirely in memory.
    """
    port = int(input_json_data.get("port", 443))
    timeout = float(input_json_data.get("timeout", 5.0))
    skip_ciphers = bool(input_json_data.get("no_cipher_scan", False))

    targets: List[str] = []
    if "subdomains" in input_json_data:
        subs_node = input_json_data["subdomains"]
        if isinstance(subs_node, dict):
            targets = list(subs_node.keys())
        elif isinstance(subs_node, list):
            targets = list(set(subs_node))
    elif "target" in input_json_data:
        target_field = input_json_data["target"]
        targets = [target_field] if isinstance(target_field, str) else list(target_field)

    if not targets:
        raise ValueError("Input JSON configuration is missing a clean positional 'target' or 'subdomains' map layer.")

    scan_results = {}
    for target in targets:
        try:
            res_obj = run_scan(target, port, timeout, skip_ciphers=skip_ciphers)
            scan_results[target] = dataclasses.asdict(res_obj)
        except Exception as exc:
            scan_results[target] = {
                "host": target,
                "port": port,
                "status": "error",
                "error_msg": str(exc)
            }

    return {
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_targets_scanned": len(targets),
        "results": scan_results
    }