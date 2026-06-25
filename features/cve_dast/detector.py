#!/usr/bin/env python3
"""
vapt_pipeline.py — Async VAPT Orchestrator (Windows-optimised)

Three root causes of the original bottleneck, and how this rewrite fixes them:

  1. WORKER-QUEUE THUNDERING HERD
     Original: 1 000 asyncio workers all calling open_connection() with a 1 s
     timeout.  At t=1.0 s every worker times out simultaneously, hammering the
     OS with 1 000 concurrent socket-close events and re-scheduling 1 000 new
     coroutines at once.  Workers also spin idle via get_nowait() when the queue
     drains faster than new items arrive.
     Fix: asyncio.Semaphore(N).  N coroutines — one per subdomain — compete for
     the semaphore gate.  Completed probes release the gate immediately, so the
     pool stays saturated with zero idle spinning.

  2. DNS THREAD-POOL STARVATION
     open_connection() calls loop.getaddrinfo() internally, which is a blocking
     OS syscall dispatched through loop.run_in_executor().  Python's default
     ThreadPoolExecutor caps at min(32, cpu_count+4) threads ≈ 36.  With 1 000
     concurrent open_connection() calls, ~964 are queued behind 36 DNS slots —
     the true bottleneck, never visible in the async layer.
     Fix: loop.set_default_executor(ThreadPoolExecutor(max_workers=256)).

  3. DOUBLE DNS PER HOST + TIME_WAIT PORT EXHAUSTION
     The original probed port 443 and port 80 via separate open_connection()
     calls, triggering two getaddrinfo() round-trips per subdomain.  Each
     successful connect also left a TIME_WAIT socket (Windows default: 4 min).
     With 80 k+ probes the ~16 k ephemeral port range fills up, causing
     WSAEADDRINUSE failures that look like dropped connections.
     Fix: single loop.getaddrinfo() per host reused for both port checks, plus
     SO_LINGER(1,0) on every socket to send RST-on-close, bypassing TIME_WAIT.

─────────────────────────────────────────────────────────────────────────────
JSON FILE MODE  (-f / --file)                                    ← NEW
─────────────────────────────────────────────────────────────────────────────
Accepts a pre-enumerated subdomain file produced by aggregator.py / the
enumerate module.  Expected format:

    {
        "target":    "example.com",
        "generated": "2026-06-15 11:32:31 UTC",
        "alive_count": 4,
        "subdomains": {
            "example.com":     "13.0.0.1",
            "sub.example.com": "13.0.0.2"
        }
    }

When -f is supplied:
  • Subfinder is skipped entirely (subdomains are already known).
  • Each subdomain's pre-resolved IP is used directly for TCP probing,
    eliminating all getaddrinfo() calls and the DNS thread-pool bottleneck
    for the live-host filter stage.
  • The domain is taken from the JSON "target" field unless -d is also
    given, in which case -d takes precedence.

OUTPUT FILE  (-o / --output)
─────────────────────────────────────────────────────────────────────────────
The pipeline always writes its report to a JSON file.  The destination is
controlled by -o / --output:

  Not supplied          → <cwd>/<domain>_vapt_report.json
  -o /path/to/dir/      → /path/to/dir/<domain>_vapt_report.json
  -o /path/to/file.json → /path/to/file.json   (used verbatim)
  -o report             → <cwd>/report.json     (.json appended if absent)

Parent directories are created automatically.  A concise human-readable
summary is always printed to stdout; the full JSON payload goes only to the
file so that stdout stays pipe-friendly.

Usage examples:
  python vapt_pipeline.py -d example.com
  python vapt_pipeline.py -d example.com -o /results/
  python vapt_pipeline.py -d example.com -o /results/scan.json
  python vapt_pipeline.py -f subdomains.json
  python vapt_pipeline.py -f subdomains.json -o ./reports/
  python vapt_pipeline.py -f subdomains.json -d override.com -o scan.json
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import logging
import os
import socket
import struct
import sys
import tempfile
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

# ── Windows: ProactorEventLoop (IOCP) is already the 3.8+ default, but
#    pinning the policy prevents third-party libraries from replacing it.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("VAPT_Orchestrator")

# ──────────────────────────────────────────────────────────────────────────────
# TUNING DEFAULTS  (all exposed as CLI flags)
# ──────────────────────────────────────────────────────────────────────────────
DEFAULT_CONCURRENCY   = 350    # Max simultaneous TCP probes (semaphore cap)
DEFAULT_PROBE_TIMEOUT = 2.0    # Seconds — combined DNS + TCP connect budget
DEFAULT_BATCH_SIZE    = 5_000  # Subdomains per asyncio.gather() wave
DEFAULT_DNS_THREADS   = 256    # ThreadPoolExecutor workers for getaddrinfo()

NUCLEI_CONCURRENCY = 70
NUCLEI_BULK_SIZE   = 35
NUCLEI_RATE_LIMIT  = 200

# ──────────────────────────────────────────────────────────────────────────────
# DATA SCHEMA
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class VulnerabilityReport:
    template_id: str
    name:        str
    severity:    str
    type:        str
    target:      str
    matched_at:  str
    description: str
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ──────────────────────────────────────────────────────────────────────────────
# ASYNC CLI RUNNER
# ──────────────────────────────────────────────────────────────────────────────
class AsyncToolRunner:
    """Thin async wrapper around external binary execution."""

    @staticmethod
    async def execute(
        cmd: List[str], timeout: int = 1800
    ) -> Tuple[int, str, str]:
        logger.info("Exec: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return (
                proc.returncode,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            logger.error("Timed out: %s", " ".join(cmd))
            try:
                proc.kill()  # type: ignore[possibly-undefined]
            except Exception:
                pass
            return -1, "", "Timeout"
        except Exception as exc:
            logger.error("Execution failed: %s", exc)
            return -1, "", str(exc)


# ──────────────────────────────────────────────────────────────────────────────
# LIVE-HOST FILTER  ← the performance-critical layer
# ──────────────────────────────────────────────────────────────────────────────
class LiveHostFilter:
    """
    High-throughput TCP prober for 100k+ subdomain lists on Windows.

    Design notes
    ─────────────
    Semaphore gate (not worker pool)
        asyncio.Semaphore(N) is the correct primitive for I/O bound fan-out.
        One coroutine is created per subdomain; at most N hold the gate at any
        instant.  Completed probes release the gate immediately — no idle
        workers, no empty-queue polling, no thundering-herd wake-up storms.

    loop.sock_connect() over asyncio.open_connection()
        open_connection() allocates a StreamReader + StreamWriter per call.
        sock_connect() issues a raw IOCP ConnectEx (on Windows) and discards
        the socket the moment we know the port is open.  At 100k probes this
        saves ~150 MB of stream buffer allocation and roughly 30% of per-probe
        object overhead.

    Single DNS resolution per subdomain
        DNS is resolved once via loop.getaddrinfo() and the resulting IP is
        reused for both port 443 and port 80 checks.  The original issued two
        independent open_connection() calls, each triggering its own
        getaddrinfo() round-trip — 160k DNS queries for 80k subdomains.

    SO_LINGER(1, 0) — RST on close
        A normal TCP close generates FIN/ACK → TIME_WAIT (240 s on Windows).
        With tens-of-thousands of probes the ~16k ephemeral port range fills
        up, causing WSAEADDRINUSE failures that masquerade as connection drops.
        Setting l_onoff=1, l_linger=0 sends RST instead of FIN, bypassing
        TIME_WAIT entirely and keeping the ephemeral port pool free.

    Oversized ThreadPoolExecutor for DNS
        getaddrinfo() is a blocking syscall executed in the default executor.
        Python caps the default pool at ≈32–36 threads; 350 concurrent probes
        queue 314 DNS lookups behind those 36 slots.  Raising the pool to 256
        threads lets the bottleneck shift back to the network where it belongs.

    Batched asyncio.gather()
        Scheduling 80k Task objects at once is legal but allocates ~8–10 MB of
        Task state up front.  BATCH_SIZE chunks keep peak allocation bounded and
        provide regular progress log lines without slowing the scan.

    IP-aware fast path  (filter_with_ips)                        ← NEW
        When a pre-resolved {subdomain: ip} map is supplied (e.g. from a JSON
        file produced by the enumerate module), DNS is bypassed entirely.
        _probe_with_ip() uses the provided IP directly, eliminating every
        getaddrinfo() call and the associated ThreadPoolExecutor pressure.
    """

    # l_onoff=1, l_linger=0 packed as two unsigned shorts (both Windows + Linux)
    _LINGER_RST = struct.pack("HH", 1, 0)

    def __init__(
        self,
        concurrency:   int   = DEFAULT_CONCURRENCY,
        probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
        batch_size:    int   = DEFAULT_BATCH_SIZE,
    ) -> None:
        self._sem          = asyncio.Semaphore(concurrency)
        self.probe_timeout = probe_timeout
        self.batch_size    = batch_size
        self._concurrency  = concurrency

    # ── internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _get_af(ip: str) -> int:
        """
        Return socket.AF_INET6 if *ip* is a valid IPv6 address,
        socket.AF_INET otherwise.  Used by the DNS-bypass fast path.
        """                                                          # ← NEW
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return socket.AF_INET6
        except OSError:
            return socket.AF_INET

    async def _resolve(
        self, host: str, port: int
    ) -> Optional[Tuple[int, tuple]]:
        """
        Executor-backed non-blocking DNS lookup.
        Returns (socket_family, sockaddr) of the first result, or None on any
        failure (NXDOMAIN, timeout, unreachable resolver, etc.).
        """
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP),
                timeout=self.probe_timeout,
            )
            if not infos:
                return None
            family, _, _, _, sockaddr = infos[0]
            return family, sockaddr
        except Exception:
            return None

    async def _tcp_connect(self, family: int, sockaddr: tuple) -> bool:
        """
        Raw async TCP connect via loop.sock_connect() (maps to IOCP ConnectEx
        on Windows).  The socket is closed with RST immediately after the
        connect attempt — success or failure.
        """
        loop = asyncio.get_running_loop()
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)

        # Apply socket options; silently skip any that the platform rejects
        for level, opt, val in (
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
            (socket.SOL_SOCKET, socket.SO_LINGER,    self._LINGER_RST),
        ):
            try:
                sock.setsockopt(level, opt, val)
            except OSError:
                pass

        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, sockaddr),
                timeout=self.probe_timeout,
            )
            return True
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return False
        finally:
            try:
                sock.close()
            except Exception:
                pass

    async def _probe(self, subdomain: str) -> Optional[str]:
        """
        Full probe for one subdomain under the shared semaphore:
          1. DNS resolved once for port 443 (same IP used for port 80).
          2. TCP connect attempted on 443 (HTTPS).
          3. If 443 is closed, port component swapped to 80 (HTTP) and retried.
          4. Returns the first live URL, or None if both ports are unreachable.

        Acquiring the semaphore is the only point of contention between
        coroutines — once inside, all I/O is non-blocking and independent.
        """
        async with self._sem:
            resolved = await self._resolve(subdomain, 443)
            if resolved is None:
                # NXDOMAIN or resolver timeout — no point checking port 80
                return None

            family, sa_https = resolved

            if await self._tcp_connect(family, sa_https):
                return f"https://{subdomain}"

            # Reuse the resolved IP; only replace the port field.
            # IPv4 sockaddr: (host, port)          — sa_https[2:] is empty
            # IPv6 sockaddr: (host, port, flow, id) — sa_https[2:] preserved
            sa_http = (sa_https[0], 80) + sa_https[2:]
            if await self._tcp_connect(family, sa_http):
                return f"http://{subdomain}"

        return None

    async def _probe_with_ip(                                      # ← NEW
        self, subdomain: str, ip: str
    ) -> Optional[str]:
        """
        DNS-bypass fast path.  Uses the pre-resolved *ip* directly so that
        no getaddrinfo() call is issued — eliminating the ThreadPoolExecutor
        bottleneck entirely for file-sourced subdomain lists.

        Socket family is inferred from the IP address string so both IPv4
        and IPv6 entries from the JSON file are handled transparently.

        The returned URL uses the original *subdomain* hostname (not the raw
        IP) so that Nuclei's HTTP probes send the correct Host header.
        """
        family = self._get_af(ip)

        async with self._sem:
            # IPv6 sockaddr needs (host, port, flowinfo, scope_id)
            if family == socket.AF_INET6:
                sa_https: tuple = (ip, 443, 0, 0)
            else:
                sa_https = (ip, 443)

            if await self._tcp_connect(family, sa_https):
                return f"https://{subdomain}"

            if family == socket.AF_INET6:
                sa_http: tuple = (ip, 80, 0, 0)
            else:
                sa_http = (ip, 80)

            if await self._tcp_connect(family, sa_http):
                return f"http://{subdomain}"

        return None

    # ── public API ────────────────────────────────────────────────────────────

    async def filter(self, subdomains: List[str]) -> List[str]:
        """
        Processes *subdomains* in BATCH_SIZE waves via asyncio.gather().
        Between each wave a progress line is logged and fully completed Task
        objects are GC-eligible — keeping peak RAM proportional to batch_size
        rather than the total list length.

        Returns a deduplicated list of reachable URLs in discovery order.
        """
        total = len(subdomains)
        logger.info(
            "Live-host filter (DNS mode): %s subdomains | concurrency=%d | "
            "timeout=%.1fs | batch=%s",
            f"{total:,}",
            self._concurrency,
            self.probe_timeout,
            f"{self.batch_size:,}",
        )

        live: List[str] = []
        processed = 0

        for i in range(0, total, self.batch_size):
            chunk = subdomains[i : i + self.batch_size]

            # return_exceptions=True ensures one slow/failing host can't
            # propagate an unhandled exception that aborts the entire wave.
            results = await asyncio.gather(
                *(self._probe(sub) for sub in chunk),
                return_exceptions=True,
            )

            # Collect only str returns (successful probes); discard None + exc
            live.extend(r for r in results if isinstance(r, str))
            processed += len(chunk)

            logger.info(
                "  [%s / %s | %.1f%%] — %s live targets found so far",
                f"{processed:,}",
                f"{total:,}",
                processed / total * 100,
                f"{len(live):,}",
            )

        # dict.fromkeys preserves insertion order while deduplicating
        unique = list(dict.fromkeys(live))
        logger.info(
            "Filter complete: %s raw subdomains → %s live web targets.",
            f"{total:,}",
            f"{len(unique):,}",
        )
        return unique

    async def filter_with_ips(                                     # ← NEW
        self, subdomain_ip_map: Dict[str, str]
    ) -> List[str]:
        """
        IP-aware variant of filter() for use when subdomains were loaded from
        a JSON file that already contains resolved IP addresses.

        Compared to filter():
          • Calls _probe_with_ip() instead of _probe() — zero getaddrinfo().
          • All DNS thread-pool pressure is eliminated.
          • Subdomains whose IP value is empty or non-string are silently
            fallen back to the standard DNS path via _probe().

        Returns a deduplicated list of reachable URLs in discovery order.
        """
        items      = list(subdomain_ip_map.items())   # [(subdomain, ip), ...]
        total      = len(items)
        live: List[str] = []
        processed  = 0

        # Count how many entries have a usable pre-resolved IP for logging
        ip_hits  = sum(1 for _, ip in items if ip and isinstance(ip, str))
        ip_misses = total - ip_hits

        logger.info(
            "Live-host filter (IP-bypass mode): %s subdomains | "
            "%s with pre-resolved IPs | %s falling back to DNS | "
            "concurrency=%d | timeout=%.1fs | batch=%s",
            f"{total:,}",
            f"{ip_hits:,}",
            f"{ip_misses:,}",
            self._concurrency,
            self.probe_timeout,
            f"{self.batch_size:,}",
        )

        for i in range(0, total, self.batch_size):
            chunk = items[i : i + self.batch_size]

            results = await asyncio.gather(
                *(
                    self._probe_with_ip(sub, ip)
                    if ip and isinstance(ip, str)
                    else self._probe(sub)
                    for sub, ip in chunk
                ),
                return_exceptions=True,
            )

            live.extend(r for r in results if isinstance(r, str))
            processed += len(chunk)

            logger.info(
                "  [%s / %s | %.1f%%] — %s live targets found so far",
                f"{processed:,}",
                f"{total:,}",
                processed / total * 100,
                f"{len(live):,}",
            )

        unique = list(dict.fromkeys(live))
        logger.info(
            "Filter complete: %s subdomains → %s live web targets.",
            f"{total:,}",
            f"{len(unique):,}",
        )
        return unique


# ──────────────────────────────────────────────────────────────────────────────
# VAPT PIPELINE
# ──────────────────────────────────────────────────────────────────────────────
class VAPTPipeline:

    def __init__(
        self,
        concurrency:   int   = DEFAULT_CONCURRENCY,
        probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
        batch_size:    int   = DEFAULT_BATCH_SIZE,
    ) -> None:
        self.runner         = AsyncToolRunner()
        self.host_filter    = LiveHostFilter(concurrency, probe_timeout, batch_size)
        self.subfinder_path = os.path.abspath("subfinder.exe")
        self.nuclei_path    = os.path.abspath("nuclei.exe")

    # ── stages ────────────────────────────────────────────────────────────────

    async def _run_subfinder(self, domain: str) -> List[str]:
        if not os.path.exists(self.subfinder_path):
            logger.error("Subfinder binary not found: %s", self.subfinder_path)
            return []

        _, stdout, _ = await self.runner.execute(
            [self.subfinder_path, "-d", domain, "-silent"], timeout=450
        )
        subs = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        logger.info("Subfinder: %s raw subdomains discovered.", f"{len(subs):,}")
        return subs

    async def _run_nuclei(self, targets: List[str]) -> List[VulnerabilityReport]:
        if not targets:
            logger.info("No live targets — skipping Nuclei.")
            return []

        if not os.path.exists(self.nuclei_path):
            logger.error("Nuclei binary not found: %s", self.nuclei_path)
            return []

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tf:
            tf.write("\n".join(targets))
            target_file = tf.name

        output_file = tempfile.mktemp(suffix=".jsonl")

        try:
            await self.runner.execute(
                [
                    self.nuclei_path,
                    "-l",          target_file,
                    "-jsonl",
                    "-o",          output_file,
                    "-silent",
                    "-c",          str(NUCLEI_CONCURRENCY),
                    "-bulk-size",  str(NUCLEI_BULK_SIZE),
                    "-rate-limit", str(NUCLEI_RATE_LIMIT),
                    "-tags",       "tech,exposure,misconfig,http",
                ],
                timeout=7200,
            )
            return self._parse_nuclei_output(output_file)
        finally:
            for path in (target_file, output_file):
                try:
                    os.remove(path)
                except OSError:
                    pass

    @staticmethod
    def _parse_nuclei_output(filepath: str) -> List[VulnerabilityReport]:
        reports: List[VulnerabilityReport] = []
        if not os.path.exists(filepath):
            return reports

        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                if not raw_line.strip():
                    continue
                try:
                    data = json.loads(raw_line)
                    info = data.get("info", {})
                    reports.append(
                        VulnerabilityReport(
                            template_id = data.get("template-id", "unknown"),
                            name        = info.get("name",        "Unknown Vulnerability"),
                            severity    = info.get("severity",    "info"),
                            type        = data.get("type",        "unknown"),
                            target      = data.get("host",        "unknown"),
                            matched_at  = data.get("matched-at",  "unknown"),
                            description = info.get("description", "No description."),
                            remediation = info.get("remediation"),
                        )
                    )
                except json.JSONDecodeError:
                    continue

        return reports

    # ── JSON file loader  ← NEW ───────────────────────────────────────────────

    @staticmethod
    def load_subdomains_from_file(                                 # ← NEW
        filepath: str,
    ) -> Tuple[str, Dict[str, str]]:
        """
        Parse a JSON subdomain file produced by aggregator.py / the enumerate
        module and return (target_domain, {subdomain: ip}).

        Accepted formats for the "subdomains" value:

          Flat map (enumerate / alive-check output):
              {"sub.example.com": "1.2.3.4", ...}

          Nested map (fingerprinting output — ip extracted from inner dict):
              {"sub.example.com": {"ip": "1.2.3.4", "waf_vendor": ...}, ...}

          Any subdomain whose value cannot be resolved to an IP string is
          stored as "" so it falls back to the DNS path in filter_with_ips().

        Raises
        ──────
        FileNotFoundError  if *filepath* does not exist.
        ValueError         if the JSON is missing the "subdomains" key or it
                           is not a dict.
        json.JSONDecodeError  if the file is not valid JSON.
        """
        filepath = os.path.abspath(filepath)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Subdomain file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        if not isinstance(data, dict):
            raise ValueError("JSON file root must be an object.")

        raw_subs = data.get("subdomains")
        if raw_subs is None:
            raise ValueError(
                "JSON file is missing the required 'subdomains' key. "
                "Expected format: {\"subdomains\": {\"host\": \"ip\", ...}}"
            )
        if not isinstance(raw_subs, dict):
            raise ValueError(
                f"'subdomains' must be a JSON object, got {type(raw_subs).__name__}."
            )

        # Normalise: extract IP regardless of whether the value is a plain
        # string or a nested object with an "ip" / "address" field.
        subdomain_ip_map: Dict[str, str] = {}
        for subdomain, value in raw_subs.items():
            if isinstance(value, str):
                # Flat map: value is the IP directly
                subdomain_ip_map[subdomain] = value
            elif isinstance(value, dict):
                # Nested map: look for common IP key names
                ip = (
                    value.get("ip")
                    or value.get("address")
                    or value.get("resolved_ip")
                    or value.get("ipv4")
                    or ""
                )
                subdomain_ip_map[subdomain] = ip if isinstance(ip, str) else ""
            else:
                # Unknown shape — store empty string → DNS fallback
                subdomain_ip_map[subdomain] = ""

        target = data.get("target", "")

        logger.info(
            "Loaded %s subdomains from %s (target=%r, generated=%s)",
            f"{len(subdomain_ip_map):,}",
            os.path.basename(filepath),
            target,
            data.get("generated", "unknown"),
        )
        return target, subdomain_ip_map

    # ── orchestration ─────────────────────────────────────────────────────────

    async def run_cve(                                                  # ← MODIFIED
        self,
        domain: str,
        subdomain_ip_map: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Execute the full three-stage pipeline.

        Parameters
        ──────────
        domain
            Root domain used for labelling in the output report and as the
            Subfinder target when no *subdomain_ip_map* is provided.

        subdomain_ip_map : optional                                 ← NEW
            Pre-resolved {subdomain: ip} dict loaded from a JSON file.
            When supplied:
              • Stage 1 (Subfinder) is skipped entirely.
              • Stage 2 uses filter_with_ips() — no DNS calls are made.
        """
        banner = f"  VAPT Pipeline  ·  Target: {domain}  "
        logger.info("─" * len(banner))
        logger.info(banner)
        logger.info("─" * len(banner))

        if subdomain_ip_map is not None:
            # ── FILE MODE: subdomains already known ──────────────────────────
            logger.info(
                "Stage 1 [Subfinder] — SKIPPED  "
                "(%s subdomains loaded from file)",
                f"{len(subdomain_ip_map):,}",
            )
            raw_sub_count = len(subdomain_ip_map)

            # Stage 2 — Live-host filtering (IP-bypass, zero DNS calls)
            logger.info("Stage 2 [Live-host filter] — IP-bypass mode")
            if subdomain_ip_map:
                live_targets = await self.host_filter.filter_with_ips(
                    subdomain_ip_map
                )
            else:
                logger.warning("Subdomain file was empty — falling back to root domain.")
                live_targets = [f"https://{domain}", f"http://{domain}"]

        else:
            # ── DISCOVERY MODE: run Subfinder first ──────────────────────────
            logger.info("Stage 1 [Subfinder] — discovering subdomains for %s", domain)
            raw_subs = await self._run_subfinder(domain)
            raw_sub_count = len(raw_subs)

            # Stage 2 — Live-host filtering (standard DNS path)
            logger.info("Stage 2 [Live-host filter] — DNS mode")
            if raw_subs:
                live_targets = await self.host_filter.filter(raw_subs)
            else:
                logger.warning("Subfinder returned nothing — falling back to root domain.")
                live_targets = [f"https://{domain}", f"http://{domain}"]

        # Stage 3 — Vulnerability scanning (identical in both modes)
        logger.info(
            "Stage 3 [Nuclei] — scanning %s live targets", f"{len(live_targets):,}"
        )
        vulns = await self._run_nuclei(live_targets)

        report = {
            "target_domain":            domain,
            "raw_subdomains_found":     raw_sub_count,
            "live_web_targets_scanned": len(live_targets),
            "total_vulnerabilities":    len(vulns),
            "vulnerabilities":          [v.to_dict() for v in vulns],
        }
        return json.dumps(report, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# OUTPUT PATH RESOLVER
# ──────────────────────────────────────────────────────────────────────────────
def _resolve_output_path(output_arg: Optional[str], domain: str) -> str:
    """
    Turn the raw -o / --output argument (or its absence) into an absolute
    path to a writable .json file.

    Rules (in priority order):
      1. Not supplied         → <cwd>/<domain>_vapt_report.json
      2. Existing directory   → <that_dir>/<domain>_vapt_report.json
      3. Any other string     → taken verbatim; .json appended if the path
                                has no extension at all (e.g. "report" →
                                "report.json", but "report.txt" is left as-is
                                so the caller's intent is never silently changed)

    Parent directories that do not yet exist are created here so that a
    subsequent open(..., "w") cannot fail with FileNotFoundError.

    Raises
    ──────
    OSError  if the parent directory cannot be created (e.g. permission denied).
    """
    default_filename = f"{domain}_vapt_report.json"

    if output_arg is None:
        # Rule 1: default to CWD
        path = os.path.join(os.getcwd(), default_filename)

    elif os.path.isdir(output_arg):
        # Rule 2: caller gave an existing directory — append default filename
        path = os.path.join(output_arg, default_filename)

    else:
        # Rule 3: treat as a file path; add .json only when there is no
        # extension at all (splitext returns "" for the suffix in that case)
        root, ext = os.path.splitext(output_arg)
        path = output_arg if ext else output_arg + ".json"

    # Ensure the path is absolute so log messages are unambiguous
    path = os.path.abspath(path)

    # Create any missing parent directories now, before the pipeline starts
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)

    return path


# ──────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Async VAPT Pipeline  |  [Subfinder →] Live-Filter → Nuclei\n\n"
            "Input modes (mutually exclusive):\n"
            "  -d DOMAIN        Run Subfinder to discover subdomains, then scan.\n"
            "  -f FILE          Load pre-enumerated subdomains from a JSON file\n"
            "                   and scan them directly (Subfinder is skipped).\n"
            "  -f FILE -d DOM   Use FILE for subdomains; override the target\n"
            "                   domain label with DOM instead of the file's\n"
            "                   'target' field.\n\n"
            "Output:\n"
            "  -o PATH          Write the JSON report to PATH (file or directory).\n"
            "                   Defaults to <cwd>/<domain>_vapt_report.json."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Input source (at least one of -d / -f must be provided) ──────────────
    input_grp = parser.add_argument_group("input (provide -d, -f, or both)")
    input_grp.add_argument(
        "-d", "--domain",
        default=None,
        metavar="DOMAIN",
        help=(
            "Root domain to scan (e.g. example.com).  "
            "Required when -f is not supplied.  "
            "When combined with -f, overrides the domain label."
        ),
    )
    input_grp.add_argument(
        "-f", "--file",
        default=None,
        metavar="FILE",
        help=(
            "Path to a JSON file with pre-discovered subdomains.  "
            "Subfinder is skipped; IPs from the file bypass DNS resolution.  "
            "The 'target' field in the file is used as the domain unless -d "
            "is also provided."
        ),
    )

    # ── Output ────────────────────────────────────────────────────────────────
    out_grp = parser.add_argument_group("output")
    out_grp.add_argument(
        "-o", "--output",
        default=None,
        metavar="PATH",
        help=(
            "Destination for the JSON report.  "
            "Accepts a file path, a directory (default filename is appended), "
            "or a name without extension (.json is added automatically).  "
            "Defaults to <cwd>/<domain>_vapt_report.json."
        ),
    )

    # ── Performance tuning ────────────────────────────────────────────────────
    perf_grp = parser.add_argument_group("performance tuning")
    perf_grp.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        metavar="N",
        help=f"Max simultaneous TCP probes — semaphore cap. (default: {DEFAULT_CONCURRENCY})",
    )
    perf_grp.add_argument(
        "--probe-timeout",
        type=float,
        default=DEFAULT_PROBE_TIMEOUT,
        metavar="SECS",
        help=f"Per-probe timeout in seconds — covers DNS + TCP connect. (default: {DEFAULT_PROBE_TIMEOUT})",
    )
    perf_grp.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        metavar="N",
        help=f"Subdomain chunk size per asyncio.gather() wave. (default: {DEFAULT_BATCH_SIZE:,})",
    )
    perf_grp.add_argument(
        "--dns-threads",
        type=int,
        default=DEFAULT_DNS_THREADS,
        metavar="N",
        help=(
            f"ThreadPoolExecutor workers for blocking getaddrinfo() calls. "
            f"Ignored when -f is used (no DNS calls are made). "
            f"(default: {DEFAULT_DNS_THREADS})"
        ),
    )

    args = parser.parse_args()

    # ── Validate: at least one input source must be given ────────────────────
    if not args.domain and not args.file:
        parser.error("Provide at least one of -d/--domain or -f/--file.")

    # ── Resolve domain and (optionally) load subdomain map from file ─────────
    subdomain_ip_map: Optional[Dict[str, str]] = None

    if args.file:
        try:
            file_target, subdomain_ip_map = VAPTPipeline.load_subdomains_from_file(
                args.file
            )
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            logger.error("Failed to load subdomain file: %s", exc)
            sys.exit(1)

        # -d overrides the domain label from the file; file's target is the fallback
        domain = args.domain or file_target
        if not domain:
            parser.error(
                "Could not determine target domain: the JSON file has no 'target' "
                "field.  Supply -d/--domain explicitly."
            )
    else:
        # Discovery mode: -d is the only input source
        domain = args.domain

    # ── Resolve output path (domain must be known before this call) ───────────
    try:
        output_path = _resolve_output_path(args.output, domain)
    except OSError as exc:
        logger.error("Cannot create output directory: %s", exc)
        sys.exit(1)

    logger.info("Report will be written to: %s", output_path)

    # ── Build a dedicated event loop with an oversized executor ───────────────
    # asyncio.run() is avoided here because we must set_default_executor()
    # before any coroutines are scheduled — the executor is consumed by
    # getaddrinfo() calls the moment the first probe coroutine starts.
    loop = asyncio.new_event_loop()
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(max_workers=args.dns_threads)
    )
    asyncio.set_event_loop(loop)

    pipeline = VAPTPipeline(
        concurrency   = args.concurrency,
        probe_timeout = args.probe_timeout,
        batch_size    = args.batch_size,
    )

    report_json: Optional[str] = None
    try:
        report_json = loop.run_until_complete(
            pipeline.run(domain, subdomain_ip_map=subdomain_ip_map)
        )
    except KeyboardInterrupt:
        logger.info("Interrupted — pipeline terminated by user.")
    finally:
        loop.close()

    if report_json is None:
        logger.warning("Pipeline produced no output — report file not written.")
        sys.exit(1)

    # ── Write JSON report to file ─────────────────────────────────────────────
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(report_json)
    except OSError as exc:
        logger.error("Failed to write report to %s: %s", output_path, exc)
        sys.exit(1)

    # ── Print concise summary to stdout (full JSON lives in the file) ─────────
    report_data = json.loads(report_json)
    vuln_counts: Dict[str, int] = {}
    for v in report_data.get("vulnerabilities", []):
        sev = v.get("severity", "unknown")
        vuln_counts[sev] = vuln_counts.get(sev, 0) + 1

    sev_order   = ["critical", "high", "medium", "low", "info", "unknown"]
    sev_summary = "  ".join(
        f"{s.upper()}: {vuln_counts[s]}"
        for s in sev_order
        if s in vuln_counts
    ) or "none"

    width = 62
    print()
    print("═" * width)
    print("  VAPT Pipeline — Complete")
    print("─" * width)
    print(f"  Target          : {report_data['target_domain']}")
    print(f"  Subdomains      : {report_data['raw_subdomains_found']:,}")
    print(f"  Live targets    : {report_data['live_web_targets_scanned']:,}")
    print(f"  Vulnerabilities : {report_data['total_vulnerabilities']:,}  ({sev_summary})")
    print(f"  Report saved    : {output_path}")
    print("═" * width)


if __name__ == "__main__":
    main()