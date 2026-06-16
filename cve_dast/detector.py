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

    async def _resolve(
        self, host: str, port: int
    ) -> Optional[Tuple[int, tuple]]:
        """
        Executor-backed non-blocking DNS lookup.
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
        Raw async TCP connect via loop.sock_connect()
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
        async with self._sem:
            resolved = await self._resolve(subdomain, 443)
            if resolved is None:
                return None

            family, sa_https = resolved

            if await self._tcp_connect(family, sa_https):
                return f"https://{subdomain}"

            # Reuse the resolved IP; only replace the port field.
            sa_http = (sa_https[0], 80) + sa_https[2:]
            if await self._tcp_connect(family, sa_http):
                return f"http://{subdomain}"

        return None

    # ── public API ────────────────────────────────────────────────────────────

    async def filter(self, subdomains: List[str]) -> List[str]:
        total = len(subdomains)
        logger.info(
            "Live-host filter: %s subdomains | concurrency=%d | "
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
            results = await asyncio.gather(
                *(self._probe(sub) for sub in chunk),
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
            "Filter complete: %s raw subdomains → %s live web targets.",
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
                    "-tags",       "tech,exposure,misconfig,http"
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

    # ── orchestration ─────────────────────────────────────────────────────────

    async def run(self, domain: str, import_alive_path: Optional[str] = None) -> str:
        banner = f"  VAPT Pipeline  ·  Target: {domain}  "
        logger.info("─" * len(banner))
        logger.info(banner)
        logger.info("─" * len(banner))

        raw_subs = []

        # Stage 1 — Subdomain recon
        if import_alive_path:
            if os.path.exists(import_alive_path):
                logger.info("Importing subdomains from discovery file: %s", import_alive_path)
                try:
                    with open(import_alive_path, "r", encoding="utf-8", errors="replace") as f:
                        data = json.load(f)
                        subs_dict = data.get("subdomains", {})
                        raw_subs = list(subs_dict.keys())
                    logger.info("Imported %s subdomains from file.", f"{len(raw_subs):,}")
                except Exception as e:
                    logger.error("Failed to parse discovery file: %s. Falling back to subfinder.", e)
                    raw_subs = await self._run_subfinder(domain)
            else:
                logger.error("Specified path does not exist: %s. Falling back to subfinder.", import_alive_path)
                raw_subs = await self._run_subfinder(domain)
        else:
            raw_subs = await self._run_subfinder(domain)

        # Stage 2 — Live-host filtering
        if raw_subs:
            live_targets = await self.host_filter.filter(raw_subs)
        else:
            logger.warning("Subfinder returned nothing — falling back to root domain.")
            live_targets = [f"https://{domain}", f"http://{domain}"]

        # Stage 3 — Vulnerability scanning
        vulns = await self._run_nuclei(live_targets)

        report = {
            "target_domain":            domain,
            "raw_subdomains_found":     len(raw_subs),
            "live_web_targets_scanned": len(live_targets),
            "total_vulnerabilities":    len(vulns),
            "vulnerabilities":          [v.to_dict() for v in vulns],
        }
        return json.dumps(report, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Async VAPT Pipeline  |  Subfinder → Live-Filter → Nuclei",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Changed required=False to allow usage of only --import-alive
    parser.add_argument(
        "-d", "--domain",
        required=False,
        help="Root domain to scan (e.g. example.com)",
    )
    parser.add_argument(
        "--import-alive",
        type=str,
        default=None,
        help="Path to pre-generated domain.com_alive_subdomains.json file",
    )
    # ... (Keep other arguments as they were) ...
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--probe-timeout", type=float, default=DEFAULT_PROBE_TIMEOUT)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--dns-threads", type=int, default=DEFAULT_DNS_THREADS)
    args = parser.parse_args()

    # Ensure at least one input method is provided
    if not args.domain and not args.import_alive:
        parser.error("You must provide either -d/--domain or --import-alive")
    
    # If no domain is provided, try to infer it from the filename or prompt the user
    target_domain = args.domain or "imported_domain"

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

    try:
        report = loop.run_until_complete(pipeline.run(target_domain, import_alive_path=args.import_alive))
        print("\n=== FINAL NORMALIZED REPORT ===")
        print(report)
    except KeyboardInterrupt:
        logger.info("Interrupted — pipeline terminated by user.")
    finally:
        loop.close()