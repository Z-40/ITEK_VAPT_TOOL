#!/usr/bin/env python3
"""
enumerate.py  —  Async Subdomain Enumeration & DNS Validation

Passive sources (all three run concurrently):
  1. subfinder  —  tool, fast, breadth-first
  2. amass      —  tool, passive mode, hard time-capped
  3. crt.sh     —  certificate transparency via HTTPS, no tool required

Active validation:
  aiodns  —  event-loop-native DNS via c-ares. No thread pool. No GIL
             contention. Handles 50k subdomains in seconds, not minutes.

Install:
  pip install aiodns aiohttp

Usage:
  python enumerate.py example.com
  python enumerate.py example.com --dns-concurrency 750 --amass-timeout 5
"""

import asyncio
import argparse
import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiodns
import aiohttp

# ---------------------------------------------------------------------------
# Defaults  (all overridable via CLI)
# ---------------------------------------------------------------------------

SUBFINDER_THREADS:  int        = 50
AMASS_TIMEOUT_MIN:  int        = 10
SUBPROCESS_TIMEOUT: int        = 660       # wall-clock kill cap per tool (seconds)
CRTSH_TIMEOUT:      int        = 30        # crt.sh HTTP request timeout
DNS_CONCURRENCY:    int        = 500       # parallel aiodns coroutines
DNS_TIMEOUT:        float      = 3.0       # per-host resolution timeout
DNS_NAMESERVERS:    List[str]  = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def preflight(tools: List[str]) -> bool:
    ok = True
    for t in tools:
        if shutil.which(t) is None:
            log.error("Tool not found in PATH: %s", t)
            ok = False
    return ok

# ---------------------------------------------------------------------------
# Passive source 1 & 2  —  subprocess tools
# ---------------------------------------------------------------------------

async def run_tool(cmd: List[str], label: str, timeout: int) -> Set[str]:
    """
    Execute a subprocess, stream stdout until completion or timeout,
    return a deduplicated lowercase set of non-empty lines.
    """
    log.info("[%s] %s", label, " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            log.warning("[%s] Killed after %ds timeout.", label, timeout)
            return set()

        found = {ln.strip().lower() for ln in stdout.decode("utf-8", errors="replace").splitlines() if ln.strip()}
        log.info("[%s] %d subdomains.", label, len(found))
        return found

    except FileNotFoundError:
        log.error("[%s] Binary missing at exec time: %s", label, cmd[0])
        return set()
    except Exception as exc:
        log.error("[%s] %s", label, exc)
        return set()

# ---------------------------------------------------------------------------
# Passive source 3  —  crt.sh (certificate transparency)
# ---------------------------------------------------------------------------

async def run_crtsh(domain: str, timeout: int) -> Set[str]:
    """
    Query crt.sh for all certificates issued to *.domain.
    No external tool required — pure HTTPS.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    log.info("[crt.sh] %s", url)
    found: Set[str] = set()

    try:
        connector = aiohttp.TCPConnector(ssl=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Accept": "application/json"},
            ) as resp:
                if resp.status != 200:
                    log.warning("[crt.sh] HTTP %d — skipping.", resp.status)
                    return found
                data = await resp.json(content_type=None)

        suffix = f".{domain}"
        for entry in data:
            for raw in entry.get("name_value", "").splitlines():
                name = raw.strip().lstrip("*.").lower()
                if name and (name == domain or name.endswith(suffix)):
                    found.add(name)

        log.info("[crt.sh] %d subdomains.", len(found))

    except asyncio.TimeoutError:
        log.warning("[crt.sh] Timed out after %ds.", timeout)
    except Exception as exc:
        log.warning("[crt.sh] %s", exc)

    return found

# ---------------------------------------------------------------------------
# Passive orchestration
# ---------------------------------------------------------------------------

async def gather_passive(
    domain: str,
    subprocess_timeout: int,
    amass_timeout_min: int,
    subfinder_threads: int,
    crtsh_timeout: int,
) -> Set[str]:
    """Run all three sources concurrently; return merged, deduplicated set."""
    sf, am, ct = await asyncio.gather(
        run_tool(
            ["subfinder", "-d", domain, "-silent", "-t", str(subfinder_threads)],
            label="subfinder",
            timeout=subprocess_timeout,
        ),
        run_tool(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", str(amass_timeout_min)],
            label="amass",
            timeout=subprocess_timeout,
        ),
        run_crtsh(domain, crtsh_timeout),
    )

    merged = sf | am | ct
    log.info(
        "Passive complete. subfinder=%d | amass=%d | crt.sh=%d | unique=%d",
        len(sf), len(am), len(ct), len(merged),
    )
    return merged

# ---------------------------------------------------------------------------
# Active DNS validation  —  aiodns, no thread pool
# ---------------------------------------------------------------------------

async def resolve_one(
    subdomain: str,
    resolver: aiodns.DNSResolver,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> Tuple[str, Optional[str]]:
    """
    Resolve a single A record.  Returns (subdomain, ip) or (subdomain, None).
    The semaphore limits how many c-ares queries are in-flight simultaneously.
    All exceptions (NXDOMAIN, SERVFAIL, timeout, malformed name) map to None.
    """
    async with semaphore:
        try:
            result = await asyncio.wait_for(
                resolver.query_dns(subdomain, "A"),
                timeout=timeout,
            )
            return subdomain, result.answer[0].data.addr
        except Exception:
            return subdomain, None


async def validate(
    subdomains: Set[str],
    nameservers: List[str],
    concurrency: int,
    timeout: float,
) -> Dict[str, str]:
    """
    Resolve all candidates concurrently using aiodns.
    Logs progress every 2,000 completions so long runs stay visible.
    """
    total = len(subdomains)
    log.info(
        "DNS validation: %d candidates | concurrency=%d | timeout=%.1fs | ns=%s",
        total, concurrency, timeout, ",".join(nameservers),
    )

    resolver  = aiodns.DNSResolver(nameservers=nameservers)
    semaphore = asyncio.Semaphore(concurrency)
    alive: Dict[str, str] = {}
    done = 0
    REPORT_INTERVAL = 2000

    tasks = [
        asyncio.ensure_future(resolve_one(s, resolver, semaphore, timeout))
        for s in subdomains
    ]

    for future in asyncio.as_completed(tasks):
        subdomain, ip = await future
        if ip is not None:
            alive[subdomain] = ip
        done += 1
        if done % REPORT_INTERVAL == 0:
            log.info("  ... %d / %d resolved (alive so far: %d)", done, total, len(alive))

    return alive

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def save(domain: str, alive: Dict[str, str]) -> Path:
    path = Path(f"{domain}_alive_subdomains.json")
    ts   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    payload = {
        "target": domain,
        "generated": ts,
        "alive_count": len(alive),
        "subdomains": {k: v for k, v in sorted(alive.items())}
    }

    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=4)

    return path.resolve()

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def pipeline(
    domain: str,
    subprocess_timeout: int,
    amass_timeout_min: int,
    subfinder_threads: int,
    crtsh_timeout: int,
    dns_concurrency: int,
    dns_timeout: float,
    dns_nameservers: List[str],
) -> None:
    t0 = asyncio.get_running_loop().time()

    log.info("=" * 60)
    log.info("  enumerate.py  |  target: %s", domain)
    log.info("  %s UTC", datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    log.info("=" * 60)

    if not preflight(["subfinder", "amass"]):
        log.error("Aborting: missing required tools.")
        sys.exit(1)

    # Stage 1 — Passive
    log.info("--- Stage 1: Passive Recon ---")
    candidates = await gather_passive(
        domain, subprocess_timeout, amass_timeout_min,
        subfinder_threads, crtsh_timeout,
    )

    if not candidates:
        log.info("No subdomains discovered. Exiting.")
        sys.exit(0)

    # Stage 2 — DNS Validation
    log.info("--- Stage 2: DNS Validation ---")
    alive = await validate(candidates, dns_nameservers, dns_concurrency, dns_timeout)

    pct = len(alive) / len(candidates) * 100
    log.info(
        "Validation complete: %d alive / %d candidates (%.1f%%)",
        len(alive), len(candidates), pct,
    )

    # Stage 3 — Output
    log.info("--- Stage 3: Output ---")
    if alive:
        path = save(domain, alive)
        log.info("Saved: %s", path)
    else:
        log.info("No alive subdomains to write.")

    log.info("Finished in %.2fs.", asyncio.get_running_loop().time() - t0)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="enumerate.py",
        description="Async subdomain enumeration: subfinder + amass + crt.sh → aiodns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "install:  pip install aiodns aiohttp\n"
            "example:  python enumerate.py example.com\n"
            "          python enumerate.py example.com --dns-concurrency 750 --amass-timeout 5\n"
        ),
    )
    ap.add_argument("domain",
                    help="Target root domain (e.g. example.com)")
    ap.add_argument("--subprocess-timeout", type=int,   default=SUBPROCESS_TIMEOUT,
                    metavar="SECS",  help=f"Kill cap per tool process (default: {SUBPROCESS_TIMEOUT}s)")
    ap.add_argument("--amass-timeout",      type=int,   default=AMASS_TIMEOUT_MIN,
                    metavar="MINS",  help=f"Passed as -timeout to amass (default: {AMASS_TIMEOUT_MIN}m)")
    ap.add_argument("--subfinder-threads",  type=int,   default=SUBFINDER_THREADS,
                    metavar="N",     help=f"Passed as -t to subfinder (default: {SUBFINDER_THREADS})")
    ap.add_argument("--crtsh-timeout",      type=int,   default=CRTSH_TIMEOUT,
                    metavar="SECS",  help=f"crt.sh HTTP timeout (default: {CRTSH_TIMEOUT}s)")
    ap.add_argument("--dns-concurrency",    type=int,   default=DNS_CONCURRENCY,
                    metavar="N",     help=f"Parallel DNS coroutines (default: {DNS_CONCURRENCY})")
    ap.add_argument("--dns-timeout",        type=float, default=DNS_TIMEOUT,
                    metavar="SECS",  help=f"Per-host DNS timeout (default: {DNS_TIMEOUT}s)")
    ap.add_argument("--dns-nameservers",    nargs="+",  default=DNS_NAMESERVERS,
                    metavar="IP",    help=f"Resolver IPs (default: {' '.join(DNS_NAMESERVERS)})")

    args = ap.parse_args()

    try:
        asyncio.run(pipeline(
            domain             = args.domain,
            subprocess_timeout = args.subprocess_timeout,
            amass_timeout_min  = args.amass_timeout,
            subfinder_threads  = args.subfinder_threads,
            crtsh_timeout      = args.crtsh_timeout,
            dns_concurrency    = args.dns_concurrency,
            dns_timeout        = args.dns_timeout,
            dns_nameservers    = args.dns_nameservers,
        ))
    except KeyboardInterrupt:
        log.info("Interrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()