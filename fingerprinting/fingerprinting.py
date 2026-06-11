#!/usr/bin/env python3
"""
fingerprint.py — Web Fingerprinting & Asset Inventory Tool
===========================================================
Reads a subdomain enumeration JSON produced by an upstream tool,
concurrently probes every host over both HTTP and HTTPS, and writes a
structured fingerprint report (with summary statistics) to a JSON file
named ``<target>_web_fingerprints.json`` in the same directory as the
input file.

Usage
-----
    # Minimal
    python fingerprint.py scan.json

    # Full flags
    python fingerprint.py scan.json --concurrency 50 --timeout 15

Expected input format
---------------------
    {
        "target": "example.com",
        "generated": "2026-06-11 06:10:04 UTC",
        "alive_count": 3,
        "subdomains": {
            "qa.example.com":       "10.0.0.1",
            "retail.example.com":   "10.0.0.2"
        }
    }

Dependencies (one-time install)
--------------------------------
    pip install aiohttp

Python: 3.10+   (uses ``match`` and new-style type hints internally)
"""

from __future__ import annotations  # PEP 563: postponed evaluation of annotations

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Dependency guard — give the user a clear install hint if aiohttp is absent
# ---------------------------------------------------------------------------
try:
    import aiohttp
    from aiohttp import (
        ClientConnectorError,
        ClientError,
        ClientResponseError,
        ClientSSLError,
        ServerDisconnectedError,
        ServerTimeoutError,
        TooManyRedirects,
    )
except ImportError:
    sys.exit(
        "[ERROR] aiohttp is not installed.\n"
        "        Run:  pip install aiohttp"
    )


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Read only the first N bytes of each response body.
# 64 KiB is large enough to capture any realistic <head> block while
# avoiding the cost of buffering entire multi-MB downloads.
_BODY_READ_LIMIT: int = 65_536

# Pre-compiled once; DOTALL lets '.' cross newlines inside <title> tags.
_TITLE_RE: re.Pattern[str] = re.compile(
    r"<title[^>]*>(.*?)</title>",
    re.IGNORECASE | re.DOTALL,
)

# Schemes to probe for every discovered subdomain.
_SCHEMES: tuple[str, ...] = ("http", "https")


# ---------------------------------------------------------------------------
# Mutable counter (thread-safe within asyncio's single-threaded event loop)
# ---------------------------------------------------------------------------

class _Counter:
    """Tiny mutable integer wrapper used for atomic-ish progress counting."""

    __slots__ = ("value",)

    def __init__(self) -> None:
        self.value: int = 0

    def increment(self) -> int:
        """Bump and return the new value."""
        self.value += 1
        return self.value


# ---------------------------------------------------------------------------
# Per-probe record skeleton
# ---------------------------------------------------------------------------

def _new_probe_record(url: str) -> dict[str, Any]:
    """
    Return a zeroed-out probe record for *url*.

    Explicit ``None``/``[]`` defaults make the schema predictable for
    downstream consumers — they never encounter a missing key.
    """
    return {
        "probed_url": url,
        "final_url": None,   # URL after all redirects have been followed
        "status_code": None,   # Integer HTTP status (e.g. 200, 301, 403)
        "server": None,   # Value of the "Server" response header
        "x_powered_by": None,   # Value of the "X-Powered-By" header
        "title": None,   # Inner text of the HTML <title> element
        "redirect_chain": [],     # Ordered list of URLs traversed (populated
                                  # only when at least one redirect occurred)
        "error": None,   # Human-readable failure reason, or None
    }


# ---------------------------------------------------------------------------
# Core async probe — the hot path
# ---------------------------------------------------------------------------

async def probe_url(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    url: str,
    timeout: aiohttp.ClientTimeout,
    counter: _Counter,
    total: int,
) -> dict[str, Any]:
    """
    Perform a single HTTP GET against *url* and return a fingerprint record.

    The function *never raises* — all exceptions are caught and stored in
    ``record["error"]``, so ``asyncio.gather()`` can collect every result
    even when individual hosts are unreachable.

    Parameters
    ----------
    session : Shared ``aiohttp.ClientSession`` (ssl=False already set on the
              underlying connector — no certificate validation is performed).
    sem     : ``asyncio.Semaphore`` that caps simultaneous in-flight requests.
    url     : Fully-qualified URL to probe (e.g. ``https://qa.example.com``).
    timeout : ``aiohttp.ClientTimeout`` applied to the entire request lifecycle.
    counter : Shared mutable counter incremented after each probe completes.
    total   : Total number of probes scheduled (used for progress display).

    Returns
    -------
    ``dict`` with keys: probed_url, final_url, status_code, server,
    x_powered_by, title, redirect_chain, error.
    """
    record = _new_probe_record(url)

    # Only ``concurrency`` coroutines may execute the body block simultaneously.
    async with sem:
        try:
            async with session.get(
                url,
                timeout=timeout,
                allow_redirects=True,   # follow 3xx chains automatically
            ) as resp:

                # ── Basic metadata from the final response ────────────────
                record["status_code"] = resp.status
                record["final_url"] = str(resp.url)
                record["server"] = resp.headers.get("Server")
                record["x_powered_by"] = resp.headers.get("X-Powered-By")

                # ── Redirect chain ────────────────────────────────────────
                # ``resp.history`` is a tuple of ClientResponse objects for
                # every intermediate hop; ``resp.url`` is the final landing URL.
                # We only populate the list when at least one hop occurred.
                if resp.history:
                    record["redirect_chain"] = (
                        [str(hop.url) for hop in resp.history]
                        + [str(resp.url)]
                    )

                # ── HTML <title> extraction (pure regex, no extra deps) ───
                # We read a bounded chunk of the body so large binary
                # responses (file downloads, media) are not fully buffered.
                try:
                    chunk = await resp.content.read(_BODY_READ_LIMIT)
                    # Decode leniently; replace any undecodable byte sequences.
                    snippet = chunk.decode("utf-8", errors="replace")
                    match = _TITLE_RE.search(snippet)
                    if match:
                        # Collapse internal whitespace and stray newlines that
                        # HTML authors routinely embed inside <title> tags.
                        record["title"] = " ".join(match.group(1).split())
                except Exception:
                    # A body-read failure is non-fatal; title stays None.
                    pass

        # ── Exception ladder (most specific → most general) ───────────────

        except asyncio.TimeoutError:
            # The request exceeded the total timeout.
            record["error"] = "timeout"

        except ServerTimeoutError:
            # The remote server took too long to respond.
            record["error"] = "server_timeout"

        except TooManyRedirects:
            # aiohttp hit its internal redirect limit (default: 10).
            record["error"] = "too_many_redirects"

        except ClientSSLError as exc:
            # Defensive catch: ssl=False disables cert verification, but
            # some environments still raise on TLS protocol-level failures.
            record["error"] = f"ssl_error: {exc}"

        except (ClientConnectorError, ServerDisconnectedError) as exc:
            # Host unreachable, refused connection, or mid-stream disconnect.
            record["error"] = f"connection_error: {exc}"

        except ClientResponseError as exc:
            # Server returned an error response that aiohttp chose to raise.
            record["error"] = f"http_error: {exc.status}"

        except ClientError as exc:
            # Catch-all for any remaining aiohttp-specific errors.
            record["error"] = f"client_error: {type(exc).__name__}: {exc}"

        except Exception as exc:
            # Last-resort safety net — should never fire in normal operation.
            record["error"] = f"unexpected_error: {type(exc).__name__}: {exc}"

    # ── Progress reporting ────────────────────────────────────────────────
    # Incrementing outside the semaphore block means the counter advances
    # as soon as the probe finishes, regardless of sem contention.
    n = counter.increment()
    pct = n / total * 100

    # Build a compact one-liner: index | percentage | status | url
    tag = "OK " if record["error"] is None else "ERR"
    sc = record["status_code"] or "---"
    print(f"  [{n:>4}/{total}] {pct:5.1f}%  [{tag}] {sc}  {url}", flush=True)

    return record


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def run_fingerprinting(
    subdomains: dict[str, str],
    *,
    concurrency: int,
    timeout_secs: float,
) -> list[dict[str, Any]]:
    """
    Fan-out probes across all *subdomains* (HTTP + HTTPS) concurrently and
    return results grouped by subdomain.

    Parameters
    ----------
    subdomains    : ``{hostname: resolved_ip}`` mapping from the input JSON.
    concurrency   : Upper bound on simultaneous in-flight HTTP connections.
    timeout_secs  : Per-request wall-clock timeout in seconds.

    Returns
    -------
    List of dicts, each with keys:
    ``subdomain``, ``ip``, ``probes`` (list of two probe records — one per
    scheme in the order ``http``, ``https``).
    """
    sem = asyncio.Semaphore(concurrency)
    timeout = aiohttp.ClientTimeout(total=timeout_secs)

    # TCPConnector settings
    # ─────────────────────
    # ssl=False  → skip certificate validation entirely; essential for
    #              QA / UAT hosts that use self-signed or expired certs.
    # limit      → mirror the semaphore ceiling in the connection pool so
    #              we never create more pooled connections than we can use.
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)

    # Build the flat list of (hostname, ip, scheme) triples.
    # Preserving insertion order means HTTP always precedes HTTPS for each
    # host in the final grouped output.
    probes_meta: list[tuple[str, str, str]] = [
        (hostname, ip, scheme)
        for hostname, ip in subdomains.items()
        for scheme in _SCHEMES
    ]

    total = len(probes_meta)
    counter = _Counter()

    async with aiohttp.ClientSession(connector=connector) as session:
        # Create one Task per (host × scheme) combination.
        # Named tasks make asyncio debug output more readable.
        tasks = [
            asyncio.create_task(
                probe_url(
                    session,
                    sem,
                    f"{scheme}://{hostname}",
                    timeout,
                    counter,
                    total,
                ),
                name=f"{scheme}://{hostname}",
            )
            for hostname, ip, scheme in probes_meta
        ]

        # asyncio.gather never raises here because probe_url catches
        # every exception internally.
        probe_results: list[dict[str, Any]] = await asyncio.gather(*tasks)

    # ── Re-group flat probe list by subdomain ─────────────────────────────
    # We want one top-level record per subdomain that contains both probe
    # results (http first, then https), for clean JSON structure.
    per_host: dict[str, dict[str, Any]] = {}
    for (hostname, ip, _scheme), result in zip(probes_meta, probe_results):
        if hostname not in per_host:
            per_host[hostname] = {
                "subdomain": hostname,
                "ip": ip,
                "probes": [],
            }
        per_host[hostname]["probes"].append(result)

    return list(per_host.values())


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Derive high-level statistics from the collected probe results.

    Returns a dict suitable for the top-level ``"summary"`` section of the
    output report.
    """
    all_probes: list[dict[str, Any]] = [
        probe
        for host in results
        for probe in host["probes"]
    ]

    successful = [p for p in all_probes if p["error"] is None]
    failed = [p for p in all_probes if p["error"] is not None]

    # Collect observable characteristics from successful probes only.
    status_codes = sorted({p["status_code"] for p in successful})
    servers = sorted({p["server"] for p in successful if p["server"]})
    technologies = sorted({p["x_powered_by"] for p in successful if p["x_powered_by"]})

    # Hosts where at least one probe responded (either scheme).
    live_hosts = sorted({
        host["subdomain"]
        for host in results
        if any(p["error"] is None for p in host["probes"])
    })

    # Unique error types observed across all failed probes.
    error_types = sorted({
        p["error"].split(":")[0]            # e.g. "connection_error"
        for p in failed
        if p["error"]
    })

    return {
        "total_probes": len(all_probes),
        "successful_probes": len(successful),
        "failed_probes": len(failed),
        "live_hosts": live_hosts,
        "unique_status_codes": status_codes,
        "unique_servers": servers,
        "unique_technologies": technologies,
        "observed_error_types": error_types,
    }


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def load_and_validate_input(path: str) -> dict[str, Any]:
    """
    Load, parse, and schema-validate the upstream enumeration JSON.

    Calls ``sys.exit()`` with a clear message on any I/O or schema problem,
    so the caller can assume the returned dict is always well-formed.
    """
    if not os.path.isfile(path):
        sys.exit(f"[ERROR] File not found: '{path}'")

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data: dict[str, Any] = json.load(fh)
    except json.JSONDecodeError as exc:
        sys.exit(f"[ERROR] Malformed JSON in '{path}': {exc}")

    # Required top-level keys.
    for key in ("target", "subdomains"):
        if key not in data:
            sys.exit(f"[ERROR] Input JSON is missing required key: '{key}'")

    if not isinstance(data["subdomains"], dict):
        sys.exit(
            "[ERROR] 'subdomains' must be a JSON object "
            "(keys = hostnames, values = IP strings)."
        )

    if not data["subdomains"]:
        sys.exit("[ERROR] 'subdomains' object is empty — nothing to probe.")

    return data


def derive_output_path(input_path: str, target: str) -> str:
    """
    Build the output file path.

    The output file is placed in the *same directory* as the input file so
    the pair stays co-located on disk.

    Example
    -------
    >>> derive_output_path("/tmp/scans/run.json", "example.com")
    '/tmp/scans/example.com_web_fingerprints.json'
    """
    directory = os.path.dirname(os.path.abspath(input_path))
    filename = f"{target}_web_fingerprints.json"
    return os.path.join(directory, filename)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_cli() -> argparse.Namespace:
    """
    Declare and parse the command-line interface.

    Returns a populated ``argparse.Namespace`` with attributes:
    ``input_file``, ``concurrency``, ``timeout``.
    """
    parser = argparse.ArgumentParser(
        prog="fingerprint.py",
        description=(
            "Web fingerprinting & asset inventory — probes every subdomain "
            "in an enumeration JSON over HTTP and HTTPS and writes a "
            "structured report."
        ),
        # Append "(default: N)" to each optional arg's help string automatically.
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # ── Positional ────────────────────────────────────────────────────────
    parser.add_argument(
        "input_file",
        metavar="INPUT_JSON",
        help="Path to the upstream subdomain enumeration JSON file.",
    )

    # ── Optional flags ────────────────────────────────────────────────────
    parser.add_argument(
        "--concurrency",
        type=int,
        default=100,
        metavar="N",
        help="Maximum simultaneous in-flight HTTP requests.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECS",
        help="Per-request total timeout in seconds.",
    )

    args = parser.parse_args()

    # ── Sanity checks ─────────────────────────────────────────────────────
    if args.concurrency < 1:
        parser.error("--concurrency must be an integer >= 1.")
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number.")

    return args


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    """
    Main coroutine.

    Execution flow
    ──────────────
    1. Parse CLI args.
    2. Load and validate the input JSON.
    3. Print a pre-flight banner.
    4. Run the async fingerprinting engine.
    5. Assemble the final report dict.
    6. Write the report to disk.
    7. Print a post-scan summary.
    """
    args = parse_cli()
    input_data = load_and_validate_input(args.input_file)

    target: str = input_data["target"]
    subdomains: dict[str, str] = input_data["subdomains"]
    n_hosts: int = len(subdomains)
    n_probes: int = n_hosts * len(_SCHEMES)

    # ── Pre-flight banner ─────────────────────────────────────────────────
    print("=" * 60)
    print("  fingerprint.py  — Web Asset Fingerprinting Engine")
    print("=" * 60)
    print(f"  Target             : {target}")
    print(f"  Subdomains loaded  : {n_hosts}")
    print(f"  Endpoints to probe : {n_probes}  ({'/'.join(_SCHEMES)} × {n_hosts})")
    print(f"  Concurrency        : {args.concurrency}")
    print(f"  Timeout            : {args.timeout}s per request")
    print("=" * 60)
    print()

    scan_start = datetime.now(timezone.utc)

    # ── Execute fingerprinting ────────────────────────────────────────────
    results = await run_fingerprinting(
        subdomains,
        concurrency=args.concurrency,
        timeout_secs=args.timeout,
    )

    scan_end = datetime.now(timezone.utc)
    elapsed = (scan_end - scan_start).total_seconds()

    # ── Assemble the final report ─────────────────────────────────────────
    summary = build_summary(results)

    report: dict[str, Any] = {
        # Tracking metadata — always the first key for quick inspection.
        "scan_metadata": {
            "target": target,
            "source_file": os.path.abspath(args.input_file),
            # Pass through the timestamp from the upstream enumerator (if any).
            "upstream_generated": input_data.get("generated"),
            "scanned_at": scan_start.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "scan_duration_seconds": round(elapsed, 3),
            "total_subdomains": n_hosts,
            "total_endpoints_probed": n_probes,
            "concurrency": args.concurrency,
            "timeout_seconds": args.timeout,
        },

        # Aggregated statistics — useful at a glance without parsing results.
        "summary": summary,

        # Full per-subdomain probe data.
        "results": results,
    }

    # ── Write output JSON ─────────────────────────────────────────────────
    output_path = derive_output_path(args.input_file, target)
    with open(output_path, "w", encoding="utf-8") as fh:
        # indent=2 keeps the file human-readable; ensure_ascii=False preserves
        # any non-ASCII characters in page titles or server banners.
        json.dump(report, fh, indent=2, ensure_ascii=False)

    # ── Post-scan summary banner ──────────────────────────────────────────
    print()
    print("=" * 60)
    print(f"  Scan complete in {elapsed:.2f}s")
    print(f"  Probes         : {summary['successful_probes']} OK  /  "
          f"{summary['failed_probes']} ERR  /  "
          f"{summary['total_probes']} total")
    print(f"  Live hosts     : {', '.join(summary['live_hosts']) or 'none'}")
    print(f"  Status codes   : {summary['unique_status_codes'] or 'n/a'}")
    print(f"  Servers        : {', '.join(summary['unique_servers']) or 'none detected'}")
    print(f"  Technologies   : {', '.join(summary['unique_technologies']) or 'none detected'}")
    if summary["observed_error_types"]:
        print(f"  Error types    : {', '.join(summary['observed_error_types'])}")
    print(f"  Output written : {output_path}")
    print("=" * 60)


if __name__ == "__main__":
    # asyncio.run() creates a fresh event loop, runs ``main()`` to completion,
    # then cleanly closes the loop and releases all resources.
    asyncio.run(main())