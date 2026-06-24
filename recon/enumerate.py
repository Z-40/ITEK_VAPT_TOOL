import asyncio
import logging
import shutil
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import aiodns
import aiohttp

# ---------------------------------------------------------------------------
# Logging (Optional: can be disabled if you want silent pipeline execution)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Passive source 1 & 2  —  subprocess tools
# ---------------------------------------------------------------------------
async def run_tool(cmd: List[str], label: str, timeout: int) -> Set[str]:
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
                    return found
                data = await resp.json(content_type=None)

        suffix = f".{domain}"
        for entry in data:
            for raw in entry.get("name_value", "").splitlines():
                name = raw.strip().lstrip("*.").lower()
                if name and (name == domain or name.endswith(suffix)):
                    found.add(name)

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
    sf, am, ct = await asyncio.gather(
        run_tool(["subfinder", "-d", domain, "-silent", "-t", str(subfinder_threads)], "subfinder", subprocess_timeout),
        run_tool(["amass", "enum", "-passive", "-d", domain, "-timeout", str(amass_timeout_min)], "amass", subprocess_timeout),
        run_crtsh(domain, crtsh_timeout),
    )
    return sf | am | ct

# ---------------------------------------------------------------------------
# Active DNS validation
# ---------------------------------------------------------------------------
async def resolve_one(
    subdomain: str, resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore, timeout: float
) -> Tuple[str, Optional[str]]:
    async with semaphore:
        try:
            result = await asyncio.wait_for(resolver.query_dns(subdomain, "A"), timeout=timeout)
            return subdomain, result.answer[0].data.addr
        except Exception:
            return subdomain, None

async def validate(
    subdomains: Set[str], nameservers: List[str], concurrency: int, timeout: float
) -> Dict[str, str]:
    resolver = aiodns.DNSResolver(nameservers=nameservers)
    semaphore = asyncio.Semaphore(concurrency)
    alive: Dict[str, str] = {}
    
    tasks = [asyncio.ensure_future(resolve_one(s, resolver, semaphore, timeout)) for s in subdomains]

    for future in asyncio.as_completed(tasks):
        subdomain, ip = await future
        if ip is not None:
            alive[subdomain] = ip

    return alive

# ---------------------------------------------------------------------------
# Async Pipeline Core
# ---------------------------------------------------------------------------
async def _pipeline(
    domain: str,
    subprocess_timeout: int,
    amass_timeout_min: int,
    subfinder_threads: int,
    crtsh_timeout: int,
    dns_concurrency: int,
    dns_timeout: float,
    dns_nameservers: List[str],
) -> Dict:
    
    candidates = await gather_passive(
        domain, subprocess_timeout, amass_timeout_min,
        subfinder_threads, crtsh_timeout,
    )

    if not candidates:
        return {
            "target": domain,
            "generated": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "alive_count": 0,
            "subdomains": {}
        }

    alive = await validate(candidates, dns_nameservers, dns_concurrency, dns_timeout)

    return {
        "target": domain,
        "generated": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "alive_count": len(alive),
        "subdomains": {k: v for k, v in sorted(alive.items())}
    }

# ---------------------------------------------------------------------------
# Synchronous Entry Point (The JSON interface)
# ---------------------------------------------------------------------------
def enumerate(input_data: Dict) -> Dict:
    """
    Accepts a dictionary of parameters, runs the async enumeration pipeline, 
    and returns the resulting alive subdomains as a dictionary.
    """
    domain = input_data.get("domain")
    if not domain:
        raise ValueError("Input dictionary must contain a 'domain' key.")

    # Extract optional parameters with the original script's defaults
    subprocess_timeout = input_data.get("subprocess_timeout", 660)
    amass_timeout_min  = input_data.get("amass_timeout", 10)
    subfinder_threads  = input_data.get("subfinder_threads", 50)
    crtsh_timeout      = input_data.get("crtsh_timeout", 30)
    dns_concurrency    = input_data.get("dns_concurrency", 500)
    dns_timeout        = input_data.get("dns_timeout", 3.0)
    dns_nameservers    = input_data.get("dns_nameservers", ["1.1.1.1", "8.8.8.8", "9.9.9.9"])

    # Run the async loop and return the exact output dict
    return asyncio.run(
        _pipeline(
            domain=domain,
            subprocess_timeout=subprocess_timeout,
            amass_timeout_min=amass_timeout_min,
            subfinder_threads=subfinder_threads,
            crtsh_timeout=crtsh_timeout,
            dns_concurrency=dns_concurrency,
            dns_timeout=dns_timeout,
            dns_nameservers=dns_nameservers,
        )
    )