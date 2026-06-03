import asyncio
import aiohttp
import json
import argparse
import os
import re
from datetime import datetime, timezone


# =========================================================================
# PROTOCOL REGISTRIES & CANONICAL MAPS
# =========================================================================
CANONICAL_IANA_WHITELIST = ["292", "426", "1343", "694"] 
PUBLIC_ROLE_EMAILS = ["abuse@", "noc@", "legal@", "security@", "hostmaster@", "postmaster@"]
DOMAIN_REGEX = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')

class UI:
    C_GREEN = "\033[38;5;82m"; C_YELLOW = "\033[38;5;214m"; C_RED = "\033[38;5;196m"
    C_CYAN = "\033[38;5;45m"; C_SLATE = "\033[38;5;244m"; C_WHITE = "\033[38;5;255m"
    B_BOLD = "\033[1m"; RESET = "\033[0m"

    @classmethod
    def banner(cls):
        print(f"{cls.C_CYAN}{cls.B_BOLD}" + "="*72)
        print(f" 🛡️  DOMAIN STATUS AUDIT ENGINE")
        print(f"    v7.6 // Browser Masking Enabled // 2026")
        print("="*72 + f"{cls.RESET}")

    @classmethod
    def show_legend(cls):
        print(f"\n{cls.C_CYAN}{cls.B_BOLD} DECODER: WHAT THESE RESULTS MEAN{cls.RESET}")
        print(f"{cls.C_SLATE}──────────────────────────────────────────────────────────────────────{cls.RESET}")
        print(f"{cls.C_WHITE}• Expiration:   {cls.RESET}Registry lease date. Low days = risk of site outage.")
        print(f"{cls.C_WHITE}• Name Servers: {cls.RESET}Redundancy check. 2+ is standard. 1 = failure point.")
        print(f"{cls.C_WHITE}• Registrar:    {cls.RESET}Your 'landlord'. Confirms if managed by authorized corporate vendor.")
        print(f"{cls.C_WHITE}• Transfer Lock:{cls.RESET}Active = Hijack protection. Inactive = Open door to theft.")
        print(f"{cls.C_WHITE}• DNSSEC:       {cls.RESET}Cryptographic sign. Verified = Security against interception.")
        print(f"{cls.C_SLATE}──────────────────────────────────────────────────────────────────────{cls.RESET}\n")

# =========================================================================
# STAGE 1-3: LOGIC & EVALUATION
# =========================================================================
def enforce_rdap_schema_guard(raw_json):
    sanitized = {"events": [], "entities": [], "status": [], "nameservers": [], "secureDNS": {}, "schema_completeness": 100.0}
    if not isinstance(raw_json, dict): return sanitized, 0.0
    for node in ["events", "entities", "status"]:
        if node in raw_json and isinstance(raw_json[node], list): sanitized[node] = raw_json[node]
    if "nameservers" in raw_json: sanitized["nameservers"] = raw_json["nameservers"]
    if "secureDNS" in raw_json: sanitized["secureDNS"] = raw_json["secureDNS"]
    return sanitized, 100.0

def extract_facts(domain, validated_json):
    facts = {
        "target": domain, "is_cctld": len(domain.split('.')[-1]) == 2,
        "expiration_raw": "DATA_NOT_PROVIDED", "epp_statuses": [],
        "dnssec_state": "DATA_NOT_PROVIDED", "nameservers": [], "canonical_iana_id": None
    }
    for event in validated_json.get("events", []):
        if isinstance(event, dict) and event.get("eventAction") == "expiration":
            facts["expiration_raw"] = str(event.get("eventDate"))
            break
    facts["epp_statuses"] = [str(s).lower().strip() for s in validated_json.get("status", [])]
    facts["dnssec_state"] = "SIGNED" if validated_json.get("secureDNS", {}).get("delegationSigned") is True else "UNSIGNED"
    for ns in validated_json.get("nameservers", []):
        if isinstance(ns, dict): facts["nameservers"].append(str(ns.get("ldhName", "")).lower())
    for entity in validated_json.get("entities", []):
        for pid in entity.get("publicIds", []):
            if "iana" in str(pid.get("type")).lower(): facts["canonical_iana_id"] = str(pid.get("identifier"))
    return facts

def evaluate_compliance_matrix(facts, schema_score):
    matrix = {"Target": facts["target"], "Type": "ccTLD" if facts["is_cctld"] else "gTLD", "Axes": {}}
    if facts["expiration_raw"] != "DATA_NOT_PROVIDED":
        try:
            exp = datetime.fromisoformat(facts["expiration_raw"].replace("Z", "+00:00"))
            days = (exp - datetime.now(timezone.utc)).days
            matrix["Axes"]["Expiration"] = {"State": "CRITICAL" if days < 0 else "OK", "Details": f"{days} days remaining."}
        except: matrix["Axes"]["Expiration"] = {"State": "INFO", "Details": "Date parse error."}
    else:
        matrix["Axes"]["Expiration"] = {"State": "INFO", "Details": "No date provided."}
    
    ns_count = len(facts["nameservers"])
    matrix["Axes"]["Name Servers"] = {"State": "OK" if ns_count >= 2 else "WARNING", "Details": f"{ns_count} servers detected."}
    
    is_authorized = facts["canonical_iana_id"] in CANONICAL_IANA_WHITELIST
    matrix["Axes"]["Registrar"] = {"State": "OK" if is_authorized else "WARNING", "Details": f"ID: {facts['canonical_iana_id'] or 'Unknown'}"}
    
    is_locked = any(kw in str(facts["epp_statuses"]) for kw in ["prohibited", "locked"])
    matrix["Axes"]["Transfer Lock"] = {"State": "OK" if is_locked else "WARNING", "Details": "Lock active" if is_locked else "No lock detected."}
    
    matrix["Axes"]["DNSSEC"] = {"State": "OK" if facts["dnssec_state"] == "SIGNED" else "INFO", "Details": facts["dnssec_state"]}
    return matrix

# =========================================================================
# STAGE 4: RENDERING
# =========================================================================
def render_pretty_console(matrix):
    print(f" {UI.C_CYAN}┌─────────────────────────────────────────────────────────────┐{UI.RESET}")
    print(f"  {UI.B_BOLD}{UI.C_WHITE}🎯 TARGET: {matrix['Target'].ljust(40)}{UI.RESET}")
    print(f"  {UI.C_SLATE}Type: {matrix['Type']}{UI.RESET}")
    
    state_colors = {"OK": UI.C_GREEN, "INFO": UI.C_CYAN, "WARNING": UI.C_RED, "CRITICAL": UI.C_RED}
    
    for axis, data in matrix["Axes"].items():
        color = state_colors.get(data["State"], UI.C_WHITE)
        print(f"    {UI.C_SLATE}• {axis.ljust(15)} {color}[{data['State'].ljust(8)}]{UI.RESET} {data['Details']}")
    print(f" {UI.C_CYAN}└─────────────────────────────────────────────────────────────┘{UI.RESET}")

# =========================================================================
# ORCHESTRATION
# =========================================================================
async def fetch_rdap_raw(session, domain):
    # Masking as a real browser to bypass WAF 403 blocks
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        async with session.get(f"https://rdap.org/domain/{domain}", headers=headers, timeout=10) as r:
            if r.status != 200: return {"Error": f"Registry returned HTTP {r.status}"}
            return await r.json()
    except Exception as e: return {"Error": str(e)}

async def pipeline(session, domain, output):
    raw = await fetch_rdap_raw(session, domain)
    if "Error" in raw:
        print(f" {UI.C_RED}❌ ERROR: {domain} -> {raw['Error']}{UI.RESET}")
        return {"Target": domain, "Error": raw["Error"]}
        
    val, score = enforce_rdap_schema_guard(raw)
    facts = extract_facts(domain, val)
    matrix = evaluate_compliance_matrix(facts, score)
    if not output: render_pretty_console(matrix)
    return matrix

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domains", nargs="+")
    parser.add_argument("-f", "--file")
    parser.add_argument("-o", "--output")
    parser.add_argument("--legend", action="store_true")
    args = parser.parse_args()

    if args.legend: UI.show_legend()
    
    targets = args.domains or []
    if args.file and os.path.exists(args.file):
        with open(args.file) as f: targets = [l.strip() for l in f if l.strip()]

    if not targets and not args.legend:
        print("Error: No domains provided.")
        return

    async with aiohttp.ClientSession() as session:
        if not args.output and targets: UI.banner()
        tasks = [pipeline(session, d, args.output) for d in targets]
        results = await asyncio.gather(*tasks)
        if args.output:
            with open(args.output, "w") as f: json.dump(results, f, indent=4)

if __name__ == "__main__":
    asyncio.run(main())