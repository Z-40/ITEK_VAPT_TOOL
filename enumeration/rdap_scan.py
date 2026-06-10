import asyncio
import aiohttp
import json
import argparse
import os
import re
from datetime import datetime

class UI:
    C_CYAN = "\033[38;5;45m"; C_SLATE = "\033[38;5;244m"; C_WHITE = "\033[38;5;255m"
    B_BOLD = "\033[1m"; RESET = "\033[0m"

    @classmethod
    def banner(cls):
        print(f"{cls.C_CYAN}{cls.B_BOLD}" + "="*85)
        print(f" 🛡️  DOMAIN STATUS AUDIT ENGINE // COMPLETE RAW INVENTORY MODE // 2026")
        print("="*85 + f"{cls.RESET}")


# =========================================================================
# DETAILED DEEP HARVESTING LOGIC (NO GRADING - PURE FACTS)
# =========================================================================
def extract_complete_facts(domain, raw_json):
    if not isinstance(raw_json, dict):
        return {"target": domain, "error": "Invalid JSON payload"}

    # Initialize a wide, structured fact dictionary
    facts = {
        "target": domain,
        "registrar_name": "DATA_NOT_PROVIDED",
        "canonical_iana_id": "DATA_NOT_PROVIDED",
        "created_date": "DATA_NOT_PROVIDED",
        "updated_date": "DATA_NOT_PROVIDED",
        "expiration_date": "DATA_NOT_PROVIDED",
        "epp_statuses": [],
        "nameservers": [],
        "dnssec_state": "UNSIGNED",
        "extracted_emails": []
    }

    # 1. Parse Event Timestamps
    for event in raw_json.get("events", []):
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action == "registration":
            facts["created_date"] = date
        elif action == "last changed":
            facts["updated_date"] = date
        elif action == "expiration":
            facts["expiration_date"] = date

    # 2. Parse Core Statuses & Nameservers
    facts["epp_statuses"] = [str(s).lower().strip() for s in raw_json.get("status", [])]
    
    for ns in raw_json.get("nameservers", []):
        if isinstance(ns, dict) and "ldhName" in ns:
            facts["nameservers"].append(ns["ldhName"].lower())

    # 3. Parse DNSSEC
    if raw_json.get("secureDNS", {}).get("delegationSigned") is True:
        facts["dnssec_state"] = "SIGNED"

    # 4. Recursive Entity Harvesting (Registrar Name, IANA ID, and Contact Emails)
    emails_found = set()
    
    def parse_entities(entities_list):
        for entity in entities_list:
            # Look for registrar roles and properties
            roles = entity.get("roles", [])
            if "registrar" in roles:
                for vcard in entity.get("vcardArray", []):
                    if isinstance(vcard, list):
                        for item in vcard:
                            if isinstance(item, list) and item[0] == "fn":
                                facts["registrar_name"] = item[3]

            # Grab IANA ID tokens
            for pid in entity.get("publicIds", []):
                if "iana" in str(pid.get("type")).lower():
                    facts["canonical_iana_id"] = str(pid.get("identifier"))

            # Scrape vcard blocks for email arrays
            for vcard in entity.get("vcardArray", []):
                if isinstance(vcard, list):
                    for item in vcard:
                        if isinstance(item, list) and item[0] == "email":
                            # Handle both direct string and nested list variations in vcard specs
                            email_val = item[3]
                            if isinstance(email_val, str):
                                emails_found.add(email_val.lower().strip())

            # Recurse down nested sub-entities if present
            if "entities" in entity:
                parse_entities(entity["entities"])

    if "entities" in raw_json:
        parse_entities(raw_json["entities"])

    facts["extracted_emails"] = list(emails_found)
    return facts


# =========================================================================
# DETAILED OUTPUT FORMATTER
# =========================================================================
def render_complete_console(facts):
    print(f" {UI.C_CYAN}┌───────────────────────────────────────────────────────────────────────────────────┐{UI.RESET}")
    print(f"  {UI.B_BOLD}{UI.C_WHITE}🎯 TARGET FACT SHEET: {facts['target'].ljust(60)}{UI.RESET}")
    print(f" {UI.C_CYAN}├───────────────────────────────────────────────────────────────────────────────────┤{UI.RESET}")
    
    print(f"    {UI.C_SLATE}• Registrar Name   :{UI.RESET} {UI.C_WHITE}{facts['registrar_name']}{UI.RESET}")
    print(f"    {UI.C_SLATE}• Registrar IANA   :{UI.RESET} {UI.C_WHITE}{facts['canonical_iana_id']}{UI.RESET}")
    print(f"    {UI.C_SLATE}• DNSSEC Root State:{UI.RESET} {UI.C_WHITE}{facts['dnssec_state']}{UI.RESET}")
    print(f" {UI.C_CYAN}├───────────────────────────────────────────────────────────────────────────────────┤{UI.RESET}")
    print(f"    {UI.C_SLATE}• Created Timestamp:{UI.RESET} {UI.C_WHITE}{facts['created_date']}{UI.RESET}")
    print(f"    {UI.C_SLATE}• Updated Timestamp:{UI.RESET} {UI.C_WHITE}{facts['updated_date']}{UI.RESET}")
    print(f"    {UI.C_SLATE}• Expire Timestamp :{UI.RESET} {UI.C_WHITE}{facts['expiration_date']}{UI.RESET}")
    print(f" {UI.C_CYAN}├───────────────────────────────────────────────────────────────────────────────────┤{UI.RESET}")
    
    ns_text = ", ".join(facts["nameservers"]) if facts["nameservers"] else "None detected"
    print(f"    {UI.C_SLATE}• Name Servers     :{UI.RESET} {UI.C_WHITE}{ns_text}{UI.RESET}")
    
    status_text = ", ".join(facts["epp_statuses"]) if facts["epp_statuses"] else "None detected"
    print(f"    {UI.C_SLATE}• Active EPP Status:{UI.RESET} {UI.C_WHITE}{status_text}{UI.RESET}")
    
    email_text = ", ".join(facts["extracted_emails"]) if facts["extracted_emails"] else "None detected / Redacted by GDPR"
    print(f"    {UI.C_SLATE}• Harvested Emails :{UI.RESET} {UI.C_WHITE}{email_text}{UI.RESET}")
    
    print(f" {UI.C_CYAN}└───────────────────────────────────────────────────────────────────────────────────┘{UI.RESET}")


async def fetch_rdap_raw(session, domain):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        async with session.get(f"https://rdap.org/domain/{domain}", headers=headers, timeout=10) as r:
            if r.status != 200: return {"Error": f"Registry returned HTTP {r.status}"}
            return await r.json()
    except Exception as e: return {"Error": str(e)}

async def pipeline(session, domain, output):
    raw = await fetch_rdap_raw(session, domain)
    if "Error" in raw:
        print(f" Error: {domain} -> {raw['Error']}")
        return {"target": domain, "error": raw["Error"]}
        
    facts = extract_complete_facts(domain, raw)
    
    if not output: 
        render_complete_console(facts)
        
    return facts

async def main():
    parser = argparse.ArgumentParser(description="RDAP Deep Fact Harvester")
    parser.add_argument("-d", "--domains", nargs="+")
    parser.add_argument("-f", "--file")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    
    targets = args.domains or []
    if args.file and os.path.exists(args.file):
        with open(args.file) as f: targets = [l.strip() for l in f if l.strip()]

    if not targets:
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