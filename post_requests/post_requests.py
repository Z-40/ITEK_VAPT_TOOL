#!/usr/bin/env python3
"""
gen_requests.py — OpenAPI/Swagger → Live-Fidelity Browser HTTP POST Generator
---------------------------------------------------------------------
Parses a local OpenAPI 3.x or Swagger 2.x spec and emits raw HTTP/1.1
POST request blocks modeled after authentic Google Chrome browser traffic.

Usage:
    python3 gen_requests.py <spec.json|spec.yaml>
    python3 gen_requests.py <spec.json|spec.yaml> --output requests.txt
"""

import sys
import json
import random
import argparse
from urllib.parse import urlencode, urlparse

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

DELIMITER = "=" * 70

# ---------------------------------------------------------------------------
# Spec loading
# ---------------------------------------------------------------------------

def load_spec(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        if HAS_YAML:
            return yaml.safe_load(raw)
        raise RuntimeError(
            "Spec appears to be YAML but PyYAML is not installed.\n"
            "Run: pip install pyyaml"
        )

# ---------------------------------------------------------------------------
# Host extraction
# ---------------------------------------------------------------------------

def extract_host(spec: dict) -> str:
    # OpenAPI 3.x
    servers = spec.get("servers", [])
    if servers:
        url = servers[0].get("url", "")
        parsed = urlparse(url)
        return parsed.netloc or url.split("/")[0]
    # Swagger 2.x
    return spec.get("host", "api.target.com")

def extract_base_path(spec: dict) -> str:
    return spec.get("basePath", "")

# ---------------------------------------------------------------------------
# $ref resolution
# ---------------------------------------------------------------------------

def resolve_ref(ref: str, spec: dict) -> dict:
    parts = ref.lstrip("#/").split("/")
    node = spec
    for part in parts:
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}

def resolve(schema: dict, spec: dict) -> dict:
    if "$ref" in schema:
        return resolve(resolve_ref(schema["$ref"], spec), spec)
    return schema

# ---------------------------------------------------------------------------
# High-Fidelity Data Generation Heuristics
# ---------------------------------------------------------------------------

def generate_realistic_value(key: str, schema: dict, spec: dict):
    """
    Returns realistic, context-aware user inputs instead of placeholder blocks.
    """
    schema = resolve(schema, spec)
    k = key.lower()
    t = schema.get("type", "string")
    enum = schema.get("enum")

    if enum:
        return enum[0]

    # --- String Context Identification Rules ---
    if any(x in k for x in ["email", "mail"]):
        return random.choice(["johndoe@gmail.com", "alex.smith@yahoo.com", "user.test@outlook.com"])
    if any(x in k for x in ["password", "pwd", "pass", "secret"]):
        return "SecurePassword1!"
    if any(x in k for x in ["username", "user_name", "login"]):
        return "johndoe88"
    if any(x in k for x in ["phone", "mobile", "tel"]):
        return "555-0199"
    if any(x in k for x in ["firstname", "first_name"]):
        return "John"
    if any(x in k for x in ["lastname", "last_name", "surname"]):
        return "Doe"
    if "name" in k:
        return "John Doe"
    if any(x in k for x in ["url", "link", "href", "uri"]):
        return "https://example.com/profile"
    if any(x in k for x in ["date", "timestamp", "created", "updated"]):
        return "2026-03-15T10:30:00Z"
    if any(x in k for x in ["token", "jwt", "key", "auth", "bearer"]):
        return "bearer_tok_sandbox8839"
    if any(x in k for x in ["address", "street", "city"]):
        return "123 Main Street"
    if any(x in k for x in ["description", "comment", "note", "message", "body", "text", "content"]):
        return "Looks good, please proceed with processing."

    # --- Non-String Primitive Identifiers ---
    if t in ("integer", "number"):
        if "age" in k: return random.randint(22, 45)
        if "id" in k: return random.randint(10000, 99999)
        if "amount" in k or "price" in k: return random.randint(10, 250)
        return 100
    if t == "boolean":
        if "confirm" in k or "agree" in k: return True
        return random.choice([True, False])
    if t == "array":
        items_schema = schema.get("items", {})
        return [generate_realistic_value("item", items_schema, spec)]
    if t == "object":
        return build_object(schema, spec)

    return f"valid_{key}_val"

def build_object(schema: dict, spec: dict) -> dict:
    schema = resolve(schema, spec)
    props = schema.get("properties", {})
    if not props:
        return {}
    return {k: generate_realistic_value(k, v, spec) for k, v in props.items()}

def build_body(schema: dict, spec: dict):
    schema = resolve(schema, spec)
    t = schema.get("type", "object")
    if t == "array":
        items = schema.get("items", {})
        return [build_body(items, spec)]
    return build_object(schema, spec)

# ---------------------------------------------------------------------------
# Request body extraction (OpenAPI 3.x and Swagger 2.x)
# ---------------------------------------------------------------------------

PREFERRED_CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
]

def get_body(operation: dict, spec: dict) -> tuple:
    req_body = operation.get("requestBody", {})
    if req_body:
        if "$ref" in req_body:
            req_body = resolve_ref(req_body["$ref"], spec)
        content = req_body.get("content", {})
        for ct in PREFERRED_CONTENT_TYPES:
            if ct in content:
                schema = content[ct].get("schema", {})
                return ct, build_body(schema, spec)
        for ct, ct_obj in content.items():
            schema = ct_obj.get("schema", {})
            return ct, build_body(schema, spec)

    for p in operation.get("parameters", []):
        if p.get("in") == "body":
            schema = p.get("schema", {})
            return "application/json", build_body(schema, spec)

    form_params = [p for p in operation.get("parameters", []) if p.get("in") == "formData"]
    if form_params:
        body = {}
        for p in form_params:
            schema = p.get("schema", {"type": p.get("type", "string")})
            body[p["name"]] = generate_realistic_value(p["name"], schema, spec)
        uses = operation.get("consumes", spec.get("consumes", ["application/json"]))
        ct = "multipart/form-data" if "multipart/form-data" in uses else "application/x-www-form-urlencoded"
        return ct, body

    return "application/json", {}

# ---------------------------------------------------------------------------
# Payload serialisation
# ---------------------------------------------------------------------------

def serialise(content_type: str, body) -> str:
    if content_type == "application/json":
        return json.dumps(body, separators=(",", ":"))
    if content_type in ("application/x-www-form-urlencoded", "multipart/form-data"):
        flat = {k: str(v) for k, v in body.items()} if isinstance(body, dict) else {}
        return urlencode(flat)
    return json.dumps(body, separators=(",", ":"))

# ---------------------------------------------------------------------------
# Desktop Google Chrome Request Assembly
# ---------------------------------------------------------------------------

def build_request_block(path: str, operation: dict, spec: dict,
                        host: str, base_path: str) -> str:
    full_path = (base_path.rstrip("/") + "/" + path.lstrip("/")) or path

    content_type, body = get_body(operation, spec)
    payload = serialise(content_type, body)
    content_length = len(payload.encode("utf-8"))

    # Compilation of native desktop Google Chrome system headers
    headers = [
        f"POST {full_path} HTTP/1.1",
        f"Host: {host}",
        f"Connection: keep-alive",
        f"Content-Length: {content_length}",
        f'sec-ch-ua: "Not A(A:Brand";v="99", "Google Chrome";v="149", "Chromium";v="149"',
        f"sec-ch-ua-mobile: ?0",
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        f"Content-Type: {content_type}",
        f"Accept: application/json, text/plain, */*",
        f'sec-ch-ua-platform: "Windows"',
        f"Origin: https://{host}",
        f"Sec-Fetch-Site: same-origin",
        f"Sec-Fetch-Mode: cors",
        f"Sec-Fetch-Dest: empty",
        f"Referer: https://{host}{full_path}",
        f"Accept-Encoding: gzip, deflate, br",
        f"Accept-Language: en-US,en;q=0.9",
    ]

    return "\n".join(headers) + "\n\n" + payload

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate clean, realistic browser HTTP POST requests from an OpenAPI/Swagger spec."
    )
    parser.add_argument("spec", help="Path to OpenAPI/Swagger JSON or YAML file")
    parser.add_argument(
        "--output", "-o", default=None,
        help="Write output to this file instead of stdout"
    )
    args = parser.parse_args()

    spec = load_spec(args.spec)
    host = extract_host(spec)
    base_path = extract_base_path(spec)

    blocks = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        op = path_item.get("post")
        if op and isinstance(op, dict):
            blocks.append(build_request_block(path, op, spec, host, base_path))

    if not blocks:
        print("No POST routes found in specification.", file=sys.stderr)
        sys.exit(0)

    separator = f"\n{DELIMITER}\n"
    output = separator.join(blocks)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Written {len(blocks)} request(s) to {args.output}", file=sys.stderr)
    else:
        print(output)

if __name__ == "__main__":
    main()