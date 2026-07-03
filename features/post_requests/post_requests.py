#!/usr/bin/env python3
import sys
import json
import random
import os
from urllib.parse import urlencode, urlparse
from typing import Dict, Any, List

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ---------------------------------------------------------------------------
# Spec Parsing from Memory
# ---------------------------------------------------------------------------
def parse_raw_spec(spec_content: str) -> dict:
    try:
        return json.loads(spec_content)
    except json.JSONDecodeError:
        if HAS_YAML:
            return yaml.safe_load(spec_content)
        raise RuntimeError(
            "Spec appears to be YAML but PyYAML is not installed.\n"
            "Run: pip install pyyaml"
        )

# ---------------------------------------------------------------------------
# Host extraction
# ---------------------------------------------------------------------------
def extract_host(spec: dict) -> str:
    if "servers" in spec and isinstance(spec["servers"], list) and len(spec["servers"]) > 0:
        url = spec["servers"][0].get("url", "")
        if url:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            parsed = urlparse(url)
            if parsed.netloc:
                return parsed.netloc
    return spec.get("host", "api.example.com")

def extract_base_path(spec: dict) -> str:
    if "servers" in spec and isinstance(spec["servers"], list) and len(spec["servers"]) > 0:
        url = spec["servers"][0].get("url", "")
        if url and url.startswith(("http://", "https://")):
            parsed = urlparse(url)
            return parsed.path.rstrip("/")
    return spec.get("basePath", "").rstrip("/")

# ---------------------------------------------------------------------------
# Mock data generators
# ---------------------------------------------------------------------------
def resolve_ref(ref: str, spec: dict) -> dict:
    if not ref.startswith("#/"):
        return {}
    parts = ref.split("/")[1:]
    current = spec
    for p in parts:
        if isinstance(current, dict) and p in current:
            current = current[p]
        else:
            return {}
    return current if isinstance(current, dict) else {}

def generate_mock_value(schema: dict, spec: dict, depth: int = 0) -> Any:
    if depth > 5:
        return None
        
    if "$ref" in schema:
        resolved = resolve_ref(schema["$ref"], spec)
        return generate_mock_value(resolved, spec, depth + 1)
        
    t = schema.get("type")
    
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and isinstance(schema["enum"], list) and len(schema["enum"]) > 0:
        return random.choice(schema["enum"])

    if t == "string":
        fmt = schema.get("format", "")
        if fmt == "date-time":
            return "2026-06-24T11:58:00.000Z"
        if fmt == "date":
            return "2026-06-24"
        if fmt == "uuid":
            return "123e4567-e89b-12d3-a456-426614174000"
        if fmt == "email":
            return "user@example.com"
        return "string_data"
        
    elif t == "integer" or t == "number":
        return 1
        
    elif t == "boolean":
        return True
        
    elif t == "array":
        items = schema.get("items", {})
        return [generate_mock_value(items, spec, depth + 1)]
        
    elif t == "object" or "properties" in schema:
        obj = {}
        props = schema.get("properties", {})
        for k, v in props.items():
            if isinstance(v, dict):
                obj[k] = generate_mock_value(v, spec, depth + 1)
        return obj
        
    return "data"

def extract_json_payload(op: dict, spec: dict) -> str:
    rb = op.get("requestBody")
    if not isinstance(rb, dict):
        return ""
    content = rb.get("content", {})
    json_media = content.get("application/json", {})
    schema = json_media.get("schema")
    if isinstance(schema, dict):
        mock_obj = generate_mock_value(schema, spec)
        if mock_obj is not None:
            return json.dumps(mock_obj, indent=2)
    return ""

def extract_form_payload(op: dict, spec: dict) -> str:
    rb = op.get("requestBody")
    if isinstance(rb, dict):
        content = rb.get("content", {})
        form_media = content.get("application/x-www-form-urlencoded", {})
        schema = form_media.get("schema")
        if isinstance(schema, dict):
            mock_obj = generate_mock_value(schema, spec)
            if isinstance(mock_obj, dict):
                return urlencode(mock_obj)

    params = op.get("parameters", [])
    if not isinstance(params, list):
        return ""
    form_data = {}
    for p in params:
        if not isinstance(p, dict):
            continue
        if p.get("in") == "formData":
            name = p.get("name")
            if name:
                form_data[name] = generate_mock_value(p, spec)
    if form_data:
        return urlencode(form_data)
    return ""

# ---------------------------------------------------------------------------
# Traffic modeling builders
# ---------------------------------------------------------------------------
def build_request_block(path: str, op: dict, spec: dict, host: str, base_path: str) -> str:
    full_path = f"{base_path}{path}"
    
    payload = extract_json_payload(op, spec)
    ct = "application/json"
    if not payload:
        payload = extract_form_payload(op, spec)
        ct = "application/x-www-form-urlencoded"
    if not payload:
        payload = "{}"
        ct = "application/json"

    cl = len(payload.encode("utf-8"))

    headers = [
        f"POST {full_path} HTTP/1.1",
        f"Host: {host}",
        "Connection: keep-alive",
        f"Content-Length: {cl}",
        "sec-ch-ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
        "sec-ch-ua: ?0",
        "sec-ch-ua-mobile: ?0",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        f"Content-Type: {ct}",
        "Accept: application/json, text/plain, */*",
        "sec-ch-ua-platform: \"Windows\"",
        "Origin: https://" + host,
        "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-Mode: cors",
        "Sec-Fetch-Dest: empty",
        "Referer: https://" + host + full_path,
        "Accept-Encoding: gzip, deflate, br",
        "Accept-Language: en-US,en;q=0.9",
    ]

    return "\n".join(headers) + "\n\n" + payload

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SYNCHRONOUS IN-MEMORY INTERFACE WITH DISK WRITE CAPABILITY
# ─────────────────────────────────────────────────────────────────────────────
def get_post_requests(input_json_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts a structured payload dictionary containing an OpenAPI specification and 
    a target output directory path. Generates raw HTTP/1.1 POST blocks and exports 
    each individual route separately as a clean .txt file inside the folder.
    """
    raw_spec_content = input_json_data.get("spec")
    if not raw_spec_content:
        raise ValueError("Input JSON dataset is missing the mandatory 'spec' parameter key.")

    output_dir = input_json_data.get("output_dir", "").strip()
    if not output_dir:
        raise ValueError("Input JSON configuration is missing the mandatory 'output_dir' target directory path.")

    # Standardize output landing directory structure
    os.makedirs(output_dir, exist_ok=True)

    if isinstance(raw_spec_content, dict):
        spec = raw_spec_content
    else:
        spec = parse_raw_spec(str(raw_spec_content))

    host = extract_host(spec)
    base_path = extract_base_path(spec)

    saved_files = []
    paths = spec.get("paths", {})

    if isinstance(paths, dict):
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            op = path_item.get("post")
            if op and isinstance(op, dict):
                # Format raw request block string text
                block_content = build_request_block(path, op, spec, host, base_path)
                
                # Sanitize endpoint path to build a safe local file name string
                safe_name = path.strip("/").replace("/", "_").replace("{", "").replace("}", "")
                if not safe_name:
                    safe_name = "root_post"
                
                file_path = os.path.join(output_dir, f"post_{safe_name}.txt")
                
                # Commit individual output track record to disk
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(block_content)
                    
                saved_files.append(os.path.abspath(file_path))

    return {
        "status": "success",
        "total_post_routes_found": len(saved_files),
        "output_directory": os.path.abspath(output_dir),
        "generated_files": saved_files
    }