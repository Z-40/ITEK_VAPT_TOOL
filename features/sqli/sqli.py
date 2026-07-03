import os
import json
import re
import time
import datetime
import subprocess

SQLMAP_PATH = "sqlmap"

# sqlmap's real log entries all look like "[14:51:10] [INFO] ..." /
# "[14:51:10] [CRITICAL] ...". Everything else in stdout -- the ASCII art
# banner, the legal disclaimer, the "[*] starting @ ..." line, blank padding
# -- doesn't match this and gets dropped.
_LOG_LINE_RE = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]")


def _extract_log_lines(text):
    """Strip banner artwork/disclaimer noise from raw sqlmap stdout, keeping
    only the actual timestamped log lines."""
    if not text:
        return text
    return "\n".join(line for line in text.splitlines() if _LOG_LINE_RE.match(line))


def _unique_output_path(out_dir, stem):
    """Return a JSON output path that won't overwrite an existing file."""
    candidate = os.path.join(out_dir, f"{stem}.json")
    if not os.path.exists(candidate):
        return candidate
    counter = 2
    while True:
        candidate = os.path.join(out_dir, f"{stem}_{counter}.json")
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def run_sqli(req_dir, out_dir, filename_prefix=""):
    """
    Run sqlmap against every .txt request file in req_dir.
    Each result is saved as its own JSON file in out_dir, named
    "{filename_prefix}{request_file_stem}.json".

    Returns a list of the JSON file paths that were written.
    """
    os.makedirs(out_dir, exist_ok=True)

    files = sorted(
        f for f in os.listdir(req_dir)
        if f.lower().endswith(".txt") and os.path.isfile(os.path.join(req_dir, f))
    )

    if not files:
        print(f"No .txt files found in '{req_dir}'.")
        return []

    output_paths = []

    for file_name in files:
        file_path = os.path.join(req_dir, file_name)
        stem = f"{filename_prefix}{os.path.splitext(file_name)[0]}"
        command = [SQLMAP_PATH, "-r", file_path, "--batch"]

        record = {
            "input_file": file_name,
            "input_path": os.path.abspath(file_path),
            "command": " ".join(command),
            "started_at": datetime.datetime.now().isoformat(timespec="seconds"),
        }

        print(f"🚀 Running: {file_name}")
        start = time.time()

        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            record.update({
                "status": "success" if proc.returncode == 0 else "failed",
                "return_code": proc.returncode,
                "stdout": _extract_log_lines(proc.stdout),
                "stderr": proc.stderr,
            })
            icon = "✅" if proc.returncode == 0 else "⚠️"
            print(f"{icon} Finished: {file_name} (exit code {proc.returncode})")

        except FileNotFoundError:
            record.update({
                "status": "error",
                "return_code": None,
                "stdout": "",
                "stderr": f"Command '{SQLMAP_PATH}' not found. Is it installed and on PATH?",
            })
            print(f"❌ Error: '{SQLMAP_PATH}' not found while processing {file_name}")

        except Exception as e:
            record.update({
                "status": "error",
                "return_code": None,
                "stdout": "",
                "stderr": str(e),
            })
            print(f"❌ Error processing {file_name}: {e}")

        record["duration_seconds"] = round(time.time() - start, 2)
        record["finished_at"] = datetime.datetime.now().isoformat(timespec="seconds")

        output_path = _unique_output_path(out_dir, stem)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)

        print(f"   → Saved: {os.path.basename(output_path)}")
        output_paths.append(output_path)

    print(f"\n✅ Processed {len(files)} file(s). Results saved in '{out_dir}'.")
    return output_paths


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run sqlmap against every .txt file in req_dir, saving each result as JSON in out_dir."
    )
    parser.add_argument("-d", "--dir", required=True, dest="req_dir", help="Directory containing .txt request files")
    parser.add_argument("-o", "--output", required=True, dest="out_dir", help="Target directory for JSON results")
    args = parser.parse_args()

    run_sqli(args.req_dir, args.out_dir)