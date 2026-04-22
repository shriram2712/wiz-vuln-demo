import os
import re
import json
import requests
import subprocess
import textwrap
from tabulate import tabulate

WIZ_CLIENT_ID = os.getenv("WIZ_CLIENT_ID")
WIZ_CLIENT_SECRET = os.getenv("WIZ_CLIENT_SECRET")
WIZ_API_URL = os.getenv("WIZ_API_URL", "https://api.us1.app.wiz.io/graphql")
WIZ_AUTH_URL = "https://auth.app.wiz.io/oauth/token"


def get_wiz_token():
    payload = {
        "grant_type": "client_credentials",
        "audience": "wiz-api",
        "client_id": WIZ_CLIENT_ID,
        "client_secret": WIZ_CLIENT_SECRET,
    }
    resp = requests.post(WIZ_AUTH_URL, data=payload)
    resp.raise_for_status()
    return resp.json()["access_token"]


def parse_message_text(text):
    """Wiz packs fields as 'Key: value' lines in message.text. Parse them out."""
    fields = {}
    if not text:
        return fields
    # Only look at lines up to Description (Description can contain colons itself)
    for line in text.split("\n"):
        m = re.match(r"^([A-Za-z ]+):\s*(.*)$", line)
        if m:
            key = m.group(1).strip().lower()
            val = m.group(2).strip()
            if key not in fields:   # keep first occurrence
                fields[key] = val
        if "description" in fields:
            # Capture the rest as description
            idx = text.find("Description:")
            if idx >= 0:
                fields["description"] = text[idx + len("Description:"):].strip()
            break
    return fields


def wrap(text, width):
    if not text:
        return ""
    return "\n".join(textwrap.wrap(str(text), width=width)) or str(text)


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}


def main():
    print("Step 1: Running Wiz CLI scan...")
    subprocess.run(
        ["wizcli", "dir", "scan", "--path", ".",
         "--format", "sarif", "--output", "raw.sarif,sarif,vulnerabilities"],
        check=False,
    )

    if not os.path.exists("raw.sarif"):
        print("Error: Scan failed to produce raw.sarif")
        return

    # Try to get API token for enrichment, but don't fail if it doesn't work
    token = None
    try:
        token = get_wiz_token()
    except Exception as e:
        print(f"Warning: API enrichment disabled ({e})")

    with open("raw.sarif", "r") as f:
        sarif = json.load(f)

    rows = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            cve = result.get("ruleId", "N/A")
            msg_text = (result.get("message") or {}).get("text", "")
            fields = parse_message_text(msg_text)

            severity = fields.get("severity", "").upper() or "UNKNOWN"
            component = fields.get("component", "N/A")
            version = fields.get("version", "N/A")
            fixed_version = fields.get("fixed version", "N/A")
            description = fields.get("description", "").split("\n")[0]

            # Location (file path)
            locs = result.get("locations") or []
            file_path = "N/A"
            if locs:
                file_path = locs[0].get("physicalLocation", {}) \
                                   .get("artifactLocation", {}).get("uri", "N/A")

            status = f"fixed in {fixed_version}" if fixed_version != "N/A" else "no fix"

            rows.append({
                "cve": cve,
                "severity": severity,
                "component": component,
                "version": version,
                "status": status,
                "file": file_path,
                "description": description,
            })

    # Sort by severity: Critical first
    rows.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 99))

    # Build display rows
    display_rows = [
        [
            wrap(r["cve"], 16),
            r["severity"],
            wrap(r["component"], 18),
            wrap(r["version"], 12),
            wrap(r["status"], 18),
            wrap(r["file"], 20),
            wrap(r["description"], 55),
        ]
        for r in rows
    ]

    headers = ["CVE", "SEVERITY", "COMPONENT", "VERSION",
               "STATUS", "FILE", "DESCRIPTION"]

    print("\nVulnerabilities")
    print(tabulate(display_rows, headers=headers, tablefmt="grid"))

    # Summary counts
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    print(f"\nTotal findings: {len(rows)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]:
        if counts.get(sev):
            print(f"  {sev}: {counts[sev]}")

    # GitHub Step Summary (nice markdown view in Actions UI)
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        md_rows = [
            [r["cve"], r["severity"], r["component"], r["version"],
             r["status"], r["file"], r["description"][:120]]
            for r in rows
        ]
        with open(summary_path, "a") as f:
            f.write("## Wiz Vulnerability Report\n\n")
            f.write(f"**Total findings:** {len(rows)}\n\n")
            f.write(tabulate(md_rows, headers=headers, tablefmt="github"))
            f.write("\n")

    with open("wiz_enriched.sarif", "w") as f:
        json.dump(sarif, f, indent=2)


if __name__ == "__main__":
    main()
