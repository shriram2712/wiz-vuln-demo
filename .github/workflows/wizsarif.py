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

# ANSI color codes for terminal output
ANSI = {
    "CRITICAL": "\033[1;37;41m",   # white on red, bold
    "HIGH":     "\033[1;31m",       # bright red
    "MEDIUM":   "\033[1;33m",       # yellow
    "LOW":      "\033[1;32m",       # green
    "INFORMATIONAL": "\033[1;90m",  # grey
    "UNKNOWN":  "\033[0m",
    "RESET":    "\033[0m",
}

# Emoji indicators for markdown summary
EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFORMATIONAL": "⚪",
    "UNKNOWN":  "⚫",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                  "INFORMATIONAL": 4, "UNKNOWN": 5}


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


def fetch_findings_by_cve(token, cve_ids):
    """Batch fetch first-seen dates from Wiz for a list of CVE IDs."""
    if not cve_ids:
        return {}

    query = """
    query VulnFindings($filterBy: VulnerabilityFindingFilters, $first: Int) {
      vulnerabilityFindings(filterBy: $filterBy, first: $first) {
        nodes {
          id
          name
          firstDetectedAt
          lastDetectedAt
          vulnerableAsset {
            ... on VulnerableAssetBase {
              name
            }
          }
          CVEDescription
          fixedVersion
        }
      }
    }
    """

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    variables = {
        "filterBy": {"vulnerability": list(cve_ids)},
        "first": 500,
    }

    resp = requests.post(WIZ_API_URL, json={"query": query, "variables": variables},
                         headers=headers, timeout=30)
    if resp.status_code != 200:
        print(f"Warning: Wiz API returned {resp.status_code}: {resp.text[:200]}")
        return {}

    data = resp.json()
    if "errors" in data:
        print(f"Warning: GraphQL errors: {data['errors']}")
        return {}

    # Build CVE -> earliest firstDetectedAt mapping
    cve_to_date = {}
    nodes = data.get("data", {}).get("vulnerabilityFindings", {}).get("nodes", []) or []
    for node in nodes:
        cve = node.get("name")  # finding name is usually the CVE
        first_seen = node.get("firstDetectedAt")
        if not cve or not first_seen:
            continue
        # Keep earliest date if we see the same CVE multiple times (multiple assets)
        if cve not in cve_to_date or first_seen < cve_to_date[cve]:
            cve_to_date[cve] = first_seen

    return cve_to_date


def parse_message_text(text):
    fields = {}
    if not text:
        return fields
    for line in text.split("\n"):
        m = re.match(r"^([A-Za-z ]+):\s*(.*)$", line)
        if m:
            key = m.group(1).strip().lower()
            val = m.group(2).strip()
            if key not in fields:
                fields[key] = val
        if "description" in fields:
            idx = text.find("Description:")
            if idx >= 0:
                fields["description"] = text[idx + len("Description:"):].strip()
            break
    return fields


def wrap(text, width):
    if not text:
        return ""
    return "\n".join(textwrap.wrap(str(text), width=width)) or str(text)


def colored_severity(sev):
    return f"{ANSI.get(sev, '')}{sev}{ANSI['RESET']}"


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

    with open("raw.sarif", "r") as f:
        sarif = json.load(f)

    # First pass: extract findings
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
                "first_seen": "N/A",  # filled in below
            })

    # Second pass: enrich with Wiz API first-seen dates
    print("Step 2: Enriching with Wiz API (first-seen dates)...")
    try:
        token = get_wiz_token()
        cve_ids = list({r["cve"] for r in rows if r["cve"] and r["cve"] != "N/A"})
        cve_to_date = fetch_findings_by_cve(token, cve_ids)
        print(f"  Retrieved first-seen dates for {len(cve_to_date)}/{len(cve_ids)} CVEs")
        for r in rows:
            d = cve_to_date.get(r["cve"])
            if d:
                r["first_seen"] = d[:10]  # YYYY-MM-DD
    except Exception as e:
        print(f"  Warning: enrichment failed ({e}) — continuing without first-seen dates")

    # Sort Critical -> High -> Medium -> ...
    rows.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 99))

    # Build colored display rows for terminal
    display_rows = [
        [
            wrap(r["cve"], 16),
            colored_severity(r["severity"]),
            wrap(r["component"], 18),
            wrap(r["version"], 12),
            wrap(r["status"], 18),
            r["first_seen"],
            wrap(r["file"], 20),
            wrap(r["description"], 55),
        ]
        for r in rows
    ]

    headers = ["CVE", "SEVERITY", "COMPONENT", "VERSION",
               "STATUS", "FIRST SEEN", "FILE", "DESCRIPTION"]

    print("\nVulnerabilities")
    print(tabulate(display_rows, headers=headers, tablefmt="grid"))

    # Severity counts
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    print(f"\nTotal findings: {len(rows)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]:
        if counts.get(sev):
            print(f"  {colored_severity(sev)}: {counts[sev]}")

    # GitHub Step Summary (markdown with emoji severity)
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        md_rows = [
            [
                r["cve"],
                f"{EMOJI.get(r['severity'], '')} {r['severity']}",
                r["component"],
                r["version"],
                r["status"],
                r["first_seen"],
                r["file"],
                r["description"][:120],
            ]
            for r in rows
        ]
        with open(summary_path, "a") as f:
            f.write("## Wiz Vulnerability Report\n\n")
            f.write(f"**Total findings:** {len(rows)}\n\n")
            # Severity breakdown
            f.write("**Breakdown:** ")
            parts = []
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]:
                if counts.get(sev):
                    parts.append(f"{EMOJI[sev]} {sev}: {counts[sev]}")
            f.write(" | ".join(parts) + "\n\n")
            f.write(tabulate(md_rows, headers=headers, tablefmt="github"))
            f.write("\n")

    with open("wiz_enriched.sarif", "w") as f:
        json.dump(sarif, f, indent=2)


if __name__ == "__main__":
    main()
