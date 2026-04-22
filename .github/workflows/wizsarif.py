import os
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


def get_finding_details(token, finding_id):
    query = """
    query GetFinding($id: ID!) {
      vulnerabilityFinding(id: $id) {
        portalUrl
        firstDetectedAt
        lastDetectedAt
        fixedVersion
      }
    }
    """
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.post(
        WIZ_API_URL,
        json={"query": query, "variables": {"id": finding_id}},
        headers=headers,
    )
    return resp.json().get("data", {}).get("vulnerabilityFinding", {}) or {}


def wrap(text, width):
    if not text:
        return ""
    return "\n".join(textwrap.wrap(str(text), width=width)) or str(text)


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

    token = get_wiz_token()

    with open("raw.sarif", "r") as f:
        sarif = json.load(f)

    rows = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            props = result.get("properties", {}) or {}
            finding_id = props.get("vulnerabilityId")
            pkg_name = props.get("vulnerabilityPackageName", "N/A")
            pkg_version = props.get("vulnerabilityPackageVersion", "N/A")
            cve = props.get("vulnerabilityExternalId", "N/A")
            severity = (result.get("level") or "warning").upper()
            cvss = props.get("vulnerabilityCvssScore", "N/A")

            details = get_finding_details(token, finding_id) if finding_id else {}

            fix_version = details.get("fixedVersion") or props.get("vulnerabilityFixedVersion") or "N/A"
            first_seen = (details.get("firstDetectedAt") or "N/A")[:10]
            status = f"fixed in {fix_version}" if fix_version != "N/A" else "no fix"

            msg = (result.get("message") or {}).get("text", "")
            description = msg.split("\n")[0][:200]

            # Update SARIF for GitHub Security tab
            props.update({
                "wizFirstDiscovered": details.get("firstDetectedAt"),
                "wizFixVersion": details.get("fixedVersion"),
                "wizPortalUrl": details.get("portalUrl"),
            })

            rows.append([
                wrap(cve, 16),
                severity,
                cvss,
                wrap(pkg_name, 20),
                wrap(pkg_version, 12),
                wrap(status, 18),
                first_seen,
                wrap(description, 50),
            ])

    headers = ["CVE", "SEVERITY", "CVSS", "PACKAGE", "VERSION",
               "STATUS", "DISCOVERED", "DESCRIPTION"]

    print("\nVulnerabilities")
    print(tabulate(rows, headers=headers, tablefmt="grid"))
    print(f"\nTotal findings: {len(rows)}")

    with open("wiz_enriched.sarif", "w") as f:
        json.dump(sarif, f, indent=2)


if __name__ == "__main__":
    main()
