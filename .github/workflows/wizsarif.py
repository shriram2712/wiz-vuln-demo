import os
import json
import requests
import subprocess
from rich.console import Console
from rich.table import Table

# Force color rendering for GitHub Action logs
console = Console(force_terminal=True)

# Configuration from GitHub Secrets
WIZ_CLIENT_ID = os.getenv("WIZ_CLIENT_ID")
WIZ_CLIENT_SECRET = os.getenv("WIZ_CLIENT_SECRET")
WIZ_API_URL = os.getenv("WIZ_API_URL", "https://api.us1.app.wiz.io/graphql")
WIZ_AUTH_URL = "https://auth.app.wiz.io/oauth/token"

def get_wiz_token():
    payload = {
        'grant_type': 'client_credentials',
        'audience': 'wiz-api',
        'client_id': WIZ_CLIENT_ID,
        'client_secret': WIZ_CLIENT_SECRET
    }
    resp = requests.post(WIZ_AUTH_URL, data=payload)
    resp.raise_for_status()
    return resp.json().get('access_token')

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
    resp = requests.post(WIZ_API_URL, json={'query': query, 'variables': {"id": finding_id}}, headers=headers)
    return resp.json().get("data", {}).get("vulnerabilityFinding", {})

def main():
    console.print("[bold blue]Step 1:[/bold blue] Running Wiz CLI scan...")
    # Run scan; check=False because exit code 4 (findings found) shouldn't crash the script
    subprocess.run(["wizcli", "scan", "dir", ".", "--stdout", "sarif", "--sarif-output-file", "raw.sarif"], check=False)

    if not os.path.exists("raw.sarif"):
        console.print("[bold red]Error:[/bold red] Scan failed to produce raw.sarif")
        return

    token = get_wiz_token()
    with open("raw.sarif", "r") as f:
        sarif = json.load(f)

    table = Table(title="Wiz Security Report", expand=True)
    table.add_column("Package", style="cyan", ratio=1)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Fix Version", style="green")
    table.add_column("First Discovered", justify="right")
    table.add_column("Wiz URL", ratio=2)

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            props = result.get("properties", {})
            finding_id = props.get("vulnerabilityId")
            pkg_name = props.get("vulnerabilityPackageName", "N/A")
            severity = result.get("level", "warning").upper()
            
            if finding_id:
                details = get_finding_details(token, finding_id)
                
                # Update SARIF for GitHub UI
                props.update({
                    "wizFirstDiscovered": details.get("firstDetectedAt"),
                    "wizFixVersion": details.get("fixedVersion"),
                    "wizPortalUrl": details.get("portalUrl")
                })
                
                # Render terminal UI
                sev_color = "bold red" if severity in ["CRITICAL", "ERROR"] else "yellow"
                table.add_row(
                    pkg_name,
                    f"[{sev_color}]{severity}[/]",
                    details.get("fixedVersion") or "N/A",
                    (details.get("firstDetectedAt") or "N/A")[:10],
                    details.get("portalUrl")
                )

    console.print(table)
    with open("wiz_enriched.sarif", "w") as f:
        json.dump(sarif, f, indent=2)

if __name__ == "__main__":
    main()
    
