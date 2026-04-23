import os
import re
import json
import textwrap
from tabulate import tabulate

# ANSI color codes for terminal output
ANSI = {
    "CRITICAL": "\033[1;37;41m",
    "HIGH":     "\033[1;31m",
    "MEDIUM":   "\033[1;33m",
    "LOW":      "\033[1;32m",
    "INFORMATIONAL": "\033[1;90m",
    "UNKNOWN":  "\033[0m",
    "RESET":    "\033[0m",
}

# Emoji indicators for the GitHub Step Summary markdown view
EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFORMATIONAL": "⚪",
    "UNKNOWN":  "⚫",
}

SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
    "INFORMATIONAL": 4, "UNKNOWN": 5,
}

# CVSS-style numeric severity GitHub uses for proper severity badges
# (https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object)
SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH":     "8.0",
    "MEDIUM":   "5.5",
    "LOW":      "3.0",
    "INFORMATIONAL": "0.5",
    "UNKNOWN":  "0.0",
}

# Map our severity to SARIF level (what GitHub displays as Error/Warning/Note)
LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFORMATIONAL": "note",
    "UNKNOWN":  "note",
}

SARIF_FILES = [
    ("Source Dependencies (SCA)",          "dir.sarif"),
    ("Dockerfile Misconfigurations (IaC)", "dockerfile.sarif"),
    ("Container Image",                    "image.sarif"),
]


def parse_message_text(text):
    """Wiz packs fields as 'Key: value' lines in message.text. Parse them out."""
    fields = {}
    if not text:
        return fields
    for line in text.split("\n"):
        m = re.match(r"^([A-Za-z ]+):\s*(.*)$", line)
        if m:
            key = m.group(1).strip().lower()
            val = m.group(2).strip()
            fields.setdefault(key, val)
    idx = text.find("Description:")
    if idx >= 0:
        fields["description"] = text[idx + len("Description:"):].strip()
    return fields


def wrap(text, width):
    if not text:
        return ""
    return "\n".join(textwrap.wrap(str(text), width=width)) or str(text)


def enrich_sarif_with_severity(sarif):
    """Add security-severity to each rule so GitHub shows proper severity badges."""
    # First, build a map of ruleId -> severity by scanning results
    rule_severity = {}
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rid = result.get("ruleId")
            msg_text = (result.get("message") or {}).get("text", "")
            fields = parse_message_text(msg_text)
            sev = fields.get("severity", "").upper() or "UNKNOWN"
            if rid and sev:
                rule_severity[rid] = sev

            # Also update the result level to match
            result["level"] = LEVEL_MAP.get(sev, "warning")

    # Then, enrich each rule definition
    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        rules = tool.get("rules", []) or []
        for rule in rules:
            rid = rule.get("id")
            sev = rule_severity.get(rid, "UNKNOWN")
            props = rule.setdefault("properties", {})
            props["security-severity"] = SECURITY_SEVERITY[sev]
            # Tags help GitHub filtering
            tags = props.setdefault("tags", [])
            if "security" not in tags:
                tags.append("security")
            if sev.lower() not in tags:
                tags.append(sev.lower())
    return sarif


def extract_rows(sarif):
    rows = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "N/A")
            msg_text = (result.get("message") or {}).get("text", "")
            fields = parse_message_text(msg_text)

            severity = fields.get("severity", "").upper() or "UNKNOWN"
            component = fields.get("component", "N/A")
            version = fields.get("version", "N/A")
            fixed = fields.get("fixed version", "N/A")
            desc = (fields.get("description", "") or msg_text).split("\n")[0]

            locs = result.get("locations") or []
            file_path = "N/A"
            if locs:
                file_path = (
                    locs[0]
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "N/A")
                )

            status = f"fixed in {fixed}" if fixed != "N/A" else "no fix"

            rows.append({
                "rule": rule_id,
                "severity": severity,
                "component": component,
                "version": version,
                "status": status,
                "file": file_path,
                "description": desc,
            })

    rows.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 99))
    return rows


def print_report(title, rows):
    headers = ["RULE / CVE", "SEVERITY", "COMPONENT", "VERSION",
               "STATUS", "FILE", "DESCRIPTION"]
    display = [
        [
            wrap(r["rule"], 18),
            f"{ANSI.get(r['severity'], '')}{r['severity']}{ANSI['RESET']}",
            wrap(r["component"], 18),
            wrap(r["version"], 12),
            wrap(r["status"], 18),
            wrap(r["file"], 24),
            wrap(r["description"], 50),
        ]
        for r in rows
    ]

    bar = "=" * 100
    print(f"\n{bar}\n{title}  ({len(rows)} findings)\n{bar}")

    if rows:
        print(tabulate(display, headers=headers, tablefmt="grid"))
    else:
        print("No findings.")

    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1

    if counts:
        print("\nSummary: " + " | ".join(
            f"{ANSI.get(s, '')}{s}: {counts[s]}{ANSI['RESET']}"
            for s in SEVERITY_ORDER if counts.get(s)
        ))

    return counts


def write_summary(title, rows, counts):
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    headers = ["Rule / CVE", "Severity", "Component", "Version",
               "Status", "File", "Description"]
    md_rows = [
        [
            r["rule"],
            f"{EMOJI.get(r['severity'], '')} {r['severity']}",
            r["component"],
            r["version"],
            r["status"],
            r["file"],
            r["description"][:120],
        ]
        for r in rows
    ]

    with open(summary_path, "a") as f:
        f.write(f"\n## {title}\n\n")
        f.write(f"**Total findings shown:** {len(rows)}\n\n")
        if counts:
            f.write("**Breakdown:** " + " | ".join(
                f"{EMOJI[s]} {s}: {counts[s]}"
                for s in SEVERITY_ORDER if counts.get(s)
            ) + "\n\n")
        if rows:
            f.write(tabulate(md_rows, headers=headers, tablefmt="github"))
            f.write("\n")


def main():
    any_found = False
    for title, path in SARIF_FILES:
        if not os.path.exists(path):
            print(f"Skipping {title}: {path} not found")
            continue
        any_found = True

        with open(path) as f:
            sarif = json.load(f)

        # Enrich SARIF so GitHub shows proper Critical/High/Medium badges
        sarif = enrich_sarif_with_severity(sarif)

        # Write the enriched SARIF back so the upload step picks it up
        with open(path, "w") as f:
            json.dump(sarif, f, indent=2)

        rows = extract_rows(sarif)

        # Dedupe: one finding per component+version
        seen = set()
        deduped = []
        for r in rows:
            key = (r["component"], r["version"])
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        # Keep only top 3 for a clean demo console table
        # (Full SARIF still uploads to GitHub Security tab)
        rows = deduped[:3]

        counts = print_report(title, rows)
        write_summary(title, rows, counts)

    if not any_found:
        print("No SARIF files found. Did the scan steps run?")


if __name__ == "__main__":
    main()
