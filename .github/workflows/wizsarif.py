import os
import re
import json
import textwrap
import traceback
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

SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH":     "8.0",
    "MEDIUM":   "5.5",
    "LOW":      "3.0",
    "INFORMATIONAL": "0.5",
    "UNKNOWN":  "0.0",
}

LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFORMATIONAL": "note",
    "UNKNOWN":  "note",
}

# SARIF `level` -> severity fallback when nothing else is available
SARIF_LEVEL_TO_SEVERITY = {
    "error":   "HIGH",
    "warning": "MEDIUM",
    "note":    "LOW",
    "none":    "INFORMATIONAL",
}

SARIF_FILES = [
    ("Source Dependencies (SCA)",          "dir.sarif"),
    ("Dockerfile Misconfigurations (IaC)", "dockerfile.sarif"),
    ("Container Image",                    "image.sarif"),
]


def parse_message_text(text):
    """Parse 'Key: value' lines from Wiz's SARIF message text."""
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


def severity_from_cvss(score_str):
    """Convert a CVSS numeric score string to our severity labels."""
    try:
        score = float(score_str)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFORMATIONAL"


def get_rule_map(sarif):
    """Build a map of ruleId -> rule definition for quick lookup."""
    rule_map = {}
    for run in sarif.get("runs", []):
        rules = (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        for rule in rules:
            rid = rule.get("id")
            if rid:
                rule_map[rid] = rule
    return rule_map


def get_severity_for_result(result, rule_map):
    """Look up severity from multiple possible SARIF locations."""
    # 1. Try message.text "Severity: Medium" format (Wiz vulnerabilities)
    msg_text = (result.get("message") or {}).get("text", "")
    fields = parse_message_text(msg_text)
    sev = fields.get("severity", "").upper()
    if sev and sev in SECURITY_SEVERITY:
        return sev, fields

    # 2. Try result.properties.severity
    props = result.get("properties") or {}
    prop_sev = str(props.get("severity", "")).upper()
    if prop_sev and prop_sev in SECURITY_SEVERITY:
        return prop_sev, fields

    # 3. Try the rule definition's properties
    rid = result.get("ruleId")
    rule = rule_map.get(rid, {}) if rid else {}
    rule_props = rule.get("properties") or {}

    # 3a. rule.properties.security-severity (numeric CVSS)
    css = rule_props.get("security-severity")
    if css:
        mapped = severity_from_cvss(css)
        if mapped:
            return mapped, fields

    # 3b. rule.properties.severity
    rp_sev = str(rule_props.get("severity", "")).upper()
    if rp_sev and rp_sev in SECURITY_SEVERITY:
        return rp_sev, fields

    # 3c. rule.properties.problem.severity (common in some tools)
    problem = rule_props.get("problem") or {}
    problem_sev = str(problem.get("severity", "")).upper()
    if problem_sev and problem_sev in SECURITY_SEVERITY:
        return problem_sev, fields

    # 4. Fall back to SARIF level from rule.defaultConfiguration or result.level
    default_cfg = rule.get("defaultConfiguration") or {}
    level = (result.get("level") or default_cfg.get("level") or "").lower()
    if level in SARIF_LEVEL_TO_SEVERITY:
        return SARIF_LEVEL_TO_SEVERITY[level], fields

    return "UNKNOWN", fields


def enrich_sarif_with_severity(sarif):
    """Add security-severity to each rule so GitHub shows proper severity badges."""
    rule_map = get_rule_map(sarif)
    rule_severity = {}

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rid = result.get("ruleId")
            sev, _ = get_severity_for_result(result, rule_map)
            if sev not in SECURITY_SEVERITY:
                sev = "UNKNOWN"
            if rid:
                rule_severity[rid] = sev
            result["level"] = LEVEL_MAP.get(sev, "warning")

    for run in sarif.get("runs", []):
        rules = (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        for rule in rules:
            rid = rule.get("id")
            sev = rule_severity.get(rid, "UNKNOWN")
            props = rule.setdefault("properties", {})
            props["security-severity"] = SECURITY_SEVERITY.get(sev, "0.0")
            tags = props.setdefault("tags", [])
            if "security" not in tags:
                tags.append("security")
            if sev.lower() not in tags:
                tags.append(sev.lower())
    return sarif


def extract_rows(sarif):
    rule_map = get_rule_map(sarif)
    rows = []

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "N/A")
            severity, fields = get_severity_for_result(result, rule_map)

            # Try rule.shortDescription / fullDescription / name for IaC findings
            rule = rule_map.get(rule_id, {})
            rule_short = (rule.get("shortDescription") or {}).get("text", "")
            rule_name = rule.get("name") or ""

            component = fields.get("component") or rule_name or "N/A"
            version = fields.get("version", "N/A")
            fixed = fields.get("fixed version", "N/A")

            msg_text = (result.get("message") or {}).get("text", "")
            desc = (fields.get("description", "") or rule_short or msg_text).split("\n")[0]

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

            # For IaC: rule_id is a UUID, replace with friendlier label
            display_rule = rule_id
            if rule_name and len(rule_id) > 30 and "-" in rule_id:
                display_rule = rule_name

            rows.append({
                "rule": display_rule,
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
            wrap(r["rule"], 30),
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


def print_layer_report(json_path="image-layers.json"):
    """Print per-layer breakdown. Fails gracefully — never crash the whole script."""
    if not os.path.exists(json_path):
        print(f"\n(Skipping per-layer report: {json_path} not found)")
        return

    try:
        with open(json_path) as f:
            data = json.load(f)
    except Exception as e:
        print(f"\n(Could not parse {json_path}: {e})")
        return

    try:
        # Debug: show top-level structure
        top_keys = list(data.keys()) if isinstance(data, dict) else []
        print(f"\n(Layer report: JSON top-level keys = {top_keys})")

        result = data.get("result") or data.get("scan") or data or {}
        if not isinstance(result, dict):
            print("(Layer report: unexpected JSON structure, skipping)")
            return

        os_packages = result.get("osPackages", []) or []
        libraries = result.get("libraries", []) or []
        all_findings = os_packages + libraries

        if not all_findings:
            # Some wizcli versions put data in different keys
            print(f"(Layer report: no osPackages/libraries keys found. result keys = {list(result.keys())})")
            return

        layers = {}
        for pkg in all_findings:
            vulns = pkg.get("vulnerabilities", []) or []
            for v in vulns:
                layer_key = (v.get("layerID") or v.get("layerDigest")
                             or pkg.get("layerID") or pkg.get("layerDigest")
                             or "unknown")
                layer_instruction = (v.get("layerInstruction")
                                     or pkg.get("layerInstruction") or "")
                key = (layer_key, layer_instruction)
                layers.setdefault(key, []).append({
                    "cve": v.get("name", "N/A"),
                    "severity": (v.get("severity") or "UNKNOWN").upper(),
                    "component": pkg.get("name", "N/A"),
                    "version": pkg.get("version", "N/A"),
                    "fixed": v.get("fixedVersion", "N/A"),
                })

        if not layers:
            print("(Layer report: no layer-tagged vulnerabilities found)")
            return

        bar = "=" * 100
        print(f"\n{bar}\nPer-Layer Vulnerability Report\n{bar}")

        sorted_layers = sorted(layers.items(), key=lambda x: str(x[0][0]))

        for idx, ((layer_key, instruction), findings) in enumerate(sorted_layers):
            sev_counts = {}
            for f in findings:
                sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

            layer_short = str(layer_key)[:16] if layer_key != "unknown" else "unknown"
            header = f"\nLayer #{idx + 1}  [{layer_short}]"
            if instruction:
                header += f"\n  Instruction: {instruction[:120]}"
            print(header)

            sev_summary = " | ".join(
                f"{ANSI.get(s, '')}{s}: {sev_counts[s]}{ANSI['RESET']}"
                for s in SEVERITY_ORDER if sev_counts.get(s)
            )
            print(f"  Findings: {len(findings)}  ({sev_summary})")

            findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
            seen = set()
            deduped = []
            for f in findings:
                key = (f["component"], f["cve"])
                if key not in seen:
                    seen.add(key)
                    deduped.append(f)
            top = deduped[:5]

            rows = [
                [
                    wrap(f["cve"], 16),
                    f"{ANSI.get(f['severity'], '')}{f['severity']}{ANSI['RESET']}",
                    wrap(f["component"], 22),
                    wrap(f["version"], 14),
                    wrap(f["fixed"], 14),
                ]
                for f in top
            ]
            print(tabulate(
                rows,
                headers=["CVE", "SEVERITY", "COMPONENT", "VERSION", "FIXED"],
                tablefmt="grid",
            ))
            if len(findings) > 5:
                print(f"  ... and {len(findings) - 5} more in this layer")

        # GitHub Step Summary
        summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a") as f:
                f.write("\n## Per-Layer Vulnerability Report\n\n")
                for idx, ((layer_key, instruction), findings) in enumerate(sorted_layers):
                    sev_counts = {}
                    for fd in findings:
                        sev_counts[fd["severity"]] = sev_counts.get(fd["severity"], 0) + 1

                    layer_short = str(layer_key)[:16] if layer_key != "unknown" else "unknown"
                    f.write(f"### Layer #{idx + 1} — `{layer_short}`\n\n")
                    if instruction:
                        f.write(f"**Instruction:** `{instruction[:150]}`\n\n")
                    f.write(f"**Findings:** {len(findings)} — " + " | ".join(
                        f"{EMOJI.get(s, '')} {s}: {sev_counts[s]}"
                        for s in SEVERITY_ORDER if sev_counts.get(s)
                    ) + "\n\n")

                    findings.sort(key=lambda fd: SEVERITY_ORDER.get(fd["severity"], 99))
                    seen = set()
                    deduped = []
                    for fd in findings:
                        key = (fd["component"], fd["cve"])
                        if key not in seen:
                            seen.add(key)
                            deduped.append(fd)
                    top = deduped[:5]

                    md_rows = [
                        [
                            fd["cve"],
                            f"{EMOJI.get(fd['severity'], '')} {fd['severity']}",
                            fd["component"],
                            fd["version"],
                            fd["fixed"],
                        ]
                        for fd in top
                    ]
                    f.write(tabulate(
                        md_rows,
                        headers=["CVE", "Severity", "Component", "Version", "Fixed"],
                        tablefmt="github",
                    ))
                    f.write("\n\n")
                    if len(findings) > 5:
                        f.write(f"_... and {len(findings) - 5} more in this layer_\n\n")

    except Exception as e:
        print(f"\n(Per-layer report failed: {e})")
        print(traceback.format_exc())


def main():
    any_found = False
    for title, path in SARIF_FILES:
        if not os.path.exists(path):
            print(f"Skipping {title}: {path} not found")
            continue
        any_found = True

        try:
            with open(path) as f:
                sarif = json.load(f)

            sarif = enrich_sarif_with_severity(sarif)

            with open(path, "w") as f:
                json.dump(sarif, f, indent=2)

            rows = extract_rows(sarif)

            seen = set()
            deduped = []
            for r in rows:
                key = (r["component"], r["version"], r["rule"])
                if key not in seen:
                    seen.add(key)
                    deduped.append(r)

            rows = deduped[:3]

            counts = print_report(title, rows)
            write_summary(title, rows, counts)
             # Per-layer image report — wrapped in try/except so it never crashes
            try:
                print_layer_report("image-layers.json")
            except Exception as e:
                print(f"\n(Per-layer report outer failure: {e})")
        except Exception as e:
            print(f"\n(Error processing {title}: {e})")
            print(traceback.format_exc())

    if not any_found:
        print("No SARIF files found. Did the scan steps run?")

if __name__ == "__main__":
    main()
