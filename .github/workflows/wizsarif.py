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

def cap_results(sarif, max_results=2000):
    """
    Aggressively trim large SARIFs so GitHub can successfully process them.

    GitHub's docs say 25k max, but in practice large image SARIFs (>3000 results)
    often fail during backend processing even though upload succeeds.
    Keep highest-severity findings and drop unused rules to shrink the file.
    """
    severity_priority = {"error": 0, "warning": 1, "note": 2, "none": 3}

    total_kept = 0
    kept_rule_ids = set()

    for run in sarif.get("runs", []):
        results = run.get("results", []) or []
        if not results:
            continue

        # Sort so highest-severity findings are kept
        results.sort(key=lambda r: severity_priority.get(
            (r.get("level") or "warning").lower(), 9
        ))

        remaining_budget = max(0, max_results - total_kept)
        if len(results) > remaining_budget:
            run["results"] = results[:remaining_budget]
        total_kept += len(run["results"])

        # Collect rule IDs actually used by the kept results
        for r in run["results"]:
            rid = r.get("ruleId")
            if rid:
                kept_rule_ids.add(rid)

        # Drop unused rules — they bloat the file by 20-40%
        tool_driver = run.get("tool", {}).get("driver", {})
        all_rules = tool_driver.get("rules", []) or []
        kept_rules = [r for r in all_rules if r.get("id") in kept_rule_ids]
        tool_driver["rules"] = kept_rules

        # Recalculate ruleIndex on each result to match the new rules array
        rule_id_to_index = {r.get("id"): i for i, r in enumerate(kept_rules)}
        for result in run["results"]:
            rid = result.get("ruleId")
            if rid and rid in rule_id_to_index:
                result["ruleIndex"] = rule_id_to_index[rid]
            else:
                # Rule reference broken — remove the orphan ruleIndex
                result.pop("ruleIndex", None)

    return sarif

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

    # 3c. rule.properties.problem.severity
    problem = rule_props.get("problem") or {}
    problem_sev = str(problem.get("severity", "")).upper()
    if problem_sev and problem_sev in SECURITY_SEVERITY:
        return problem_sev, fields

    # 4. Fall back to SARIF level
    default_cfg = rule.get("defaultConfiguration") or {}
    level = (result.get("level") or default_cfg.get("level") or "").lower()
    if level in SARIF_LEVEL_TO_SEVERITY:
        return SARIF_LEVEL_TO_SEVERITY[level], fields

    return "UNKNOWN", fields
def rewrite_alert_titles(sarif, scan_label):
    """
    Rewrite result.message.text so the GitHub Code Scanning alert title
    shows our custom format:
        [Wiz CLI Scan] <CVE/Rule> : <Component> <ver> → <fix> : <custom message>
    """
    rule_map = get_rule_map(sarif)

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "UNKNOWN")
            severity, fields = get_severity_for_result(result, rule_map)

            component = fields.get("component", "")
            version = fields.get("version", "")
            fixed = fields.get("fixed version", "")

            # Build the custom message based on scan type
            if scan_label == "SCA" or scan_label == "Image":
                parts = [f"[Wiz CLI Scan] {rule_id}"]
                if component and version:
                    ver_info = f"{component} {version}"
                    if fixed and fixed.lower() not in ("n/a", ""):
                        ver_info += f" → fix: {fixed}"
                    parts.append(ver_info)
                parts.append(f"{severity} vulnerability detected")
                new_title = " : ".join(parts)

            elif scan_label == "IaC":
                rule = rule_map.get(rule_id, {}) or {}
                rule_name = rule.get("name") or ""
                rule_short = (rule.get("shortDescription") or {}).get("text", "")
                desc = rule_short or rule_name or "Misconfiguration detected"
                new_title = f"[Wiz CLI Scan] {rule_name or rule_id} : {desc} : {severity}"

            else:
                new_title = f"[Wiz CLI Scan] {rule_id}"

            # Preserve the original detailed description, just prepend our title
            original_text = (result.get("message") or {}).get("text", "")
            original_md = (result.get("message") or {}).get("markdown", "")

            result["message"] = {
                "text": f"{new_title}\n\n{original_text}",
                "markdown": f"### {new_title}\n\n{original_md or original_text}",
            }

    return sarif

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

            # For IaC findings whose ruleId is a UUID, use rule.name if present
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


def _extract_layer_info(obj):
    """
    Returns (layer_id, instruction, index, is_base_layer) from layerMetadata.
    """
    if not isinstance(obj, dict):
        return None, "", None, False

    meta = obj.get("layerMetadata")
    if not isinstance(meta, dict):
        return None, "", None, False

    layer_id = (
        meta.get("id")
        or meta.get("layerId")
        or meta.get("layerID")
        or meta.get("digest")
        or meta.get("layerDigest")
        or meta.get("sha")
        or meta.get("hash")
    )

    # Wiz uses "details" to hold the Dockerfile-instruction-like string
    instruction = (
        meta.get("details")
        or meta.get("createdBy")
        or meta.get("instruction")
        or meta.get("command")
        or meta.get("cmd")
        or meta.get("layerInstruction")
        or ""
    )

    index = meta.get("index") or meta.get("layerIndex") or meta.get("order")
    is_base = bool(meta.get("isBaseLayer", False))

    return (
        str(layer_id) if layer_id else None,
        str(instruction) if instruction else "",
        index,
        is_base,
    )


def print_layer_report(json_path="image-layers.json"):
    """Group findings by layerMetadata and print a per-layer report."""
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
        result = data.get("result") or {}
        all_findings = []
        for key in ("osPackages", "libraries", "applications"):
            all_findings.extend(result.get(key, []) or [])

        if not all_findings:
            print(f"(Layer report: no findings in result. Keys = {list(result.keys())})")
            return

        # Group findings by (layer_id, instruction)
        layers = {}
        for pkg in all_findings:
            layer_id, instruction, index, is_base = _extract_layer_info(pkg)
            if not layer_id:
                layer_id = "unknown"

            vulns = pkg.get("vulnerabilities", []) or []
            for v in vulns:
                key = (layer_id, instruction)
                layers.setdefault(key, {
                    "findings": [],
                    "index": index if index is not None else 999,
                    "is_base": is_base,
                })
                layers[key]["findings"].append({
                    "cve": v.get("name", "N/A"),
                    "severity": (v.get("severity") or "UNKNOWN").upper(),
                    "component": pkg.get("name", "N/A"),
                    "version": pkg.get("version", "N/A"),
                    "fixed": v.get("fixedVersion") or "no fix",
                })

        if not layers:
            print("(Layer report: no vulnerabilities found)")
            return

        # Sort by layer index if we have it; otherwise by layer_id string
        def sort_key(item):
            (layer_id, _), payload = item
            return (payload["index"], str(layer_id))

        sorted_layers = sorted(layers.items(), key=sort_key)

        bar = "=" * 100
        print(f"\n{bar}\nPer-Layer Vulnerability Report  ({len(sorted_layers)} layers)\n{bar}")

        for idx, ((layer_id, instruction), payload) in enumerate(sorted_layers):
            findings = payload["findings"]
            is_base = payload.get("is_base", False)

            sev_counts = {}
            for f in findings:
                sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

            base_tag = " [BASE IMAGE]" if is_base else ""
            print(f"\nLayer #{idx + 1}{base_tag}")
            print(f"  Digest:      {layer_id}")
            if instruction:
                wrapped = textwrap.fill(
                    instruction,
                    width=140,
                    initial_indent="  Instruction: ",
                    subsequent_indent="               ",
                )
                print(wrapped)

            sev_summary = " | ".join(
                f"{ANSI.get(s, '')}{s}: {sev_counts[s]}{ANSI['RESET']}"
                for s in SEVERITY_ORDER if sev_counts.get(s)
            )
            print(f"  Findings:    {len(findings)}  ({sev_summary})")

            findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
            seen = set()
            deduped = []
            for f in findings:
                k = (f["component"], f["cve"])
                if k not in seen:
                    seen.add(k)
                    deduped.append(f)
            top = deduped[:5]

            rows = [
                [
                    wrap(f["cve"], 16),
                    f"{ANSI.get(f['severity'], '')}{f['severity']}{ANSI['RESET']}",
                    wrap(f["component"], 24),
                    wrap(f["version"], 16),
                    wrap(f["fixed"], 16),
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
                f.write(f"\n## Per-Layer Vulnerability Report  ({len(sorted_layers)} layers)\n\n")
                for idx, ((layer_id, instruction), payload) in enumerate(sorted_layers):
                    findings = payload["findings"]
                    is_base = payload.get("is_base", False)

                    sev_counts = {}
                    for fd in findings:
                        sev_counts[fd["severity"]] = sev_counts.get(fd["severity"], 0) + 1

                    base_tag = " 🏛️ **BASE IMAGE**" if is_base else ""
                    f.write(f"### Layer #{idx + 1}{base_tag}\n\n")
                    f.write(f"**Digest:** `{layer_id}`\n\n")
                    if instruction:
                        f.write(f"**Instruction:** `{instruction}`\n\n")
                    f.write(f"**Findings:** {len(findings)} — " + " | ".join(
                        f"{EMOJI.get(s, '')} {s}: {sev_counts[s]}"
                        for s in SEVERITY_ORDER if sev_counts.get(s)
                    ) + "\n\n")

                    findings.sort(key=lambda fd: SEVERITY_ORDER.get(fd["severity"], 99))
                    seen = set()
                    deduped = []
                    for fd in findings:
                        k = (fd["component"], fd["cve"])
                        if k not in seen:
                            seen.add(k)
                            deduped.append(fd)
                    top = deduped[:5]

                    md_rows = [
                        [fd["cve"],
                         f"{EMOJI.get(fd['severity'], '')} {fd['severity']}",
                         fd["component"], fd["version"], fd["fixed"]]
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

            # 1. Enrich: add security-severity to each rule
            sarif = enrich_sarif_with_severity(sarif)

            # 2. Rewrite titles: [Wiz CLI Scan] CVE : component : severity
            scan_label = "SCA" if "dir" in path else (
                "IaC" if "dockerfile" in path else "Image"
            )
            sarif = rewrite_alert_titles(sarif, scan_label)

            # 3. Cap results LAST so ruleIndex gets recomputed correctly
            if "image" in path.lower():
                sarif = cap_results(sarif, max_results=2000)
            else:
                sarif = cap_results(sarif, max_results=25000)

            # Save compact SARIF for upload
            with open(path, "w") as f:
                json.dump(sarif, f, separators=(",", ":"))

            size_kb = os.path.getsize(path) / 1024
            result_count = sum(
                len(run.get("results", [])) for run in sarif.get("runs", [])
            )
            print(f"  Saved {path}: {size_kb:.1f} KB, {result_count} results")

            # Extract rows from the enriched (in-memory) SARIF for printing
            rows = extract_rows(sarif)

            # Dedupe
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
        except Exception as e:
            print(f"\n(Error processing {title}: {e})")
            print(traceback.format_exc())

    if not any_found:
        print("No SARIF files found. Did the scan steps run?")

    # Per-layer container image report (from --driver mountWithLayers JSON)
    try:
        print_layer_report("image-layers.json")
    except Exception as e:
        print(f"\n(Per-layer report outer failure: {e})")

if __name__ == "__main__":
    main()
