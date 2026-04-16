import json
import pathlib
import hashlib

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
SEVERITY_RANK = {severity: idx for idx, severity in enumerate(SEVERITY_LEVELS)}

SARIF_TO_SEVERITY = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "info": "INFO",
    "none": "UNKNOWN",
}

def normalize_tool_name(raw_name: str, file_path: pathlib.Path) -> str:
    name = str(raw_name).lower()
    if "trivy" in name:
        if "sca" in file_path.name.lower(): return "trivy-sca"
        if "iac" in file_path.name.lower(): return "trivy-iac"
        return "trivy-sca"
    if "semgrep" in name: return "semgrep"
    if "gitleaks" in name: return "gitleaks"
    if "mobsf" in name: return "mobsfscan"
    return name

def generate_issue_id(rule_id: str, uri: str, line: str, snippet: str) -> str:
    unique_string = f"{rule_id}|{uri}|{line}|{snippet}"
    unique_id = hashlib.sha256(unique_string.encode('utf-8')).hexdigest()
    return unique_id[:6]

def extract_severity(result: dict, rule: dict, tool_name: str) -> str:
    props = rule.get("properties", {})

    sec_sev = props.get("security-severity") or props.get("security_severity")
    if sec_sev is not None:
        try:
            val = float(sec_sev)
            if val >= 9.0: return "CRITICAL"
            if val >= 7.0: return "HIGH"
            if val >= 4.0: return "MEDIUM" 
            return "LOW"
        except ValueError:
            pass

    tags = props.get("tags", [])
    found_severities = []
    
    for tag in tags:
        words = str(tag).upper().replace("-", " ").replace("_", " ").split()
        for word in words:
            if word in SEVERITY_RANK:
                found_severities.append(word)

    if found_severities:
        return sorted(found_severities, key=lambda s: SEVERITY_RANK[s])[0]

    raw_level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
    if raw_level:
        mapped_sev = SARIF_TO_SEVERITY.get(raw_level.lower())
        if mapped_sev:
            return mapped_sev

    return "UNKNOWN"

def parse_sarif_issues(path: pathlib.Path) -> list:
    with open(path) as f:
        sarif = json.load(f)

    issues = []
    for run in sarif.get("runs", []):
        raw_tool_name = run.get("tool", {}).get("driver", {}).get("name", "Unknown Tool")
        tool_name = normalize_tool_name(raw_tool_name, path)

        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            message = result.get("message", {}).get("text", "")
            
            uri, line, snippet = "", "", ""
            locs = result.get("locations", [])
            if locs:
                region = locs[0].get("physicalLocation", {}).get("region", {})
                uri = locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                line = str(region.get("startLine", ""))
                snippet = region.get("snippet", {}).get("text", "")

            if tool_name == "trivy-sca" and rule_id.startswith("CVE"):
                pass 

            metadata = {
                "fingerprints": result.get("partialFingerprints", {}) or result.get("fingerprints", {}),
                "properties": rule.get("properties", {})
            }

            issues.append({
                "id": generate_issue_id(rule_id, uri, line, snippet),
                "tool": tool_name,
                "rule_id": rule_id,
                "severity": extract_severity(result, rule, tool_name),
                "message": message,
                "uri": uri,
                "line": line,
                "snippet": snippet,
                "location": f"{uri}:{line}" if line else uri,
                "metadata": metadata
            })

    return issues