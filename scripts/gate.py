import os
import sys
import pathlib
import yaml

import exception_core
from issues_parse import SEVERITY_RANK, parse_sarif_issues

DISPLAY_LIMIT = 30

def _trunc(text: str, limit: int = 90) -> str:
    text = str(text or "").strip()
    return text if len(text) <= limit else text[:limit] + "..."

def _md_cell(text: str) -> str:
    return _trunc(str(text or "").replace("|", "\\|").replace("\n", " ").strip())

def _extract_rich_context(issue: dict) -> str:
    props = issue.get("metadata", {}).get("properties", {})
    pkg = props.get("PkgName") or props.get("package")
    installed = props.get("InstalledVersion")
    if pkg and installed:
        return f"Pkg: {pkg}@{installed}"
    if "title" in props:
        return props["title"]
    return issue.get("message") or issue.get("snippet") or "No description"

def normalize_policy_severity(value: str) -> str | None:
    if not value or str(value).strip().upper() in ("OFF", "DISABLED", "NONE"):
        return None
    sev = str(value).strip().upper()
    if sev not in SEVERITY_RANK:
        raise ValueError(f"Invalid severity in policy: {value}")
    return sev

def validate_policy(policy_path: pathlib.Path) -> dict:
    if not policy_path.exists():
        print(f"[WARN] Policy file '{policy_path}' not found. Using secure defaults.", file=sys.stderr)
        return {}
    
    try:
        with open(policy_path) as f:
            raw_policy = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[WARN] Error reading policy file: {e}", file=sys.stderr)
        return {}
    
    if "tools" in raw_policy and isinstance(raw_policy["tools"], dict):
        raw_policy = raw_policy["tools"]

    CATEGORY_TO_TOOLS = {
        "sca": ["trivy-sca"],
        "sast": ["semgrep", "mobsfscan"],
        "secrets": ["gitleaks"],
        "iac": ["trivy-iac"],
        "mobile-sast": ["mobsfscan"],
    }

    normalized = {}
    for k, v in raw_policy.items():
        clean_key = str(k).strip().lower().replace("_", "-")

        if isinstance(v, dict) and "block_on" in v:
            val = normalize_policy_severity(v.get("block_on"))
        elif isinstance(v, str):
            val = normalize_policy_severity(v)
        else:
            continue

        if clean_key in CATEGORY_TO_TOOLS:
            for tool in CATEGORY_TO_TOOLS[clean_key]:
                normalized[tool] = val
            continue

        if "semgrep" in clean_key: normalized["semgrep"] = val
        elif "gitleaks" in clean_key: normalized["gitleaks"] = val
        elif "mobsf" in clean_key: normalized["mobsfscan"] = val
        else: normalized[clean_key] = val

    print(f"[INFO] Loaded Active Policies: {normalized}", file=sys.stderr)
    return normalized

def write_summary(content: str):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(content + "\n")
    else:
        print(content)

def main():
    results_dir   = pathlib.Path(os.environ.get("RESULTS_DIR", "scan-results"))
    policy_path   = pathlib.Path(os.environ.get("POLICY_PATH", "security-config/policies/severity-policy.yml"))
    exception_dir = pathlib.Path(os.environ.get("EXCEPTION_DIR", "security-config/exceptions"))
    bypass_reason = os.environ.get("BYPASS_REASON", "").strip()
    bypass_actor  = os.environ.get("BYPASS_ACTOR", "unknown")
    repository    = os.environ.get("GITHUB_REPOSITORY", "unknown/repo")

    try:
        policy = validate_policy(policy_path)
    except ValueError as exc:
        print(f"[ERROR] Invalid severity policy: {exc}", file=sys.stderr)
        sys.exit(1)

    exception_path = exception_dir / exception_core.EXCEPTION_FILE
    results = {}
    any_blocked = False

    sarif_files = list(results_dir.rglob("*.sarif"))

    # Phase 1: Aggregate Issues
    for filepath in sarif_files:
        try:
            issues = parse_sarif_issues(filepath)
        except Exception:
            continue

        if not issues:
            continue
        tool_name = issues[0]["tool"]
        
        if tool_name not in results:
            policy_val = policy[tool_name] if isinstance(policy, dict) and tool_name in policy else None
            block_val = "HIGH" if policy_val is None else policy_val

            results[tool_name] = {
                "all_issues": [],
                "block_on": block_val
            }
            print(f"[INFO] Detected tool '{tool_name}': effective_block_on={block_val}", file=sys.stderr)
            
        results[tool_name]["all_issues"].extend(issues)

    # Phase 2: Evaluation & Suppressions
    for tool, r in results.items():
        suppressions = exception_core.list_active_suppressions(exception_path, repository, tool)
        active = [f for f in r["all_issues"] if not exception_core.is_suppressed(f["id"], suppressions)]
        deduped = list({f["id"]: f for f in active}.values())
        block_on = r["block_on"]
        
        blocking_issues = [
            f for f in deduped 
            if block_on and SEVERITY_RANK.get(f.get("severity", "UNKNOWN"), 99) <= SEVERITY_RANK[block_on]
        ]

        r["after_exceptions"] = len(deduped)
        r["blocking_issues"] = blocking_issues
        r["blocking_count"] = len(blocking_issues)
        r["status"] = "FAIL" if blocking_issues else "PASS"
        
        if blocking_issues:
            any_blocked = True

    # Phase 3: Build Report (ONLY BLOCKING issues are detailed)
    lines = ["## Security Scan Results", "", "| Tool | Status | Total Visible | Blocking | Threshold |", "|---|---|---|---|---|"]
    
    for tool, r in results.items():
        icon = "❌ FAIL" if r["status"] == "FAIL" else "✅ PASS"
        threshold = r["block_on"] or "DISABLED"
        lines.append(f"| {tool} | {icon} | {r['after_exceptions']} | {r['blocking_count']} | {threshold} |")

    lines.append("\n> Note: Only issues that breach the blocking threshold are listed below.\n")

    for tool, r in results.items():
        if not r["blocking_issues"]: 
            continue
        
        display_issues = sorted(r["blocking_issues"], key=lambda x: SEVERITY_RANK.get(x["severity"], 99))
        
        lines.extend([
            f"### {tool} - Blocking Issues",
            f"- Threshold: `>= {r['block_on']}`",
            "",
            "| ID | Rule / ID | Severity | Context | Location |",
            "|----|-----------|----------|---------|----------|"
        ])
        
        for f in display_issues[:DISPLAY_LIMIT]:
            issue_id = f.get('id', 'unknown')
            context = _md_cell(_extract_rich_context(f))
            rule_id = _md_cell(f.get('rule_id', 'unknown'))
            location = _md_cell(f.get('location', ''))
            severity = f.get('severity', 'UNKNOWN')
            
            lines.append(f"| `{issue_id}` | `{rule_id}` | {severity} | {context} | {location} |")
        
        if len(display_issues) > DISPLAY_LIMIT:
            lines.append(f"\n*...and {len(display_issues) - DISPLAY_LIMIT} more hidden blocking issues.*")
        lines.append("")

    # Phase 4: Bypass logic & Final Exit
    if bypass_reason:
        lines.extend([
            "---", "## Gate Bypass Active",
            f"**Actor:** `{bypass_actor}` | **Reason:** {bypass_reason}"
        ])
        write_summary("\n".join(lines))
        print(f"⚠️ GATE BYPASSED by {bypass_actor} - reason: {bypass_reason}", file=sys.stderr)
        sys.exit(0)

    write_summary("\n".join(lines))

    if any_blocked:
        print("\n❌ GATE BLOCKED: Issues exceed the configured severity threshold.", file=sys.stderr)
        for tool, r in results.items():
            if r["blocking_count"] > 0:
                print(f" -> {tool}: {r['blocking_count']} blocking issue(s).", file=sys.stderr)
        sys.exit(1)

    print(f"✅ GATE PASSED: Clean or accepted risk.")
    sys.exit(0)

if __name__ == "__main__":
    main()