import argparse
import io
import json
import os
import pathlib
import sys
import tempfile
import zipfile
from datetime import date
import requests

import exception_core
from issues_parse import SEVERITY_RANK, parse_sarif_issues

def write_step_summary(content: str):
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as f:
            f.write(content + "\n\n")

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

def write_gate_like_summary(body_lines: list):
    output = "\n".join(body_lines)
    print(output)
    write_step_summary(output)

def _gh_token() -> str:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")

def _api_request(url_path: str, method: str = "GET", payload: dict = None) -> dict:
    token = _gh_token()
    if not token:
        print("[ERROR] GH_TOKEN not set.", file=sys.stderr)
        sys.exit(1)
    
    url = f"https://api.github.com{url_path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    resp = requests.request(method, url, headers=headers, json=payload)
    resp.raise_for_status()
    return resp.json() if resp.content else {}

def _last_pipeline_run_id(repo: str) -> str:
    workflows = _api_request(f"/repos/{repo}/actions/workflows?per_page=100")
    wf_id = next((wf["id"] for wf in workflows.get("workflows", []) if "security" in wf["name"].lower() or "pipeline" in wf["path"].lower()), None)
    if not wf_id: sys.exit("[ERROR] Could not auto-detect security workflow. Pass --run-id.")
    
    runs = _api_request(f"/repos/{repo}/actions/workflows/{wf_id}/runs?per_page=1&status=completed")
    if not runs.get("workflow_runs"): sys.exit("[ERROR] No completed runs found.")
    return str(runs["workflow_runs"][0]["id"])

def download_artifacts(repo: str, run_id: str, dest: pathlib.Path):
    dest.mkdir(parents=True, exist_ok=True)
    artifacts = _api_request(f"/repos/{repo}/actions/runs/{run_id}/artifacts")
    for a in artifacts.get("artifacts", []):
        if not a["name"].startswith("result-"): continue
        headers = {"Authorization": f"Bearer {_gh_token()}"}
        resp = requests.get(a["archive_download_url"], headers=headers)
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            zf.extractall(dest)

def collect_visible_issues(repo: str, run_id: str, exception_path: pathlib.Path) -> list:
    with tempfile.TemporaryDirectory() as tmp:
        results_dir = pathlib.Path(tmp)
        download_artifacts(repo, run_id, results_dir)

        all_issues = []
        for sarif_file in results_dir.rglob("*.sarif"):
            all_issues.extend(parse_sarif_issues(sarif_file))

        deduped = list({f["id"]: f for f in all_issues}.values())
        
        visible = []
        for f in deduped:
            suppressions = exception_core.list_active_suppressions(exception_path, repo, f["tool"])
            if not exception_core.is_suppressed(f["id"], suppressions):
                visible.append(f)
                
        return visible

def print_issues_table(issues: list):
    results = {}
    for f in issues:
        results.setdefault(f.get("tool", "unknown"), []).append(f)

    body_lines = ["## Security Scan Results", ""]
    body_lines.append("\n> Copy the `ID` values from the detailed tables to suppress issues.\n")

    for tool in sorted(results.keys()):
        flist = results[tool]
        if not flist:
            continue

        display_issues = sorted(flist, key=lambda x: SEVERITY_RANK.get(x.get("severity", "UNKNOWN"), 99))

        body_lines.extend([
            f"### {tool} Issues",
            "",
            "| ID | Rule / ID | Severity | Context | Location |",
            "|----|-----------|----------|---------|----------|"
        ])

        for f in display_issues:
            issue_id = f.get("id", "unknown")
            context = _md_cell(_extract_rich_context(f))
            rule_id = _md_cell(f.get("rule_id", "unknown"))
            location = _md_cell(f.get("location", ""))
            severity = f.get("severity", "UNKNOWN")
            body_lines.append(f"| `{issue_id}` | `{rule_id}` | {severity} | {context} | {location} |")

        body_lines.append("")

    write_gate_like_summary(body_lines)

def run_list(args):
    exception_path = pathlib.Path(args.exception_dir) / exception_core.EXCEPTION_FILE
    run_id = args.run_id or _last_pipeline_run_id(args.repo)
    issues = collect_visible_issues(args.repo, run_id, exception_path)
    
    if args.tool: 
        issues = [f for f in issues if f["tool"] == args.tool]
        
    if args.min_severity:
        min_rank = SEVERITY_RANK.get(args.min_severity.upper(), 99)
        issues = [f for f in issues if SEVERITY_RANK.get(f.get("severity", "UNKNOWN"), 99) <= min_rank]
    
    if not issues:
        msg = f"### ✅ No active issues found matching the criteria for `{args.repo}`."
        print(msg)
        write_gate_like_summary([msg])
        return 0
        
    print_issues_table(issues)
    return 0

def run_add_suppression(args):
    exception_path = pathlib.Path(args.exception_dir) / exception_core.EXCEPTION_FILE
    run_id = args.run_id or _last_pipeline_run_id(args.repo)
    issues = collect_visible_issues(args.repo, run_id, exception_path)

    ids_to_suppress = [s.strip() for s in args.ids.split(",")]
    issues_map = {f.get("id"): f for f in issues if f.get("id")}

    today = date.today().strftime("%Y-%m-%d")
    added = 0

    summary_lines = [f"### 🛡️ Suppression Results — Target: `{args.repo}`"]

    for fid in ids_to_suppress:
        if fid not in issues_map:
            msg = f"- ⚠️ ID `{fid}` not found in current active issues."
            print(msg)
            summary_lines.append(msg)
            continue
            
        entry = exception_core.build_suppression_entry(
            issues_map[fid], args.repo, args.reason, args.approved_by, today
        )
        if exception_core.append_suppression(exception_path, entry):
            msg = f"- ✅ Suppressed: `{fid}` ({entry['tool']})"
            print(msg)
            summary_lines.append(msg)
            added += 1

    if added > 0:
        note = "\n**Note:** Exceptions update requested. Pending commit/PR."
        print(note)
        summary_lines.append(note)
    
    write_gate_like_summary(summary_lines)
    return 0

def run_list_suppressions(args):
    exception_path = pathlib.Path(args.exception_dir) / exception_core.EXCEPTION_FILE
    suppressions = exception_core.list_active_suppressions(exception_path, args.repo, args.tool)
    
    if not suppressions:
        msg = f"### ℹ️ No active suppressions found for `{args.repo}`."
        print(msg)
        write_gate_like_summary([msg])
        return 0
        
    lines = [
        f"### 🔒 Active Suppressions — Target: `{args.repo}`",
        "| ID | Tool | Rule/ID | Reason | Approved By | Date |",
        "|----|------|---------|--------|-------------|------|"
    ]
    
    for s in suppressions:
        fid = s.get('id', '')
        lines.append(f"| `{fid}` | {s.get('tool','')} | {s.get('id','')} | {s.get('reason','')} | {s.get('approved_by','')} | {s.get('approved_on','')} |")
    
    lines.append(f"\n**Total Active Suppressions:** {len(suppressions)}")
    
    write_gate_like_summary(lines)
    return 0

def run_remove_suppression(args):
    exception_path = pathlib.Path(args.exception_dir) / exception_core.EXCEPTION_FILE
    ids_to_remove = [s.strip() for s in args.ids.split(",")]

    removed, _, invalid, ambiguous = exception_core.remove_suppressions_by_ids(
        exception_path, ids_to_remove, args.repo, args.tool
    )
    
    summary_lines = [f"### 🗑️ Removal Results — Target: `{args.repo}`"]

    for fid in invalid:
        msg = f"- ❌ ID `{fid}` not found."
        print(msg)
        summary_lines.append(msg)
    for fid in ambiguous:
        msg = f"- ⚠️ ID `{fid}` is ambiguous (matches multiple entries)."
        print(msg)
        summary_lines.append(msg)
        
    for r in removed:
        msg = f"- ✅ Removed suppression for: `{r.get('id')}` ({r.get('tool')})"
        print(msg)
        summary_lines.append(msg)
        
    if removed:
        note = "\n**Note:** Exceptions update requested. Pending commit/PR."
        print(note)
        summary_lines.append(note)
    
    write_gate_like_summary(summary_lines)
    return 0

def main():
    parser = argparse.ArgumentParser(description="AppSec Exceptions CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lp = subparsers.add_parser("list-issues")
    lp.add_argument("--repo", required=True)
    lp.add_argument("--run-id")
    lp.add_argument("--tool")
    lp.add_argument("--exception-dir", default="exceptions")
    lp.add_argument("--min-severity")

    sp = subparsers.add_parser("add-suppression")
    sp.add_argument("--repo", required=True)
    sp.add_argument("--ids", required=True)
    sp.add_argument("--reason", required=True)
    sp.add_argument("--approved-by", required=True)
    sp.add_argument("--run-id")
    sp.add_argument("--tool")
    sp.add_argument("--min-severity")
    sp.add_argument("--pipeline-repo")
    sp.add_argument("--exception-dir", default="exceptions")

    ls = subparsers.add_parser("list-suppressions")
    ls.add_argument("--repo", required=True)
    ls.add_argument("--tool")
    ls.add_argument("--exception-dir", default="exceptions")

    rp = subparsers.add_parser("remove-suppression")
    rp.add_argument("--repo", required=True)
    rp.add_argument("--ids", required=True)
    rp.add_argument("--reason", required=True)
    rp.add_argument("--approved-by", required=True)
    rp.add_argument("--tool")
    rp.add_argument("--pipeline-repo")
    rp.add_argument("--exception-dir", default="exceptions")

    args = parser.parse_args()
    
    if args.command == "list-issues": sys.exit(run_list(args))
    elif args.command == "add-suppression": sys.exit(run_add_suppression(args))
    elif args.command == "list-suppressions": sys.exit(run_list_suppressions(args))
    elif args.command == "remove-suppression": sys.exit(run_remove_suppression(args))

if __name__ == "__main__":
    main()
