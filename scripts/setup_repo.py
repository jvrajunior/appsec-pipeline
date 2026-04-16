import argparse
import json
import os
import sys
import base64
import requests


PIPELINE_REPO = "jvrajunior/appsec-pipeline"
ORCHESTRATOR_REF = "main"

WORKFLOW_TEMPLATE = """\
name: Security Pipeline

on:
  pull_request:
    branches: ["**"]
    types: [opened, synchronize, reopened]
  workflow_dispatch:
  schedule:
    - cron: '0 8 * * *'

concurrency:
  group: security-${{{{ github.event.pull_request.number || github.ref }}}}
  cancel-in-progress: true

jobs:

  security-scan:
    uses: {pipeline_repo}/.github/workflows/appsec-pipeline.yml@{ref}
    secrets: inherit
    with:
      mobile: {mobile}
"""

RULESET_PAYLOAD = {
    "name": "Pipeline",
    "target": "branch",
    "enforcement": "active",
    "conditions": {
        "ref_name": {
            "include": ["~DEFAULT_BRANCH"],
            "exclude": [],
        }
    },
    "rules": [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        {
            "type": "pull_request",
            "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": False,
                "require_code_owner_review": False,
                "require_last_push_approval": False,
                "required_review_thread_resolution": False,
                "allowed_merge_methods": ["merge", "squash", "rebase"],
            },
        },
        {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": False,
                "do_not_enforce_on_create": False,
                "required_status_checks": [
                    {
                        "context": "security-scan / Security Gate",
                        "integration_id": 15368,
                    }
                ],
            },
        },
    ],
    "bypass_actors": [],
}


def get_token() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        # Try to get from gh CLI
        import subprocess
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True
        )
        if result.returncode == 0:
            token = result.stdout.strip()
    if not token:
        print("Error: GH_TOKEN not found. Set the environment variable or run 'gh auth login'.")
        sys.exit(1)
    return token


def github_api(method: str, path: str, token: str, payload: dict | None = None):
    url = f"https://api.github.com{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    response = requests.request(method, url, headers=headers, json=payload)
    return response


def get_existing_pipeline_ruleset_id(repo: str, token: str) -> int | None:
    """Returns the id of the existing 'Pipeline' ruleset, or None if not found."""
    resp = github_api("GET", f"/repos/{repo}/rulesets", token)
    resp.raise_for_status()
    existing = [r for r in resp.json() if r["name"] == "Pipeline"]
    return existing[0]["id"] if existing else None


def set_ruleset_enforcement(repo: str, ruleset_id: int, enforcement: str, token: str) -> None:
    resp = github_api(
        "PUT", f"/repos/{repo}/rulesets/{ruleset_id}", token,
        {**RULESET_PAYLOAD, "enforcement": enforcement},
    )
    resp.raise_for_status()


def apply_ruleset(repo: str, token: str) -> None:
    print(f"[ruleset] Checking existing rulesets in {repo}...")
    existing_id = get_existing_pipeline_ruleset_id(repo, token)

    if existing_id:
        print(f"[ruleset] Ruleset 'Pipeline' already exists (id={existing_id}). Updating...")
        resp = github_api("PUT", f"/repos/{repo}/rulesets/{existing_id}", token, RULESET_PAYLOAD)
    else:
        print("[ruleset] Creating ruleset 'Pipeline'...")
        resp = github_api("POST", f"/repos/{repo}/rulesets", token, RULESET_PAYLOAD)

    resp.raise_for_status()
    print(f"[ruleset] OK — id={resp.json()['id']}")


def get_default_branch(repo: str, token: str) -> str:
    resp = github_api("GET", f"/repos/{repo}", token)
    resp.raise_for_status()
    return resp.json()["default_branch"]


def apply_workflow(repo: str, mobile: bool, token: str) -> None:
    workflow_path = ".github/workflows/security-pipeline.yml"
    content = WORKFLOW_TEMPLATE.format(
        pipeline_repo=PIPELINE_REPO,
        ref=ORCHESTRATOR_REF,
        mobile=str(mobile).lower(),
    )
    encoded = base64.b64encode(content.encode()).decode()

    print(f"[workflow] Checking if {workflow_path} already exists in {repo}...")
    resp = github_api("GET", f"/repos/{repo}/contents/{workflow_path}", token)

    if resp.status_code == 200:
        file_data = resp.json()
        sha = file_data["sha"]
        # Decode existing content (GitHub returns it base64-encoded with newlines)
        existing_content = base64.b64decode(file_data["content"]).decode()
        if existing_content == content:
            print("[workflow] Content identical to current. No changes required.")
            return
        print("[workflow] File already exists with different content.")
        confirm = input("[workflow] Overwrite existing workflow? [y/N] ").strip().lower()
        if confirm not in ["y", "yes"]:
            print("[workflow] Update cancelled by user.")
            return
        payload = {
            "message": "[Auto] Update security pipeline workflow",
            "content": encoded,
            "sha": sha,
        }
    elif resp.status_code == 404:
        print("[workflow] File does not exist. Creating...")
        payload = {
            "message": "[Auto] Add security pipeline workflow",
            "content": encoded,
        }
    else:
        resp.raise_for_status()

    resp = github_api("PUT", f"/repos/{repo}/contents/{workflow_path}", token, payload)

    # If blocked by an existing ruleset, temporarily disable it and retry.
    if resp.status_code == 409:
        ruleset_id = get_existing_pipeline_ruleset_id(repo, token)
        if ruleset_id:
            print(f"[workflow] Commit blocked by ruleset (id={ruleset_id}). Temporarily disabling...")
            set_ruleset_enforcement(repo, ruleset_id, "disabled", token)
            try:
                resp = github_api("PUT", f"/repos/{repo}/contents/{workflow_path}", token, payload)
            finally:
                print(f"[workflow] Re-enabling ruleset (id={ruleset_id})...")
                set_ruleset_enforcement(repo, ruleset_id, "active", token)
        else:
            print(f"[workflow] Error {resp.status_code}: {resp.json().get('message', resp.text)}")

    if not resp.ok:
        print(f"[workflow] Error {resp.status_code}: {resp.json().get('message', resp.text)}")
        resp.raise_for_status()
    print(f"[workflow] OK — commit {resp.json()['commit']['sha'][:7]}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Configure ruleset and workflow for the AppSec Pipeline on a GitHub repository."
    )
    parser.add_argument("repo", help="Repository in owner/repo format")
    parser.add_argument(
        "--mobile",
        action="store_true",
        default=False,
        help="Enable mobile scanner (mobsfscan) in the workflow",
    )
    parser.add_argument(
        "--no-workflow",
        action="store_true",
        default=False,
        help="Skip creating/updating the workflow",
    )
    parser.add_argument(
        "--remove-ruleset",
        action="store_true",
        default=False,
        help="Remove the 'Pipeline' ruleset from the repository and exit",
    )
    args = parser.parse_args()

    if "/" not in args.repo:
        print("Error: repository must be in owner/repo format")
        sys.exit(1)

    token = get_token()

    if args.remove_ruleset:
        print(f"\nRemoving ruleset from: {args.repo}\n")
        ruleset_id = get_existing_pipeline_ruleset_id(args.repo, token)
        if ruleset_id:
            resp = github_api("DELETE", f"/repos/{args.repo}/rulesets/{ruleset_id}", token)
            resp.raise_for_status()
            print(f"[ruleset] Ruleset 'Pipeline' (id={ruleset_id}) removed.")
        else:
            print("[ruleset] No 'Pipeline' ruleset found.")
        print("\nDone.")
        return

    print(f"\nConfiguring repository: {args.repo}")
    print(f"Mobile:   {args.mobile}")
    print(f"Workflow: {'no' if args.no_workflow else 'yes'}\n")

    # The workflow is applied before the ruleset to avoid branch protection
    # blocking commits directly to the default branch.
    if not args.no_workflow:
        apply_workflow(args.repo, args.mobile, token)

    apply_ruleset(args.repo, token)

    print("\nDone.")


if __name__ == "__main__":
    main()
