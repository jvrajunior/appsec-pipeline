import pathlib
import yaml

EXCEPTION_FILE = "exception.yml"

def load_exceptions(path: pathlib.Path) -> dict:
    if not path.exists():
        return {"suppressions": []}
    raw = path.read_text()
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        data = {}
    if not isinstance(data.get("suppressions"), list):
        data["suppressions"] = []
    return data

def save_exceptions(path: pathlib.Path, data: dict) -> None:
    body = yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)
    path.write_text(body)

def list_active_suppressions(exception_path: pathlib.Path, repository: str | None = None, tool: str | None = None) -> list:
    """Return suppressions filtered by optional repository and tool."""
    data = load_exceptions(exception_path)
    return [
        e
        for e in data.get("suppressions", [])
        if isinstance(e, dict)
        and (repository is None or e.get("repository") == repository)
        and (tool is None or e.get("tool") == tool)
    ]

def is_suppressed(issue_id: str, suppressions: list) -> bool:
    return any(e.get("id") == issue_id for e in suppressions)

def build_suppression_entry(issue: dict, repository: str, reason: str, approved_by: str, approved_on: str) -> dict:
    return {
        "id": issue["id"],
        "tool": issue["tool"],
        "repository": repository,
        "reason": reason,
        "approved_by": approved_by,
        "approved_on": approved_on,
    }

def append_suppression(exception_path: pathlib.Path, entry: dict) -> bool:
    data = load_exceptions(exception_path)
    existing_keys = {(e.get("id"), e.get("tool"), e.get("repository")) for e in data["suppressions"] if isinstance(e, dict)}
    key = (entry.get("id"), entry.get("tool"), entry.get("repository"))
    if key in existing_keys:
        return False
    data["suppressions"].append(entry)
    save_exceptions(exception_path, data)
    return True

def remove_suppressions_by_ids(exception_path: pathlib.Path, ids: list[str], repository: str, tool: str | None = None):
    data = load_exceptions(exception_path)
    scoped = []
    for idx, e in enumerate(data.get("suppressions", [])):
        if isinstance(e, dict) and e.get("repository") == repository and (not tool or e.get("tool") == tool):
            scoped.append((idx, e, e.get("id")))

    id_map = {}
    for idx, e, fid in scoped:
        id_map.setdefault(fid, []).append((idx, e))
    invalid = sorted(set(ids) - set(id_map.keys()))
    ambiguous = sorted([fid for fid in ids if len(id_map.get(fid, [])) > 1])

    if invalid or ambiguous:
        return [], len(scoped), invalid, ambiguous
    indices_to_remove = sorted([id_map[fid][0][0] for fid in ids], reverse=True)
    removed = [data["suppressions"].pop(idx) for idx in indices_to_remove]

    if removed:
        save_exceptions(exception_path, data)
    return removed, len(scoped), [], []
