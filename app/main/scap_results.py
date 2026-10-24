import json
import re
from pathlib import Path

from flask import current_app

# os_version / referte / certname must be a plain file name: no slashes, no leading dot
SAFE_NAME = re.compile(r"^\w[\w.-]*$")

# result per control on the server page, sorted fail first
STATUS_ORDER = {'fail': 0, 'error': 0, 'pass': 2, 'fixed': 2, 'pass (uitzondering)': 2}


def _read_json(*parts, default=None):
    """Read reports/<parts...>, or return default when the file is missing or unreadable."""
    if not all(part and SAFE_NAME.match(part) for part in parts):
        return default
    path = Path(current_app.config["SCAP_REPORT_DIR"]).joinpath(*parts[:-1], f"{parts[-1]}.json")
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def referte_sort_key(ref):
    """Sortable string for '1.1.2.6.1', so that 1.10 comes after 1.9."""
    return ".".join(p.zfill(4) if p.isdigit() else p for p in str(ref).split("."))


def lookup(os_version, ruleid):
    """SCAP results for one referte, as written by group_facts_by_osmajversion.py.

    Returns {"failed", "passed", "other", "rules": {id: {"titel", "failed", "passed", "other"}}}
    or None when there are no results for this os_version/referte.
    """
    if not (os_version and SAFE_NAME.match(os_version)):
        return None
    return _read_json(os_version, ruleid)


def summary(os_version):
    """Fail/pass totals for all refertes of one os_version: {referte: {"failed": n, "passed": n}}.

    Returns {} when there is no summary for this os_version.
    """
    return _read_json(f"{os_version}.summary" if os_version else None, default={})


def servers(os_version):
    """Servers of one os_version: [{certname, failed, passed, other, controls}], or []."""
    return _read_json(os_version, "servers", "_index", default=[])


def server(os_version, certname):
    """All control results of one server, sorted fail first, or None for an unknown server.

    Each row: {rule_id, referte, referte_sort, titel, schaal, resultaat, status, status_order, reason}
    where status is the resultaat, or 'pass (uitzondering)' for a fail with an accepted exception.
    """
    results = _read_json(os_version, "servers", certname)
    if results is None:
        return None
    rules = _read_json(os_version, "servers", "_rules", default={})

    rows = []
    for rule_id, result in results.items():
        rule = rules.get(rule_id, {})
        status = result.get("resultaat") or ""
        if status in ("fail", "error") and result.get("exception"):
            status = "pass (uitzondering)"
        rows.append({
            "rule_id": rule_id,
            "referte": rule.get("referte", ""),
            "referte_sort": referte_sort_key(rule.get("referte", "")),
            "titel": rule.get("titel", ""),
            "schaal": rule.get("schaal", ""),
            "resultaat": result.get("resultaat") or "",
            "status": status,
            "status_order": STATUS_ORDER.get(status, 1),
            "reason": result.get("reason", ""),
        })
    rows.sort(key=lambda row: (row["status_order"], row["referte_sort"]))
    return rows
