"""Read-only access to the history of the nightly SCAP results (scap_history.sqlite).

The nightly script group_facts_by_osmajversion.py writes the database (see scap_history.py next
to it); the web app only reads it. Every function returns empty results when the database or a
table is missing, so the pages keep working without history.
"""
from contextlib import closing
from datetime import date, timedelta
from pathlib import Path
import sqlite3

from flask import current_app

TREND_DAYS = 90        # trend lines on the benchmark card and the server page
CHANGE_DAYS = 30       # changes on the benchmark card
COMPARE_DAYS = 7       # "x days ago -> now" on the benchmark card
STALE_FACTS_DAYS = 2   # facts this much older than the scan get a warning
MAX_REFERTE_CHANGES = 200
MAX_SERVER_CHANGES = 2000

STATUS_LABELS = {None: "nieuw", "removed": "verwijderd"}


def nl_date(value):
    """'2026-10-29' or '2026-10-29T05:00:00Z' -> '29-10-2026'."""
    if not value:
        return ""
    try:
        return date.fromisoformat(str(value)[:10]).strftime("%d-%m-%Y")
    except ValueError:
        return str(value)


def status_label(status):
    return STATUS_LABELS.get(status, status)


def _from_date(days):
    return (date.today() - timedelta(days=days)).isoformat()


def _query(sql, params):
    path = Path(current_app.config["SCAP_HISTORY_DB"])
    if not path.exists():
        return []
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        with closing(conn):
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(sql, params)]
    except sqlite3.Error as e:
        current_app.logger.warning("SCAP history %s: %s", path, e)
        return []


def _changes(rows):
    for row in rows:
        row["datum"] = nl_date(row["scan_date"])
        row["old"] = status_label(row.pop("old_status"))
        row["new"] = status_label(row.pop("new_status"))
    return rows


def _trend_points(rows):
    return [{"date": nl_date(row["scan_date"]), "value": row["failed"]} for row in rows]


def referte(os_version, cis_version, ref):
    """History of one referte for the benchmark card, or None when there is none.

    {trend: [{date, value}], now: row, before: row or None, changes: [...], truncated: bool}
    where a row is {scan_date, failed, passed, other} and a change is
    {scan_date, datum, certname, rule_id, old, new}.
    """
    trend = _query(
        "SELECT scan_date, failed, passed, other FROM scap_referte_daily"
        " WHERE os_version = ? AND referte = ? AND cis_version IS ? AND scan_date >= ?"
        " ORDER BY scan_date",
        (os_version, ref, cis_version, _from_date(TREND_DAYS)))
    changes = _query(
        "SELECT scan_date, certname, rule_id, old_status, new_status FROM scap_change"
        " WHERE os_version = ? AND referte = ? AND cis_version IS ? AND scan_date >= ?"
        " ORDER BY scan_date DESC, certname, rule_id LIMIT ?",
        (os_version, ref, cis_version, _from_date(CHANGE_DAYS), MAX_REFERTE_CHANGES + 1))
    if not trend:
        return None

    now = trend[-1]
    compare_date = (date.fromisoformat(now["scan_date"]) - timedelta(days=COMPARE_DAYS)).isoformat()
    before = next((row for row in reversed(trend) if row["scan_date"] <= compare_date), None)
    return {
        "days": TREND_DAYS,
        "change_days": CHANGE_DAYS,
        "trend": _trend_points(trend),
        "now": now,
        "before": before,
        "changes": _changes(changes[:MAX_REFERTE_CHANGES]),
        "truncated": len(changes) > MAX_REFERTE_CHANGES,
    }


def server(os_version, cis_version, certname):
    """History of one server for the server page.

    {trend: [{date, value}], since: {rule id: date}, start: date or None, changes: [...],
     truncated: bool, last_scan: date or None, stale_facts: timestamp or None}
    start is the first scan of this os_version: a control whose since is on or before it
    already had its status when the history started.
    """
    trend = _query(
        "SELECT scan_date, failed, facts_timestamp FROM scap_server_daily"
        " WHERE os_version = ? AND certname = ? AND cis_version IS ? AND scan_date >= ?"
        " ORDER BY scan_date",
        (os_version, certname, cis_version, _from_date(TREND_DAYS)))
    since = {row["rule_id"]: row["since"] for row in _query(
        "SELECT rule_id, since FROM scap_state WHERE os_version = ? AND certname = ?",
        (os_version, certname))}
    first = _query(
        "SELECT scan_date FROM scap_server_daily WHERE os_version = ? ORDER BY scan_date LIMIT 1",
        (os_version,))
    changes = _query(
        "SELECT scan_date, rule_id, referte, old_status, new_status FROM scap_change"
        " WHERE os_version = ? AND certname = ? AND cis_version IS ? AND scan_date >= ?"
        " ORDER BY scan_date DESC, rule_id LIMIT ?",
        (os_version, certname, cis_version, _from_date(TREND_DAYS), MAX_SERVER_CHANGES + 1))

    last_scan, stale_facts = None, None
    if trend:
        last_scan = trend[-1]["scan_date"]
        facts = trend[-1]["facts_timestamp"]
        try:
            age = date.fromisoformat(last_scan) - date.fromisoformat(str(facts)[:10])
            if age.days > STALE_FACTS_DAYS:
                stale_facts = facts
        except ValueError:
            pass

    return {
        "days": TREND_DAYS,
        "trend": _trend_points(trend),
        "since": since,
        "start": first[0]["scan_date"] if first else None,
        "changes": _changes(changes[:MAX_SERVER_CHANGES]),
        "truncated": len(changes) > MAX_SERVER_CHANGES,
        "last_scan": last_scan,
        "stale_facts": stale_facts,
    }
