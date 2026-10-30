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

TREND_DAYS = 90        # trend lines on the benchmark card and the server page, default on the Historie page
PERIODS = (30, 90, 365)  # periods to choose from on the Historie page
LIST_DAYS = 7          # default date range of the changes table on the Historie page
MAX_LIST_CHANGES = 20000
MAX_MOVERS = 10
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


def _iter_query(sql, params):
    """Rows as dicts, one at a time, so a large CSV export does not have to fit in memory."""
    path = Path(current_app.config["SCAP_HISTORY_DB"])
    if not path.exists():
        return
    logger = current_app.logger
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        with closing(conn):
            conn.row_factory = sqlite3.Row
            for row in conn.execute(sql, params):
                yield dict(row)
    except sqlite3.Error as e:
        logger.warning("SCAP history %s: %s", path, e)


def _query(sql, params):
    return list(_iter_query(sql, params))


def _change(row):
    row["datum"] = nl_date(row["scan_date"])
    row["old"] = status_label(row.pop("old_status"))
    row["new"] = status_label(row.pop("new_status"))
    return row


def _changes(rows):
    return [_change(row) for row in rows]


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


def os_totals(os_version, cis_version, days):
    """Trend of one os_version for the Historie page.

    {days, points: [{scan_date, date, servers, avg_failed, pass_pct}], worse: [...], better: [...]}
      servers     servers in the report that day
      avg_failed  failing refertes per server, over the servers with results
      pass_pct    passed / (passed + failed) of all referte results, "other" left out
    worse/better: the refertes whose number of failing servers rose/fell the most between the
    first and the last day of the period: [{referte, before, now, delta}]
    """
    since = _from_date(days)
    servers = {row["scan_date"]: row for row in _query(
        "SELECT scan_date, COUNT(*) AS servers, AVG(CASE WHEN controls > 0 THEN failed END) AS avg_failed"
        " FROM scap_server_daily WHERE os_version = ? AND cis_version IS ? AND scan_date >= ?"
        " GROUP BY scan_date",
        (os_version, cis_version, since))}
    refertes = {row["scan_date"]: row for row in _query(
        "SELECT scan_date, SUM(passed) AS passed, SUM(failed) AS failed"
        " FROM scap_referte_daily WHERE os_version = ? AND cis_version IS ? AND scan_date >= ?"
        " GROUP BY scan_date",
        (os_version, cis_version, since))}

    points = []
    for scan_date in sorted(set(servers) | set(refertes)):
        srv, ref = servers.get(scan_date, {}), refertes.get(scan_date, {})
        judged = (ref.get("passed") or 0) + (ref.get("failed") or 0)
        avg_failed = srv.get("avg_failed")
        points.append({
            "scan_date": scan_date,
            "date": nl_date(scan_date),
            "servers": srv.get("servers", 0),
            "avg_failed": round(avg_failed, 1) if avg_failed is not None else None,
            "pass_pct": round(100 * ref["passed"] / judged, 1) if judged else None,
        })

    worse, better = [], []
    if len(points) > 1:
        first, last = points[0]["scan_date"], points[-1]["scan_date"]
        failed = {}
        for row in _query(
                "SELECT scan_date, referte, failed FROM scap_referte_daily"
                " WHERE os_version = ? AND cis_version IS ? AND scan_date IN (?, ?)",
                (os_version, cis_version, first, last)):
            failed.setdefault(row["referte"], {})[row["scan_date"]] = row["failed"]
        # only refertes measured on both days
        moves = [{"referte": ref, "before": by_date[first], "now": by_date[last],
                  "delta": by_date[last] - by_date[first]}
                 for ref, by_date in failed.items() if first in by_date and last in by_date]
        worse = sorted((m for m in moves if m["delta"] > 0), key=lambda m: -m["delta"])[:MAX_MOVERS]
        better = sorted((m for m in moves if m["delta"] < 0), key=lambda m: m["delta"])[:MAX_MOVERS]

    return {"days": days, "points": points, "worse": worse, "better": better}


def os_changes(os_version, cis_version, date_from, date_to, include_new=False, limit=None):
    """Changes of one os_version from date_from up to and including date_to, newest first.

    Yields {scan_date, datum, certname, referte, rule_id, old, new}. Without include_new,
    controls of new servers and of servers that left PuppetDB are left out.
    """
    sql = ("SELECT scan_date, certname, referte, rule_id, old_status, new_status FROM scap_change"
           " WHERE os_version = ? AND cis_version IS ? AND scan_date BETWEEN ? AND ?")
    params = [os_version, cis_version, date_from, date_to]
    if not include_new:
        sql += " AND old_status IS NOT NULL AND new_status != 'removed'"
    sql += " ORDER BY scan_date DESC, certname, rule_id"
    if limit:
        sql += " LIMIT ?"
        params.append(limit)
    for row in _iter_query(sql, params):
        yield _change(row)
