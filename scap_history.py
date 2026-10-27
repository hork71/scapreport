"""History of the nightly SCAP results, kept in a separate SQLite file.

Layer 1, daily totals for trends:
  scap_referte_daily  fail/pass/other servers per referte per day
  scap_server_daily   fail/pass/other refertes per server per day, plus the PuppetDB facts timestamp

Layer 2, changes per control for "since when?":
  scap_state          current status per server/control and the date it got that status
  scap_change         every status change: old_status -> new_status on scan_date
                      (old_status NULL: new control or server; new_status 'removed': gone)

Only group_facts_by_osmajversion.py writes this database, once a night. Rerunning on the same
day is safe: totals are replaced and changes are only logged against the stored state.
"""
from datetime import date, timedelta
import sqlite3

RETENTION_DAYS = 365

FAIL = {"fail", "error"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS scap_referte_daily (
    scan_date   TEXT NOT NULL,
    os_version  TEXT NOT NULL,
    cis_version TEXT,
    referte     TEXT NOT NULL,
    failed      INTEGER NOT NULL,
    passed      INTEGER NOT NULL,
    other       INTEGER NOT NULL,
    PRIMARY KEY (scan_date, os_version, referte)
);
CREATE TABLE IF NOT EXISTS scap_server_daily (
    scan_date       TEXT NOT NULL,
    os_version      TEXT NOT NULL,
    cis_version     TEXT,
    certname        TEXT NOT NULL,
    failed          INTEGER NOT NULL,
    passed          INTEGER NOT NULL,
    other           INTEGER NOT NULL,
    controls        INTEGER NOT NULL,
    facts_timestamp TEXT,
    PRIMARY KEY (scan_date, os_version, certname)
);
CREATE TABLE IF NOT EXISTS scap_state (
    os_version TEXT NOT NULL,
    certname   TEXT NOT NULL,
    rule_id    TEXT NOT NULL,
    status     TEXT NOT NULL,
    since      TEXT NOT NULL,
    PRIMARY KEY (os_version, certname, rule_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS scap_change (
    id          INTEGER PRIMARY KEY,
    scan_date   TEXT NOT NULL,
    os_version  TEXT NOT NULL,
    cis_version TEXT,
    certname    TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    referte     TEXT,
    old_status  TEXT,
    new_status  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scap_change_control ON scap_change (os_version, certname, rule_id, scan_date);
CREATE INDEX IF NOT EXISTS scap_change_date ON scap_change (scan_date);
"""


def control_status(control):
    """Status of one control, the same way the server page shows it."""
    status = control.get("resultaat") or ""
    if status in FAIL and control.get("exception"):
        return "pass (uitzondering)"
    return status


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    return conn


def record_os(conn, scan_date, os_version, cis_version, referte_data, index, rules, results, timestamps):
    """Store one OS version's results of this run. Call inside one transaction for the whole run.

    referte_data  {referte: {failed: [...], passed: [...], other: [...], ...}}, from group_by_referte
    index         [{certname, failed, passed, other, controls}], from group_by_server
    rules         {rule id: {referte, ...}}, from group_by_server
    results       {certname: {rule id: {resultaat, exception, reason}}}, from group_by_server
    timestamps    {certname: PuppetDB facts timestamp}
    Returns the number of changes logged.
    """
    # layer 1: daily totals, replaced on a rerun of the same day
    conn.execute("DELETE FROM scap_referte_daily WHERE scan_date = ? AND os_version = ?", (scan_date, os_version))
    conn.executemany(
        "INSERT INTO scap_referte_daily VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(scan_date, os_version, cis_version, ref,
          len(entry["failed"]), len(entry["passed"]), len(entry["other"]))
         for ref, entry in referte_data.items() if ref != "(no referte)"],
    )
    conn.execute("DELETE FROM scap_server_daily WHERE scan_date = ? AND os_version = ?", (scan_date, os_version))
    conn.executemany(
        "INSERT INTO scap_server_daily VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [(scan_date, os_version, cis_version, s["certname"], s["failed"], s["passed"], s["other"],
          s["controls"], timestamps.get(s["certname"]))
         for s in index],
    )

    # layer 2: compare with the stored state
    previous = {
        (certname, rule_id): status
        for certname, rule_id, status in conn.execute(
            "SELECT certname, rule_id, status FROM scap_state WHERE os_version = ?", (os_version,))
    }
    current = {
        (certname, rule_id): control_status(control)
        for certname, controls in results.items()
        for rule_id, control in controls.items()
    }

    if not previous:
        # first run for this os_version: store the starting point, no changes to log
        conn.executemany(
            "INSERT INTO scap_state VALUES (?, ?, ?, ?, ?)",
            [(os_version, certname, rule_id, status, scan_date) for (certname, rule_id), status in current.items()],
        )
        return 0

    changes, upserts, removed = [], [], []
    for key, status in current.items():
        old = previous.get(key)
        if old != status:
            changes.append((key, old, status))
            upserts.append((os_version, *key, status, scan_date))
    for key, old in previous.items():
        if key not in current:
            changes.append((key, old, "removed"))
            removed.append((os_version, *key))

    conn.executemany(
        "INSERT INTO scap_change (scan_date, os_version, cis_version, certname, rule_id, referte, old_status, new_status)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(scan_date, os_version, cis_version, certname, rule_id, rules.get(rule_id, {}).get("referte") or None, old, new)
         for (certname, rule_id), old, new in changes],
    )
    conn.executemany("INSERT OR REPLACE INTO scap_state VALUES (?, ?, ?, ?, ?)", upserts)
    conn.executemany("DELETE FROM scap_state WHERE os_version = ? AND certname = ? AND rule_id = ?", removed)
    return len(changes)


def apply_retention(conn, scan_date, days=RETENTION_DAYS):
    """Delete history older than the retention period. scap_state is the current state and stays."""
    cutoff = (date.fromisoformat(scan_date) - timedelta(days=days)).isoformat()
    for table in ("scap_referte_daily", "scap_server_daily", "scap_change"):
        conn.execute(f"DELETE FROM {table} WHERE scan_date < ?", (cutoff,))
    return cutoff
