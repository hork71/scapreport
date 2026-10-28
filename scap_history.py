"""History of the nightly SCAP results, kept in a separate SQLite file.

Layer 1, daily totals for trends:
  scap_referte_daily  fail/pass/other servers per referte per day
  scap_server_daily   fail/pass/other refertes per server per day, plus the PuppetDB facts timestamp

Layer 2, changes per control for "since when?":
  scap_state          current status per server/control and the date it got that status
  scap_change         every status change: old_status -> new_status on scan_date
                      (old_status NULL: new control or server; new_status 'removed': gone)

Layer 3, audit evidence:
  history/<scan_date>.json.gz   the raw PuppetDB response of that night, exactly as received
  scap_archive                  per file: SHA-256 of the raw response and of the .gz file,
                                number of rows, sizes and when it was fetched
  python3 scap_history.py verify   checks every archived file against its checksums

Only group_facts_by_osmajversion.py writes this database, once a night. Rerunning on the same
day is safe: totals are replaced and changes are only logged against the stored state.
"""
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import gzip
import hashlib
import io
import sqlite3
import sys

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
CREATE TABLE IF NOT EXISTS scap_archive (
    scan_date   TEXT PRIMARY KEY,
    file        TEXT NOT NULL,
    raw_sha256  TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    rows        INTEGER NOT NULL,
    raw_bytes   INTEGER NOT NULL,
    file_bytes  INTEGER NOT NULL,
    fetched_at  TEXT NOT NULL
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


def write_archive(archive_dir, scan_date, raw):
    """Write the raw PuppetDB response to <archive_dir>/<scan_date>.json.gz.

    The gzip header has no time or file name, so the same response always gives the same file.
    A rerun on the same day replaces that day's file. Returns the values for record_archive.
    """
    archive_dir = Path(archive_dir)
    archive_dir.mkdir(exist_ok=True)
    name = f"{scan_date}.json.gz"
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=buffer, mtime=0) as gz:
        gz.write(raw)
    packed = buffer.getvalue()
    tmp_file = archive_dir / f".{name}.tmp"
    tmp_file.write_bytes(packed)
    tmp_file.replace(archive_dir / name)
    return {
        "file": name,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "file_sha256": hashlib.sha256(packed).hexdigest(),
        "raw_bytes": len(raw),
        "file_bytes": len(packed),
    }


def record_archive(conn, scan_date, archive, rows, fetched_at=None):
    """Store the checksums of the file from write_archive. Call inside the run's transaction."""
    fetched_at = fetched_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        "INSERT OR REPLACE INTO scap_archive VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_date, archive["file"], archive["raw_sha256"], archive["file_sha256"],
         rows, archive["raw_bytes"], archive["file_bytes"], fetched_at),
    )


def apply_retention(conn, scan_date, days=RETENTION_DAYS):
    """Delete history older than the retention period. scap_state is the current state and stays.

    Archive rows are deleted here as well; the files they name are returned, so they can be
    removed with remove_files once this transaction is committed.
    """
    cutoff = (date.fromisoformat(scan_date) - timedelta(days=days)).isoformat()
    for table in ("scap_referte_daily", "scap_server_daily", "scap_change"):
        conn.execute(f"DELETE FROM {table} WHERE scan_date < ?", (cutoff,))
    old_files = [file for (file,) in conn.execute(
        "SELECT file FROM scap_archive WHERE scan_date < ?", (cutoff,))]
    conn.execute("DELETE FROM scap_archive WHERE scan_date < ?", (cutoff,))
    return cutoff, old_files


def remove_files(archive_dir, files):
    for file in files:
        try:
            (Path(archive_dir) / file).unlink()
        except FileNotFoundError:
            pass


def verify(conn, archive_dir):
    """Check every archived file against its stored checksums. Returns the number of problems."""
    problems = 0
    for scan_date, file, raw_sha256, file_sha256, rows in conn.execute(
            "SELECT scan_date, file, raw_sha256, file_sha256, rows FROM scap_archive ORDER BY scan_date"):
        path = Path(archive_dir) / file
        if not path.exists():
            result = "MISSING"
        else:
            packed = path.read_bytes()
            if hashlib.sha256(packed).hexdigest() != file_sha256:
                result = "FILE CHECKSUM WRONG"
            elif hashlib.sha256(gzip.decompress(packed)).hexdigest() != raw_sha256:
                result = "CONTENT CHECKSUM WRONG"
            else:
                result = "ok"
        problems += result != "ok"
        print(f"{scan_date}  {file}  {rows} rows  {result}")
    return problems


if __name__ == "__main__":
    # python3 scap_history.py verify [scap_history.sqlite] [history dir]
    if sys.argv[1:2] != ["verify"]:
        sys.exit("usage: python3 scap_history.py verify [db file] [archive dir]")
    here = Path(__file__).resolve().parent
    db_file = Path(sys.argv[2]) if len(sys.argv) > 2 else here / "scap_history.sqlite"
    archive_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else here / "history"
    if not db_file.exists():
        sys.exit(f"{db_file} not found")
    conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    problems = verify(conn, archive_dir)
    conn.close()
    print("all files ok" if not problems else f"{problems} problem(s)")
    sys.exit(1 if problems else 0)
