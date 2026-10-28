from collections import defaultdict
from datetime import date
from pathlib import Path
import importlib.util
import json
import re
import shutil
import requests

import scap_history

requests.packages.urllib3.disable_warnings()

url = "https://puppetdb.example.com:8081/pdb/query/v4"

query = """
inventory[certname, timestamp, facts.openscap.resultaten, facts.operatingsystemmajrelease] {
  facts.openscap is not null and facts.operatingsystemmajrelease is not null and facts.operatingsystemmajrelease != '20.04'
}
"""

response = requests.get(
    url,
    params={'query': query},
    headers={'X-Authentication': 'removed'},
    timeout=30,
    verify=False,
)
response.raise_for_status()
rows = response.json()

by_os_release = defaultdict(list)
for row in rows:
    release = row["facts.operatingsystemmajrelease"]
    by_os_release[release].append({
        "certname": row["certname"],
        "openscap": row["facts.openscap.resultaten"],
        "timestamp": row.get("timestamp"),
    })

FAIL = {"fail", "error"}
PASS = {"pass", "fixed"}
NO_REF = "(no referte)"


def referte_key(ref):
    """Sort '1.1.2.6.1' numerically instead of as a string."""
    # (0, int) for numeric parts, (1, str) otherwise, so mixed refs stay comparable
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in str(ref).split("."))


def server_status(results):
    """Collapse all rule results for one server/referte into one status."""
    statuses = set()
    for r in results:
        res = r.get("resultaat")
        if res in FAIL and r.get("exception"):
            res = "pass"
        statuses.add(res)
    if statuses & FAIL:
        return "failed"
    if statuses <= PASS:
        return "passed"
    return "other"


def bucket_servers(per_server):
    """Split {certname: [rule results]} into sorted failed/passed/other lists."""
    buckets = {"failed": [], "passed": [], "other": []}
    for certname, results in per_server.items():
        buckets[server_status(results)].append(certname)
    return {k: sorted(v) for k, v in buckets.items()}


def group_by_referte(servers):
    # referte -> certname -> [rule results]
    per_ref = defaultdict(lambda: defaultdict(list))
    # referte -> rule id -> certname -> [rule results]
    per_rule = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    titles = defaultdict(dict)

    for server in servers:
        for r in server["openscap"] or []:
            ref = r.get("referte") or NO_REF
            rule_id = r.get("id", "?")
            per_ref[ref][server["certname"]].append(r)
            per_rule[ref][rule_id][server["certname"]].append(r)
            titles[ref][rule_id] = r.get("titel", "")

    out = {}
    for ref in sorted(per_ref, key=referte_key):
        out[ref] = {
            **bucket_servers(per_ref[ref]),
            "rules": {
                rule_id: {"titel": titles[ref][rule_id], **bucket_servers(per_server)}
                for rule_id, per_server in per_rule[ref].items()
            },
        }
    return out


def group_by_server(servers):
    """Per-server view of the results.

    Returns (index, rules, results):
      index   [{certname, failed, passed, other, controls}], counts per referte
      rules   {rule id: {referte, titel, schaal}}, shared by all servers
      results {certname: {rule id: {resultaat, exception, reason}}}
    """
    index, rules, results = [], {}, {}
    for server in servers:
        certname = server["certname"]
        per_ref = defaultdict(list)
        controls = {}
        for r in server["openscap"] or []:
            rule_id = r.get("id", "?")
            ref = r.get("referte") or NO_REF
            per_ref[ref].append(r)
            rules[rule_id] = {
                "referte": r.get("referte") or "",
                "titel": r.get("titel", ""),
                "schaal": r.get("schaal", ""),
            }
            controls[rule_id] = {
                "resultaat": r.get("resultaat"),
                "exception": bool(r.get("exception")),
                "reason": r.get("reason", ""),
            }

        # same rule as the referte totals: a referte fails when any of its controls fails
        counts = {"failed": 0, "passed": 0, "other": 0}
        for ref, ref_results in per_ref.items():
            if ref != NO_REF:
                counts[server_status(ref_results)] += 1
        index.append({"certname": certname, **counts, "controls": len(controls)})
        results[certname] = controls

    index.sort(key=lambda s: s["certname"])
    return index, rules, results


RELEASE_NAMES = {
    "8": "rh_8",
    "9": "rh_9",
    "22.04": "ub_22",
    "24.04": "ub_24",
    "15": "sl_15",
    "16": "sl_16",
}

# unmapped releases keep their original PuppetDB value
servers_by_name = {RELEASE_NAMES.get(release, release): servers
                   for release, servers in by_os_release.items()}
report = {
    RELEASE_NAMES.get(release, release): group_by_referte(servers)
    for release, servers in sorted(by_os_release.items(),
                                   key=lambda kv: RELEASE_NAMES.get(kv[0], kv[0]))
}

#print(json.dumps(by_os_release['8'], indent=2))
OUTPUT_DIR = Path(__file__).resolve().parent / "reports"
OUTPUT_DIR.mkdir(exist_ok=True)

# referte values that are safe to use as a file name (same rule as the Flask lookup)
SAFE_NAME = re.compile(r"^\w[\w.-]*$")


def load_cis_versions():
    """{os_version: cis_version} from the Flask app's tab list, so both use the same versions."""
    tabs_file = Path(__file__).resolve().parent / "app" / "main" / "tabs.py"
    spec = importlib.util.spec_from_file_location("baseline_tabs", tabs_file)
    tabs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tabs)
    return {tab["os_version"]: tab["cis_version"] for tab in tabs.TABS}


# history of totals and changes per control, see scap_history.py
HISTORY_DB = Path(__file__).resolve().parent / "scap_history.sqlite"
ARCHIVE_DIR = Path(__file__).resolve().parent / "history"
SCAN_DATE = date.today().isoformat()
CIS_VERSIONS = load_cis_versions()
history = scap_history.connect(HISTORY_DB)
history_rows = []

# layer 3: keep the raw response as audit evidence, before anything is derived from it
archive = scap_history.write_archive(ARCHIVE_DIR, SCAN_DATE, response.content)
print(f"archived {len(rows)} rows to {ARCHIVE_DIR / archive['file']} ({archive['file_bytes']} bytes)")


def write_json(path, data, compact=False):
    if compact:
        path.write_text(json.dumps(data, separators=(",", ":")) + "\n")
    else:
        path.write_text(json.dumps(data, indent=2) + "\n")


for name, data in report.items():
    out_file = OUTPUT_DIR / f"{name}.json"
    # write to a temp file and rename, so the Flask app never reads a half-written file
    tmp_file = out_file.with_suffix(".json.tmp")
    write_json(tmp_file, data)
    tmp_file.replace(out_file)
    print(f"wrote {out_file}")

    # fail/pass totals per referte for the homepage tables: reports/<os>.summary.json
    summary_file = OUTPUT_DIR / f"{name}.summary.json"
    tmp_file = summary_file.with_suffix(".json.tmp")
    write_json(tmp_file, {
        ref: {"failed": len(entry["failed"]), "passed": len(entry["passed"])}
        for ref, entry in data.items()
    })
    tmp_file.replace(summary_file)
    print(f"wrote {summary_file}")

    # one small file per referte for the Flask benchmark page: reports/<os>/<referte>.json
    # built in a temp dir and swapped in, so stale refertes disappear as well
    out_dir = OUTPUT_DIR / name
    tmp_dir = OUTPUT_DIR / f".{name}.tmp"
    old_dir = OUTPUT_DIR / f".{name}.old"
    for d in (tmp_dir, old_dir):
        shutil.rmtree(d, ignore_errors=True)
    tmp_dir.mkdir()
    written = 0
    for ref, entry in data.items():
        if SAFE_NAME.match(ref):
            write_json(tmp_dir / f"{ref}.json", entry)
            written += 1

    # per-server results for the server pages: reports/<os>/servers/
    #   _index.json      server list with fail/pass/other counts
    #   _rules.json      referte, titel and schaal per control
    #   <certname>.json  that server's result per control
    index, rules, results = group_by_server(servers_by_name[name])
    index = [entry for entry in index if SAFE_NAME.match(entry["certname"])]
    servers_dir = tmp_dir / "servers"
    servers_dir.mkdir()
    write_json(servers_dir / "_index.json", index)
    write_json(servers_dir / "_rules.json", rules)
    for entry in index:
        write_json(servers_dir / f"{entry['certname']}.json", results[entry["certname"]], compact=True)

    timestamps = {server["certname"]: server["timestamp"] for server in servers_by_name[name]}
    history_rows.append((name, data, index, rules, results, timestamps))

    if out_dir.exists():
        out_dir.rename(old_dir)
    tmp_dir.rename(out_dir)
    shutil.rmtree(old_dir, ignore_errors=True)
    print(f"wrote {written} referte files and {len(index)} server files to {out_dir}")

# all OS versions in one transaction: a failed run leaves the history as it was
with history:
    for name, data, index, rules, results, timestamps in history_rows:
        changes = scap_history.record_os(history, SCAN_DATE, name, CIS_VERSIONS.get(name),
                                         data, index, rules, results, timestamps)
        print(f"history {name}: {len(index)} servers, {changes} changes")
    scap_history.record_archive(history, SCAN_DATE, archive, len(rows))
    cutoff, old_files = scap_history.apply_retention(history, SCAN_DATE)
history.close()
# delete expired archive files only after their rows are gone from the database
scap_history.remove_files(ARCHIVE_DIR, old_files)
print(f"history in {HISTORY_DB}, kept from {cutoff}, removed {len(old_files)} old archive file(s)")
