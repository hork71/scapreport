from collections import defaultdict
from pathlib import Path
import json
import re
import shutil
import requests

requests.packages.urllib3.disable_warnings()

url = "https://puppetdb.example.com:8081/pdb/query/v4"

query = """
inventory[certname, facts.openscap.resultaten, facts.operatingsystemmajrelease] {
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


RELEASE_NAMES = {
    "8": "rh_8",
    "9": "rh_9",
    "22.04": "ub_22",
    "24.04": "ub_24",
    "15": "sl_15",
    "16": "sl_16",
}

# unmapped releases keep their original PuppetDB value
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


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


for name, data in report.items():
    out_file = OUTPUT_DIR / f"{name}.json"
    # write to a temp file and rename, so the Flask app never reads a half-written file
    tmp_file = out_file.with_suffix(".json.tmp")
    write_json(tmp_file, data)
    tmp_file.replace(out_file)
    print(f"wrote {out_file}")

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
    if out_dir.exists():
        out_dir.rename(old_dir)
    tmp_dir.rename(out_dir)
    shutil.rmtree(old_dir, ignore_errors=True)
    print(f"wrote {written} referte files to {out_dir}")
