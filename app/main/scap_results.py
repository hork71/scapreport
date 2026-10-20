import json
import re
from pathlib import Path

from flask import current_app

# os_version / referte must be a plain file name: no slashes, no leading dot
SAFE_NAME = re.compile(r"^\w[\w.-]*$")


def lookup(os_version, ruleid):
    """SCAP results for one referte, as written by group_facts_by_osmajversion.py.

    Returns {"failed", "passed", "other", "rules": {id: {"titel", "failed", "passed", "other"}}}
    or None when there are no results for this os_version/referte.
    """
    if not (os_version and ruleid and SAFE_NAME.match(os_version) and SAFE_NAME.match(ruleid)):
        return None

    path = Path(current_app.config["SCAP_REPORT_DIR"]) / os_version / f"{ruleid}.json"
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None
