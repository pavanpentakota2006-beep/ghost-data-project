"""Fail-soft dataset schema check: reports missing/unrecognised columns before a run."""
from pathlib import Path
from .util import read_csv
from .config import ALIASES

EXPECTED = {
    "deletion_requests.csv": ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"],
    "user_identities.csv": ["user_id", "email"],
    "user_audit_log.csv": ["audit_id", "user_id", "field", "old_value", "new_value", "ts"],
    "system_activity.csv": ["activity_id", "ts", "system_id", "resource_id", "operation"],
    "deletion_rules.csv": ["category", "rule_action"],
    "evidence_files.csv": ["file_id", "path"],
}


def check_dataset(ds: Path):
    """Return a list of human-readable warnings (empty list means the schema looks as expected)."""
    warnings = []
    for fname, keys in EXPECTED.items():
        p = ds / fname
        if not p.exists():
            warnings.append(f"missing file: {fname}")
            continue
        rows = read_csv(p)
        if not rows:
            warnings.append(f"{fname}: no rows")
            continue
        cols = set(rows[0].keys())
        for k in keys:
            if not (set(ALIASES.get(k, [k])) & cols):
                warnings.append(f"{fname}: no column for '{k}' (looked for {ALIASES.get(k, [k])}; found {sorted(cols)}). Add an alias in audit/config.py")
    return warnings
