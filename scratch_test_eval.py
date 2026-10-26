import csv, json, re, base64, zlib, sqlite3
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

# 1. Canonical system mapping
PREFIX_TO_SYSTEM = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "data": "integration_service",
    "backup": "backup_service",
    "audit": "security_service",
    "tombstone": "identity_service",
}

def get_system(resource_id):
    pfx = resource_id.split('_')[0]
    return PREFIX_TO_SYSTEM.get(pfx, pfx)

PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
OPS = [
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
]
OP_INDEX = {op: i for i, (_, op, _) in enumerate(OPS)}
OP_META = {op: (ph, st) for ph, op, st in OPS}

def make_step(operation, system_id, resource_id, evidence_id=""):
    phase, state = OP_META[operation]
    return {"phase": phase, "system_id": system_id, "resource_id": resource_id,
            "operation": operation, "state": state, "evidence_id": evidence_id or ""}

def order_and_number(steps):
    seen, uniq = set(), []
    for s in steps:
        k = (s["operation"], s["system_id"], s["resource_id"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    uniq.sort(key=lambda s: (PHASES.index(s["phase"]), OP_INDEX[s["operation"]], s["system_id"], s["resource_id"]))
    out = []
    for i, s in enumerate(uniq, 1):
        d = {"step_no": i}
        d.update(s)
        out.append(d)
    return out

# Load dataset metadata
dataset_dir = Path("dataset")
users_csv = list(csv.DictReader(open(dataset_dir / "user_identities.csv", encoding="utf-8-sig")))
users = {r["user_id"]: r for r in users_csv}
audit_csv = list(csv.DictReader(open(dataset_dir / "user_audit_log.csv", encoding="utf-8-sig")))
manifest = {r["file_id"]: r for r in csv.DictReader(open(dataset_dir / "evidence_files.csv", encoding="utf-8-sig"))}
system_activity = list(csv.DictReader(open(dataset_dir / "system_activity.csv", encoding="utf-8-sig")))

print(f"Loaded {len(users)} users, {len(audit_csv)} audit rows, {len(manifest)} evidence files.")
