import csv, json, re, base64, zlib, sqlite3
from pathlib import Path
from collections import defaultdict
from datetime import datetime

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

DELETE_STEMS = [
    "delet", "eras", "remov", "forget", "close", "wipe", "purg", "suppr", "effac", "elimin",
    "borr", "lösch", "losch", "entfern", "cancell", "exclu", "apag", "verwijder",
    "削除", "消去", "삭제", "删除", "刪除", "удал", "usuń", "usun", "sil"
]
NON_DELETE_PHRASES = [
    "do not delete", "don't delete", "do not remove", "don't remove", "keep my account",
    "copy of my data", "access my profile", "resetting the login", "marketing lists only",
    "newsletter", "last year's invoices", "copy of the information", "export my", "download my"
]

def requests_deletion(text):
    t = (text or "").lower()
    for nd in NON_DELETE_PHRASES:
        if nd in t:
            return False
    return any(s in t for s in DELETE_STEMS)

dataset_dir = Path("dataset")
users_csv = list(csv.DictReader(open(dataset_dir / "user_identities.csv", encoding="utf-8-sig")))
users = {r["user_id"]: r for r in users_csv}
audit_csv = list(csv.DictReader(open(dataset_dir / "user_audit_log.csv", encoding="utf-8-sig")))
manifest = {r["file_id"]: r for r in csv.DictReader(open(dataset_dir / "evidence_files.csv", encoding="utf-8-sig"))}
system_activity = list(csv.DictReader(open(dataset_dir / "system_activity.csv", encoding="utf-8-sig")))

def get_user_identifiers(email, audit_at):
    e = email.strip().lower()
    uid = None
    for r in users_csv:
        if r["email"].strip().lower() == e:
            uid = r["user_id"]
            break
    if not uid:
        for r in audit_csv:
            if r["event_time"] <= audit_at:
                if r["field_name"] == "email" and e in (r["old_value"].strip().lower(), r["new_value"].strip().lower()):
                    uid = r["user_id"]
                    break
    if not uid:
        return None, set()
    
    tokens = {uid.lower(), uid}
    u = users.get(uid, {})
    for k in ["email", "phone", "email_hash", "name"]:
        v = u.get(k)
        if v:
            tokens.add(v.strip().lower())
            tokens.add(v.strip())
            
    for r in audit_csv:
        if r["user_id"] == uid and r["event_time"] <= audit_at:
            for v in [r["old_value"], r["new_value"]]:
                if v:
                    tokens.add(v.strip().lower())
                    tokens.add(v.strip())
    return uid, tokens

print("Loaded metadata.")
