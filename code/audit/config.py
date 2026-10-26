"""Configuration, schema aliases, and canonical mappings for Ghost Data audit agent."""

# Canonical system mapping by resource prefix
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
    pfx = str(resource_id).split('_')[0]
    return PREFIX_TO_SYSTEM.get(pfx, pfx)

# Contract phase, operation, and state order (problem_statement §6.3, §6.4)
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

# Schema aliases so loaders tolerate small column name differences
ALIASES = {
    "user_id": ["user_id", "uid", "subject_id"],
    "name": ["name", "full_name"],
    "email": ["email", "email_address"],
    "phone": ["phone", "phone_number", "mobile"],
    "email_hash": ["email_hash", "email_sha256", "hash"],
    "field": ["field", "field_name", "changed_field", "attribute"],
    "old_value": ["old_value", "previous_value", "from_value", "old"],
    "new_value": ["new_value", "to_value", "new"],
    "ts": ["changed_at", "timestamp", "ts", "occurred_at", "updated_at", "created_at", "captured_at", "event_time"],
    "audit_id": ["audit_id", "id"],
    "activity_id": ["activity_id", "id", "event_id"],
    "system_id": ["system_id", "system", "service", "source_system", "target_system"],
    "resource_id": ["resource_id", "resource", "record_id"],
    "operation": ["operation", "event_type", "action", "type"],
    "status": ["status", "result", "reported_result", "state"],
    "details": ["details", "message", "description", "notes"],
    "file_id": ["file_id", "id"],
    "path": ["path", "file_path", "filepath"],
    "origin": ["source_origin", "origin", "source", "system_id", "system"],
    "category": ["category", "data_category"],
    "condition": ["condition", "when"],
    "rule_action": ["action", "required_action", "treatment"],
}

# Multilingual intent classification stems and negation phrases
DELETE_STEMS = [
    "delet", "eras", "remov", "forget", "close", "wipe", "purg", "suppr", "effac", "elimin",
    "borr", "lösch", "losch", "entfern", "cancell", "exclu", "apag", "verwijder", "gone",
    "削除", "消去", "삭제", "删除", "刪除", "удал", "usuń", "usun", "sil"
]

NON_DELETE_PHRASES = [
    "do not delete", "don't delete", "do not remove", "don't remove", "keep my account",
    "copy of my data", "access my profile", "resetting the login", "marketing lists only",
    "newsletter", "last year's invoices", "copy of the information", "export my", "download my"
]

# Activity classification keywords
FLOW_WORDS = ["sync", "import", "replicat", "pipeline", "etl", "reindex", "indexing", "export job", "scheduled export", "cron"]
RESTORE_WORDS = ["backup", "snapshot", "restore", "archive"]
STOP_WORDS = ["disable", "stopped", "paused", "pause", "cancel", "suspend", "revoked", "turned off"]
BLOCK_WORDS = ["blocked", "excluded", "purged", "tombstoned from backup", "restore denied"]
DELETE_EVENT_WORDS = ["delete", "erase", "purge", "remove"]

# Column preference for choosing a row's resource id inside SQL snapshots
RESOURCE_ID_COLUMNS = ["resource_id", "record_id", "id"]

