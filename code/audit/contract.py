"""Output contract: allowed operations, ordering, numbering, serialization, validation."""
import json

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
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}


def step(operation, system_id, resource_id, evidence_id=""):
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


def serialize(steps):
    return json.dumps(steps, separators=(",", ":"), ensure_ascii=False)


def validate_row(case_id, status, steps):
    errs = []
    if status not in STATUSES:
        errs.append(f"{case_id}: bad status {status}")
    if status == "NOT_APPLICABLE" and steps:
        errs.append(f"{case_id}: NOT_APPLICABLE must have []")
    last = (-1, -1, "", "")
    for i, s in enumerate(steps, 1):
        if s.get("step_no") != i:
            errs.append(f"{case_id}: step_no {s.get('step_no')} != {i}")
        if s["operation"] not in OP_META or OP_META[s["operation"]] != (s["phase"], s["state"]):
            errs.append(f"{case_id}: bad op/phase/state at {i}")
            continue
        key = (PHASES.index(s["phase"]), OP_INDEX[s["operation"]], s["system_id"], s["resource_id"])
        if key < last:
            errs.append(f"{case_id}: order violation at {i}")
        last = key
        if status == "INCOMPLETE" and s["phase"] != "FINDING" and s["evidence_id"]:
            errs.append(f"{case_id}: non-finding step {i} must have empty evidence_id")
        if status == "COMPLETE" and (s["phase"] != "VERIFICATION" or not s["evidence_id"]):
            errs.append(f"{case_id}: COMPLETE needs evidence-backed VERIFICATION only (step {i})")
    if status == "INCOMPLETE" and steps and steps[0]["phase"] != "FINDING":
        errs.append(f"{case_id}: INCOMPLETE must start with findings")
    return errs
