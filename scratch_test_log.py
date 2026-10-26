import csv, json, re, base64, zlib, sqlite3
from pathlib import Path
from collections import defaultdict

dataset_dir = Path("dataset")
users_csv = list(csv.DictReader(open(dataset_dir / "user_identities.csv", encoding="utf-8-sig")))
users = {r["user_id"]: r for r in users_csv}
audit_csv = list(csv.DictReader(open(dataset_dir / "user_audit_log.csv", encoding="utf-8-sig")))
manifest = {r["file_id"]: r for r in csv.DictReader(open(dataset_dir / "evidence_files.csv", encoding="utf-8-sig"))}

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

class Observation:
    def __init__(self, fid, captured_at, system_id, resource_id, status, user_token=""):
        self.fid = fid
        self.captured_at = captured_at
        self.system_id = system_id
        self.resource_id = resource_id
        self.status = status
        self.user_token = str(user_token).strip().lower()

def parse_log(fid, fpath, cat):
    obs = []
    txt = fpath.read_text(encoding="utf-8", errors="ignore")
    # Group lines by trace_id
    traces = defaultdict(list)
    no_trace = []
    for line in txt.splitlines():
        tr_m = re.search(r'trace_id=([a-zA-Z0-9_-]+)', line)
        if tr_m:
            traces[tr_m.group(1)].append(line)
        else:
            no_trace.append(line)
            
    for tr_id, lines in traces.items():
        toks = set()
        rids = set()
        status = None
        for l in lines:
            for k in ["lookup_key", "customer_reference", "subject_reference", "subject_ref",
                      "matched_value", "correlation_key", "customer_email", "email", "match_key", "subject_key"]:
                m = re.search(rf'{k}=["\']?([^"\'\s,]+)["\']?', l)
                if m:
                    toks.add(m.group(1))
            rid_m = re.search(r'resource_id=([a-zA-Z0-9_]+)', l) or re.search(r'resource="([a-zA-Z0-9_]+)"', l)
            if rid_m:
                rids.add(rid_m.group(1))
                
            if "http_status=404" in l or "rows=0" in l or "result=miss" in l:
                status = "ABSENT"
            elif "result=hit" in l or "http_status=200" in l or "attachment_pii_scan" in l:
                status = "PRESENT"
            elif "message_pii_scan" in l:
                status = "IDENTIFIABLE"
            elif "marker_found=false" in l:
                status = "PRESENT"
            elif "email=null" in l and "phone=null" in l:
                status = "ANONYMIZED"
            elif "requester_email=null" in l:
                status = "REDACTED"
            elif "enabled=false" in l or "status=stopped" in l:
                status = "DISABLED"
            elif "enabled=true" in l:
                status = "ACTIVE"
            elif "restore_allowed=false" in l:
                status = "BLOCKED"
            elif "restore_allowed=true" in l:
                status = "ACTIVE"
            elif "rows=1" in l or "audit_record_read_completed" in l:
                if not status: status = "FOUND"
                
        if rids and toks:
            for rid in rids:
                sys_id = get_system(rid)
                st = status or "FOUND"
                for tok in toks:
                    obs.append(Observation(fid, cat, sys_id, rid, st, tok))
                    
    # Also check no_trace lines
    for l in no_trace:
        rid_m = re.search(r'resource_id=([a-zA-Z0-9_]+)', l) or re.search(r'resource="([a-zA-Z0-9_]+)"', l)
        if not rid_m: continue
        rid = rid_m.group(1)
        sys_id = get_system(rid)
        for k in ["lookup_key", "customer_reference", "subject_reference", "subject_ref",
                  "matched_value", "correlation_key", "customer_email", "email", "match_key", "subject_key"]:
            m = re.search(rf'{k}=["\']?([^"\'\s,]+)["\']?', l)
            if m:
                obs.append(Observation(fid, cat, sys_id, rid, "FOUND", m.group(1)))
    return obs

# Test parse on evidence_01
obs01 = parse_log("evidence_01", dataset_dir / "evidence/logs/service_events_ap_south_20260915.log", "2026-09-15T11:59:39Z")
print(f"evidence_01 parsed into {len(obs01)} observations.")
e_varga = [o for o in obs01 if "e.varga" in o.user_token]
for o in e_varga:
    print(f"  {o.system_id} | {o.resource_id} | {o.status} | {o.user_token}")
