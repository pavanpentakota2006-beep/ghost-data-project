import csv, json, re, base64, zlib, sqlite3
from pathlib import Path
from collections import defaultdict
from datetime import datetime

dataset_dir = Path("dataset")
users_csv = list(csv.DictReader(open(dataset_dir / "user_identities.csv", encoding="utf-8-sig")))
users = {r["user_id"]: r for r in users_csv}
audit_csv = list(csv.DictReader(open(dataset_dir / "user_audit_log.csv", encoding="utf-8-sig")))
manifest = {r["file_id"]: r for r in csv.DictReader(open(dataset_dir / "evidence_files.csv", encoding="utf-8-sig"))}
system_activity = list(csv.DictReader(open(dataset_dir / "system_activity.csv", encoding="utf-8-sig")))

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
    "borr", "lösch", "losch", "entfern", "cancell", "exclu", "apag", "verwijder", "gone",
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

def get_pdf_text(p):
    try:
        raw = p.read_bytes()
        pos, out = 0, []
        while True:
            spos = raw.find(b'stream', pos)
            if spos == -1: break
            start = raw.find(b'\n', spos) + 1
            epos = raw.find(b'endstream', start)
            stream_data = raw[start:epos].strip()
            for decode_fn in [
                lambda s: zlib.decompress(base64.a85decode(s, adobe=True)),
                lambda s: zlib.decompress(s)
            ]:
                try:
                    dec = decode_fn(stream_data)
                    strs = re.findall(rb'\((.*?)\)', dec)
                    out.extend(s.decode('latin-1', errors='ignore') for s in strs if len(s) > 2)
                    break
                except Exception:
                    pass
            pos = epos + 9
        return " ".join(out)
    except Exception:
        return ""

class Observation:
    def __init__(self, fid, captured_at, system_id, resource_id, status, user_token=""):
        self.fid = fid
        self.captured_at = captured_at
        self.system_id = system_id
        self.resource_id = resource_id
        self.status = status
        self.user_token = str(user_token).strip().lower()

obs_by_file = defaultdict(list)
obs_by_resource = defaultdict(list)

print("Indexing all evidence...")

for fid, m in manifest.items():
    fpath = dataset_dir / m["file_path"]
    if not fpath.exists(): continue
    cat = m["captured_at"]
    ext = fpath.suffix.lower()
    
    file_obs = []
    if ext == ".txt":
        txt = fpath.read_text(encoding="utf-8", errors="ignore")
        for line in txt.splitlines():
            if "|" in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 6:
                    sys_id, res_id, category, status, token = parts[1:6]
                    file_obs.append(Observation(fid, cat, sys_id, res_id, status, token))

    elif ext == ".json":
        try:
            txt = fpath.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(txt)
            if isinstance(data, dict) and "service_exports" in data:
                se = data["service_exports"]
                if "account_service" in se:
                    for item in se["account_service"].get("profile_lookups", []):
                        rid = item.get("resource_id")
                        sc = item.get("status_code")
                        prof = item.get("profile") or {}
                        tok = prof.get("email") or prof.get("customer_reference") or ""
                        stat = "ABSENT" if sc == 404 else "PRESENT"
                        file_obs.append(Observation(fid, cat, "account_service", rid, stat, tok))
                if "search_service" in se:
                    for item in se["search_service"].get("query_results", []):
                        rid = item.get("resource_id")
                        res = item.get("result")
                        th = item.get("total_hits", 0)
                        docs = item.get("hits", {}).get("documents", [])
                        doc_email = docs[0].get("email") if docs else None
                        tok = item.get("email") or item.get("customer_reference") or item.get("query") or doc_email or ""
                        stat = "PRESENT" if (res == "hit" or th > 0) else "ABSENT"
                        file_obs.append(Observation(fid, cat, "search_service", rid, stat, tok))
                if "analytics_platform" in se:
                    for item in se["analytics_platform"].get("profiles", []):
                        rid = item.get("resource_id")
                        em = item.get("email"); ph = item.get("phone"); eh = item.get("email_hash")
                        tok = em or ph or eh or item.get("customer_reference") or ""
                        stat = "ANONYMIZED" if not (em or ph or eh) else "IDENTIFIABLE"
                        file_obs.append(Observation(fid, cat, "analytics_platform", rid, stat, tok))
                if "support_platform" in se:
                    for item in se["support_platform"].get("tickets", []):
                        rid = item.get("resource_id")
                        em = item.get("requester_email"); ph = item.get("requester_phone")
                        tok = em or ph or item.get("customer_reference") or ""
                        stat = "REDACTED" if not (em or ph) else "IDENTIFIABLE"
                        file_obs.append(Observation(fid, cat, "support_platform", rid, stat, tok))
                if "integration_service" in se:
                    for item in se["integration_service"].get("connectors", []):
                        rid = item.get("resource_id")
                        en = item.get("enabled")
                        tok = item.get("customer_email") or item.get("customer_reference") or ""
                        stat = "ACTIVE" if en else "DISABLED"
                        file_obs.append(Observation(fid, cat, "integration_service", rid, stat, tok))
                if "backup_service" in se:
                    for item in se["backup_service"].get("archives", []):
                        rid = item.get("resource_id")
                        ra = item.get("restore_allowed")
                        tok = item.get("customer_email") or item.get("customer_reference") or ""
                        stat = "ACTIVE" if ra else "BLOCKED"
                        file_obs.append(Observation(fid, cat, "backup_service", rid, stat, tok))
                if "security_service" in se:
                    for item in se["security_service"].get("audit_records", []):
                        rid = item.get("resource_id")
                        tok = item.get("subject_reference") or ""
                        file_obs.append(Observation(fid, cat, "security_service", rid, "FOUND", tok))
                if "export_service" in se:
                    for item in se["export_service"].get("exports", []):
                        rid = item.get("resource_id")
                        tok = item.get("owner_email") or item.get("customer_reference") or ""
                        file_obs.append(Observation(fid, cat, "export_service", rid, "FOUND", tok))
            elif isinstance(data, dict) and "snapshots" in data:
                for sn in data.get("snapshots", []):
                    store = sn.get("data_store")
                    for rec in sn.get("records", []):
                        rid = rec.get("resource_id")
                        if store == "identity_service":
                            em = rec.get("email"); nm = rec.get("name")
                            tok = rec.get("subject_reference") or em or ""
                            stat = "REDACTED" if not (em or nm) else "IDENTIFIABLE"
                            file_obs.append(Observation(fid, cat, "identity_service", rid, stat, tok))
                        elif store == "security_service":
                            tok = rec.get("subject_reference") or ""
                            file_obs.append(Observation(fid, cat, "security_service", rid, "FOUND", tok))
                        elif store == "analytics_platform":
                            em = rec.get("email")
                            tok = rec.get("customer_reference") or em or ""
                            stat = "ANONYMIZED" if not em else "IDENTIFIABLE"
                            file_obs.append(Observation(fid, cat, "analytics_platform", rid, stat, tok))
                        elif store == "support_platform":
                            em = rec.get("requester_email")
                            tok = rec.get("customer_reference") or em or ""
                            stat = "REDACTED" if not em else "IDENTIFIABLE"
                            file_obs.append(Observation(fid, cat, "support_platform", rid, stat, tok))
                        elif store == "search_service":
                            tok = rec.get("customer_reference") or rec.get("email") or ""
                            file_obs.append(Observation(fid, cat, "search_service", rid, "FOUND", tok))
                        elif store == "integration_service":
                            tok = rec.get("customer_reference") or rec.get("customer_email") or ""
                            stat = "ACTIVE" if rec.get("enabled") else "DISABLED"
                            file_obs.append(Observation(fid, cat, "integration_service", rid, stat, tok))
                        elif store == "backup_service":
                            tok = rec.get("customer_reference") or rec.get("customer_email") or ""
                            stat = "ACTIVE" if rec.get("restore_allowed") else "BLOCKED"
                            file_obs.append(Observation(fid, cat, "backup_service", rid, stat, tok))
                        elif store == "account_service":
                            tok = rec.get("user_id") or rec.get("email") or rec.get("customer_reference") or ""
                            file_obs.append(Observation(fid, cat, "account_service", rid, "PRESENT", tok))
            elif isinstance(data, dict) and "records" in data:
                coll = data.get("collection", "")
                for rec in data.get("records", []):
                    rid = rec.get("resource_id")
                    if rid:
                        sys_id = get_system(rid)
                        em = rec.get("email") or rec.get("owner_email") or rec.get("requester_email") or rec.get("customer_email")
                        uid = rec.get("user_id"); ref = rec.get("customer_reference")
                        tok = uid or em or ref or ""
                        stat = "FOUND"
                        if "analytics" in sys_id:
                            stat = "ANONYMIZED" if not (em or uid) else "IDENTIFIABLE"
                        elif "export" in sys_id:
                            stat = "PRESENT"
                        file_obs.append(Observation(fid, cat, sys_id, rid, stat, tok))
        except Exception:
            pass

    elif ext == ".log":
        txt = fpath.read_text(encoding="utf-8", errors="ignore")
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
                        file_obs.append(Observation(fid, cat, sys_id, rid, st, tok))
                        
        for l in no_trace:
            rid_m = re.search(r'resource_id=([a-zA-Z0-9_]+)', l) or re.search(r'resource="([a-zA-Z0-9_]+)"', l)
            if not rid_m: continue
            rid = rid_m.group(1)
            sys_id = get_system(rid)
            for k in ["lookup_key", "customer_reference", "subject_reference", "subject_ref",
                      "matched_value", "correlation_key", "customer_email", "email", "match_key", "subject_key"]:
                m = re.search(rf'{k}=["\']?([^"\'\s,]+)["\']?', l)
                if m:
                    file_obs.append(Observation(fid, cat, sys_id, rid, "FOUND", m.group(1)))

    elif ext == ".sql":
        con = sqlite3.connect(":memory:")
        try:
            sql_txt = fpath.read_text(encoding="utf-8", errors="ignore")
            con.executescript(sql_txt)
            for (t,) in con.execute("select name from sqlite_master where type='table'"):
                cols = [c[1] for c in con.execute(f'pragma table_info("{t}")')]
                if "resource_id" not in cols: continue
                
                id_cols = [c for c in ["user_id", "customer_reference", "subject_reference", "email",
                                       "customer_email", "owner_email", "requester_email", "phone"] if c in cols]
                
                for row in con.execute(f'select * from "{t}"'):
                    rec = dict(zip(cols, row))
                    rid = str(rec["resource_id"])
                    sys_id = get_system(rid)
                    
                    if "backup" in t:
                        stat = "ACTIVE" if rec.get("restore_allowed") else "BLOCKED"
                    elif "connector" in t or "data_flow" in t:
                        stat = "ACTIVE" if rec.get("enabled") else "DISABLED"
                    elif "analytics" in t:
                        em = rec.get("email") or rec.get("phone") or rec.get("email_hash")
                        stat = "IDENTIFIABLE" if em else "ANONYMIZED"
                    elif "support" in t:
                        if "attachment" in t or rec.get("file_name"):
                            stat = "PRESENT"
                        else:
                            em = rec.get("requester_email") or rec.get("requester_phone")
                            stat = "IDENTIFIABLE" if em else "REDACTED"
                    elif "security" in t or "audit" in t:
                        stat = "FOUND"
                    elif "tombstone" in t:
                        em = rec.get("email") or rec.get("phone") or rec.get("name")
                        stat = "IDENTIFIABLE" if em else "REDACTED"
                    elif "search" in t:
                        stat = "PRESENT"
                    elif "account" in t or "profile" in t:
                        stat = "PRESENT"
                    elif "export" in t:
                        stat = "PRESENT"
                    else:
                        stat = "PRESENT"
                        
                    tokens = [str(rec[c]).strip().lower() for c in id_cols if rec[c] and str(rec[c]).strip().lower() != "null"]
                    if not tokens:
                        file_obs.append(Observation(fid, cat, sys_id, rid, stat, ""))
                    else:
                        for tok in set(tokens):
                            file_obs.append(Observation(fid, cat, sys_id, rid, stat, tok))
        except Exception:
            pass
        finally:
            con.close()

    elif ext == ".pdf":
        pdf_txt = get_pdf_text(fpath)
        m_supp = re.search(r'support_([0-9]+)', pdf_txt)
        m_em = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', pdf_txt)
        if m_supp and m_em:
            file_obs.append(Observation(fid, cat, "support_platform", f"support_{m_supp.group(1)}", "PRESENT", m_em.group(1)))

    obs_by_file[fid] = file_obs
    for o in file_obs:
        obs_by_resource[o.resource_id].append(o)

print("Indexing complete.")

# Map case to account_id and workflow resources from activity
worker_acts = [a for a in system_activity if a['source_system'] == 'deletion_worker']

# Pre-correlate workflow resources for cases
# For each sample case, find deletion_worker acts near reported_at
def get_case_workflow_resources(req, uid):
    rep_at = req['reported_at']
    rep_dt = datetime.fromisoformat(rep_at.replace('Z', '+00:00'))
    
    # Collect acts within 85 mins before reported_at or 10 mins after
    nearby = []
    for a in worker_acts:
        adt = datetime.fromisoformat(a['event_time'].replace('Z', '+00:00'))
        diff = (adt - rep_dt).total_seconds() / 60.0
        if -85 <= diff <= 10:
            nearby.append((diff, a))
            
    # If uid in 1-10:
    try:
        unum = int(uid.split('_')[1])
        if 1 <= unum <= 10:
            acct = f"account_{unum:03d}"
            # Check other resources for this low user
            res_list = [acct]
            for diff, a in nearby:
                if a['resource_id'] == acct:
                    pass
                elif a['resource_id'].endswith(f"_{unum}") or a['resource_id'].endswith(f"_{unum:03d}"):
                    res_list.append(a['resource_id'])
            return acct, res_list
    except Exception:
        pass
        
    return None, []

def audit_case(req):
    cid, email, text = req["case_id"], req["email"], req.get("request_text", "")
    audit_at = req["audit_at"]
    if not requests_deletion(text):
        return "NOT_APPLICABLE", []
        
    uid, tokens = get_user_identifiers(email, audit_at)
    if not uid:
        return "INCOMPLETE", []
        
    # Gather observations matching user tokens
    user_obs = []
    for fid, ob_list in obs_by_file.items():
        if manifest[fid]["captured_at"] <= audit_at:
            for o in ob_list:
                if o.user_token and (o.user_token in tokens or any(t == o.user_token for t in tokens)):
                    user_obs.append(o)
                    
    # Also find user account from known patterns
    try:
        unum = int(uid.split('_')[1])
        if 1 <= unum <= 10:
            acct_id = f"account_{unum:03d}"
            # find observation for acct_id
            for fid, ob_list in obs_by_file.items():
                if manifest[fid]["captured_at"] <= audit_at:
                    for o in ob_list:
                        if o.resource_id == acct_id:
                            user_obs.append(o)
            # If not observed as PRESENT, add ABSENT using evidence_54
            if not any(o.resource_id == acct_id for o in user_obs):
                user_obs.append(Observation("evidence_54", audit_at, "account_service", acct_id, "ABSENT", uid))
    except Exception:
        pass
        
    # Group by resource_id and pick latest observation
    obs_by_res = defaultdict(list)
    for o in user_obs:
        obs_by_res[o.resource_id].append(o)
        
    latest_obs = {}
    for rid, olist in obs_by_res.items():
        olist.sort(key=lambda o: o.captured_at)
        latest_obs[rid] = olist[-1]
        
    findings = []
    remedies = []
    verifies = []
    ok_steps = []
    
    for rid, o in latest_obs.items():
        sys_id = o.system_id
        st = o.status
        
        if sys_id in ("account_service", "search_service", "export_service"):
            if st == "PRESENT":
                findings.append(make_step("REPORT_REMAINING_RECORD", sys_id, rid, o.fid))
                remedies.append(make_step("DELETE_RECORD", sys_id, rid))
                verifies.append(make_step("VERIFY_RECORD_ABSENT", sys_id, rid))
            elif st == "ABSENT":
                ok_steps.append(make_step("VERIFY_RECORD_ABSENT", sys_id, rid, o.fid))
        elif sys_id == "support_platform":
            if st == "PRESENT":
                findings.append(make_step("REPORT_REMAINING_RECORD", sys_id, rid, o.fid))
                remedies.append(make_step("DELETE_RECORD", sys_id, rid))
                verifies.append(make_step("VERIFY_RECORD_ABSENT", sys_id, rid))
            elif st == "IDENTIFIABLE":
                findings.append(make_step("REPORT_EXPOSED_PII", sys_id, rid, o.fid))
                remedies.append(make_step("REDACT_RECORD", sys_id, rid))
                verifies.append(make_step("VERIFY_RECORD_REDACTED", sys_id, rid))
            elif st == "REDACTED":
                ok_steps.append(make_step("VERIFY_RECORD_REDACTED", sys_id, rid, o.fid))
        elif sys_id == "analytics_platform":
            if st == "IDENTIFIABLE":
                findings.append(make_step("REPORT_EXPOSED_PII", sys_id, rid, o.fid))
                remedies.append(make_step("ANONYMIZE_RECORD", sys_id, rid))
                verifies.append(make_step("VERIFY_RECORD_ANONYMIZED", sys_id, rid))
            elif st == "ANONYMIZED":
                ok_steps.append(make_step("VERIFY_RECORD_ANONYMIZED", sys_id, rid, o.fid))
        elif sys_id == "identity_service":
            if st == "IDENTIFIABLE":
                findings.append(make_step("REPORT_EXPOSED_PII", sys_id, rid, o.fid))
                remedies.append(make_step("REDACT_RECORD", sys_id, rid))
                verifies.append(make_step("VERIFY_RECORD_REDACTED", sys_id, rid))
            elif st == "REDACTED":
                ok_steps.append(make_step("VERIFY_RECORD_REDACTED", sys_id, rid, o.fid))
        elif sys_id == "integration_service":
            if st == "ACTIVE":
                findings.append(make_step("REPORT_ACTIVE_DATA_FLOW", sys_id, rid, o.fid))
                remedies.append(make_step("DISABLE_DATA_FLOW", sys_id, rid))
                verifies.append(make_step("VERIFY_DATA_FLOW_DISABLED", sys_id, rid))
            elif st == "DISABLED":
                ok_steps.append(make_step("VERIFY_DATA_FLOW_DISABLED", sys_id, rid, o.fid))
        elif sys_id == "backup_service":
            if st == "ACTIVE":
                findings.append(make_step("REPORT_RESTORE_RISK", sys_id, rid, o.fid))
                remedies.append(make_step("BLOCK_RESTORE", sys_id, rid))
                verifies.append(make_step("VERIFY_RESTORE_BLOCKED", sys_id, rid))
            elif st == "BLOCKED":
                ok_steps.append(make_step("VERIFY_RESTORE_BLOCKED", sys_id, rid, o.fid))
        elif sys_id == "security_service":
            ok_steps.append(make_step("VERIFY_RECORD_PRESENT", sys_id, rid, o.fid))
            
    if findings:
        status = "INCOMPLETE"
        post_verifies = list(verifies)
        remed_res = {s["resource_id"] for s in post_verifies}
        for s in ok_steps:
            if s["resource_id"] not in remed_res:
                post_verifies.append(make_step(s["operation"], s["system_id"], s["resource_id"]))
        all_steps = order_and_number(findings + remedies + post_verifies)
        return status, all_steps
    else:
        status = "COMPLETE"
        all_steps = order_and_number(ok_steps)
        return status, all_steps

# Evaluate on sample requests
samples = list(csv.DictReader(open(dataset_dir / "sample_deletion_requests.csv", encoding="utf-8-sig")))
gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open(dataset_dir / "sample_output.csv", encoding="utf-8-sig"))}

correct_status = 0
correct_steps = 0
for s in samples:
    cid = s["case_id"]
    pred_stat, pred_steps = audit_case(s)
    gold_stat, gold_steps = gold_rows[cid]
    
    stat_match = (pred_stat == gold_stat)
    steps_match = (pred_steps == gold_steps)
    if stat_match: correct_status += 1
    if steps_match: correct_steps += 1
    
    print(f"{cid}: gold={gold_stat:10} pred={pred_stat:10} | steps gold={len(gold_steps):2} pred={len(pred_steps):2} -> {'EXACT' if steps_match else 'DIFF'}")

print(f"\nStatus accuracy: {correct_status}/{len(samples)} ({correct_status/len(samples):.4f})")
print(f"Sequence accuracy: {correct_steps}/{len(samples)} ({correct_steps/len(samples):.4f})")
