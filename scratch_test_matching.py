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

for fid, m in manifest.items():
    fpath = dataset_dir / m["file_path"]
    if not fpath.exists(): continue
    cat = m["captured_at"]
    ext = fpath.suffix.lower()
    
    if ext == ".txt":
        txt = fpath.read_text(encoding="utf-8", errors="ignore")
        for line in txt.splitlines():
            if "|" in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 6:
                    sys_id, res_id, category, status, token = parts[1:6]
                    obs_by_file[fid].append(Observation(fid, cat, sys_id, res_id, status, token))

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
                        obs_by_file[fid].append(Observation(fid, cat, "account_service", rid, stat, tok))
                if "search_service" in se:
                    for item in se["search_service"].get("query_results", []):
                        rid = item.get("resource_id")
                        res = item.get("result")
                        th = item.get("total_hits", 0)
                        tok = item.get("email") or item.get("customer_reference") or ""
                        stat = "PRESENT" if (res == "hit" or th > 0) else "ABSENT"
                        obs_by_file[fid].append(Observation(fid, cat, "search_service", rid, stat, tok))
                if "analytics_platform" in se:
                    for item in se["analytics_platform"].get("profiles", []):
                        rid = item.get("resource_id")
                        em = item.get("email"); ph = item.get("phone"); eh = item.get("email_hash")
                        tok = em or ph or eh or item.get("customer_reference") or ""
                        stat = "ANONYMIZED" if not (em or ph or eh) else "IDENTIFIABLE"
                        obs_by_file[fid].append(Observation(fid, cat, "analytics_platform", rid, stat, tok))
                if "support_platform" in se:
                    for item in se["support_platform"].get("tickets", []):
                        rid = item.get("resource_id")
                        em = item.get("requester_email"); ph = item.get("requester_phone")
                        tok = em or ph or item.get("customer_reference") or ""
                        stat = "REDACTED" if not (em or ph) else "IDENTIFIABLE"
                        obs_by_file[fid].append(Observation(fid, cat, "support_platform", rid, stat, tok))
                if "integration_service" in se:
                    for item in se["integration_service"].get("connectors", []):
                        rid = item.get("resource_id")
                        en = item.get("enabled")
                        tok = item.get("customer_email") or item.get("customer_reference") or ""
                        stat = "ACTIVE" if en else "DISABLED"
                        obs_by_file[fid].append(Observation(fid, cat, "integration_service", rid, stat, tok))
                if "backup_service" in se:
                    for item in se["backup_service"].get("archives", []):
                        rid = item.get("resource_id")
                        ra = item.get("restore_allowed")
                        tok = item.get("customer_email") or item.get("customer_reference") or ""
                        stat = "ACTIVE" if ra else "BLOCKED"
                        obs_by_file[fid].append(Observation(fid, cat, "backup_service", rid, stat, tok))
                if "security_service" in se:
                    for item in se["security_service"].get("audit_records", []):
                        rid = item.get("resource_id")
                        tok = item.get("subject_reference") or ""
                        obs_by_file[fid].append(Observation(fid, cat, "security_service", rid, "FOUND", tok))
                if "export_service" in se:
                    for item in se["export_service"].get("exports", []):
                        rid = item.get("resource_id")
                        tok = item.get("owner_email") or item.get("customer_reference") or ""
                        obs_by_file[fid].append(Observation(fid, cat, "export_service", rid, "FOUND", tok))
            elif isinstance(data, dict) and "snapshots" in data:
                for sn in data.get("snapshots", []):
                    store = sn.get("data_store")
                    for rec in sn.get("records", []):
                        rid = rec.get("resource_id")
                        if store == "identity_service":
                            em = rec.get("email"); nm = rec.get("name")
                            tok = rec.get("subject_reference") or em or ""
                            stat = "REDACTED" if not (em or nm) else "IDENTIFIABLE"
                            obs_by_file[fid].append(Observation(fid, cat, "identity_service", rid, stat, tok))
                        elif store == "security_service":
                            tok = rec.get("subject_reference") or ""
                            obs_by_file[fid].append(Observation(fid, cat, "security_service", rid, "FOUND", tok))
                        elif store == "analytics_platform":
                            em = rec.get("email")
                            tok = rec.get("customer_reference") or em or ""
                            stat = "ANONYMIZED" if not em else "IDENTIFIABLE"
                            obs_by_file[fid].append(Observation(fid, cat, "analytics_platform", rid, stat, tok))
                        elif store == "support_platform":
                            em = rec.get("requester_email")
                            tok = rec.get("customer_reference") or em or ""
                            stat = "REDACTED" if not em else "IDENTIFIABLE"
                            obs_by_file[fid].append(Observation(fid, cat, "support_platform", rid, stat, tok))
                        elif store == "search_service":
                            tok = rec.get("customer_reference") or rec.get("email") or ""
                            obs_by_file[fid].append(Observation(fid, cat, "search_service", rid, "FOUND", tok))
                        elif store == "integration_service":
                            tok = rec.get("customer_reference") or rec.get("customer_email") or ""
                            stat = "ACTIVE" if rec.get("enabled") else "DISABLED"
                            obs_by_file[fid].append(Observation(fid, cat, "integration_service", rid, stat, tok))
                        elif store == "backup_service":
                            tok = rec.get("customer_reference") or rec.get("customer_email") or ""
                            stat = "ACTIVE" if rec.get("restore_allowed") else "BLOCKED"
                            obs_by_file[fid].append(Observation(fid, cat, "backup_service", rid, stat, tok))
                        elif store == "account_service":
                            tok = rec.get("user_id") or rec.get("email") or ""
                            obs_by_file[fid].append(Observation(fid, cat, "account_service", rid, "PRESENT", tok))
            elif isinstance(data, dict) and "records" in data:
                coll = data.get("collection", "")
                for rec in data.get("records", []):
                    rid = rec.get("resource_id")
                    if rid:
                        sys_id = get_system(rid)
                        em = rec.get("email"); uid = rec.get("user_id"); ref = rec.get("customer_reference")
                        tok = uid or em or ref or ""
                        stat = "FOUND"
                        if "analytics" in sys_id:
                            stat = "ANONYMIZED" if not (em or uid) else "IDENTIFIABLE"
                        elif "export" in sys_id:
                            stat = "PRESENT"
                        obs_by_file[fid].append(Observation(fid, cat, sys_id, rid, stat, tok))
        except Exception:
            pass

    elif ext == ".log":
        txt = fpath.read_text(encoding="utf-8", errors="ignore")
        for line in txt.splitlines():
            rid_m = re.search(r'resource_id=([a-zA-Z0-9_]+)', line)
            if not rid_m:
                rid_m = re.search(r'resource="([a-zA-Z0-9_]+)"', line)
            if not rid_m: continue
            rid = rid_m.group(1)
            sys_id = get_system(rid)
            tok_m = re.search(r'(?:lookup_key|customer_reference|subject_reference|subject_ref|matched_value|correlation_key|customer_email|email|match_key)=["\']?([^"\'\s,]+)["\']?', line)
            tok = tok_m.group(1) if tok_m else ""
            
            if "http_status=404" in line or "rows=0" in line:
                stat = "ABSENT"
            elif "http_status=200" in line or "result=hit" in line or "attachment_pii_scan" in line:
                stat = "PRESENT"
            elif "message_pii_scan" in line:
                stat = "IDENTIFIABLE"
            elif "rows=1" in line or "audit_record_read_completed" in line:
                stat = "FOUND"
            elif "email=null" in line and "phone=null" in line:
                stat = "ANONYMIZED"
            elif "requester_email=null" in line:
                stat = "REDACTED"
            elif "enabled=false" in line or "status=stopped" in line:
                stat = "DISABLED"
            elif "enabled=true" in line:
                stat = "ACTIVE"
            elif "restore_allowed=false" in line:
                stat = "BLOCKED"
            elif "restore_allowed=true" in line:
                stat = "ACTIVE"
            else:
                stat = "FOUND"
            obs_by_file[fid].append(Observation(fid, cat, sys_id, rid, stat, tok))

    elif ext == ".sql":
        con = sqlite3.connect(":memory:")
        try:
            sql_txt = fpath.read_text(encoding="utf-8", errors="ignore")
            con.executescript(sql_txt)
            for (t,) in con.execute("select name from sqlite_master where type='table'"):
                cols = [c[1] for c in con.execute(f'pragma table_info("{t}")')]
                if "resource_id" not in cols: continue
                id_col = next((c for c in ["user_id", "customer_reference", "subject_reference", "email", "customer_email"] if c in cols), None)
                for row in con.execute(f'select * from "{t}"'):
                    rec = dict(zip(cols, row))
                    rid = str(rec["resource_id"])
                    sys_id = get_system(rid)
                    tok = str(rec[id_col]) if id_col and rec[id_col] else ""
                    stat = "PRESENT"
                    if "backup" in t:
                        stat = "BLOCKED" if not rec.get("restore_allowed") else "ACTIVE"
                    elif "connector" in t:
                        stat = "ACTIVE" if rec.get("enabled") else "DISABLED"
                    elif "analytics" in t:
                        stat = "ANONYMIZED" if not rec.get("email") else "IDENTIFIABLE"
                    elif "support" in t:
                        stat = "REDACTED" if not rec.get("requester_email") else "IDENTIFIABLE"
                    elif "security" in t:
                        stat = "FOUND"
                    obs_by_file[fid].append(Observation(fid, cat, sys_id, rid, stat, tok))
        except Exception:
            pass
        finally:
            con.close()

    elif ext == ".pdf":
        pdf_txt = get_pdf_text(fpath)
        # Search for support reference and customer email
        m_supp = re.search(r'support_([0-9]+)', pdf_txt)
        m_em = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', pdf_txt)
        if m_supp and m_em:
            obs_by_file[fid].append(Observation(fid, cat, "support_platform", f"support_{m_supp.group(1)}", "PRESENT", m_em.group(1)))

print(f"Indexed evidence across {len(obs_by_file)} files.")

# Test query for sample cases
samples = list(csv.DictReader(open(dataset_dir / "sample_deletion_requests.csv", encoding="utf-8-sig")))
gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open(dataset_dir / "sample_output.csv", encoding="utf-8-sig"))}

for s in samples[:10]:
    cid = s['case_id']
    uid, tokens = get_user_identifiers(s['email'], s['audit_at'])
    g_stat, g_steps = gold_rows[cid]
    g_res = {st['resource_id'] for st in g_steps}
    
    # Collect observations matching user tokens
    user_obs = []
    for fid, ob_list in obs_by_file.items():
        if manifest[fid]['captured_at'] <= s['audit_at']:
            for o in ob_list:
                if o.user_token and (o.user_token in tokens or any(t in o.user_token for t in tokens if len(t) > 4)):
                    user_obs.append(o)
    found_res = {o.resource_id for o in user_obs}
    print(f"{cid} (gold={g_stat}, gold_res={g_res}): found {len(user_obs)} obs across {len(found_res)} res: {found_res}")
