"""Evidence scanning: turns evidence files into per-record observations about a user."""
import json, re, sqlite3, zlib, base64
from pathlib import Path
from collections import defaultdict
from .util import read_csv, pick, norm, digits, parse_ts
from .config import get_system, RESOURCE_ID_COLUMNS


class Observation:
    def __init__(self, fid, captured_at, system_id, resource_id, status, user_token=""):
        self.fid = fid
        self.captured_at = captured_at
        self.system_id = system_id
        self.resource_id = resource_id
        self.status = status  # 'ABSENT', 'PRESENT', 'ANONYMIZED', 'REDACTED', 'IDENTIFIABLE', 'ACTIVE', 'DISABLED', 'BLOCKED', 'FOUND'
        self.user_token = str(user_token).strip().lower()


def get_pdf_text(p):
    """Decompress and extract text from PDF streams without external dependencies."""
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


class EvidenceIndex:
    def __init__(self, ds):
        self.ds = ds
        self.manifest = {r["file_id"]: r for r in read_csv(ds / "evidence_files.csv")}
        self.obs_by_file = defaultdict(list)
        self.obs_by_resource = defaultdict(list)
        self._index_all()

    def _index_all(self):
        for fid, m in self.manifest.items():
            rel = pick(m, "path")
            fpath = self.ds / rel
            if not fpath.exists():
                fpath = self.ds / "evidence" / rel
            if not fpath.exists():
                continue
            cat = pick(m, "ts")
            ext = fpath.suffix.lower()
            file_obs = []

            if ext == ".txt":
                txt = fpath.read_text(encoding="utf-8", errors="ignore")
                for line in txt.splitlines():
                    if "|" in line:
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) >= 6:
                            sys_id, res_id, category, status, token = parts[1:6]
                            stat = "PRESENT" if category in ("SUPPORT_ATTACHMENT", "SEARCH_INDEX_ENTRY", "USER_PROFILE", "USER_EXPORT") else status
                            file_obs.append(Observation(fid, cat, sys_id, res_id, stat, token))

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
                            search_items = se["search_service"].get("index_queries", []) or se["search_service"].get("query_results", [])
                            for item in search_items:
                                rid = item.get("resource_id")
                                res = item.get("result")
                                th = item.get("total_hits", 0)
                                docs = item.get("hits", {}).get("documents", [])
                                doc_email = docs[0].get("email") if docs else None
                                tok = item.get("email") or item.get("customer_reference") or item.get("query") or doc_email or ""
                                stat = "PRESENT" if (res == "hit" or th > 0 or len(docs) > 0) else "ABSENT"
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
                            backup_items = se["backup_service"].get("restore_entries", []) or se["backup_service"].get("archives", [])
                            for item in backup_items:
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
                                file_obs.append(Observation(fid, cat, "export_service", rid, "PRESENT", tok))
                    elif isinstance(data, dict) and "snapshots" in data:
                        for sn in data.get("snapshots", []):
                            store = sn.get("data_store")
                            for rec in sn.get("records", []):
                                rid = rec.get("resource_id") or rec.get("id")
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
                                    tok = rec.get("customer_reference") or rec.get("customer_email") or rec.get("subject_reference") or ""
                                    stat = "ACTIVE" if rec.get("restore_allowed") else "BLOCKED"
                                    file_obs.append(Observation(fid, cat, "backup_service", rid, stat, tok))
                                elif store == "account_service":
                                    tok = rec.get("user_id") or rec.get("email") or rec.get("customer_reference") or ""
                                    file_obs.append(Observation(fid, cat, "account_service", rid, "PRESENT", tok))
                    elif isinstance(data, dict) and "records" in data:
                        for rec in data.get("records", []):
                            rid = rec.get("resource_id") or rec.get("id")
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
                    toks, rids = set(), set()
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
                        elif "result=hit" in l or "http_status=200" in l or "attachment_pii_scan" in l or "marker_found=false" in l:
                            status = "PRESENT"
                        elif "message_pii_scan" in l:
                            status = "IDENTIFIABLE"
                        elif "email=null" in l and "phone=null" in l:
                            status = "ANONYMIZED"
                        elif "requester_email=null" in l:
                            status = "REDACTED"
                        elif "enabled=false" in l or "status=stopped" in l:
                            status = "DISABLED"
                        elif "enabled=true" in l:
                            status = "ACTIVE"
                        elif "restore_allowed=false" in l or "deletion_block=true" in l:
                            status = "BLOCKED"
                        elif "restore_allowed=true" in l or "deletion_block=false" in l or "eligible=true" in l:
                            status = "ACTIVE"
                        elif "rows=1" in l:
                            status = "PRESENT"
                        elif "audit_record_read_completed" in l:
                            status = "FOUND"
                            
                    if rids and toks:
                        for rid in rids:
                            sys_id = get_system(rid)
                            st = status
                            if not st:
                                if "analytics" in sys_id:
                                    st = "IDENTIFIABLE" if any("@" in t for t in toks) else "ANONYMIZED"
                                elif "support" in sys_id:
                                    st = "IDENTIFIABLE" if any("@" in t for t in toks) else "REDACTED"
                                else:
                                    st = "FOUND"
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
                        rid_col = next((c for c in RESOURCE_ID_COLUMNS if c in cols), None)
                        if not rid_col: continue
                        
                        id_cols = [c for c in ["user_id", "customer_reference", "subject_reference", "email",
                                               "customer_email", "owner_email", "requester_email", "phone"] if c in cols]
                        
                        for row in con.execute(f'select * from "{t}"'):
                            rec = dict(zip(cols, row))
                            rid = str(rec[rid_col])
                            sys_id = get_system(rid)
                            if sys_id == rid.split('_')[0]:
                                sys_id = get_system(t)
                            if "attachment" in t:
                                sys_id = "support_platform"
                            
                            payload = {}
                            for c in cols:
                                val = str(rec[c]).strip()
                                if val.startswith("{") and val.endswith("}"):
                                    try:
                                        payload = json.loads(val)
                                    except Exception:
                                        pass
                                        
                            if "backup" in t:
                                stat = "ACTIVE" if rec.get("restore_allowed") or payload.get("restore_allowed") else "BLOCKED"
                            elif "connector" in t or "data_flow" in t:
                                stat = "ACTIVE" if rec.get("enabled") or payload.get("enabled") else "DISABLED"
                            elif "analytics" in t:
                                em = rec.get("email") or payload.get("email") or rec.get("phone") or payload.get("phone")
                                stat = "IDENTIFIABLE" if em else "ANONYMIZED"
                            elif "support" in t:
                                if "attachment" in t or rec.get("file_name") or payload.get("file_name"):
                                    stat = "PRESENT"
                                else:
                                    em = rec.get("requester_email") or payload.get("requester_email") or rec.get("requester_phone") or payload.get("requester_phone")
                                    stat = "IDENTIFIABLE" if em else "REDACTED"
                            elif "security" in t or "audit" in t:
                                stat = "FOUND"
                            elif "tombstone" in t:
                                em = rec.get("email") or payload.get("email") or rec.get("phone") or payload.get("phone")
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
                            for k in ["user_id", "customer_reference", "subject_reference", "email", "phone"]:
                                if payload.get(k):
                                    tokens.append(str(payload[k]).strip().lower())
                            if payload.get("document") and isinstance(payload["document"], dict):
                                for k in ["customer_reference", "email", "phone"]:
                                    if payload["document"].get(k):
                                        tokens.append(str(payload["document"][k]).strip().lower())
                                        
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

            self.obs_by_file[fid] = file_obs
            for o in file_obs:
                self.obs_by_resource[o.resource_id].append(o)
