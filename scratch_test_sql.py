import csv, sqlite3
from pathlib import Path
from collections import defaultdict

dataset_dir = Path("dataset")
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

def parse_sql(fid, fpath, cat):
    obs = []
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
                
                # Determine status
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
                    # In replica, if present, it's remaining!
                    stat = "PRESENT"
                elif "export" in t:
                    stat = "PRESENT"
                else:
                    stat = "PRESENT"
                    
                tokens = [str(rec[c]).strip().lower() for c in id_cols if rec[c] and str(rec[c]).strip().lower() != "null"]
                if not tokens:
                    obs.append(Observation(fid, cat, sys_id, rid, stat, ""))
                else:
                    for tok in set(tokens):
                        obs.append(Observation(fid, cat, sys_id, rid, stat, tok))
    except Exception as e:
        print(f"Error parsing SQL {fpath.name}: {e}")
    finally:
        con.close()
    return obs

total_obs = 0
for fid, m in manifest.items():
    if m["file_path"].endswith(".sql"):
        p = dataset_dir / m["file_path"]
        o = parse_sql(fid, p, m["captured_at"])
        total_obs += len(o)

print(f"Parsed {total_obs} observations from 24 SQL files.")
