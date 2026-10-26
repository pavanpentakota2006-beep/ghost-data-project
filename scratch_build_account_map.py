import json, sqlite3, csv, re
from pathlib import Path
from collections import defaultdict

dataset_dir = Path("dataset")
acct_to_user = {}
user_to_acct = {}

# 1. Low user ids
for i in range(1, 11):
    uid = f"user_{i:02d}"
    aid = f"account_{i:03d}"
    acct_to_user[aid] = uid
    user_to_acct[uid] = aid

# 2. JSON snapshot bundles
for f in (dataset_dir / "evidence/records").glob("*.json"):
    try:
        data = json.load(open(f, encoding="utf-8"))
        for sn in data.get("snapshots", []):
            if sn.get("data_store") == "account_service":
                for r in sn.get("records", []):
                    aid = r.get("resource_id")
                    uid = r.get("user_id") or r.get("customer_reference")
                    if aid and uid:
                        acct_to_user[aid] = uid
                        user_to_acct[uid] = aid
    except Exception:
        pass

# 3. SQL files
for f in (dataset_dir / "evidence/databases").glob("*.sql"):
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(f.read_text(encoding="utf-8", errors="ignore"))
        for (t,) in con.execute("select name from sqlite_master where type='table'"):
            cols = [c[1] for c in con.execute(f'pragma table_info("{t}")')]
            if "resource_id" in cols and "user_id" in cols:
                for aid, uid in con.execute(f'select resource_id, user_id from "{t}"'):
                    if aid.startswith("account_") and uid.startswith("user_"):
                        acct_to_user[aid] = uid
                        user_to_acct[uid] = aid
    except Exception:
        pass
    finally:
        con.close()

# 4. Text handover file
handover = dataset_dir / "evidence/records/customer_account_handover_20261001.txt"
if handover.exists():
    for line in handover.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 6:
                sys_id, res_id, category, status, token = parts[1:6]
                if sys_id == "account_service" and token.startswith("user_"):
                    acct_to_user[res_id] = token
                    user_to_acct[token] = res_id

# 5. Logs (resource_lookup_trace, etc.)
for f in (dataset_dir / "evidence/logs").glob("*.log"):
    txt = f.read_text(encoding="utf-8", errors="ignore")
    for line in txt.splitlines():
        if "account_" in line and "user_" in line:
            aid_m = re.search(r'(account_[0-9]+)', line)
            uid_m = re.search(r'(user_[0-9]+)', line)
            if aid_m and uid_m:
                aid = aid_m.group(1)
                uid = uid_m.group(1)
                acct_to_user[aid] = uid
                user_to_acct[uid] = aid

print(f"Total mapped accounts: {len(acct_to_user)}")
print(f"Total mapped users: {len(user_to_acct)}")

# Check against sample gold
gold_rows = {r['case_id']: json.loads(r['steps_json']) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig')))
users = {r['user_id']: r for r in csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8-sig'))}
email_to_uid = {r['email'].lower(): r['user_id'] for r in users.values()}

matched = 0
for s in samples:
    cid = s['case_id']
    uid = email_to_uid.get(s['email'].lower())
    gold_acct = next((st['resource_id'] for st in gold_rows[cid] if st['system_id'] == 'account_service'), None)
    pred_acct = user_to_acct.get(uid)
    ok = (pred_acct == gold_acct)
    if ok: matched += 1
    print(f"{cid} ({uid}): gold={gold_acct} pred={pred_acct} -> {'MATCH' if ok else 'MISMATCH'}")

print(f"\nMatched: {matched}/{len(samples)}")
