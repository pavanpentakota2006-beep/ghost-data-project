import csv, json
from pathlib import Path

samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig')))
gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
manifest = {r['file_id']: r for r in csv.DictReader(open('dataset/evidence_files.csv', encoding='utf-8-sig'))}
users = {r['user_id']: r for r in csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8-sig'))}
email_to_uid = {r['email'].lower(): r['user_id'] for r in users.values()}
for r in csv.DictReader(open('dataset/user_audit_log.csv', encoding='utf-8-sig')):
    if r['field_name'] == 'email':
        email_to_uid[r['old_value'].lower()] = r['user_id']
        email_to_uid[r['new_value'].lower()] = r['user_id']

# Cache file text for all evidence files
ev_text = {}
for fid, m in manifest.items():
    p = Path('dataset') / m['file_path']
    try:
        ev_text[fid] = p.read_text(encoding='utf-8', errors='ignore').lower()
    except Exception:
        ev_text[fid] = ""

for s in samples:
    cid = s['case_id']
    email = s['email'].lower()
    uid = email_to_uid.get(email, "").lower()
    u = users.get(email_to_uid.get(email, ""), {})
    name = u.get('name', '').lower()
    aud_at = s['audit_at']
    gold_stat, gold_steps = gold_rows[cid]
    gold_evs = sorted(set(st['evidence_id'] for st in gold_steps if st['evidence_id']))
    
    # candidate files: captured_at <= aud_at that mention email or uid
    candidates = []
    for fid, m in manifest.items():
        if m['captured_at'] <= aud_at:
            t = ev_text[fid]
            if (email and email in t) or (uid and f'"{uid}"' in t or f"'{uid}'" in t or f"={uid}" in t or f" {uid}" in t):
                candidates.append((m['captured_at'], fid, m['file_path']))
    candidates.sort(reverse=True)
    c_fids = [c[1] for c in candidates]
    match = (gold_evs == c_fids[:len(gold_evs)]) or (set(gold_evs).issubset(set(c_fids)))
    print(f"{cid}: gold_evs={gold_evs} | candidates={[c[1] for c in candidates[:3]]} -> {'MATCH' if match else 'CHECK'}")
