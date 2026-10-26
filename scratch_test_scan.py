import csv, json, re, sqlite3
from pathlib import Path
from collections import defaultdict

manifest = {r['file_id']: r for r in csv.DictReader(open('dataset/evidence_files.csv', encoding='utf-8-sig'))}
users = {r['user_id']: r for r in csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8-sig'))}
email_to_uid = {r['email'].lower(): r['user_id'] for r in users.values()}
for r in csv.DictReader(open('dataset/user_audit_log.csv', encoding='utf-8-sig')):
    if r['field_name'] == 'email':
        email_to_uid[r['old_value'].lower()] = r['user_id']
        email_to_uid[r['new_value'].lower()] = r['user_id']

# All user identifiers mapping to uid
uid_by_ident = {}
for uid, u in users.items():
    uid_by_ident[uid.lower()] = uid
    if u['email']: uid_by_ident[u['email'].lower()] = uid
    if u['phone']: uid_by_ident[u['phone']] = uid
    if u['email_hash']: uid_by_ident[u['email_hash'].lower()] = uid
for r in csv.DictReader(open('dataset/user_audit_log.csv', encoding='utf-8-sig')):
    uid = r['user_id']
    for v in (r['old_value'], r['new_value']):
        if v: uid_by_ident[v.lower()] = uid

print(f"Total known user identifiers: {len(uid_by_ident)}")

# Test scanning evidence_01, evidence_03, evidence_51, evidence_92, evidence_94
test_files = ['evidence_01', 'evidence_03', 'evidence_51', 'evidence_92', 'evidence_94']
for fid in test_files:
    info = manifest[fid]
    p = Path('dataset') / info['file_path']
    print(f"\n=== {fid}: {p.name} ({info['origin']}) ===")
    # let's see how many user references we can find
    txt = p.read_text(encoding='utf-8', errors='ignore')
    hits = defaultdict(list)
    for token, uid in uid_by_ident.items():
        if len(token) >= 5 and token in txt.lower():
            hits[uid].append(token)
    print(f"Users found in {fid}: {len(hits)}")
    for uid, tokens in list(hits.items())[:5]:
        print(f"  {uid}: {tokens}")
