import csv, json
from collections import defaultdict
from pathlib import Path

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
users = {r['user_id']: r for r in csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8-sig'))}
email_to_uid = {r['email']: r['user_id'] for r in users.values()}
audit_rows = list(csv.DictReader(open('dataset/user_audit_log.csv', encoding='utf-8-sig')))
for r in audit_rows:
    if r['field_name'] == 'email':
        email_to_uid[r['old_value']] = r['user_id']
        email_to_uid[r['new_value']] = r['user_id']

# All system activity by resource
acts_by_res = defaultdict(list)
all_acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')))
for a in all_acts:
    acts_by_res[a['resource_id']].append(a)

for cid in sorted(gold_rows):
    req = samples[cid]
    uid = email_to_uid.get(req['email'])
    u = users.get(uid, {})
    stat, steps = gold_rows[cid]
    print(f"\n==========================================")
    print(f"CASE {cid}: user={uid} ({u.get('name')}, {req['email']})")
    print(f"req_at={req['requested_at']} rep={req['reported_status']} rep_at={req['reported_at']} aud_at={req['audit_at']}")
    print(f"GOLD: {stat} with {len(steps)} steps:")
    for s in steps:
        res = s['resource_id']
        acts = acts_by_res.get(res, [])
        act_summary = "; ".join(f"{a['event_time'][:10]} {a['event_type']} {a['reported_result']}" for a in acts)
        print(f"  [{s['phase']:12}] {s['operation']:25} | {s['system_id']:20} | {res:18} | ev={s['evidence_id']} | acts: {act_summary}")
