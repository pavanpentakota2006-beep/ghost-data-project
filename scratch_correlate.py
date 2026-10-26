import csv, json
from collections import defaultdict

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
users = {r['user_id']: r for r in csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8-sig'))}
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}

# Map sample cases to users
email_to_uid = {r['email']: r['user_id'] for r in users.values()}
# audit log
for r in csv.DictReader(open('dataset/user_audit_log.csv', encoding='utf-8-sig')):
    if r['field_name'] == 'email':
        email_to_uid[r['old_value']] = r['user_id']
        email_to_uid[r['new_value']] = r['user_id']

# Look at system_activity for each user
activities_by_user = defaultdict(list)
activities_by_res = defaultdict(list)
for r in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')):
    res = r['resource_id']
    activities_by_res[res].append(r)
    # check if user or email or resource mentions user
    for uid, u in users.items():
        if uid in r['details'] or u['email'] in r['details'] or (u['name'] and u['name'] in r['details']):
            activities_by_user[uid].append(r)

for cid in ['case_01', 'case_03', 'case_05', 'case_11', 'case_26', 'case_31']:
    req = samples[cid]
    uid = email_to_uid.get(req['email'])
    g_stat, g_steps = gold_rows[cid]
    print(f"\n=== {cid} (user={uid}, {req['email']}) gold={g_stat} ===")
    gold_res = {s['resource_id'] for s in g_steps}
    print("Gold resources:", gold_res)
    user_acts = activities_by_user[uid]
    print(f"Activities referencing user ({len(user_acts)}):")
    for a in user_acts:
        print(f"  {a['event_time']} | {a['event_type']} | {a['target_system']} | res={a['resource_id']} | {a['reported_result']} | {a['details']}")
