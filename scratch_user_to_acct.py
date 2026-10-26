import csv, json

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
users = {r['user_id']: r for r in csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8-sig'))}
email_to_uid = {r['email']: r['user_id'] for r in users.values()}
for r in csv.DictReader(open('dataset/user_audit_log.csv', encoding='utf-8-sig')):
    if r['field_name'] == 'email':
        email_to_uid[r['old_value']] = r['user_id']
        email_to_uid[r['new_value']] = r['user_id']

for cid, (stat, steps) in sorted(gold_rows.items()):
    req = samples[cid]
    uid = email_to_uid.get(req['email'])
    acct_steps = [s['resource_id'] for s in steps if s['system_id'] == 'account_service']
    print(f"{cid} | user={uid:8} | email={req['email']:25} | acct_res={acct_steps}")
