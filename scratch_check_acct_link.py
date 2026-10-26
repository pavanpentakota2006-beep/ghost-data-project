import csv, json
from datetime import datetime

samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8', errors='ignore')))
gold_rows = {r['case_id']: json.loads(r['steps_json']) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8', errors='ignore'))}
acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8', errors='ignore')))
users = {r['user_id']: r for r in csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8', errors='ignore'))}
email_to_uid = {r['email'].lower(): r['user_id'] for r in users.values()}

for s in samples:
    cid = s['case_id']
    steps = gold_rows[cid]
    acct = next((st['resource_id'] for st in steps if st['system_id'] == 'account_service'), None)
    rep_at = s['reported_at']
    rep_dt = datetime.fromisoformat(rep_at.replace('Z', '+00:00'))
    
    # Check acts near reported_at
    acct_acts = []
    for a in acts:
        if a['target_system'] == 'account_service' and a['resource_id'] == acct:
            adt = datetime.fromisoformat(a['event_time'].replace('Z', '+00:00'))
            diff = (adt - rep_dt).total_seconds() / 60.0
            acct_acts.append((diff, a))
            
    print(f"{cid}: acct={acct} | acts_found={len(acct_acts)}")
    for diff, a in acct_acts:
        print(f"   diff={diff:6.1f}m | {a['event_time']} | {a['event_type']} | {a['reported_result']} | {a['details']}")
