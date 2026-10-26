import sys; sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts, pick
from audit.identity import IdentityResolver
import csv, json

ds = Path('dataset')
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
gold = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
ir = IdentityResolver(ds)
system_activity = read_csv(ds / 'system_activity.csv')

# For case_23: account_410, case_29: account_7012 - find in system_activity
for cid, gold_acct in [('case_23', 'account_410'), ('case_29', 'account_7012'), ('case_30', 'account_4163')]:
    req = samples.get(cid)
    if not req:
        continue
    ident = ir.resolve(req['email'], req['audit_at'])
    tokens = ident.all_identifiers() | {ident.user_id.lower(), ident.user_id} if ident else set()
    uid = ident.user_id if ident else ''
    
    print(f'\n{cid}: uid={uid} gold_acct={gold_acct}')
    
    # Search ALL system_activity for this account  
    for a in system_activity:
        rid = pick(a, 'resource_id')
        if rid == gold_acct:
            print(f'  Activity for {gold_acct}: type={a.get("event_type","")} src={a.get("source_system","")} tgt={a.get("target_system","")} details={a.get("details","")[:80]}')
    
    # Search for uid in details
    for a in system_activity:
        details = a.get('details', '')
        if uid in details and gold_acct in details:
            print(f'  UID+ACCT in details: {details[:100]}')
    
    # Search for uid in resource_id column of activity that leads to account
    for a in system_activity:
        if uid and uid == pick(a, 'resource_id'):
            print(f'  UID as resource: src={a.get("source_system","")} tgt={a.get("target_system","")} type={a.get("event_type","")}')
