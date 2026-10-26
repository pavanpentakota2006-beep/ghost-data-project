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

# Check audit records in system_activity
for cid, gold_ar in [('case_23', 'audit_record_4128'), ('case_24', 'audit_record_7095'), ('case_29', 'audit_record_3954'), ('case_30', 'audit_record_1707')]:
    req = samples.get(cid)
    if not req:
        continue
    ident = ir.resolve(req['email'], req['audit_at'])
    uid = ident.user_id if ident else ''
    
    print(f'\n{cid}: uid={uid} gold_ar={gold_ar}')
    for a in system_activity:
        rid = pick(a, 'resource_id')
        if rid == gold_ar:
            print(f'  SA: type={a.get("event_type","")} src={a.get("source_system","")} tgt={a.get("target_system","")} det={a.get("details","")[:80]}')
    
    # Also check user audit_log csv for this user
    audit_log = read_csv(ds / 'user_audit_log.csv')
    user_audits = [r for r in audit_log if r.get('user_id') == uid]
    print(f'  User audit log rows: {len(user_audits)}')
    for r in user_audits:
        # Does it have a resource_id?
        rid = pick(r, 'resource_id')
        if rid:
            print(f'    audit row rid={rid} field={pick(r,"field")} ts={pick(r,"ts")}')
