import sys; sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts, pick
from audit.identity import IdentityResolver
from audit.evidence import EvidenceIndex
import csv, json

ds = Path('dataset')
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
gold = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
ir = IdentityResolver(ds)
ei = EvidenceIndex(ds)

system_activity = read_csv(ds / 'system_activity.csv')
worker_acts = [a for a in system_activity if pick(a, 'system_id') == 'deletion_worker']

# For cases with wrong account detection, check what token match we can do on activity details
for cid in ['case_23', 'case_29', 'case_30']:
    req = samples.get(cid)
    if not req:
        continue
    ident = ir.resolve(req['email'], req['audit_at'])
    tokens = ident.all_identifiers() | {ident.user_id.lower(), ident.user_id} if ident else set()
    
    # Gold answer account
    g_status, g_steps = gold[cid]
    g_accts = [s['resource_id'] for s in g_steps if s['system_id'] == 'account_service']
    g_audit_records = [s['resource_id'] for s in g_steps if s['system_id'] == 'security_service']
    
    print(f'\n{cid}: uid={ident.user_id if ident else None}')
    print(f'  Gold accounts: {g_accts}')
    print(f'  Gold audit_records: {g_audit_records}')
    
    # Check activity for user token match
    rep_at = req['reported_at']
    rep_dt = parse_ts(rep_at)
    for a in worker_acts:
        adt = parse_ts(pick(a, 'ts'))
        if adt:
            diff = (adt - rep_dt).total_seconds() / 60.0
            if -120 <= diff <= 15:
                rid = pick(a, 'resource_id')
                details = a.get('details', '')
                # Check if details mention user tokens
                for tok in tokens:
                    if tok and tok in details.lower():
                        print(f'  MATCH in details: diff={diff:.1f} rid={rid} tok={tok}')
    
    # Check evidence obs for account
    for fid, ob_list in ei.obs_by_file.items():
        mf = ei.manifest[fid]
        cat = pick(mf, 'ts')
        if cat > req['audit_at']:
            continue
        for o in ob_list:
            if o.system_id == 'account_service' and o.user_token in tokens:
                print(f'  Evidence account match: {o.resource_id} fid={fid} tok={o.user_token} status={o.status}')
