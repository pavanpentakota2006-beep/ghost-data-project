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

system_activity = read_csv(ds / 'system_activity.csv')
worker_acts = [a for a in system_activity if pick(a, 'system_id') == 'deletion_worker']

# For cases with wrong account detection, check the activity details text
for cid in ['case_23', 'case_24', 'case_29', 'case_30']:
    req = samples.get(cid)
    if not req:
        continue
    ident = ir.resolve(req['email'], req['audit_at'])
    tokens = ident.all_identifiers() | {ident.user_id.lower(), ident.user_id} if ident else set()
    
    g_status, g_steps = gold[cid]
    g_accts = [s['resource_id'] for s in g_steps if s['system_id'] == 'account_service']
    
    print(f'\n{cid}: uid={ident.user_id if ident else None} gold_accts={g_accts}')
    
    # Check activity details for token
    rep_at = req['reported_at']
    rep_dt = parse_ts(rep_at)
    for a in worker_acts:
        adt = parse_ts(pick(a, 'ts'))
        if adt:
            diff = (adt - rep_dt).total_seconds() / 60.0
            if -120 <= diff <= 15:
                rid = pick(a, 'resource_id')
                details = a.get('details', '')
                for tok in tokens:
                    if tok and len(tok) > 3 and tok in details:
                        print(f'  MATCH: diff={diff:.1f} rid={rid} tok={tok[:30]} detail={details[:80]}')
