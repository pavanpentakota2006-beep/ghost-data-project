"""Trace account detection for case_11."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts
from audit.identity import IdentityResolver
from collections import defaultdict
from audit.util import pick

ds = Path('dataset')
activity = read_csv(ds / 'system_activity.csv')
samples = {r['case_id']: r for r in read_csv(ds / 'sample_deletion_requests.csv')}
resolver = IdentityResolver(ds)

for cid in ['case_11', 'case_12', 'case_14', 'case_15', 'case_16', 'case_17']:
    req = samples[cid]
    ident = resolver.resolve(req['email'], req['audit_at'])
    if not ident:
        print(f'\n=== {cid} ident not found for {req["email"]} ===')
        continue
    uid = ident.user_id
    rep_at = req.get('reported_at', '')
    rep_dt = parse_ts(rep_at)
    cutoff = parse_ts(req.get('audit_at', ''))
    
    print(f'\n=== {cid} uid={uid} email={req["email"]} reported_at={rep_at} ===')
    
    worker_acts = [a for a in activity if pick(a, 'system_id') == 'deletion_worker']
    
    acct_cands = []
    for a in worker_acts:
        tgt = pick(a, 'origin') or a.get('target_system', '')
        if tgt == 'account_service':
            rid = pick(a, 'resource_id')
            adt = parse_ts(pick(a, 'ts'))
            if adt and rep_dt:
                diff = (adt - rep_dt).total_seconds() / 60.0
                if -90 <= diff <= 10 and (cutoff is None or adt <= cutoff):
                    result = pick(a, 'status')
                    acct_cands.append((abs(diff), rid, result))
    
    acct_cands.sort(key=lambda x: x[0])
    print(f'  Account candidates (within ±90min): {acct_cands[:5]}')
    
    # Check what accounts are in evidence for this user
    from audit.evidence import EvidenceIndex
    ei = EvidenceIndex(ds)
    tokens = ident.all_identifiers() | {uid.lower(), uid}
    for fid, obs in ei.obs_by_file.items():
        for o in obs:
            if o.system_id == 'account_service' and (o.user_token in tokens or any(t == o.user_token for t in tokens if len(t) > 3)):
                print(f'  Evidence: {fid} {o.resource_id} {o.status}')
