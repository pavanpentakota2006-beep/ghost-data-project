"""Trace case_09 through the planner to understand missing account verification."""
import sys, logging
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts
from audit.identity import IdentityResolver
from audit.planner import Planner
from audit.evidence import EvidenceIndex

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s %(message)s')

ds = Path('dataset')
samples = {r['case_id']: r for r in read_csv(ds / 'sample_deletion_requests.csv')}
resolver = IdentityResolver(ds)
planner = Planner(ds)
ei = EvidenceIndex(ds)

for cid in ['case_09', 'case_14', 'case_17']:
    req = samples[cid]
    ident = resolver.resolve(req['email'], req['audit_at'])
    print(f'\n=== {cid} ident={ident.user_id} emails={ident.emails} ===')
    
    # Trace account detection
    user_acct = planner._get_case_account(req, ident.user_id)
    print(f'  user_account={user_acct}')
    
    # Check what observations are present for the user
    cutoff = parse_ts(req['audit_at'])
    tokens = ident.all_identifiers() | {ident.user_id.lower(), ident.user_id}
    user_obs = []
    for fid, ob_list in ei.obs_by_file.items():
        ts = parse_ts(ei.manifest[fid].get('captured_at') or ei.manifest[fid].get('timestamp'))
        if cutoff and ts and ts > cutoff:
            continue
        for o in ob_list:
            if o.user_token and (o.user_token in tokens or any(t == o.user_token for t in tokens if len(t) > 3)):
                user_obs.append(o)
            elif user_acct and o.resource_id == user_acct:
                user_obs.append(o)
    
    print(f'  user_obs count={len(user_obs)}')
    for o in user_obs:
        print(f'    {o.system_id} {o.resource_id} {o.status} fid={o.fid}')
    
    status, steps = planner.audit(ident, req)
    print(f'\n  Result: {status} ({len(steps)} steps)')
    for s in steps:
        print(f'    {s["step_no"]}. {s["operation"]} {s["system_id"]} {s["resource_id"]}')
