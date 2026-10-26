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

# For each case, find EXACT token match for security_service
for cid in ['case_23', 'case_24', 'case_29', 'case_30']:
    req = samples.get(cid)
    if not req:
        continue
    ident = ir.resolve(req['email'], req['audit_at'])
    uid = ident.user_id if ident else ''
    tokens = ident.all_identifiers() | {uid, uid.lower()} if ident else set()
    
    g_status, g_steps = gold[cid]
    g_audit_records = [(s['resource_id'], s.get('evidence_id', '')) for s in g_steps if s['system_id'] == 'security_service']
    
    print(f'\n{cid}: uid={uid}')
    print(f'  Gold audit records: {g_audit_records}')
    print(f'  User tokens: {sorted(tokens)}')
    
    # Use EXACT match - check for user_id as exact token in evidence
    for fid, ob_list in ei.obs_by_file.items():
        mf = ei.manifest[fid]
        cat = pick(mf, 'ts')
        if cat > req['audit_at']:
            continue
        for o in ob_list:
            if o.system_id == 'security_service':
                # Exact token check
                if o.user_token == uid.lower() or o.user_token == uid:
                    print(f'  EXACT MATCH: {o.resource_id} fid={fid} tok={o.user_token}')
