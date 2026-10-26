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

# Build a uid -> account mapping from worker_acts (need to also include details parsing)
# Check if worker_acts contain email or uid in details
print("Analyzing worker act details patterns:")
import re
for a in worker_acts[:5]:
    print(f"  details: {a.get('details', '')}")

# For each case, check what's the worker account for the user
# Look at the time window around deletion_request, find all accounts touched
# Then correlate with user's identifiers from evidence

# Check if security_service audit records link to users
for cid in ['case_23', 'case_29', 'case_30']:
    req = samples.get(cid)
    if not req:
        continue
    ident = ir.resolve(req['email'], req['audit_at'])
    uid = ident.user_id if ident else ''
    tokens = ident.all_identifiers() | {uid.lower(), uid} if ident else set()
    
    g_status, g_steps = gold[cid]
    g_audit_records = [(s['resource_id'], s.get('evidence_id', '')) for s in g_steps if s['system_id'] == 'security_service']
    
    print(f'\n{cid}: uid={uid} gold audit records={g_audit_records}')
    
    # Search for audit records in system activity
    for a in system_activity:
        rid = pick(a, 'resource_id')
        if rid.startswith('audit_record') and uid in a.get('details', ''):
            print(f'  SA: {rid} details={a.get("details","")[:80]}')
    
    # Search in evidence for audit records linked to this user
    from audit.evidence import EvidenceIndex
    ei = EvidenceIndex(ds)
    for fid, ob_list in ei.obs_by_file.items():
        mf = ei.manifest[fid]
        cat = pick(mf, 'ts')
        if cat > req['audit_at']:
            continue
        for o in ob_list:
            if o.system_id == 'security_service' and (o.user_token in tokens or uid in o.user_token):
                print(f'  EV: {o.resource_id} fid={fid} tok={o.user_token}')
