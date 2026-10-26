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

# Check all security_service observations in evidence
print("All security_service obs across all evidence (sample):")
for fid, obs in ei.obs_by_file.items():
    sec_obs = [o for o in obs if o.system_id == 'security_service']
    if sec_obs:
        print(f"  {fid} ({len(sec_obs)} sec obs):")
        for o in sec_obs[:3]:
            print(f"    {o.resource_id} tok={o.user_token}")

# For specific audit records in gold, find evidence
target_ars = {'audit_record_4128', 'audit_record_7095', 'audit_record_3954', 'audit_record_1707', 
              'audit_record_4902', 'audit_record_5569', 'audit_record_6645'}
print("\nTarget audit records in observations:")
for ar in target_ars:
    obs = ei.obs_by_resource.get(ar, [])
    if obs:
        for o in obs:
            print(f"  {ar}: fid={o.fid} tok={o.user_token}")
    else:
        print(f"  {ar}: NOT IN evidence")

# Check system_activity for these audit records
print("\nSystem activity for target audit records:")
for a in system_activity:
    rid = pick(a, 'resource_id')
    if rid in target_ars:
        print(f"  {rid}: src={a.get('source_system','')} type={a.get('event_type','')} det={a.get('details','')[:60]}")
