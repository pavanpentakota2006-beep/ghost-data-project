import sys; sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts, pick
import csv

ds = Path('dataset')
system_activity = read_csv(ds / 'system_activity.csv')
worker_acts = [a for a in system_activity if pick(a, 'system_id') == 'deletion_worker']

samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}

print(f"Total worker acts: {len(worker_acts)}")
print("Sample worker act keys:", list(worker_acts[0].keys()) if worker_acts else "none")
if worker_acts:
    print("Sample worker act:", worker_acts[0])

for cid in ['case_23', 'case_24', 'case_29', 'case_30', 'case_11']:
    req = samples.get(cid)
    if not req:
        continue
    rep_at = req['reported_at']
    rep_dt = parse_ts(rep_at)
    print(f'\n{cid} reported_at={rep_at}')
    for a in worker_acts:
        adt = parse_ts(pick(a, 'ts'))
        if adt:
            diff = (adt - rep_dt).total_seconds() / 60.0
            if -120 <= diff <= 15:
                rid = pick(a, 'resource_id')
                tgt = a.get('target_system', '')
                src = pick(a, 'system_id')
                print(f'  diff={diff:.1f} rid={rid} tgt={tgt} src={src}')
