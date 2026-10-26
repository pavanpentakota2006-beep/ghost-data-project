"""Check timing of account_3960 deletion vs case_09 reported_at."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts

ds = Path('dataset')
activity = read_csv(ds / 'system_activity.csv')
samples = {r['case_id']: r for r in read_csv(ds / 'sample_deletion_requests.csv')}

req = samples['case_09']
rep_at = req.get('reported_at', '')
rep_dt = parse_ts(rep_at)
print(f'case_09 reported_at={rep_at} = {rep_dt}')
print(f'case_09 requested_at={req.get("requested_at")}')

# Find all deletion_worker events near reported_at for account_service
from audit.util import pick
worker_acts = [a for a in activity if a.get('source_system') == 'deletion_worker']

print('\nWorker acts near reported_at (±90 min):')
for a in worker_acts:
    tgt = a.get('target_system', '')
    if tgt == 'account_service':
        adt = parse_ts(a.get('event_time', ''))
        if adt and rep_dt:
            diff = (adt - rep_dt).total_seconds() / 60.0
            if -90 <= diff <= 10:
                print(f'  diff={diff:.1f}min {a.get("event_time")} {a.get("resource_id")} result={a.get("reported_result")}')

# Also check security_service worker acts near reported_at
print('\nAll worker acts near reported_at (±180 min, any service):')
for a in worker_acts:
    adt = parse_ts(a.get('event_time', ''))
    if adt and rep_dt:
        diff = (adt - rep_dt).total_seconds() / 60.0
        if -180 <= diff <= 30:
            print(f'  diff={diff:.1f}min {a.get("event_time")} {a.get("target_system")} {a.get("resource_id")} result={a.get("reported_result")}')
