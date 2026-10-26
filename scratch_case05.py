"""Check system_activity for account_005."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts

ds = Path('dataset')
activity = read_csv(ds / 'system_activity.csv')
samples = {r['case_id']: r for r in read_csv(ds / 'sample_deletion_requests.csv')}

req = samples['case_05']
print('Case 05:', req.get('email'), 'audit_at:', req.get('audit_at'))

print('\n=== account_005 in activity ===')
for a in activity:
    blob = ' '.join(str(v) for v in a.values())
    if 'account_005' in blob:
        print(dict(a))
