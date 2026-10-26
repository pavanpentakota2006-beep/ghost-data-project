"""Check case_09 - gold expects VERIFY_RECORD_ABSENT account_service account_3960."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts

ds = Path('dataset')
activity = read_csv(ds / 'system_activity.csv')
samples = {r['case_id']: r for r in read_csv(ds / 'sample_deletion_requests.csv')}

req = samples['case_09']
print('Case 09:', req.get('email'), 'audit_at:', req.get('audit_at'))

# user_61, k.appiah88@gmail.com → account_3960?
ids = read_csv(ds / 'user_identities.csv')
for r in ids:
    if 'appiah' in str(r).lower() or 'user_61' in str(r).lower():
        print('Identity:', dict(r))

# Look for account_3960 in activity
print('\n=== account_3960 activity ===')
for a in activity:
    blob = ' '.join(str(v) for v in a.values()).lower()
    if 'account_3960' in blob or 'k.appiah88@gmail.com' in blob or 'user_61' in blob:
        print(dict(a))

# Also look for audit_record_4902
print('\n=== audit_record_4902 activity ===')
for a in activity:
    blob = ' '.join(str(v) for v in a.values()).lower()
    if 'audit_record_4902' in blob:
        print(dict(a))
