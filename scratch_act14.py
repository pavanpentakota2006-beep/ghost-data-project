"""Look at system_activity for case_14 user_37 / y.tanaka32@gmail.com to understand account_3677 state."""
import csv, json, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts

ds = Path('dataset')
activity = read_csv(ds / 'system_activity.csv')
samples = {r['case_id']: r for r in read_csv(ds / 'sample_deletion_requests.csv')}

req14 = samples['case_14']
print('Case 14:', req14)
print()

# Look for activities referencing user_37, y.tanaka32@gmail.com, account_3677
tokens = {'user_37', 'y.tanaka32@gmail.com', 'account_3677'}
for a in activity:
    blob = ' '.join(str(v) for v in a.values()).lower()
    if any(t.lower() in blob for t in tokens):
        print(dict(a))
