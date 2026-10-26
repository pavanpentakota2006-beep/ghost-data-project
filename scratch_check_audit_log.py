import sys; sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, pick, parse_ts

ds = Path('dataset')
audit_log = read_csv(ds / 'user_audit_log.csv')
print("user_audit_log columns:", list(audit_log[0].keys()) if audit_log else "empty")
print("First row:", audit_log[0] if audit_log else "empty")

# Check for user_23 entries
for r in audit_log:
    if r.get('user_id') == 'user_23':
        print("user_23:", r)
    if r.get('user_id') == 'user_29':
        print("user_29:", r)
    if r.get('user_id') == 'user_30':
        print("user_30:", r)

# Check if there's an audit_record field
print("\nSample rows:")
for r in audit_log[:3]:
    print(r)
