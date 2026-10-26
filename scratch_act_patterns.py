"""Analyze what system_activity tells us about account/audit_record IDs for specific users."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts

ds = Path('dataset')
activity = read_csv(ds / 'system_activity.csv')

# Look at deletion_worker events to see what accounts/audit records are linked
print('=== deletion_worker events (first 30) ===')
for a in activity:
    if 'deletion_worker' in str(a.get('source_system', '')):
        tid = a.get('resource_id','')
        if 'account_' in tid or 'audit_record_' in tid:
            print(f"  ts={a.get('event_time','')} type={a.get('event_type','')} target={a.get('target_system','')} res={tid} result={a.get('reported_result','')} det={a.get('details','')[:60]}")

# Look specifically for user_61 (case_09) - which account was submitted to account_service
print('\n=== user_61 / k.appiah88 in activity ===')
for a in activity:
    blob = ' '.join(str(v) for v in a.values())
    if 'user_61' in blob or 'k.appiah88' in blob or 'appiah' in blob.lower():
        print(f"  {a.get('event_time','')} {a.get('event_type','')} {a.get('target_system','')} {a.get('resource_id','')} result={a.get('reported_result','')} det={a.get('details','')[:80]}")
