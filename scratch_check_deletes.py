"""Check system activity deletion events for accounts in evidence_03 that appear as PRESENT."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts

ds = Path('dataset')
activity = read_csv(ds / 'system_activity.csv')
samples = {r['case_id']: r for r in read_csv(ds / 'sample_deletion_requests.csv')}

# Accounts flagged as PRESENT in evidence_03 that appear as findings in our pred but not gold
accounts = ['account_4248', 'account_9335', 'account_3677']
for acct in accounts:
    print(f'\n=== {acct} ===')
    for a in activity:
        blob = ' '.join(str(v) for v in a.values()).lower()
        if acct.lower() in blob:
            print(f'  {a.get("event_time","?")} {a.get("event_type","?")} {a.get("source_system","?")} result={a.get("reported_result","?")} details={a.get("details","")[:80]}')
