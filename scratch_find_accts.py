import csv, json
from pathlib import Path

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}

# Gather all dataset files
all_files = [p for p in Path('dataset').rglob('*') if p.is_file() and p.name not in ('sample_output.csv', 'output.csv')]

for cid in ['case_03', 'case_09', 'case_11', 'case_12', 'case_13', 'case_14', 'case_15', 'case_16', 'case_20', 'case_25']:
    req = samples[cid]
    stat, steps = gold_rows[cid]
    acct = next(s['resource_id'] for s in steps if s['system_id'] == 'account_service')
    print(f"\n{cid} ({req['email']}) -> {acct}:")
    for f in all_files:
        try:
            txt = f.read_text(encoding='utf-8', errors='ignore')
            if acct in txt:
                print(f"   Found in {f.name}")
        except Exception:
            pass
