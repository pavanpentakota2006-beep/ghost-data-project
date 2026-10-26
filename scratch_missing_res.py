import csv, json
from pathlib import Path

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
all_resources = set(s['resource_id'] for stat, steps in gold_rows.values() for s in steps)
activity_res = set(r['resource_id'] for r in csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8-sig')))
missing = all_resources - activity_res

print(f"Missing count: {len(missing)}")
evidence_files = list(Path('dataset/evidence').rglob('*'))
res_to_files = {}
for m in missing:
    res_to_files[m] = []
    for ef in evidence_files:
        if ef.is_file():
            try:
                txt = ef.read_text(encoding='utf-8', errors='ignore')
                if m in txt:
                    res_to_files[m].append(ef.name)
            except Exception:
                pass
    print(f"  {m:25} -> {res_to_files[m]}")
