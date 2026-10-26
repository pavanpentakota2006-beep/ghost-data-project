import csv, glob
from pathlib import Path

resources = ['account_3866', 'analytics_4574', 'support_4707', 'data_flow_2295', 'backup_5970', 'audit_record_3830']

for r in resources:
    print(f"\nSearching for {r}:")
    for f in Path('dataset').rglob('*'):
        if f.is_file() and f.suffix in ('.csv', '.json', '.sql', '.log', '.txt'):
            try:
                txt = f.read_text(encoding='utf-8', errors='ignore')
                if r in txt:
                    print(f"  Found in {f.name}")
                    for line in txt.splitlines():
                        if r in line:
                            print(f"    {line.strip()[:140]}")
            except Exception:
                pass
