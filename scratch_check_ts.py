import sys; sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, pick, parse_ts

ds = Path('dataset')
manifest = {r['file_id']: r for r in read_csv(ds / 'evidence_files.csv')}
samples = {r['case_id']: r for r in read_csv(ds / 'sample_deletion_requests.csv')}

m02 = manifest.get('evidence_02')
print('evidence_02:', m02)

for cid in ['case_23', 'case_24', 'case_29', 'case_30']:
    req = samples.get(cid)
    if req:
        audit_at = req['audit_at']
        cat_str = m02.get('captured_at', '')
        cutoff = parse_ts(audit_at)
        cat = parse_ts(cat_str)
        print(f"{cid} audit_at={audit_at} vs captured_at={cat_str} -> excluded={cat and cutoff and cat > cutoff}")
