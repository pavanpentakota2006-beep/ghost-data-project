"""Check evidence_03 contents and timestamps."""
import csv, json, sys
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv, parse_ts
from audit.evidence import EvidenceIndex

ds = Path('dataset')
ei = EvidenceIndex(ds)
manifest = {r['file_id']: r for r in read_csv(ds / 'evidence_files.csv')}
samples = {r['case_id']: r for r in read_csv(ds / 'sample_deletion_requests.csv')}

m03 = manifest.get('evidence_03', {})
print('evidence_03 manifest:', m03)
print()

# Get observations from evidence_03
print('=== evidence_03 observations ===')
for o in ei.obs_by_file.get('evidence_03', []):
    print(f'  {o.system_id} {o.resource_id} {o.status} tok={o.user_token}')

# Check audit_at for case_14 vs captured_at for evidence_03
for cid in ['case_11', 'case_12', 'case_13', 'case_14', 'case_15', 'case_16']:
    req = samples.get(cid, {})
    if req:
        audit_at = req.get('audit_at', '')
        cat = m03.get('captured_at') or m03.get('timestamp') or ''
        cutoff = parse_ts(audit_at)
        cat_dt = parse_ts(cat)
        print(f'{cid} audit_at={audit_at} evidence_03 captured={cat} excluded={cat_dt and cutoff and cat_dt > cutoff}')
