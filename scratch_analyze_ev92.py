"""Analyze what evidence_92, evidence_54, evidence_51 contain for COMPLETE cases."""
import csv, json, sys
sys.path.insert(0, 'code')
from pathlib import Path
from audit.evidence import EvidenceIndex
from audit.util import read_csv, parse_ts

ds = Path('dataset')
ei = EvidenceIndex(ds)

# Check what observations are in evidence_92
print('=== evidence_92 observations ===')
for o in ei.obs_by_file.get('evidence_92', []):
    print(f'  {o.system_id} {o.resource_id} {o.status} tok={o.user_token}')

print()
print('=== evidence_54 observations ===')
for o in ei.obs_by_file.get('evidence_54', []):
    print(f'  {o.system_id} {o.resource_id} {o.status} tok={o.user_token}')

print()
print('=== evidence_51 observations ===')
for o in ei.obs_by_file.get('evidence_51', []):
    print(f'  {o.system_id} {o.resource_id} {o.status} tok={o.user_token}')
