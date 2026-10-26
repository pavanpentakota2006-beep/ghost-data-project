"""Find audit_record_4902 in evidence files."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, 'code')
from pathlib import Path
from audit.util import read_csv
from audit.evidence import EvidenceIndex

ds = Path('dataset')
ei = EvidenceIndex(ds)

# Check all files for audit_record_4902
print('=== audit_record_4902 in observations ===')
for fid, obs in ei.obs_by_file.items():
    for o in obs:
        if 'audit_record_4902' in o.resource_id:
            print(f'  fid={fid} {o.system_id} {o.resource_id} {o.status} tok={o.user_token}')

# Check which users in evidence have account_3960 or user_61
print('\n=== account_3960 in evidence ===')
for fid, obs in ei.obs_by_file.items():
    for o in obs:
        if 'account_3960' in o.resource_id:
            print(f'  fid={fid} {o.system_id} {o.resource_id} {o.status} tok={o.user_token}')

# Check which evidence files contain k.appiah88 or user_61
print('\n=== k.appiah88@gmail.com or user_61 in evidence ===')
for fid, obs in ei.obs_by_file.items():
    for o in obs:
        if 'k.appiah88' in o.user_token or 'user_61' == o.user_token:
            print(f'  fid={fid} {o.system_id} {o.resource_id} {o.status} tok={o.user_token}')
