"""Analyze gold output patterns for COMPLETE cases to understand what we're missing."""
import csv, json, sys
sys.path.insert(0, 'code')

gold = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'] or '[]'))
        for r in csv.DictReader(open('dataset/sample_output.csv', newline='', encoding='utf-8-sig'))}

# Show all COMPLETE cases
print('=== COMPLETE CASES ===')
for cid in sorted(gold):
    gs, gsteps = gold[cid]
    if gs == 'COMPLETE':
        print(f'\n{cid}: {gs}')
        for s in gsteps:
            print(f'  {s["step_no"]}. {s["operation"]} {s["system_id"]} {s["resource_id"]} ev={s["evidence_id"]}')

# Show what evidence_92 ABSENT accounts are linked to 
print('\n=== Security records in INCOMPLETE cases ===')
for cid in sorted(gold):
    gs, gsteps = gold[cid]
    sec_steps = [s for s in gsteps if s['system_id'] == 'security_service']
    if sec_steps:
        print(f'{cid} ({gs}): {[(s["operation"], s["resource_id"]) for s in sec_steps]}')
