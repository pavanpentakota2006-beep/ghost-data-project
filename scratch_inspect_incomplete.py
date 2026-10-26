import csv, json

gold = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig')))
for r in gold:
    if r['deletion_status'] != 'INCOMPLETE':
        continue
    cid = r['case_id']
    steps = json.loads(r['steps_json'])
    finds = [s for s in steps if s['phase'] == 'FINDING']
    rems = [s for s in steps if s['phase'] == 'REMEDIATION']
    vers = [s for s in steps if s['phase'] == 'VERIFICATION']
    
    find_res = {s['resource_id'] for s in finds}
    ver_res = {s['resource_id'] for s in vers}
    extra_ver = ver_res - find_res
    print(f"\n{cid}: {len(finds)} finds, {len(rems)} rems, {len(vers)} vers. Extra in vers: {extra_ver}")
    for v in vers:
        is_extra = v['resource_id'] in extra_ver
        print(f"   [{'EXTRA' if is_extra else 'REMED'}] {v['operation']} | {v['system_id']} | {v['resource_id']} | ev='{v['evidence_id']}'")
