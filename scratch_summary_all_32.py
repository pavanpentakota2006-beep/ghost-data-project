import csv, json

gold_rows = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8-sig'))}
samples = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8-sig'))}
manifest = {r['file_id']: r for r in csv.DictReader(open('dataset/evidence_files.csv', encoding='utf-8-sig'))}

# Summary of each case
for cid, (stat, steps) in sorted(gold_rows.items()):
    evs = set(s['evidence_id'] for s in steps if s['evidence_id'])
    findings = [s for s in steps if s['phase'] == 'FINDING']
    remedies = [s for s in steps if s['phase'] == 'REMEDIATION']
    verifies = [s for s in steps if s['phase'] == 'VERIFICATION']
    print(f"{cid}: {stat:10} | total={len(steps)} (find={len(findings)} rem={len(remedies)} ver={len(verifies)}) | ev={sorted(evs)}")
    if findings:
        for f in findings:
            print(f"   [F] {f['operation']} | {f['system_id']} | {f['resource_id']} | ev={f['evidence_id']}")
    else:
        for v in verifies:
            print(f"   [V] {v['operation']} | {v['system_id']} | {v['resource_id']} | ev={v['evidence_id']}")
