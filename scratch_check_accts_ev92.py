import json

data = json.loads(open('dataset/evidence/records/service_resource_export_20260915_114455.json', encoding='utf-8').read())
se = data['service_exports']
targets = {'account_410', 'account_7012', 'account_4163', 'account_5334', 'account_4248'}

for item in se['account_service']['profile_lookups']:
    rid = item.get('resource_id')
    if rid in targets:
        print(f"{rid}: status_code={item.get('status_code')} profile={item.get('profile')}")

# Check all accounts in evidence_92
print("\nAll account lookups in evidence_92:")
for item in se['account_service']['profile_lookups']:
    print(f"  {item.get('resource_id')}: sc={item.get('status_code')}")
