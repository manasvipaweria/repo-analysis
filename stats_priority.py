import json

with open('report.json', 'r') as f:
    data = json.load(f)

findings = data.get('findings', [])
levels = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

for fd in findings:
    lvl = fd.get('priority_level')
    if lvl in levels:
        levels[lvl] += 1

print(f'Total findings: {len(findings)}')
for k, v in levels.items():
    print(f'{k}: {v}')

print('\nTop 10 highest-priority findings:')
sorted_findings = sorted([f for f in findings if f.get('priority_score') is not None], key=lambda x: x.get('priority_score', 0), reverse=True)

for i, f in enumerate(sorted_findings[:10]):
    loc = f.get('location', {})
    file = loc.get('file', '') if loc else ''
    print(f'{i+1}. [{f.get("priority_level")}] Score {f.get("priority_score")} | Rule: {f.get("rule_id")} | File: {file} | Group: {f.get("group_id")}')
    reasons = f.get('priority_reasons', [])
    reason_str = '; '.join(reasons) if reasons else 'None'
    print(f'   Reason: {reason_str}')
