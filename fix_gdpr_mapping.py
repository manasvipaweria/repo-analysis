import re

with open("src/compliance/gdpr_mapping.py", "r", encoding="utf-8") as f:
    text = f.read()

# Fix: add missing rules to deterministic checks
text = text.replace(
    '        new_deterministic_checks=[],\n        evidence_types=["TLS settings", "Hashing", "Secure cookies", "Dependencies"],',
    '        new_deterministic_checks=["unprotected-pii-storage"],\n        evidence_types=["TLS settings", "Hashing", "Secure cookies", "Dependencies"],'
)

text = text.replace(
    '        new_deterministic_checks=["outbound-domain-extraction"],\n        evidence_types=["package.json", "3rd party SDKs", "Outbound HTTP domains"],',
    '        new_deterministic_checks=["outbound-domain-extraction", "third-party-transfer", "human-review-processor"],\n        evidence_types=["package.json", "3rd party SDKs", "Outbound HTTP domains"],'
)

text = text.replace(
    '        new_deterministic_checks=["personal-data-field-detected"],\n        evidence_types=["DTOs", "DB schemas", "Form inputs"],',
    '        new_deterministic_checks=["personal-data-field-detected", "unused-personal-data"],\n        evidence_types=["DTOs", "DB schemas", "Form inputs"],'
)

with open("src/compliance/gdpr_mapping.py", "w", encoding="utf-8") as f:
    f.write(text)
