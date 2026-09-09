import re

with open("src/core/orchestrator.py", "r", encoding="utf-8") as f:
    content = f.read()

old_block = r"""            # 1. Base Inventory
            for pii in flow_data.get("pii_fields", []):
                rule_id = "personal-data-field-detected"
                msg = f"Personal data detected: {pii['field']}"
                if pii["field"] == "defaultChecked_checkbox":
                    rule_id = "consent-checkbox-default"
                    msg = f"Consent UI component: {pii['field']}"
                    
                finding = Finding(
                    category=Category.SECURITY.value,
                    severity="info",
                    file=pii["file"],
                    line=pii["line"],
                    message=msg,
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P3",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context="AST extracted node"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.INVENTORY
                )
                deduped_findings.append(finding)
                
            # 2. Unused PII -> MINIMISATION_FLAG
            for pii in flow_data.get("unused_pii_fields", []):
                rule_id = "unused-personal-data"
                finding = Finding(
                    category=Category.SECURITY.value,
                    severity="medium",
                    file=pii["file"],
                    line=pii["line"],
                    message=f"Personal data collected but never read/used: {pii['field']}",
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P2",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context="AST extracted node"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.MINIMISATION_FLAG,
                    gdpr_references=["Art. 5(1)(c)"],
                    code_context=REQUIREMENTS["Art. 5(1)(c)"]
                )
                deduped_findings.append(finding)
                
            # 3. Third-party transfers
            for tx in flow_data.get("third_party_transfers", []):
                rule_id = "third-party-transfer"
                proc = tx['processor']
                
                # Assume non-EU for these examples
                is_non_eu = proc in ['twilio', 'sendgrid', 'stripe']
                arts = ["Art. 28", "Art. 44-49"] if is_non_eu else ["Art. 28"]
                req = REQUIREMENTS["Art. 44-49"] if is_non_eu else REQUIREMENTS["Art. 28"]
                
                finding = Finding(
                    category=Category.SECURITY.value,
                    severity="high",
                    file=tx["file"],
                    line=tx["line"],
                    message=f"Personal data '{tx['field']}' transmitted to external service ({proc})",
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P2",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context="AST extracted node"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.THIRD_PARTY_RISK,
                    gdpr_references=arts,
                    code_context=req
                )
                deduped_findings.append(finding)
                
            # 4. Unprotected Storage
            for store in flow_data.get("unprotected_storage", []):
                rule_id = "unprotected-pii-storage"
                finding = Finding(
                    category=Category.SECURITY.value,
                    severity="high",
                    file=store["file"],
                    line=store["line"],
                    message=f"Personal data '{store['field']}' stored without detected encryption/hashing",
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P1",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context="AST extracted node"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=True,
                    compliance_finding_type=ComplianceFindingType.SECURITY_GAP,
                    gdpr_references=["Art. 32"],
                    code_context=REQUIREMENTS["Art. 32"]
                )
                deduped_findings.append(finding)"""

new_block = r"""            # 1. Base Inventory
            for pii in flow_data.get("pii_fields", []):
                rule_id = "personal-data-field-detected"
                msg = f"Personal data detected: {pii['field']}"
                if pii["field"] == "defaultChecked_checkbox":
                    rule_id = "consent-checkbox-default"
                    msg = f"Consent UI component: {pii['field']}"
                    
                finding = Finding(
                    category=Category.SECURITY.value,
                    severity="info",
                    file=pii["file"],
                    line=pii["line"],
                    message=msg,
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P3",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context="AST extracted node"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.INVENTORY
                )
                deduped_findings.append(finding)
                
                # Human review for consent UI
                if pii["field"] == "defaultChecked_checkbox":
                    deduped_findings.append(Finding(
                        category=Category.SECURITY.value,
                        severity="info",
                        file=pii["file"],
                        line=pii["line"],
                        message="Consent UI element requires legal review.",
                        rule_id="human-review-consent",
                        finding_id=str(uuid.uuid4()),
                        status="OPEN",
                        priority="P3",
                        title="GDPR: human-review-consent",
                        evidence=FindingEvidence(code_context="Consent UI element"),
                        detected_by=["data-flow-extractor"],
                        merge_blocking=False,
                        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                        code_context=REQUIREMENTS.get("HR_CONSENT", "")
                    ))
                
            # 2. Unused PII -> MINIMISATION_FLAG
            for pii in flow_data.get("unused_pii_fields", []):
                rule_id = "unused-personal-data"
                finding = Finding(
                    category=Category.SECURITY.value,
                    severity="medium",
                    file=pii["file"],
                    line=pii["line"],
                    message=f"Personal data collected but never read/used: {pii['field']}",
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P2",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context="AST extracted node"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.MINIMISATION_FLAG,
                    gdpr_references=["Art. 5(1)(c)"],
                    code_context=REQUIREMENTS["Art. 5(1)(c)"]
                )
                deduped_findings.append(finding)
                
            # 3. Third-party transfers
            for tx in flow_data.get("third_party_transfers", []):
                rule_id = "third-party-transfer"
                proc = tx['processor']
                
                is_non_eu = proc in ['twilio', 'sendgrid', 'stripe']
                arts = ["Art. 28", "Art. 44-49"] if is_non_eu else ["Art. 28"]
                req = REQUIREMENTS["Art. 44-49"] if is_non_eu else REQUIREMENTS["Art. 28"]
                
                finding = Finding(
                    category=Category.SECURITY.value,
                    severity="high",
                    file=tx["file"],
                    line=tx["line"],
                    message=f"Personal data '{tx['field']}' transmitted to external service ({proc})",
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P2",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context="AST extracted node"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.THIRD_PARTY_RISK,
                    gdpr_references=arts,
                    code_context=req
                )
                deduped_findings.append(finding)
                
                # Human review for 3rd party
                deduped_findings.append(Finding(
                    category=Category.SECURITY.value,
                    severity="info",
                    file=tx["file"],
                    line=tx["line"],
                    message=f"Third party processor ({proc}) requires legal review",
                    rule_id="human-review-processor",
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P3",
                    title="GDPR: human-review-processor",
                    evidence=FindingEvidence(code_context=proc),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                    code_context=REQUIREMENTS.get("HR_THIRD_PARTY", "")
                ))
                
                # Messaging Human review
                if proc in ["twilio", "sendgrid"]:
                    deduped_findings.append(Finding(
                        category=Category.SECURITY.value,
                        severity="info",
                        file=tx["file"],
                        line=tx["line"],
                        message="Cannot determine from source code whether this message is service-related or promotional; classification affects applicable consent requirements.",
                        rule_id="human-review-messaging",
                        finding_id=str(uuid.uuid4()),
                        status="OPEN",
                        priority="P3",
                        title="GDPR: human-review-messaging",
                        evidence=FindingEvidence(code_context=proc),
                        detected_by=["data-flow-extractor"],
                        merge_blocking=False,
                        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                        code_context=REQUIREMENTS.get("HR_MESSAGING", "")
                    ))
                
            # 4. Unprotected Storage
            for store in flow_data.get("unprotected_storage", []):
                rule_id = "unprotected-pii-storage"
                finding = Finding(
                    category=Category.SECURITY.value,
                    severity="info",
                    file=store["file"],
                    line=store["line"],
                    message=f"Storage protection for '{store['field']}' could not be verified from application code (schema declares plain String type)",
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P3",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context="AST extracted node"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                    gdpr_references=["Art. 32"]
                )
                deduped_findings.append(finding)"""

if old_block in content:
    content = content.replace(old_block, new_block)
    with open("src/core/orchestrator.py", "w", encoding="utf-8") as f:
        f.write(content)
    print("Patched src/core/orchestrator.py")
else:
    print("FAILED to patch orchestrator")
