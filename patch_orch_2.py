
import re
with open("src/core/orchestrator.py", "r", encoding="utf-8") as f:
    text = f.read()

def repl(match):
    return match.group(0).replace("Category.SECURITY.value", "Category.PRIVACY.value")

# The block starts at `# 1. Base Inventory` and ends around `except Exception as e:`
pattern = re.compile(r'# 1\. Base Inventory.*?# Cross-reference security', re.DOTALL)

old_block = pattern.search(text).group(0)

# Build a totally new block
new_block = """# 1. Base Inventory
            for pii in flow_data.get("pii_fields", []):
                rule_id = "personal-data-field-detected"
                msg = f"Personal data detected: {pii['field']}"
                if pii["field"] == "defaultChecked_checkbox":
                    rule_id = "consent-checkbox-default"
                    msg = "Consent-related UI element detected; legal adequacy requires review."
                    
                finding = Finding(
                    category=Category.PRIVACY.value,
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
                        category=Category.PRIVACY.value,
                        severity="info",
                        file=pii["file"],
                        line=pii["line"],
                        message="Verify whether the consent language and user flow are legally adequate for informed consent.",
                        rule_id="human-review-consent",
                        finding_id=str(uuid.uuid4()),
                        status="OPEN",
                        priority="P3",
                        title="GDPR: human-review-consent",
                        evidence=FindingEvidence(code_context="Consent UI element"),
                        detected_by=["data-flow-extractor"],
                        merge_blocking=False,
                        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                        gdpr_references=["Art. 7"],
                        code_context=REQUIREMENTS.get("HR_CONSENT", "")
                    ))
                
            # 2. Unused PII -> MINIMISATION_FLAG
            for pii in flow_data.get("unused_pii_fields", []):
                rule_id = "unused-personal-data"
                finding = Finding(
                    category=Category.PRIVACY.value,
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
            
            # Deduplicate by processor and field
            tp_map = {}
            for tx in flow_data.get("third_party_transfers", []):
                key = (tx['processor'], tx['field'])
                if key not in tp_map:
                    tp_map[key] = []
                tp_map[key].append(tx)
                
            seen_processors = set()
            
            for (proc, field), tx_list in tp_map.items():
                rule_id = "third-party-transfer"
                
                # Combine locations
                locs_text = "\\n".join([f"- {t['file']}:{t['line']}" for t in tx_list])
                
                finding = Finding(
                    category=Category.PRIVACY.value,
                    severity="info",
                    file=tx_list[0]["file"],
                    line=tx_list[0]["line"],
                    message=f"Personal data '{field}' is transmitted to an external processor/service ({proc}).",
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P3",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context=f"Found at multiple locations:\\n{locs_text}"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.THIRD_PARTY_RISK,
                    gdpr_references=["Art. 28", "Art. 44-49"],
                    code_context="International-transfer applicability could not be determined from source code."
                )
                deduped_findings.append(finding)
                
                # Human review for 3rd party
                if proc not in seen_processors:
                    seen_processors.add(proc)
                    deduped_findings.append(Finding(
                        category=Category.PRIVACY.value,
                        severity="info",
                        file=tx_list[0]["file"],
                        line=tx_list[0]["line"],
                        message=f"Third party processor ({proc}) requires legal review for lawful basis, transparency, and processor-agreement adequacy.",
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
                    
                    if proc in ["twilio", "sendgrid", "wrapper[sendMessageToRecipients]", "wrapper[sendNotification]", "wrapper[sendOne]", "wrapper[sendWhatsAppViaMeta]"]:
                        deduped_findings.append(Finding(
                            category=Category.PRIVACY.value,
                            severity="info",
                            file=tx_list[0]["file"],
                            line=tx_list[0]["line"],
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
            # Group by field
            store_map = {}
            for store in flow_data.get("unprotected_storage", []):
                key = store["field"]
                if key not in store_map:
                    store_map[key] = []
                store_map[key].append(store)
                
            for field, store_list in store_map.items():
                rule_id = "unprotected-pii-storage"
                locs_text = "\\n".join([f"- {t['file']}:{t['line']}" for t in store_list])
                finding = Finding(
                    category=Category.PRIVACY.value,
                    severity="info",
                    file=store_list[0]["file"],
                    line=store_list[0]["line"],
                    message=f"Storage protection for '{field}' could not be verified from application code. Verify encryption at rest, database access controls, transport security, and retention.",
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P3",
                    title=f"GDPR: {rule_id}",
                    evidence=FindingEvidence(code_context=f"Found at multiple locations:\\n{locs_text}"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                    gdpr_references=["Art. 32"]
                )
                deduped_findings.append(finding)

        except Exception as e:
            print(f"Compliance extraction error: {e}")
            
        
        try:
            from src.compliance.security_evidence import cross_reference_security
            from src.compliance.suppression import filter_suppressed_findings
            
            # Cross-reference security"""

text = text.replace(old_block, new_block)
with open("src/core/orchestrator.py", "w", encoding="utf-8") as f:
    f.write(text)
