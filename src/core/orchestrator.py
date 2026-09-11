import datetime
from typing import List, Dict

from .models import Report, Finding, ToolResult, ToolStatus, CategoryStatus, CategorySummary, Category
from .dedup import deduplicate_findings
from src.adapters.base import BaseAdapter

class Orchestrator:
    def __init__(self, adapters: List[BaseAdapter]):
        self.adapters = adapters

    def analyze(self, repo_url: str, repo_path: str) -> Report:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        tool_results: List[ToolResult] = []
        all_findings: List[Finding] = []
        
        category_to_tools: Dict[str, List[ToolResult]] = {cat.value: [] for cat in Category}
        
        for adapter in self.adapters:
            try:
                result = adapter.run(repo_path)
            except Exception as e:
                # Fallback if adapter completely crashes
                result = ToolResult(
                    tool=adapter.tool_name,
                    status=ToolStatus.ERROR,
                    error_message=str(e)
                )
            tool_results.append(result)
            
            for cat in adapter.categories:
                if cat not in category_to_tools:
                    category_to_tools[cat] = []
                category_to_tools[cat].append(result)
                
            if result.findings:
                all_findings.extend(result.findings)
                
        deduped_findings = deduplicate_findings(all_findings)
        
        # Phase 1, 2, 3: Shared Data Flow Extraction and Deterministic GDPR Checks
        try:
            from src.compliance.data_flow import extract_data_flow
            from src.core.models import FindingLocation, FindingEvidence, ComplianceFindingType
            from src.compliance.requirement_text import REQUIREMENTS
            import uuid
            
            flow_data = extract_data_flow(repo_path)
            
            # 1. Base Inventory - Consolidated by Personal Data Field/Type
            inventory_map = {}
            consent_checkboxes = []
            
            for pii in flow_data.get("pii_fields", []):
                if pii["field"] == "defaultChecked_checkbox":
                    consent_checkboxes.append(pii)
                else:
                    field_key = pii["field"]
                    if field_key not in inventory_map:
                        inventory_map[field_key] = []
                    inventory_map[field_key].append(pii)
                    
            for field, pii_list in inventory_map.items():
                rule_id = "personal-data-field-detected"
                msg = f"Personal data field '{field}' detected across {len(pii_list)} source location(s)."
                locs_text = "\n".join([f"- {item['file']}:{item['line']}" for item in pii_list])
                
                finding = Finding(
                    category=Category.PRIVACY.value,
                    severity="info",
                    file=pii_list[0]["file"],
                    line=pii_list[0]["line"],
                    message=msg,
                    rule_id=rule_id,
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P3",
                    title=f"GDPR Inventory: {field}",
                    evidence=FindingEvidence(code_context=f"Detected across {len(pii_list)} location(s):\n{locs_text}"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.INVENTORY
                )
                deduped_findings.append(finding)

            for pii in consent_checkboxes:
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
                    evidence=FindingEvidence(code_context="Consent UI element"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.INVENTORY
                )
                deduped_findings.append(finding)
                
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
                locs_text = "\n".join([f"- {t['file']}:{t['line']}" for t in tx_list])
                
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
                    evidence=FindingEvidence(code_context=f"Found at multiple locations:\n{locs_text}"),
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
                locs_text = "\n".join([f"- {t['file']}:{t['line']}" for t in store_list])
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
                    evidence=FindingEvidence(code_context=f"Found at multiple locations:\n{locs_text}"),
                    detected_by=["data-flow-extractor"],
                    merge_blocking=False,
                    compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                    gdpr_references=["Art. 32"]
                )
                deduped_findings.append(finding)

            # DPDP Act 2023 & DPDP Rules 2025 Engine Checks
            try:
                from src.compliance.dpdp_engine import run_dpdp_checks
                dpdp_findings = run_dpdp_checks(repo_path, flow_data, deduped_findings)
                deduped_findings.extend(dpdp_findings)
            except Exception as e:
                print(f"DPDP engine execution error: {e}")

            # EU Cyber Resilience Act (CRA) Engine Checks
            try:
                from src.compliance.cra_engine import run_cra_checks
                cra_findings = run_cra_checks(repo_path, deduped_findings)
                deduped_findings.extend(cra_findings)
            except Exception as e:
                print(f"CRA engine execution error: {e}")

            # India CERT-In Directions Engine Checks
            try:
                from src.compliance.cert_in_engine import run_cert_in_checks
                cert_in_findings = run_cert_in_checks(repo_path, deduped_findings)
                deduped_findings.extend(cert_in_findings)
            except Exception as e:
                print(f"CERT-In engine execution error: {e}")

        except Exception as e:
            print(f"Compliance extraction error: {e}")
            
        
        try:
            from src.compliance.security_evidence import cross_reference_security
            from src.compliance.suppression import filter_suppressed_findings
            
            # Cross-reference security
            gdpr_items = [f for f in deduped_findings if f.compliance_finding_type is not None]
            sec_gaps = cross_reference_security(gdpr_items, deduped_findings)
            deduped_findings.extend(sec_gaps)
            
            # Filter suppressions
            deduped_findings, dismissed_count = filter_suppressed_findings(deduped_findings, repo_path)
            self.dismissed_count = dismissed_count
        except Exception as e:
            print(f"Compliance processing error: {e}")
            self.dismissed_count = 0
            
        self.enrich_findings(deduped_findings, repo_path)

        
        def is_finding_in_category(f: Finding, cat: str) -> bool:
            if f.category == cat:
                return True
            if cat == Category.AI_DESIGN.value:
                if f.rule_id and f.rule_id.startswith("gemini/"):
                    return True
                if "apnimandi-design" in f.detected_by and f.rule_id and f.rule_id.startswith("gemini/"):
                    return True
            return False

        # Build category summaries
        summary: Dict[str, CategorySummary] = {}
        for cat, results in category_to_tools.items():
            cat_findings_count = sum(1 for f in deduped_findings if is_finding_in_category(f, cat))
            
            has_error = any(r.status == ToolStatus.ERROR for r in results)
            has_skipped = any(r.status == ToolStatus.SKIPPED for r in results)
            
            if has_error:
                status = CategoryStatus.ERROR
            elif has_skipped:
                if cat_findings_count > 0:
                    status = CategoryStatus.ISSUES_FOUND
                else:
                    status = CategoryStatus.SKIPPED
            elif cat_findings_count > 0:
                status = CategoryStatus.ISSUES_FOUND
            else:
                status = CategoryStatus.PASSED
                
            tool_summaries = {}
            for r in results:
                tool_dict = {
                    "status": r.status.value,
                    "finding_count": len([f for f in r.findings if is_finding_in_category(f, cat)])
                }
                if r.metrics:
                    tool_dict["metrics"] = {
                        "passed": r.metrics.passed,
                        "failed": r.metrics.failed,
                        "skipped": r.metrics.skipped,
                        "coverage_percent": r.metrics.coverage_percent
                    }
                if r.error_message:
                    tool_dict["error_message"] = r.error_message
                    
                tool_summaries[r.tool] = tool_dict
                
            summary[cat] = CategorySummary(
                status=status,
                count=cat_findings_count,
                tools=tool_summaries
            )
            
        report = Report(
            repo=repo_url,
            timestamp=timestamp,
            summary=summary,
            findings=deduped_findings,
            data_flow=flow_data if 'flow_data' in locals() else None
        )
        return report

    def enrich_findings(self, findings: List[Finding], repo_path: str):
        import os
        for f in findings:
            # Code Context
            file_path = f.location.file if f.location else None
            line_num = f.location.line if f.location else None
            
            if file_path and line_num and line_num > 0:
                abs_path = os.path.join(repo_path, file_path)
                if os.path.isfile(abs_path):
                    try:
                        with open(abs_path, 'r', encoding='utf-8', errors='replace') as file_obj:
                            lines = file_obj.readlines()
                            start = max(0, line_num - 3)
                            end = min(len(lines), line_num + 2)
                            if not f.evidence:
                                f.evidence = __import__('src.core.models', fromlist=['FindingEvidence']).FindingEvidence()
                            if not f.evidence.code_context:
                                f.evidence.code_context = "".join(lines[start:end])
                    except Exception:
                        pass
            
            # Priority & Merge Blocking logic
            severity = f.severity.lower()
            if severity in ("critical", "high"):
                f.priority = "P1"
                f.merge_blocking = True
            elif severity == "medium":
                f.priority = "P2"
                f.merge_blocking = False
            else:
                f.priority = "P3"
                f.merge_blocking = False
                
            # Exceptions for certain categories
            if f.category == Category.SECURITY.value and f.priority == "P2":
                # Escalate medium security issues
                f.merge_blocking = True
                
            # GDPR Mapping
            from src.compliance.gdpr_mapping import get_gdpr_articles_for_rule
            articles = get_gdpr_articles_for_rule(f.rule_id)
            if not articles and f.detected_by:
                for tool in f.detected_by:
                    articles.extend(get_gdpr_articles_for_rule(f"{tool}/*"))
            
            f.gdpr_references = list(set(articles))

            # CRA Mapping
            from src.compliance.cra_mapping import get_cra_references_for_rule
            cra_refs = get_cra_references_for_rule(f.rule_id, f.detected_by)
            if cra_refs:
                existing_cra = set(f.cra_references or [])
                existing_cra.update(cra_refs)
                f.cra_references = sorted(list(existing_cra))

            # Compliance Manager Questions Enrichment
            from src.compliance.requirement_text import get_finding_spec
            spec = get_finding_spec(f.rule_id)
            if not f.requirement and spec.get("requirement"):
                f.requirement = spec["requirement"]
            if not f.detected_evidence:
                code_ctx = f.evidence.code_context if f.evidence else ""
                loc_str = f"{f.location.file}:{f.location.line}" if f.location and f.location.file else "unknown location"
                f.detected_evidence = f"WHAT WAS DETECTED: {f.description} (Location: {loc_str})" + (f"\nCode Context:\n{code_ctx}" if code_ctx else "")
            if not f.recommended_action and spec.get("recommended_action"):
                f.recommended_action = spec["recommended_action"]
            if not f.human_review_required and spec.get("human_review_required"):
                f.human_review_required = spec["human_review_required"]
