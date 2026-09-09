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
            
            # 1. Base Inventory
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
                deduped_findings.append(finding)

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

        
        # Build category summaries
        summary: Dict[str, CategorySummary] = {}
        for cat, results in category_to_tools.items():
            cat_findings_count = sum(1 for f in deduped_findings if f.category == cat)
            
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
                    "finding_count": len([f for f in r.findings if f.category == cat])
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
                # Fallback to checking tool name if rule_id didn't match directly
                # E.g. for snyk or bandit which have dynamic rule IDs
                for tool in f.detected_by:
                    articles.extend(get_gdpr_articles_for_rule(f"{tool}/*"))
            
            f.gdpr_references = list(set(articles))
