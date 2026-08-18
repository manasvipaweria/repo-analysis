import datetime
from typing import List, Dict

from .models import Report, Finding, ToolResult, ToolStatus, CategoryStatus, CategorySummary
from .dedup import deduplicate_findings
from src.adapters.base import BaseAdapter

class Orchestrator:
    def __init__(self, adapters: List[BaseAdapter]):
        self.adapters = adapters

    def analyze(self, repo_url: str, repo_path: str) -> Report:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        tool_results: List[ToolResult] = []
        all_findings: List[Finding] = []
        
        category_to_tools: Dict[str, List[ToolResult]] = {}
        
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
            findings=deduped_findings
        )
        return report
