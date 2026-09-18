from dataclasses import dataclass
from typing import Optional, Dict, List
from enum import Enum

from src.core.models import Finding
from src.adapters.base import BaseAdapter
from src.core.dedup import deduplicate_findings

class RevalidationStatus(str, Enum):
    STILL_OPEN = "STILL_OPEN"
    RESOLVED = "RESOLVED"
    UNKNOWN = "UNKNOWN"

@dataclass
class RevalidationResult:
    fingerprint: str
    status: RevalidationStatus
    tool: str
    previous_finding: Finding
    current_finding: Optional[Finding] = None
    message: str = ""

def revalidate_finding(
    finding: Finding,
    repo_path: str,
    all_adapters: Dict[str, BaseAdapter]
) -> RevalidationResult:
    fingerprint = finding.fingerprint
    if not fingerprint:
        return RevalidationResult(
            fingerprint="",
            status=RevalidationStatus.UNKNOWN,
            tool="unknown",
            previous_finding=finding,
            message="Previous finding has no fingerprint."
        )

    # 1. Identify originating tools
    runnable_tools = [t for t in finding.detected_by if t in all_adapters]
    
    if not runnable_tools:
        return RevalidationResult(
            fingerprint=fingerprint,
            status=RevalidationStatus.UNKNOWN,
            tool=",".join(finding.detected_by) if finding.detected_by else "unknown",
            previous_finding=finding,
            message="No standalone runnable tool identified for this finding (e.g., compliance engine)."
        )
        
    tool_results = []
    for tool_name in runnable_tools:
        adapter = all_adapters[tool_name]
        try:
            res = adapter.run(repo_path)
            tool_results.append(res)
        except Exception as e:
            from src.core.models import ToolResult, ToolStatus
            tool_results.append(ToolResult(tool=tool_name, status=ToolStatus.ERROR, error_message=str(e)))
            
    all_findings = []
    for r in tool_results:
        from src.core.models import ToolStatus
        if r.status in [ToolStatus.ERROR, ToolStatus.SKIPPED]:
            return RevalidationResult(
                fingerprint=fingerprint,
                status=RevalidationStatus.UNKNOWN,
                tool=",".join(runnable_tools),
                previous_finding=finding,
                message=f"Scanner {r.tool} returned {r.status}."
            )
        if r.findings:
            all_findings.extend(r.findings)
            
    # Deduplicate and assign fingerprints to the new findings
    deduped_findings = deduplicate_findings(all_findings, repo_path)
    
    # Check if the fingerprint is present
    for new_f in deduped_findings:
        if new_f.fingerprint == fingerprint:
            return RevalidationResult(
                fingerprint=fingerprint,
                status=RevalidationStatus.STILL_OPEN,
                tool=",".join(runnable_tools),
                previous_finding=finding,
                current_finding=new_f,
                message="Finding is still present."
            )
            
    return RevalidationResult(
        fingerprint=fingerprint,
        status=RevalidationStatus.RESOLVED,
        tool=",".join(runnable_tools),
        previous_finding=finding,
        current_finding=None,
        message="Finding was not detected by the successful re-run."
    )
