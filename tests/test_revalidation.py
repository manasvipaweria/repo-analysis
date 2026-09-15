import os
import pytest
from src.core.models import Finding, FindingLocation, Report
from src.core.revalidation import revalidate_finding, RevalidationStatus
from src.adapters.base import BaseAdapter

class MockAdapter(BaseAdapter):
    def __init__(self, name, findings, status="COMPLETED"):
        super().__init__()
        self._tool_name = name
        self.mock_findings = findings
        self.mock_status = status
        
    @property
    def tool_name(self):
        return self._tool_name
        
    @property
    def categories(self):
        return ["security"]
        
    def run(self, repo_path: str):
        from src.core.models import ToolResult, ToolStatus
        if self.mock_status == "ERROR":
            raise Exception("Scanner failed")
        if self.mock_status == "SKIPPED":
            return ToolResult(tool=self.tool_name, status=ToolStatus.SKIPPED)
        return ToolResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=self.mock_findings)

@pytest.fixture
def base_finding():
    f = Finding(
        category="security",
        severity="high",
        file="src/foo.py",
        line=10,
        message="SQLi",
        rule_id="B608",
        detected_by=["bandit"]
    )
    # Assign fingerprint as it would be assigned in orchestrator
    from src.core.fingerprinting import assign_fingerprints
    assign_fingerprints([f], repo_root=".")
    return f

def test_revalidate_still_open(base_finding):
    f_new = Finding(
        category="security",
        severity="high",
        file="src/foo.py",
        line=10,
        message="SQLi",
        rule_id="B608",
        detected_by=["bandit"]
    )
    adapters = {"bandit": MockAdapter("bandit", [f_new])}
    
    result = revalidate_finding(base_finding, repo_path=".", all_adapters=adapters)
    
    assert result.status == RevalidationStatus.STILL_OPEN
    assert result.fingerprint == base_finding.fingerprint
    assert result.current_finding is not None

def test_revalidate_resolved(base_finding):
    # Scanner returns empty findings
    adapters = {"bandit": MockAdapter("bandit", [])}
    
    result = revalidate_finding(base_finding, repo_path=".", all_adapters=adapters)
    
    assert result.status == RevalidationStatus.RESOLVED
    assert result.current_finding is None

def test_revalidate_error(base_finding):
    adapters = {"bandit": MockAdapter("bandit", [], status="ERROR")}
    
    result = revalidate_finding(base_finding, repo_path=".", all_adapters=adapters)
    
    assert result.status == RevalidationStatus.UNKNOWN
    assert result.current_finding is None
    assert "ToolStatus.ERROR" in result.message

def test_revalidate_skipped(base_finding):
    adapters = {"bandit": MockAdapter("bandit", [], status="SKIPPED")}
    
    result = revalidate_finding(base_finding, repo_path=".", all_adapters=adapters)
    
    assert result.status == RevalidationStatus.UNKNOWN
    assert result.current_finding is None
    assert "ToolStatus.SKIPPED" in result.message

def test_revalidate_missing_tool(base_finding):
    adapters = {} # Missing bandit
    
    result = revalidate_finding(base_finding, repo_path=".", all_adapters=adapters)
    
    assert result.status == RevalidationStatus.UNKNOWN
    assert result.current_finding is None
    assert "No standalone runnable tool identified" in result.message

def test_revalidate_wrong_fingerprint_is_resolved(base_finding):
    f_different = Finding(
        category="security",
        severity="high",
        file="src/foo.py",
        line=11, # Different line -> different fingerprint
        message="SQLi",
        rule_id="B608",
        detected_by=["bandit"]
    )
    adapters = {"bandit": MockAdapter("bandit", [f_different])}
    
    result = revalidate_finding(base_finding, repo_path=".", all_adapters=adapters)
    
    assert result.status == RevalidationStatus.RESOLVED
    assert result.current_finding is None
