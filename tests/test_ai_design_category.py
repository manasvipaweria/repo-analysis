import pytest
from src.core.models import Category, Finding, ToolResult, ToolStatus, CategoryStatus
from src.core.orchestrator import Orchestrator
from src.adapters.design_adapter import ApniMandiDesignAdapter

class MockGeminiDesignAdapter(ApniMandiDesignAdapter):
    def run(self, repo_path: str) -> ToolResult:
        findings = [
            Finding(
                category="Accessibility",
                severity="high",
                file="frontend/src/App.jsx",
                line=45,
                message="Sidebar navigation items are raw divs",
                rule_id="gemini/accessibility-semantic-nav",
                detected_by=["apnimandi-design"]
            ),
            Finding(
                category="Consistency",
                severity="medium",
                file="frontend/src/App.jsx",
                line=120,
                message="Inconsistent form control usage",
                rule_id="gemini/component-consistency",
                detected_by=["apnimandi-design"]
            ),
            Finding(
                category="Quality",
                severity="high",
                file="frontend/src/App.jsx",
                line=210,
                message="Nested interactive click handlers",
                rule_id="gemini/ux-event-bubbling",
                detected_by=["apnimandi-design"]
            )
        ]
        return ToolResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=findings)

def test_gemini_design_category_attribution():
    adapter = MockGeminiDesignAdapter()
    orch = Orchestrator([adapter])
    report = orch.analyze("http://example.com/repo", "/path/to/repo")
    
    # 1. AI Design category summary must report 3 findings and ISSUES_FOUND status
    ai_design_summary = report.summary.get("ai_design")
    assert ai_design_summary is not None, "AI Design summary must exist"
    assert ai_design_summary.status == CategoryStatus.ISSUES_FOUND
    assert ai_design_summary.count == 3, f"Expected 3 findings in AI Design summary, got {ai_design_summary.count}"
    
    # 2. apnimandi-design tool in AI Design summary must report 3 findings
    tool_info = ai_design_summary.tools.get("apnimandi-design")
    assert tool_info is not None, "apnimandi-design tool must be present in AI Design summary"
    assert tool_info["finding_count"] == 3, f"Expected apnimandi-design finding_count to be 3, got {tool_info['finding_count']}"
    
    # 3. Individual findings must preserve their original categories (Accessibility, Consistency, Quality)
    gemini_findings = [f for f in report.findings if "apnimandi-design" in f.detected_by and f.rule_id.startswith("gemini/")]
    assert len(gemini_findings) == 3
    
    categories_found = {f.category for f in gemini_findings}
    assert categories_found == {"Accessibility", "Consistency", "Quality"}
    
    # 4. Findings must not be discarded or overwritten
    rule_ids_found = {f.rule_id for f in gemini_findings}
    assert rule_ids_found == {
        "gemini/accessibility-semantic-nav",
        "gemini/component-consistency",
        "gemini/ux-event-bubbling"
    }
