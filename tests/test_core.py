import pytest
from src.core.models import Finding, ToolResult, ToolStatus, CategoryStatus, Category, TestMetrics, Report
from src.core.dedup import deduplicate_findings
from src.core.orchestrator import Orchestrator
from src.core.output import write_csv_report
from src.adapters.base import BaseAdapter
import os

def test_deduplication():
    findings = [
        Finding(Category.SECURITY.value, "high", "app.py", 10, "Use of hardcoded password", "B105", ["bandit"]),
        Finding(Category.SECURITY.value, "high", "app.py", 10, "Hardcoded password detected", "semgrep.hardcoded-password", ["semgrep"]),
        Finding(Category.QUALITY.value, "medium", "app.py", 10, "Line too long", "E501", ["ruff"]),
        Finding(Category.SECURITY.value, "medium", "app.py", 20, "Weak hashing", "B303", ["bandit"])
    ]
    
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 3
    
    # The first two should merge
    merged = next(f for f in deduped if "hardcoded" in f.description.lower())
    assert set(merged.detected_by) == {"bandit", "semgrep"}
    assert "B105" in merged.rule_id and "semgrep.hardcoded-password" in merged.rule_id

class MockAdapter(BaseAdapter):
    def __init__(self, name, cats, status, findings=None, error_msg=None):
        self._name = name
        self._cats = cats
        self._status = status
        self._findings = findings or []
        self._error_msg = error_msg

    @property
    def tool_name(self) -> str:
        return self._name

    @property
    def categories(self) -> list:
        return self._cats

    def run(self, repo_path: str) -> ToolResult:
        return ToolResult(self._name, self._status, self._findings, error_message=self._error_msg)

def test_category_status_clean():
    adapters = [MockAdapter("t1", ["sec"], ToolStatus.COMPLETED)]
    orch = Orchestrator(adapters)
    rep = orch.analyze("url", "path")
    assert rep.summary["sec"].status == CategoryStatus.PASSED

def test_category_status_error():
    adapters = [
        MockAdapter("t1", ["sec"], ToolStatus.COMPLETED),
        MockAdapter("t2", ["sec"], ToolStatus.ERROR)
    ]
    orch = Orchestrator(adapters)
    rep = orch.analyze("url", "path")
    # Even if one completed, if a required tool fails, category should be ERROR
    assert rep.summary["sec"].status == CategoryStatus.ERROR

def test_category_status_skipped():
    adapters = [MockAdapter("t1", ["sec"], ToolStatus.SKIPPED)]
    orch = Orchestrator(adapters)
    rep = orch.analyze("url", "path")
    assert rep.summary["sec"].status == CategoryStatus.SKIPPED

def test_category_status_mixed_skipped_and_findings():
    adapters = [
        MockAdapter("t1", ["sec"], ToolStatus.SKIPPED),
        MockAdapter("t2", ["sec"], ToolStatus.COMPLETED, [Finding("sec", "high", "a", 1, "m", "r", ["t2"])])
    ]
    orch = Orchestrator(adapters)
    rep = orch.analyze("url", "path")
    # Has a skipped tool but also findings
    assert rep.summary["sec"].status == CategoryStatus.ISSUES_FOUND
    assert rep.summary["sec"].count == 1

def test_csv_summary_generation(tmp_path):
    adapters = [
        MockAdapter("t1", ["sec"], ToolStatus.COMPLETED),
        MockAdapter("t2", ["qual"], ToolStatus.COMPLETED, [Finding("qual", "low", "b", 2, "m", "r", ["t2"])])
    ]
    orch = Orchestrator(adapters)
    rep = orch.analyze("url", "path")
    
    csv_file = tmp_path / "test.csv"
    write_csv_report(rep, str(csv_file))
    
    content = csv_file.read_text(encoding="utf-8")
    assert "SUMMARY,sec,PASSED,0" in content
    assert "SUMMARY,qual,ISSUES_FOUND,1" in content
    
    # Check headers
    assert "Type,Finding ID,Status,Category,Priority,Severity,Merge Blocking,File,Line,Title,Description,Rule ID,Code Context,Detected By,AI Summary,Security Impact,Remediation,False Positive Prediction" in content
    
    # Check finding fields and trailing blank AI columns
    assert "FINDING," in content
    assert ",qual," in content
    assert ",low," in content
    assert ",b,2,r,m," in content
    assert ",,,," in content # Blank AI columns at the end

def test_report_from_dict():
    # Test Report deserialization and AI field handling
    data = {
        "repo": "test_repo",
        "timestamp": "2026-08-20T00:00:00Z",
        "summary": {},
        "findings": [
            {
                "finding_id": "123",
                "category": "security",
                "severity": "high",
                "location": {"file": "app.py", "line": 42},
                "evidence": {"code_context": "password='123'"},
                "ai_fields": {
                    "analysis_summary": "Found hardcoded password",
                    "security_impact": "High",
                    "remediation_suggestion": "Use env vars",
                    "is_false_positive_prediction": False
                }
            }
        ]
    }
    
    rep = Report.from_dict(data)
    assert rep.repo == "test_repo"
    assert len(rep.findings) == 1
    f = rep.findings[0]
    assert f.finding_id == "123"
    assert f.location.file == "app.py"
    assert f.evidence.code_context == "password='123'"
    assert f.ai_fields.analysis_summary == "Found hardcoded password"
    assert f.ai_fields.is_false_positive_prediction is False

import sys
import subprocess

def test_subprocess_encoding_handling(tmp_path):
    """
    Regression test to ensure adapters don't crash when tools output non-CP1252 bytes.
    We'll test this directly via subprocess.run mirroring how adapters invoke tools.
    """
    # Create a python script that outputs a tricky byte (e.g., 0x90) and invalid UTF-8
    bad_script = tmp_path / "bad_output.py"
    bad_script.write_bytes(b"import sys\nsys.stdout.buffer.write(b'\\x90\\xffinvalid')\n")
    
    # Run it with our standard arguments (text=True, encoding="utf-8", errors="replace")
    # This should NOT raise UnicodeDecodeError
    result = subprocess.run(
        [sys.executable, str(bad_script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )
    
    # \x90 and \xff are invalid UTF-8, so they should be replaced with the replacement character U+FFFD
    assert "\ufffd" in result.stdout
    assert "invalid" in result.stdout
