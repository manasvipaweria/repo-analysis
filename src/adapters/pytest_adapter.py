import subprocess
import os
import xml.etree.ElementTree as ET
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category, TestMetrics
from src.adapters.base import BaseAdapter

class PytestAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "pytest"

    @property
    def categories(self) -> List[str]:
        return [Category.TESTING.value]

    def run(self, repo_path: str) -> ToolResult:
        report_xml = os.path.join(repo_path, "pytest_report.xml")
        cov_xml = os.path.join(repo_path, "coverage.xml")
        
        try:
            # Check if there's any tests directory or test files
            has_tests = os.path.isdir(os.path.join(repo_path, "tests")) or any(
                f.startswith("test_") and f.endswith(".py") for f in os.listdir(repo_path)
            )
            
            if not has_tests:
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    error_message="No tests found in repository."
                )
                
            cmd = [
                "pytest",
                f"--junitxml={report_xml}",
                "--cov=.",
                f"--cov-report=xml:{cov_xml}"
            ]
            
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            if result.returncode == 5:
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    error_message="No tests collected by pytest."
                )
                
            metrics = TestMetrics()
            findings = []
            
            if os.path.exists(report_xml):
                tree = ET.parse(report_xml)
                root = tree.getroot()
                suite = root if root.tag == 'testsuite' else root.find('.//testsuite')
                if suite is not None:
                    tests = int(suite.attrib.get('tests', 0))
                    failures = int(suite.attrib.get('failures', 0))
                    errors = int(suite.attrib.get('errors', 0))
                    skipped = int(suite.attrib.get('skipped', 0))
                    
                    metrics.failed = failures + errors
                    metrics.skipped = skipped
                    metrics.passed = tests - metrics.failed - metrics.skipped
                    
                    for case in suite.findall('.//testcase'):
                        failure = case.find('failure')
                        if failure is not None:
                            findings.append(Finding(
                                category=Category.TESTING.value,
                                severity="high",
                                file=case.attrib.get('file', 'unknown'),
                                line=int(case.attrib.get('line', 0)) if case.attrib.get('line') else 0,
                                message=f"Test failed: {case.attrib.get('name', 'unknown')} - {failure.attrib.get('message', 'No message')}",
                                rule_id="test_failure",
                                detected_by=[self.tool_name]
                            ))
            else:
                # If tests ran but didn't output XML (e.g., crashed completely)
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.ERROR,
                    error_message=f"Pytest failed to produce JUnit XML: {result.stderr or result.stdout}"
                )
                
            if os.path.exists(cov_xml):
                tree = ET.parse(cov_xml)
                root = tree.getroot()
                line_rate = root.attrib.get('line-rate')
                if line_rate:
                    metrics.coverage_percent = float(line_rate) * 100.0
                    
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.COMPLETED,
                findings=findings,
                metrics=metrics
            )
            
        except FileNotFoundError:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message="pytest executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
