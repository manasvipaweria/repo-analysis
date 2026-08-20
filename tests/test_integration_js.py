import os
import pytest
from src.core.orchestrator import Orchestrator
from src.adapters.semgrep_adapter import SemgrepAdapter
from src.adapters.snyk_adapter import SnykAdapter
from src.adapters.depscan_adapter import DepScanAdapter
from src.adapters.depcruise_adapter import DepcruiseAdapter
from src.adapters.sonarqube_adapter import SonarQubeAdapter

@pytest.fixture
def js_project_path():
    return os.path.join(os.path.dirname(__file__), 'fixtures', 'js_project')

def test_js_integration(js_project_path):
    adapters = [
        SemgrepAdapter(),
        SnykAdapter(),
        DepScanAdapter(),
        DepcruiseAdapter(),
        SonarQubeAdapter()
    ]
    orchestrator = Orchestrator(adapters=adapters)
    
    # We won't assert findings count because some tools might not be installed (snyk, dep-scan, sonarqube, depcruise).
    # But we can assert that the report is generated without crashing.
    report = orchestrator.analyze("test-repo", js_project_path)
    
    assert report.repo == "test-repo"
    assert len(report.summary) > 0
    
    # Check that tools were either COMPLETED or SKIPPED/ERROR (but it didn't crash)
    for cat, cat_summary in report.summary.items():
        for tool, tool_summary in cat_summary.tools.items():
            assert tool_summary['status'] in ["COMPLETED", "ERROR", "SKIPPED"]
