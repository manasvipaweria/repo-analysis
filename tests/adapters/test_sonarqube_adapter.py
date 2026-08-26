import os
import json
from unittest.mock import patch, MagicMock

from src.adapters.sonarqube_adapter import SonarQubeAdapter
from src.core.models import ToolStatus, Category

def test_sonarqube_adapter_skipped_no_config(tmp_path):
    adapter = SonarQubeAdapter()
    result = adapter.run(str(tmp_path))
    assert result.status == ToolStatus.SKIPPED
    assert "SonarQube not configured" in result.error_message

def test_sonarqube_adapter_success(tmp_path):
    (tmp_path / "sonar-project.properties").write_text("sonar.projectKey=test")
    
    adapter = SonarQubeAdapter()
    with patch('subprocess.run') as mock_run, patch('urllib.request.urlopen') as mock_urlopen:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        
        def run_side_effect(cmd, **kwargs):
            scannerwork = tmp_path / ".scannerwork"
            scannerwork.mkdir()
            (scannerwork / "report-task.txt").write_text(
                "serverUrl=http://localhost:9000\nceTaskId=TASK1\nprojectKey=test\n"
            )
            return mock_proc
        mock_run.side_effect = run_side_effect
        
        # Mock API responses
        mock_resp_task = MagicMock()
        mock_resp_task.read.return_value = json.dumps({"task": {"status": "SUCCESS"}}).encode('utf-8')
        mock_resp_task.__enter__.return_value = mock_resp_task
        
        mock_resp_issues = MagicMock()
        mock_resp_issues.read.return_value = json.dumps({
            "issues": [
                {
                    "component": "test:src/main.js",
                    "type": "VULNERABILITY",
                    "severity": "MAJOR",
                    "message": "Use of eval",
                    "rule": "javascript:S1523",
                    "line": 10
                }
            ]
        }).encode('utf-8')
        mock_resp_issues.__enter__.return_value = mock_resp_issues
        
        # We poll task, then fetch issues
        mock_urlopen.side_effect = [mock_resp_task, mock_resp_issues]
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.category == Category.SECURITY.value
        assert finding.severity == "high"
        assert finding.location.file == "src/main.js"
        assert finding.rule_id == "javascript:S1523"
        assert finding.location.line == 10
