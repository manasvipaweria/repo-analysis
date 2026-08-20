import os
import json
from unittest.mock import patch, MagicMock

from src.adapters.snyk_adapter import SnykAdapter
from src.core.models import ToolStatus, Category

def test_snyk_adapter_skipped_no_js(tmp_path):
    adapter = SnykAdapter()
    result = adapter.run(str(tmp_path))
    assert result.status == ToolStatus.SKIPPED
    assert "No JS/TS" in result.error_message

def test_snyk_adapter_success_no_vulns(tmp_path):
    # Setup dummy JS project
    (tmp_path / "package.json").write_text("{}")
    
    adapter = SnykAdapter()
    with patch('subprocess.run') as mock_run:
        # Mock subprocess
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc
        
        # We need to intercept the command to write the output JSON to the temp file SnykAdapter expects
        def side_effect(cmd, **kwargs):
            out_file = cmd[3].split('=')[1]
            with open(out_file, 'w') as f:
                json.dump([], f)
            return mock_proc
            
        mock_run.side_effect = side_effect
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 0

def test_snyk_adapter_success_with_vulns(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    
    adapter = SnykAdapter()
    with patch('subprocess.run') as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 1 # Snyk returns 1 when vulnerabilities are found
        mock_proc.stdout = ""
        mock_run.return_value = mock_proc
        
        def side_effect(cmd, **kwargs):
            out_file = cmd[3].split('=')[1]
            with open(out_file, 'w') as f:
                json.dump([{
                    "displayTargetFile": "package.json",
                    "vulnerabilities": [
                        {
                            "id": "SNYK-JS-LODASH-5678",
                            "name": "lodash",
                            "version": "4.17.15",
                            "severity": "high",
                            "identifiers": {
                                "CVE": ["CVE-2019-10744"],
                                "GHSA": ["GHSA-x5rq-j2xg-h7cg"]
                            },
                            "title": "Prototype Pollution"
                        }
                    ]
                }], f)
            return mock_proc
            
        mock_run.side_effect = side_effect
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.category == Category.DEPENDENCIES.value
        assert finding.severity == "high"
        assert finding.file == "package.json"
        assert finding.rule_id == "CVE-2019-10744"
        assert "Prototype Pollution" in finding.message
        
def test_snyk_adapter_execution_error(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    
    adapter = SnykAdapter()
    with patch('subprocess.run') as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 2 # True error
        mock_proc.stderr = "Authentication failed"
        mock_run.return_value = mock_proc
        
        # No file generated
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.ERROR
        assert "execution failed" in result.error_message
