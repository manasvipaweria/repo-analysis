import os
import json
from unittest.mock import patch, MagicMock

from src.adapters.depcruise_adapter import DepcruiseAdapter
from src.core.models import ToolStatus, Category

def test_depcruise_adapter_skipped_no_js(tmp_path):
    adapter = DepcruiseAdapter()
    result = adapter.run(str(tmp_path))
    assert result.status == ToolStatus.SKIPPED

def test_depcruise_adapter_skipped_no_config(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    adapter = DepcruiseAdapter()
    result = adapter.run(str(tmp_path))
    assert result.status == ToolStatus.SKIPPED
    assert "No dependency-cruiser configuration" in result.error_message

def test_depcruise_adapter_success_with_vulns(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / ".dependency-cruiser.js").write_text("{}")
    
    adapter = DepcruiseAdapter()
    with patch('subprocess.run') as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps({
            "summary": {
                "violations": [
                    {
                        "from": "src/index.js",
                        "to": "src/forbidden.js",
                        "rule": {
                            "name": "no-forbidden",
                            "severity": "error"
                        }
                    }
                ]
            }
        })
        mock_run.return_value = mock_proc
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.category == Category.ARCHITECTURE.value
        assert finding.severity == "high"
        assert finding.file == "src/index.js"
        assert finding.rule_id == "no-forbidden"
