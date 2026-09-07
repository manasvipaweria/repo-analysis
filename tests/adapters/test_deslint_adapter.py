import os
import json
from unittest.mock import patch, MagicMock

from src.adapters.deslint_adapter import DeslintAdapter
from src.core.models import ToolStatus, Category

def test_deslint_adapter_skipped_if_not_enabled(tmp_path):
    adapter = DeslintAdapter()
    with patch.dict(os.environ, {"ENABLE_DESLINT": "false"}, clear=True):
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.SKIPPED
        assert "Deslint is opt-in" in result.error_message

def test_deslint_adapter_skipped_no_react(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    adapter = DeslintAdapter()
    with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.SKIPPED
        assert "No React project" in result.error_message

def test_deslint_adapter_success_with_findings(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = json.dumps([
                {
                    "filePath": os.path.join(str(tmp_path), "src/App.jsx"),
                    "messages": [
                        {
                            "severity": 1,
                            "line": 42,
                            "message": "Inline style detected",
                            "ruleId": "deslint/no-inline-styles"
                        },
                        {
                            "severity": 1,
                            "line": 15,
                            "message": "Arbitrary color detected",
                            "ruleId": "deslint/no-arbitrary-colors"
                        }
                    ]
                }
            ])
            mock_run.return_value = mock_proc
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 2
            assert result.findings[0].category == Category.QUALITY.value
            assert result.findings[0].rule_id == "deslint/no-inline-styles"
            assert result.findings[0].location.file == "src/App.jsx"
            assert result.findings[1].rule_id == "deslint/no-arbitrary-colors"

def test_deslint_adapter_filters_non_deslint_rules(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = json.dumps([
                {
                    "filePath": os.path.join(str(tmp_path), "src/App.jsx"),
                    "messages": [
                        {
                            "severity": 1,
                            "line": 42,
                            "message": "Some generic eslint rule",
                            "ruleId": "react/jsx-key"
                        }
                    ]
                }
            ])
            mock_run.return_value = mock_proc
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 0
