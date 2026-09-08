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
            mock_proc.returncode = 1
            mock_proc.stdout = json.dumps([
                {
                    "filePath": os.path.join(str(tmp_path), "src/App.jsx"),
                    "messages": [
                        {
                            "severity": 1,
                            "line": 42,
                            "message": "Inline style detected",
                            "ruleId": "deslint/no-inline-styles"
                        }
                    ]
                }
            ])
            mock_run.return_value = mock_proc
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 1

def test_deslint_invalid_config(tmp_path):
    # Non-zero exit + empty stdout + stderr content -> ERROR
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_proc = MagicMock()
            mock_proc.returncode = 2
            mock_proc.stdout = ""
            mock_proc.stderr = "Configuration Error: invalid rule"
            mock_run.return_value = mock_proc
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.ERROR
            assert "exit code 2" in result.error_message
            assert "Configuration Error" in result.error_message

def test_deslint_empty_stdout_non_empty_stderr(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mock_proc.stdout = "   "
            mock_proc.stderr = "Fatal error parsing"
            mock_run.return_value = mock_proc
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.ERROR
            assert "Fatal error parsing" in result.error_message

def test_deslint_malformed_json(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "{ malformed json ]"
            mock_proc.stderr = ""
            mock_run.return_value = mock_proc
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.ERROR
            assert "Failed to parse ESLint JSON" in result.error_message

def test_deslint_empty_success(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "[]"
            mock_run.return_value = mock_proc
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 0

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
                    "messages": [{"severity": 1, "line": 42, "message": "Generic", "ruleId": "react/jsx-key"}]
                }
            ])
            mock_run.return_value = mock_proc
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 0
