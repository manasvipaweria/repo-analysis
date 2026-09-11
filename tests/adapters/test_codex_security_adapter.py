import pytest
from unittest.mock import patch, MagicMock
import os
import subprocess

from src.adapters.codex_security_adapter import CodexSecurityAdapter

@pytest.fixture
def mock_env():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
        yield

def test_codex_security_adapter_no_key():
    with patch.dict(os.environ, clear=True):
        adapter = CodexSecurityAdapter()
        result = adapter.run(".")
        assert result.status.name == "SKIPPED"
        assert len(result.findings) == 0

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_success_findings(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '''
    Some npx download logs
    {
      "repositoryFindings": [
        {
          "severity": "High",
          "title": "SQL Injection",
          "description": "Found a SQL injection",
          "ruleId": "CWE-89",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/db.py"
                },
                "region": {
                  "startLine": 42
                }
              }
            }
          ]
        }
      ]
    }
    '''
    mock_run.return_value = mock_result
    
    res = adapter.run(".")
    assert res.status.name == "COMPLETED"
    findings = res.findings
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "security"
    assert f.severity == "high"
    assert f.location.file == "src/db.py"
    assert f.location.line == 42
    assert "Found a SQL injection" in f.description
    assert f.rule_id == "CWE-89"
    assert "codex-security" in f.detected_by

    # Verify environment variables passed
    _, kwargs = mock_run.call_args
    passed_env = kwargs.get("env", {})
    assert "CODEX_HOME" in passed_env
    assert passed_env.get("CODEX_PERMISSION_PROFILE") == ":workspace"

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_success_zero_findings(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '{"repositoryFindings": []}'
    mock_run.return_value = mock_result
    
    res = adapter.run(".")
    assert res.status.name == "COMPLETED"
    assert len(res.findings) == 0
    assert res.error_message is None

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_cli_error_code_2(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    
    mock_result = MagicMock()
    mock_result.returncode = 2
    mock_result.stderr = "Error: state directory /home/runner/.codex/state/plugins/codex-security/scans could not be accessed"
    mock_result.stdout = ""
    mock_run.return_value = mock_result
    
    res = adapter.run(".")
    assert res.status.name == "ERROR"
    assert len(res.findings) == 0
    assert "CLI failed with code 2" in res.error_message

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_partial_output_on_error(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    
    mock_result = MagicMock()
    mock_result.returncode = 2
    mock_result.stderr = "Error during execution after partial scan"
    mock_result.stdout = '{"repositoryFindings": [{"title": "Partial"}]}'
    mock_run.return_value = mock_result
    
    res = adapter.run(".")
    assert res.status.name == "ERROR"
    assert len(res.findings) == 0
    assert "CLI failed with code 2" in res.error_message

@patch("src.adapters.codex_security_adapter.os.makedirs")
def test_codex_security_adapter_non_writable_dir(mock_makedirs, mock_env):
    mock_makedirs.side_effect = PermissionError("Permission denied")
    adapter = CodexSecurityAdapter()
    
    res = adapter.run(".")
    assert res.status.name == "ERROR"
    assert len(res.findings) == 0
    assert "is not writable" in res.error_message

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_shell_execution_error(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    mock_run.side_effect = FileNotFoundError("npx command not found")
    
    res = adapter.run(".")
    assert res.status.name == "ERROR"
    assert len(res.findings) == 0
    assert "Unexpected error" in res.error_message or "npx command not found" in res.error_message

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_auth_failure(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "Error: Unauthorized - you don't have Codex Security access"
    mock_result.stdout = ""
    mock_run.return_value = mock_result
    
    res = adapter.run(".")
    assert res.status.name == "SKIPPED"
    assert len(res.findings) == 0

@patch("src.adapters.codex_security_adapter.subprocess.run")
def test_codex_security_adapter_timeout(mock_run, mock_env):
    adapter = CodexSecurityAdapter()
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="npx", timeout=900)
    
    res = adapter.run(".")
    assert res.status.name == "ERROR"
    assert len(res.findings) == 0

