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
    (tmp_path / "node_modules" / "@deslint" / "eslint-plugin").mkdir(parents=True, exist_ok=True)
    
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            
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
            mock_run.side_effect = [mock_install, mock_proc]
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 1

def test_deslint_npm_install_failure(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 1
            mock_install.stderr = "npm ERR! 404 Not Found"
            mock_install.stdout = ""
            mock_run.return_value = mock_install
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.ERROR
            assert "npm install failed" in result.error_message
            assert len(result.findings) == 0

def test_deslint_missing_plugin_package(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            mock_run.return_value = mock_install
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.ERROR
            assert "Cannot find package '@deslint/eslint-plugin'" in result.error_message
            assert len(result.findings) == 0

def test_deslint_invalid_config(tmp_path):
    # Non-zero exit + empty stdout + stderr content -> ERROR
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    (tmp_path / "node_modules" / "@deslint" / "eslint-plugin").mkdir(parents=True, exist_ok=True)
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            
            mock_proc = MagicMock()
            mock_proc.returncode = 2
            mock_proc.stdout = ""
            mock_proc.stderr = "Configuration Error: invalid rule"
            mock_run.side_effect = [mock_install, mock_proc]
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.ERROR
            assert "exit code 2" in result.error_message
            assert "Configuration Error" in result.error_message

def test_deslint_empty_stdout_non_empty_stderr(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    (tmp_path / "node_modules" / "@deslint" / "eslint-plugin").mkdir(parents=True, exist_ok=True)
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mock_proc.stdout = "   "
            mock_proc.stderr = "Fatal error parsing"
            mock_run.side_effect = [mock_install, mock_proc]
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.ERROR
            assert "Fatal error parsing" in result.error_message

def test_deslint_malformed_json(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    (tmp_path / "node_modules" / "@deslint" / "eslint-plugin").mkdir(parents=True, exist_ok=True)
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "{ malformed json ]"
            mock_proc.stderr = ""
            mock_run.side_effect = [mock_install, mock_proc]
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.ERROR
            assert "Failed to parse ESLint JSON" in result.error_message

def test_deslint_empty_success(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    (tmp_path / "node_modules" / "@deslint" / "eslint-plugin").mkdir(parents=True, exist_ok=True)
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "[]"
            mock_run.side_effect = [mock_install, mock_proc]
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 0

def test_deslint_adapter_filters_non_deslint_rules(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    (tmp_path / "node_modules" / "@deslint" / "eslint-plugin").mkdir(parents=True, exist_ok=True)
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = json.dumps([
                {
                    "filePath": os.path.join(str(tmp_path), "src/App.jsx"),
                    "messages": [{"severity": 1, "line": 42, "message": "Generic", "ruleId": "react/jsx-key"}]
                }
            ])
            mock_run.side_effect = [mock_install, mock_proc]
            
            result = adapter.run(str(tmp_path))
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 0

def test_deslint_config_contains_allowlist_for_svg_props(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    (tmp_path / "node_modules" / "@deslint" / "eslint-plugin").mkdir(parents=True, exist_ok=True)
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "[]"
            mock_run.side_effect = [mock_install, mock_proc]
            adapter.run(str(tmp_path))
            
    import inspect
    import src.adapters.deslint_adapter as mod
    src_code = inspect.getsource(mod)
    assert "allowDynamic" in src_code
    assert "gridTemplateColumns" in src_code
    assert "strokeDasharray" in src_code

def test_deslint_config_disables_noisy_rules(tmp_path):
    import inspect
    import src.adapters.deslint_adapter as mod
    src_code = inspect.getsource(mod)
    assert "'deslint/consistent-border-radius': 'off'" in src_code
    assert "'deslint/consistent-component-spacing': 'off'" in src_code
    assert "'deslint/missing-states': 'off'" in src_code
    assert "'deslint/a11y-color-contrast': 'off'" in src_code

def test_deslint_multiple_findings_different_rules(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    (tmp_path / "node_modules" / "@deslint" / "eslint-plugin").mkdir(parents=True, exist_ok=True)
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mock_proc.stdout = json.dumps([
                {
                    "filePath": os.path.join(str(tmp_path), "src/App.jsx"),
                    "messages": [
                        {"severity": 1, "line": 10, "message": "Inline style", "ruleId": "deslint/no-inline-styles"},
                        {"severity": 1, "line": 20, "message": "Arbitrary color", "ruleId": "deslint/no-arbitrary-colors"},
                        {"severity": 1, "line": 30, "message": "Arbitrary spacing", "ruleId": "deslint/no-arbitrary-spacing"},
                        {"severity": 1, "line": 40, "message": "Arbitrary typography", "ruleId": "deslint/no-arbitrary-typography"},
                        {"severity": 1, "line": 50, "message": "Fixed width", "ruleId": "deslint/responsive-required"},
                    ]
                }
            ])
            mock_run.side_effect = [mock_install, mock_proc]
            result = adapter.run(str(tmp_path))
            
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 5
            rule_ids = {f.rule_id for f in result.findings}
            assert "deslint/no-inline-styles" in rule_ids
            assert "deslint/no-arbitrary-colors" in rule_ids
            assert "deslint/responsive-required" in rule_ids

def test_deslint_finding_has_quality_category(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    (tmp_path / "node_modules" / "@deslint" / "eslint-plugin").mkdir(parents=True, exist_ok=True)
    adapter = DeslintAdapter()
    with patch('subprocess.run') as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_install = MagicMock()
            mock_install.returncode = 0
            
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mock_proc.stdout = json.dumps([
                {
                    "filePath": os.path.join(str(tmp_path), "src/App.jsx"),
                    "messages": [{"severity": 1, "line": 5, "message": "Inline style", "ruleId": "deslint/no-inline-styles"}]
                }
            ])
            mock_run.side_effect = [mock_install, mock_proc]
            result = adapter.run(str(tmp_path))
            
            assert len(result.findings) == 1
            assert result.findings[0].category == Category.QUALITY.value

def test_deslint_react_dir_detection_skips_node_modules(tmp_path):
    nm = tmp_path / "node_modules" / "some-pkg"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    (tmp_path / "package.json").write_text('{"name": "root"}')

    adapter = DeslintAdapter()
    with patch("subprocess.run") as mock_run:
        with patch.dict(os.environ, {"ENABLE_DESLINT": "true"}, clear=True):
            mock_proc = MagicMock()
            mock_proc.returncode = 2
            mock_proc.stdout = ""
            mock_proc.stderr = "Cannot find package '@deslint/eslint-plugin'"
            mock_run.return_value = mock_proc

            result = adapter.run(str(tmp_path))

            if mock_run.called:
                cwd = mock_run.call_args.kwargs.get("cwd") or mock_run.call_args[1].get("cwd", "")
                assert "node_modules" not in str(cwd), "Config must never be written inside node_modules"

            assert result.status in (ToolStatus.ERROR, ToolStatus.SKIPPED)



