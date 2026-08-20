import os
import json
import subprocess
from unittest.mock import patch, MagicMock

from src.adapters.depscan_adapter import DepScanAdapter
from src.core.models import ToolStatus, Category

def test_depscan_adapter_skipped_no_js(tmp_path):
    adapter = DepScanAdapter()
    result = adapter.run(str(tmp_path))
    assert result.status == ToolStatus.SKIPPED

def test_depscan_adapter_success_no_vulns(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    
    adapter = DepScanAdapter()
    with patch('subprocess.run') as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        
        # We don't generate any depscan json files, which means no findings
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 0

def test_depscan_adapter_success_with_vulns(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    
    adapter = DepScanAdapter()
    with patch('subprocess.run') as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        
        def side_effect(cmd, **kwargs):
            reports_dir = cmd[4]
            os.makedirs(reports_dir, exist_ok=True)
            out_file = os.path.join(reports_dir, "depscan-javascript.json")
            with open(out_file, 'w') as f:
                json.dump([{
                    "id": "CVE-2019-10744",
                    "package": "lodash",
                    "version": "4.17.15",
                    "severity": "HIGH",
                    "short_description": "Prototype Pollution",
                    "manifest": os.path.join(str(tmp_path), "package.json")
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

def test_depscan_adapter_timeout(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    
    adapter = DepScanAdapter()
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="depscan", timeout=600)
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.ERROR
        assert "timed out" in result.error_message
