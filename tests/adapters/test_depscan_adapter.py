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

def test_depscan_adapter_missing_vdb(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}")
    
    # Ensure auto_download is false
    monkeypatch.setenv("DEPSCAN_AUTO_DOWNLOAD", "false")
    monkeypatch.setenv("DEPSCAN_VDB_SCOPE", "app")
    
    adapter = DepScanAdapter()
    with patch('subprocess.run') as mock_run:
        # Mock depscan-vdb info to return no database
        vdb_proc = MagicMock()
        vdb_proc.stdout = "no local database"
        mock_run.return_value = vdb_proc
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.SKIPPED
        assert "VDB is missing" in result.error_message
        assert "DEPSCAN_AUTO_DOWNLOAD=true" in result.error_message
        assert "--scope app" in result.error_message

def test_depscan_adapter_success_no_vulns(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}")
    monkeypatch.setenv("DEPSCAN_AUTO_DOWNLOAD", "true")
    
    adapter = DepScanAdapter()
    with patch('subprocess.run') as mock_run:
        def side_effect(cmd, **kwargs):
            if cmd[0] == "depscan-vdb":
                proc = MagicMock()
                proc.stdout = "Last pulled image: ghcr.io/appthreat/vdbxz-app"
                return proc
            else:
                proc = MagicMock()
                proc.returncode = 0
                return proc
                
        mock_run.side_effect = side_effect
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 0
        
        # Verify depscan was called with the correct vdb-scope
        depscan_call = [call for call in mock_run.call_args_list if call.args[0][0] == "depscan"][0]
        assert "--vdb-scope" in depscan_call.args[0]
        assert "app" in depscan_call.args[0]

def test_depscan_adapter_success_with_vulns(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}")
    monkeypatch.setenv("DEPSCAN_AUTO_DOWNLOAD", "true")
    
    adapter = DepScanAdapter()
    with patch('subprocess.run') as mock_run:
        def side_effect(cmd, **kwargs):
            if cmd[0] == "depscan-vdb":
                proc = MagicMock()
                proc.stdout = "Last pulled image: ghcr.io/appthreat/vdbxz-app"
                return proc
            else:
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
                proc = MagicMock()
                proc.returncode = 0
                return proc
            
        mock_run.side_effect = side_effect
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 1

def test_depscan_adapter_timeout(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}")
    monkeypatch.setenv("DEPSCAN_AUTO_DOWNLOAD", "true")
    
    adapter = DepScanAdapter()
    with patch('subprocess.run') as mock_run:
        def side_effect(cmd, **kwargs):
            if cmd[0] == "depscan-vdb":
                proc = MagicMock()
                proc.stdout = "Last pulled image: ghcr.io/appthreat/vdbxz-app"
                return proc
            else:
                raise subprocess.TimeoutExpired(cmd="depscan", timeout=600)
                
        mock_run.side_effect = side_effect
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.ERROR
        assert "timed out" in result.error_message
