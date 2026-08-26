import os
import json
from unittest.mock import patch, MagicMock

from src.adapters.react_doctor_adapter import ReactDoctorAdapter
from src.core.models import ToolStatus, Category

def test_react_doctor_adapter_skipped_no_react(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    adapter = ReactDoctorAdapter()
    result = adapter.run(str(tmp_path))
    assert result.status == ToolStatus.SKIPPED
    assert "No React project" in result.error_message

def test_react_doctor_adapter_success_with_findings(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}')
    
    adapter = ReactDoctorAdapter()
    with patch('subprocess.run') as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps([
            {
                "filePath": os.path.join(str(tmp_path), "src/App.jsx"),
                "messages": [
                    {
                        "severity": 2,
                        "line": 10,
                        "message": "Missing key prop",
                        "ruleId": "react/jsx-key"
                    }
                ]
            }
        ])
        mock_run.return_value = mock_proc
        
        result = adapter.run(str(tmp_path))
        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.category == Category.QUALITY.value
        assert finding.severity == "high"
        assert finding.location.file == "src/App.jsx"
        assert finding.rule_id == "react/jsx-key"
