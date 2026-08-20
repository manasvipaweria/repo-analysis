import subprocess
import json
import os
import time
import urllib.request
import urllib.error
from typing import List, Optional

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter

class SonarQubeAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "sonarqube"

    @property
    def categories(self) -> List[str]:
        return [Category.QUALITY.value, Category.SECURITY.value]

    def _get_property(self, path: str, key: str) -> Optional[str]:
        if not os.path.exists(path):
            return None
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith(f"{key}="):
                    return line.split('=', 1)[1].strip()
        return None

    def run(self, repo_path: str) -> ToolResult:
        props_path = os.path.join(repo_path, 'sonar-project.properties')
        if not os.path.exists(props_path) and not os.environ.get("SONAR_HOST_URL"):
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="SonarQube not configured (no sonar-project.properties or SONAR_HOST_URL)."
            )

        try:
            # Run sonar-scanner
            cmd = ["sonar-scanner"]
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            if result.returncode != 0:
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.ERROR,
                    error_message=f"sonar-scanner failed: {result.stderr or result.stdout}"
                )
                
            report_task_path = os.path.join(repo_path, '.scannerwork', 'report-task.txt')
            if not os.path.exists(report_task_path):
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.ERROR,
                    error_message="sonar-scanner did not produce report-task.txt"
                )
                
            task_info = {}
            with open(report_task_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if '=' in line:
                        k, v = line.strip().split('=', 1)
                        task_info[k] = v
                        
            server_url = task_info.get('serverUrl')
            task_id = task_info.get('ceTaskId')
            project_key = task_info.get('projectKey')
            
            if not all([server_url, task_id, project_key]):
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.ERROR,
                    error_message="Missing required SonarQube task information."
                )
                
            # Poll task status
            token = os.environ.get('SONAR_TOKEN')
            headers = {}
            if token:
                import base64
                auth_str = base64.b64encode(f"{token}:".encode('utf-8')).decode('utf-8')
                headers['Authorization'] = f"Basic {auth_str}"
                
            for _ in range(30):
                req = urllib.request.Request(f"{server_url}/api/ce/task?id={task_id}", headers=headers)
                with urllib.request.urlopen(req) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    status = data.get('task', {}).get('status')
                    if status in ('SUCCESS', 'FAILED', 'CANCELED'):
                        break
                time.sleep(2)
                
            if status != 'SUCCESS':
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.ERROR,
                    error_message=f"SonarQube background task finished with status: {status}"
                )
                
            # Fetch issues
            req = urllib.request.Request(f"{server_url}/api/issues/search?componentKeys={project_key}&resolved=false", headers=headers)
            with urllib.request.urlopen(req) as response:
                issues_data = json.loads(response.read().decode('utf-8'))
                
            findings = []
            for issue in issues_data.get('issues', []):
                component = issue.get('component', '')
                if ':' in component:
                    # component is usually project_key:file_path
                    file_path = component.split(':', 1)[1]
                else:
                    file_path = component
                    
                sq_type = issue.get('type', '')
                cat = Category.QUALITY.value
                if sq_type == 'VULNERABILITY':
                    cat = Category.SECURITY.value
                    
                sq_severity = issue.get('severity', 'INFO')
                if sq_severity in ('BLOCKER', 'CRITICAL'):
                    sev = 'critical'
                elif sq_severity == 'MAJOR':
                    sev = 'high'
                elif sq_severity == 'MINOR':
                    sev = 'medium'
                else:
                    sev = 'low'
                    
                findings.append(Finding(
                    category=cat,
                    severity=sev,
                    file=file_path,
                    line=issue.get('line', 0) or 0,
                    message=issue.get('message', ''),
                    rule_id=issue.get('rule', 'UNKNOWN'),
                    detected_by=[self.tool_name]
                ))
                
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.COMPLETED,
                findings=findings
            )
            
        except FileNotFoundError:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message="sonar-scanner executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
