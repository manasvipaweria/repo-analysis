import subprocess
import json
import os
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter
from src.utils.project import is_react_project

class DeslintAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "deslint"

    @property
    def categories(self) -> List[str]:
        return [Category.QUALITY.value]

    def run(self, repo_path: str) -> ToolResult:
        if os.environ.get("ENABLE_DESLINT") != "true":
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="Deslint is opt-in. Set ENABLE_DESLINT=true to run."
            )

        if not is_react_project(repo_path):
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="No React project detected."
            )

        config_content = """import deslint from '@deslint/eslint-plugin';

export default [
  {
    files: ['**/*.{js,jsx,ts,tsx}'],
    plugins: { deslint },
    rules: {
      'deslint/no-inline-styles': 'warn',
      'deslint/no-arbitrary-colors': 'warn',
      'deslint/no-arbitrary-spacing': 'warn',
      'deslint/no-arbitrary-typography': 'warn',
      'deslint/responsive-required': 'warn',
      'deslint/missing-states': 'off',
      'deslint/no-default-checked': 'warn'
    },
    languageOptions: {
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        ecmaFeatures: { jsx: true }
      }
    }
  }
];
"""
        config_path = os.path.join(repo_path, ".deslint.config.mjs")
        
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(config_content)
                
            # Install ESLint and Deslint temporarily if not present
            install_cmd = "npm install --no-save eslint@9 @deslint/eslint-plugin"
            subprocess.run(install_cmd, cwd=repo_path, capture_output=True, shell=True)

            cmd = "npx eslint -c .deslint.config.mjs . -f json"
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                shell=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            try:
                output_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                if not result.stdout.strip():
                    output_data = []
                else:
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.ERROR,
                        error_message=f"Failed to parse ESLint output: {result.stdout[:200]}"
                    )
            
            findings = []
            for file_result in output_data:
                file_path = file_result.get("filePath", "")
                if file_path.startswith(repo_path):
                    file_path = os.path.relpath(file_path, repo_path).replace("\\", "/")
                    
                for msg in file_result.get("messages", []):
                    rule_id = msg.get("ruleId") or ""
                    if not rule_id.startswith("deslint/"):
                        continue
                        
                    findings.append(Finding(
                        category=Category.QUALITY.value,
                        severity="medium",
                        file=file_path,
                        line=msg.get("line", 0),
                        message=msg.get("message", "Deslint finding"),
                        rule_id=rule_id,
                        detected_by=[self.tool_name]
                    ))
                    
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.COMPLETED,
                findings=findings
            )
            
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
        finally:
            if os.path.exists(config_path):
                os.remove(config_path)
