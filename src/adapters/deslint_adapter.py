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
      'deslint/missing-states': 'off'
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
        react_dir = repo_path
        for root_dir, dirs, files in os.walk(repo_path):
            if 'node_modules' in dirs:
                dirs.remove('node_modules')
            if 'package.json' in files:
                try:
                    with open(os.path.join(root_dir, 'package.json'), 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                        if 'react' in deps or 'react-dom' in deps:
                            react_dir = root_dir
                            break
                except Exception:
                    pass

        config_path = os.path.join(react_dir, ".deslint.config.mjs")
        
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(config_content)
                
            cmd = "npx eslint -c .deslint.config.mjs . -f json"
            result = subprocess.run(
                cmd,
                cwd=react_dir,
                capture_output=True,
                shell=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            if not result.stdout.strip():
                if result.returncode != 0:
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.ERROR,
                        error_message=f"ESLint failed with exit code {result.returncode}: {result.stderr.strip()[:500]}"
                    )
                output_data = []
            else:
                try:
                    output_data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    error_src = result.stderr if result.stderr.strip() else result.stdout
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.ERROR,
                        error_message=f"Failed to parse ESLint JSON (exit code {result.returncode}): {error_src.strip()[:500]}"
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
