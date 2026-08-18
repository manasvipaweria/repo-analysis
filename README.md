# Unified Repo Analysis Orchestrator

A unified Python orchestrator that runs code analysis, security, quality, and testing tools against a Git repository and produces a single normalized report (JSON and CSV).

## Features
- Clones target repository securely into a temporary directory.
- Runs a configurable suite of tools: Ruff, Bandit, Semgrep, Pip-audit, Mypy, Pytest (with coverage), and Import-Linter.
- Normalizes findings across all tools into a consistent format.
- Deduplicates overlapping findings across tools to reduce noise.
- Explicitly handles tool statuses (`COMPLETED`, `SKIPPED`, `ERROR`) to ensure `PASSED` means 100% clean.
- Outputs detailed JSON and summary-inclusive CSV reports.

## Setup

1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

2. Make sure the tools you intend to use are available in your `PATH` or virtual environment. The orchestrator gracefully handles missing tools by marking them as `ERROR`.

## Usage

Run the orchestrator by passing the URL to a repository (or a local directory path):

```bash
python analyze_repo.py https://github.com/user/repo
```

### Options

- `--branch main` : Analyze a specific branch.
- `--tools ruff,bandit,pytest` : Selectively run a subset of tools.
- `--output json,csv` : Select output formats.

## Adding a New Tool Adapter

1. Create a new file in `src/adapters/` (e.g., `newtool_adapter.py`).
2. Implement the `BaseAdapter` class.
3. Parse the tool's native output and convert it into `Finding` dataclasses.
4. Add the adapter to the `ALL_ADAPTERS` dictionary in `analyze_repo.py`.

```python
from src.adapters.base import BaseAdapter
from src.core.models import ToolResult, ToolStatus

class NewToolAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "new-tool"

    @property
    def categories(self) -> list:
        return ["security"]

    def run(self, repo_path: str) -> ToolResult:
        # Run tool via subprocess
        # Parse output
        # Return ToolResult
        pass
```

## GitHub Actions CI Integration

This repository includes a fully configured GitHub Actions workflow (`.github/workflows/repo-analysis.yml`).

### What triggers the workflow?
- **Push events**: Any push to any branch.
- **Pull Requests**: Creation or update of any pull request.
- **Manual Execution**: Via the `workflow_dispatch` trigger in the GitHub Actions tab.

### Where to find generated reports?
When the workflow completes, the generated `report.json` and `report.csv` files are automatically grouped and uploaded as a GitHub Actions Artifact named **`repo-analysis-report`**. 
You can download these artifacts from the summary page of the workflow run.

### Future Enhancements
The following features are intentionally deferred to a later phase and are not yet implemented:
- Merge blocking / Required status checks based on findings
- AI/LLM integration (Gemini, OpenAI, Claude) for analysis or automatic remediation
- PR comments or inline code annotations
- Automatic code fixes pushed back to the branch
- JavaScript/Node adapters
- Dashboard UI, Google Docs export, or Email notifications
