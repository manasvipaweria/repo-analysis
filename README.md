# Unified Repo Analysis Orchestrator

A unified Python orchestrator that runs code analysis, security, quality, and testing tools against a Git repository and produces a single normalized report (JSON and CSV).

## Features
- Clones target repository securely into a temporary directory.
- Runs a configurable suite of tools: Ruff, Bandit, Semgrep, Pip-audit, Mypy, Pytest (with coverage), and Import-Linter.
- Normalizes findings across all tools into a consistent format.
- Deduplicates overlapping findings across tools to reduce noise.
- Explicitly handles tool statuses (`COMPLETED`, `SKIPPED`, `ERROR`) to ensure `PASSED` means 100% clean.
- Outputs detailed JSON and summary-inclusive CSV reports.

## Supported Tools

### Python Ecosystem
- **Ruff**: Linting and code quality
- **Bandit**: Security analysis (SAST)
- **Pip-audit**: Dependency vulnerabilities
- **Mypy**: Static type checking
- **Pytest**: Unit testing and coverage
- **Import-Linter**: Architecture and dependency rules
- **Semgrep**: Advanced SAST across languages

### JS/TS/Node/React Ecosystem
- **Snyk Open Source**: Dependency vulnerabilities. Requires `snyk` CLI installed and authenticated (`snyk auth`). Handles multiple package manifests.
- **OWASP dep-scan**: Dependency vulnerabilities mapping to CVEs/GHSAs. Includes a configurable execution timeout (default 600s).
- **Dependency-Cruiser**: Architecture and forbidden dependency analysis. Requires `.dependency-cruiser.js` configuration.
- **SonarQube Community**: Code quality and SAST. Requires `sonar-scanner` and `sonar-project.properties` (or `SONAR_HOST_URL` env var).
- **React Doctor**: Code quality and best practices for React repositories. Automatically detects React via `package.json` or `.jsx`/`.tsx` files.
- **Semgrep**: Advanced SAST across languages.

*Note: The orchestrator automatically detects the ecosystem based on files (e.g. `package.json`, `.py`, `.jsx`) and gracefully skips tools that are not applicable to the repository. If a tool crashes or times out, it is isolated and the orchestrator continues with the remaining tools safely.*

## Setup

1. Install Python requirements:
   ```bash
   pip install -r requirements.txt
   ```

2. Make sure the tools you intend to use are available in your `PATH`.
   - JS tools can be installed globally via npm (e.g. `npm install -g snyk @owasp/dep-scan dependency-cruiser`).
   - SonarQube requires the `sonar-scanner` executable.
   - Snyk requires authentication via `snyk auth`.

## Usage

Run the orchestrator by passing the URL to a repository (or a local directory path):

```bash
python analyze_repo.py https://github.com/user/repo
```

### Options

- `--branch main` : Analyze a specific branch.
- `--tools ruff,bandit,pytest,snyk` : Selectively run a subset of tools.
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

This repository acts as the central hub for the Repo Analysis Orchestrator. It exposes a **Reusable GitHub Actions workflow** (`.github/workflows/reusable-analysis.yml`).

### Calling the Reusable Workflow
You can integrate this orchestrator into any other repository without copying its code.

Create a workflow file in your target repository (e.g., `Custom-Assembler/.github/workflows/code-analysis.yml`):

```yaml
name: Code Analysis

on:
  push:
    branches: [ "**" ]
  pull_request:
    branches: [ "**" ]
  workflow_dispatch:

jobs:
  analyze:
    uses: manasvipaweria/repo-analysis/.github/workflows/reusable-analysis.yml@main
```

### What happens during execution?
1. **Target repository**: GitHub Actions checks out the target repository (e.g., `Custom-Assembler`).
2. **Central repo-analysis workflow**: It fetches this central orchestrator.
3. **V2 analysis**: It runs the orchestrator against the target repository. The `code_context` will be safely extracted from the target repository's files.
4. **JSON + CSV**: It generates the reports with the target repository's identifier (e.g., `manasvipaweria/Custom-Assembler`).
5. **Artifact**: The reports are uploaded as the `repo-analysis-report` artifact to the target repository's workflow run.

### Future Enhancements
The following features are intentionally deferred to a later phase and are not yet implemented:
- Merge blocking (not yet enforced by GitHub branch protection)
- AI/LLM integration (Gemini, OpenAI, Claude) for analysis or automatic remediation
- PR comments or inline code annotations
- Automatic code fixes pushed back to the branch
