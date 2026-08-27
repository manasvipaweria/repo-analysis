#!/usr/bin/env bash
set -e

echo "=== Code Analysis Repository Onboarding ==="

# Validate that the user is inside a Git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "❌ Error: You must be inside a Git repository to onboard it."
    exit 1
fi

# Validate that an origin remote exists
if ! git config --get remote.origin.url >/dev/null 2>&1; then
    echo "❌ Error: Remote 'origin' does not exist. Please configure an origin remote."
    exit 1
fi

# Validate that the origin points to GitHub
ORIGIN_URL=$(git config --get remote.origin.url)
if [[ "$ORIGIN_URL" != *"github.com"* ]]; then
    echo "❌ Error: Remote 'origin' does not appear to point to GitHub ($ORIGIN_URL)."
    exit 1
fi

# Detect the repository's current/default branch
DEFAULT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ -z "$DEFAULT_BRANCH" ] || [ "$DEFAULT_BRANCH" = "HEAD" ]; then
    DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")
fi

echo "Repository detected. Default branch: $DEFAULT_BRANCH"

# Check whether .github/workflows/code-analysis.yml already exists
WORKFLOW_FILE=".github/workflows/code-analysis.yml"
if [ -f "$WORKFLOW_FILE" ]; then
    echo "❌ Error: The repository is already onboarded ($WORKFLOW_FILE exists)."
    echo "   Aborting to prevent overwriting existing configuration."
    exit 1
fi

# Create branch
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
BRANCH_NAME="setup/code-analysis-$TIMESTAMP"
echo "Creating setup branch: $BRANCH_NAME"
git checkout -b "$BRANCH_NAME"

# Create workflow
mkdir -p .github/workflows

# Triggers configuration
TRIGGERS="${TRIGGERS:-pull_request}"
if [ "$TRIGGERS" = "push,pull_request" ]; then
    ON_CONFIG="  push:
  pull_request:"
elif [ "$TRIGGERS" = "push" ]; then
    ON_CONFIG="  push:"
else
    ON_CONFIG="  pull_request:"
fi

cat <<YML_EOF > "$WORKFLOW_FILE"
name: Code Analysis

on:
$ON_CONFIG

jobs:
  analysis:
    uses: manasvipaweria/repo-analysis/.github/workflows/reusable-analysis.yml@main
    secrets:
      SNYK_TOKEN: \${{ secrets.SNYK_TOKEN }}
      GEMINI_API_KEY: \${{ secrets.GEMINI_API_KEY }}
YML_EOF

echo "✅ Created workflow at: $WORKFLOW_FILE"

# Commit generated workflow
git add "$WORKFLOW_FILE"
git commit -m "ci: add central Code Analysis workflow" >/dev/null
echo "✅ Committed workflow configuration."

# Push branch
echo "Pushing branch $BRANCH_NAME to origin..."
if ! git push -u origin "$BRANCH_NAME"; then
    echo "⚠️  Warning: Failed to push branch to origin. You may need to push it manually."
fi

# GitHub CLI Check / Secret Check
HAS_GH=false
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    HAS_GH=true
fi

echo ""
echo "=== Secret Visibility Check ==="
if [ "$HAS_GH" = true ]; then
    echo "Checking secrets via GitHub API..."
    # 'gh secret list' only shows repository-level secrets.
    # To check effective access, we query both the repository and shared organization secrets APIs.
    
    REPO_SECRETS=$(gh api repos/:owner/:repo/actions/secrets --jq '.secrets[].name' 2>/dev/null || echo "")
    ORG_SECRETS=$(gh api repos/:owner/:repo/actions/organization-secrets --jq '.secrets[].name' 2>/dev/null || echo "")
    
    ALL_SECRETS=$(echo -e "$REPO_SECRETS\n$ORG_SECRETS")
    
    if echo "$ALL_SECRETS" | grep -q "GEMINI_API_KEY"; then
        echo "✅ GEMINI_API_KEY is available to this repository."
    else
        echo "⚠️  GEMINI_API_KEY could not be found via the GitHub API."
        echo "   Please ensure it is set as a Repository secret or an Organization secret granted to this repo."
    fi

    if echo "$ALL_SECRETS" | grep -q "SNYK_TOKEN"; then
        echo "✅ SNYK_TOKEN is available to this repository."
    else
        echo "⚠️  SNYK_TOKEN could not be found via the GitHub API."
        echo "   Please ensure it is set as a Repository secret or an Organization secret granted to this repo."
    fi
else
    echo "⚠️  GitHub CLI (gh) is not available or not authenticated."
    echo "   Could not automatically verify if GEMINI_API_KEY and SNYK_TOKEN are available."
    echo "   Please verify manually in your repository settings."
fi

# PR creation
echo ""
echo "=== Pull Request ==="
if [ "$HAS_GH" = true ]; then
    echo "Creating Pull Request..."
    if gh pr create --title "Setup Code Analysis Workflow" \
                 --body "This PR onboards the repository to the central security and AI code analysis pipeline." \
                 --base "$DEFAULT_BRANCH" \
                 --head "$BRANCH_NAME"; then
        echo "✅ Pull Request created successfully!"
    else
        echo "⚠️  Failed to create Pull Request via GitHub CLI. Please create it manually."
    fi
else
    echo "✅ Branch pushed to origin."
    echo "⚠️  Could not create Pull Request automatically because 'gh' is not authenticated."
    echo "   Please create a Pull Request manually for branch: $BRANCH_NAME"
fi

echo ""
echo "🎉 Onboarding step complete."
