import pytest
from unittest.mock import MagicMock, patch
from onboard_org import GitHubClient, generate_template

@pytest.fixture
def mock_client():
    client = GitHubClient("fake_token")
    client._request = MagicMock()
    return client

def test_generate_template():
    content = generate_template("v1")
    assert "uses: manasvipaweria/repo-analysis/.github/workflows/reusable-analysis.yml@v1" in content
    assert "${{ secrets.SNYK_TOKEN }}" in content

def test_get_repos_pagination(mock_client):
    # Mock pagination logic
    mock_client._request.side_effect = [
        [{"full_name": "org/repo1", "archived": False, "default_branch": "main"}] * 100,
        [{"full_name": "org/repo2", "archived": False, "default_branch": "main"}] * 50
    ]
    repos = mock_client.get_repos("org")
    assert len(repos) == 150
    assert mock_client._request.call_count == 2

def test_get_repos_ignores_archived(mock_client):
    mock_client._request.side_effect = [
        [
            {"full_name": "org/repo1", "archived": False, "default_branch": "main"},
            {"full_name": "org/repo2", "archived": True, "default_branch": "main"}
        ]
    ]
    repos = mock_client.get_repos("org")
    assert len(repos) == 1
    assert repos[0]["full_name"] == "org/repo1"

def test_get_file_content_missing(mock_client):
    mock_client._request.return_value = None
    content, sha = mock_client.get_file_content("org/repo1", ".github/workflows/code-analysis.yml")
    assert content is None
    assert sha is None

def test_get_file_content_exists(mock_client):
    import base64
    fake_content = base64.b64encode(b"name: Code Analysis").decode("utf-8")
    mock_client._request.return_value = {"content": fake_content, "sha": "abcdef"}
    content, sha = mock_client.get_file_content("org/repo1", ".github/workflows/code-analysis.yml")
    assert content == "name: Code Analysis"
    assert sha == "abcdef"
