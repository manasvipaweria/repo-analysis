import subprocess
import tempfile
import os
import shutil

def clone_repo(repo_url: str, branch: str = None) -> str:
    """Clones a repository into a temporary directory and returns the path."""
    temp_dir = tempfile.mkdtemp(prefix="orchestrator_")
    
    cmd = ["git", "clone", repo_url, temp_dir]
    if branch:
        cmd = ["git", "clone", "-b", branch, repo_url, temp_dir]
        
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return temp_dir
    except subprocess.CalledProcessError as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to clone repo {repo_url}: {e.stderr}")

def cleanup_repo(repo_path: str) -> None:
    """Removes the temporary repository directory."""
    if os.path.exists(repo_path):
        # Handle readonly files on Windows
        def onerror(func, path, exc_info):
            import stat
            if not os.access(path, os.W_OK):
                try:
                    os.chmod(path, stat.S_IWUSR)
                    func(path)
                except Exception:
                    pass
            else:
                pass
        shutil.rmtree(repo_path, onerror=onerror)
