import os
import pytest
from src.core.models import Finding, FindingLocation
from src.core.fingerprinting import normalize_path, generate_fingerprint, assign_fingerprints

def test_normalize_path():
    # Test path normalization
    assert normalize_path(r"C:\runner\repo\src\foo.py", r"C:\runner\repo") == "src/foo.py"
    assert normalize_path("/home/runner/work/repo/repo/src/foo.py", "/home/runner/work/repo/repo") == "src/foo.py"
    assert normalize_path("./src/foo.py") == "src/foo.py"
    assert normalize_path("src/foo.py") == "src/foo.py"

def test_deterministic_fingerprint():
    f1 = Finding(
        category="security",
        severity="high",
        file="src/foo.py",
        line=10,
        message="SQLi",
        rule_id="B608",
        detected_by=["bandit"]
    )
    f2 = Finding(
        category="security",
        severity="high",
        file="src/foo.py",
        line=10,
        message="SQLi",
        rule_id="B608",
        detected_by=["bandit"]
    )
    fp1 = generate_fingerprint(f1)
    fp2 = generate_fingerprint(f2)
    assert fp1 == fp2
    assert f1.finding_id != f2.finding_id

def test_different_rule_fingerprint():
    f1 = Finding(
        category="security",
        severity="high",
        file="src/foo.py",
        line=10,
        message="SQLi",
        rule_id="B608",
        detected_by=["bandit"]
    )
    f2 = Finding(
        category="security",
        severity="high",
        file="src/foo.py",
        line=10,
        message="SQLi",
        rule_id="B101",
        detected_by=["bandit"]
    )
    assert generate_fingerprint(f1) != generate_fingerprint(f2)

def test_different_location_fingerprint():
    f1 = Finding(
        category="security",
        severity="high",
        file="src/foo.py",
        line=10,
        message="SQLi",
        rule_id="B608",
        detected_by=["bandit"]
    )
    f2 = Finding(
        category="security",
        severity="high",
        file="src/foo.py",
        line=11,
        message="SQLi",
        rule_id="B608",
        detected_by=["bandit"]
    )
    assert generate_fingerprint(f1) != generate_fingerprint(f2)

def test_missing_fields_no_crash():
    f1 = Finding(
        category="security",
        severity="high",
        file=None,
        line=None,
        message="SQLi",
        rule_id="",
        detected_by=[]
    )
    fp = generate_fingerprint(f1)
    assert fp is not None
