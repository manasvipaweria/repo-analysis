import os
import json
import pytest
from pathlib import Path
from src.compliance.vendor_registry import VendorRegistry, VendorMatch, get_vendor_registry

@pytest.fixture
def temp_repo(tmp_path):
    repo = tmp_path / "target_repo"
    repo.mkdir()
    return repo

def test_vendor_registry_default_load():
    registry = get_vendor_registry()
    match = registry.is_approved_vendor("twilio")
    assert match.status == "APPROVED"
    assert match.vendor_name == "Twilio"

def test_vendor_registry_domain_match():
    registry = get_vendor_registry()
    match = registry.is_approved_vendor("api.twilio.com")
    assert match.status == "APPROVED"

def test_vendor_registry_unknown_vendor():
    registry = get_vendor_registry()
    match = registry.is_approved_vendor("unknown-tracker.com")
    assert match.status == "NOT_FOUND"

def test_vendor_registry_case_insensitive():
    registry = get_vendor_registry()
    match = registry.is_approved_vendor("TWILIO.COM")
    assert match.status == "APPROVED"

def test_vendor_registry_target_override(temp_repo):
    compliance_dir = temp_repo / ".compliance"
    compliance_dir.mkdir()
    target_config = compliance_dir / "approved_vendors.json"
    target_config.write_text(json.dumps({
        "vendors": [
            {
                "name": "Twilio",
                "status": "NOT_ALLOWED",
                "identifiers": ["twilio"]
            },
            {
                "name": "NewVendor",
                "status": "APPROVED",
                "identifiers": ["new-vendor.com"]
            }
        ]
    }))
    
    registry = VendorRegistry(str(temp_repo))
    match_twilio = registry.is_approved_vendor("twilio")
    assert match_twilio.status == "NOT_ALLOWED"
    
    match_new = registry.is_approved_vendor("new-vendor.com")
    assert match_new.status == "APPROVED"

def test_vendor_registry_malformed_target(temp_repo):
    compliance_dir = temp_repo / ".compliance"
    compliance_dir.mkdir()
    target_config = compliance_dir / "approved_vendors.json"
    target_config.write_text("INVALID JSON")
    
    with pytest.raises(ValueError, match="Configuration error: Invalid target vendor registry"):
        VendorRegistry(str(temp_repo))

def test_vendor_registry_false_positive():
    registry = get_vendor_registry()
    match = registry.is_approved_vendor("not-twilio.com")
    assert match.status == "NOT_FOUND"
    
    match_pkg = registry.is_approved_vendor("atwilio")
    assert match_pkg.status == "NOT_FOUND"
