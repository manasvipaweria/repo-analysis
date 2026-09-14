import os
import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path

@dataclass
class VendorMatch:
    status: str
    vendor_name: Optional[str] = None
    category: Optional[str] = None

class VendorRegistry:
    def __init__(self, target_repo_path: Optional[str] = None):
        self.vendors: Dict[str, dict] = {}
        self._load_default_registry()
        if target_repo_path:
            self._load_target_registry(target_repo_path)

    def _load_default_registry(self):
        default_path = Path(__file__).resolve().parent.parent.parent / "config" / "approved_vendors.default.json"
        self._merge_registry(default_path)

    def _load_target_registry(self, repo_path: str):
        target_path = Path(repo_path) / ".compliance" / "approved_vendors.json"
        if target_path.exists():
            try:
                self._merge_registry(target_path)
            except Exception as e:
                raise ValueError(f"Configuration error: Invalid target vendor registry at {target_path}. Details: {e}")

    def _merge_registry(self, path: Path):
        if not path.exists():
            return
        
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        if "vendors" not in data:
            return
            
        for vendor in data.get("vendors", []):
            v_name = vendor.get("name")
            if not v_name:
                continue
            
            key = v_name.lower()
            if key in self.vendors:
                self.vendors[key].update(vendor)
            else:
                self.vendors[key] = vendor

    def _normalize_identifier(self, identifier: str) -> str:
        ident = identifier.lower().strip()
        ident = re.sub(r'^https?://', '', ident)
        
        # Avoid breaking scoped packages like @twilio/client. 
        # If it doesn't start with @ and has a slash, it might be a URL path, so strip path.
        if '/' in ident and not ident.startswith('@'):
            ident = ident.split('/')[0]
            
        return ident
        
    def is_approved_vendor(self, identifier: str) -> VendorMatch:
        if not identifier:
            return VendorMatch(status="NOT_FOUND")
            
        norm_id = self._normalize_identifier(identifier)
        
        for key, vendor in self.vendors.items():
            identifiers = [i.lower() for i in vendor.get("identifiers", [])]
            
            for i in identifiers:
                if norm_id == i:
                    return VendorMatch(
                        status=vendor.get("status", "APPROVED"),
                        vendor_name=vendor.get("name"),
                        category=vendor.get("category")
                    )
                
                # domain/subdomain matching
                if '.' in i and norm_id.endswith("." + i):
                    return VendorMatch(
                        status=vendor.get("status", "APPROVED"),
                        vendor_name=vendor.get("name"),
                        category=vendor.get("category")
                    )
                    
        return VendorMatch(status="NOT_FOUND")

_registry_instance = None

def get_vendor_registry(target_repo_path: Optional[str] = None) -> VendorRegistry:
    global _registry_instance
    if _registry_instance is None or getattr(_registry_instance, "_target_repo_path", None) != target_repo_path:
        _registry_instance = VendorRegistry(target_repo_path)
        _registry_instance._target_repo_path = target_repo_path
    return _registry_instance
