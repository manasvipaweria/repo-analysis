from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Category(str, Enum):
    SECURITY = "security"
    ARCHITECTURE = "architecture"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    DEPENDENCIES = "dependencies"
    TESTING = "testing"
    TYPING = "typing"

class ToolStatus(str, Enum):
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class CategoryStatus(str, Enum):
    PASSED = "PASSED"
    ISSUES_FOUND = "ISSUES_FOUND"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

@dataclass
class Finding:
    category: str
    severity: str
    file: str
    line: int
    message: str
    rule_id: str
    detected_by: List[str] = field(default_factory=list)
    confidence: Optional[str] = None

@dataclass
class TestMetrics:
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    coverage_percent: Optional[float] = None

@dataclass
class ToolResult:
    tool: str
    status: ToolStatus
    findings: List[Finding] = field(default_factory=list)
    metrics: Optional[TestMetrics] = None
    error_message: Optional[str] = None

@dataclass
class CategorySummary:
    status: CategoryStatus
    count: int
    tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    metrics: Optional[Dict[str, Any]] = None

@dataclass
class Report:
    repo: str
    timestamp: str
    summary: Dict[str, CategorySummary] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        import dataclasses
        
        def dict_factory(data):
            return {k: v for k, v in data if v is not None}
            
        # Standard asdict converts enums to their string values if they inherit from str
        raw_dict = dataclasses.asdict(self)
        
        # We need to manually clean up nested enums if standard asdict doesn't do it perfectly
        # But since our enums inherit from str, json.dumps will handle them natively.
        return raw_dict
