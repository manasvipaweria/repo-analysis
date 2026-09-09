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
    DEPENDENCIES = "dependency_security"
    PRIVACY = "privacy"
    ARCHITECTURE = "architecture"
    UI_DESIGN = "ui_design"
    AI_DESIGN = "ai_design"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    TESTING = "testing"
    TYPING = "typing"


class ComplianceFindingType(str, Enum):
    INVENTORY = "inventory"                 # personal data detected, no risk indicator attached
    THIRD_PARTY_RISK = "third_party_risk"   # personal data transmitted to an external service
    SECURITY_GAP = "security_gap"           # personal data inadequately protected (Art. 32)
    MINIMISATION_FLAG = "minimisation_flag" # field collected but no downstream use detected
    HUMAN_REVIEW = "human_review"           # cannot be determined from source code

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

import uuid

@dataclass
class FindingLocation:
    file: Optional[str] = None
    line: Optional[int] = None

@dataclass
class FindingEvidence:
    code_context: Optional[str] = None
    # Structured classification for inline-style findings. Values:
    #   EXACT_MIGRATION       - has a verified Tailwind/design-system equivalent
    #   TOKEN_CONTEXT_REQUIRED - uses a CSS custom property with no verified Tailwind utility
    #   DYNAMIC_ALLOWED       - runtime/computed value, correct to be inline
    #   TEST_FIXTURE          - intentional test file, not a production issue
    #   UNCATEGORIZED         - default when classification is not applicable or undetermined
    classification: Optional[str] = None
    # For EXACT_MIGRATION: the specific Tailwind class that replaces the inline style.
    # Only set when the equivalence is verified against the actual design system.
    suggested_migration: Optional[str] = None

@dataclass
class AIFutureFields:
    # Kept separate to ensure tool-generated data is distinct from future AI outputs.
    analysis_summary: Optional[str] = None
    security_impact: Optional[str] = None
    remediation_suggestion: Optional[str] = None
    is_false_positive_prediction: Optional[bool] = None

@dataclass(init=False)
class Finding:
    finding_id: str
    status: str
    category: str
    severity: str
    priority: str
    title: str
    description: str
    location: FindingLocation
    detected_by: List[str]
    rule_id: str
    evidence: FindingEvidence
    merge_blocking: bool
    confidence: Optional[str] = None
    ai_fields: Optional[AIFutureFields] = None
    gdpr_references: Optional[List[str]] = None
    compliance_finding_type: Optional['ComplianceFindingType'] = None
    # Compliance report fields — human-readable answers for every GDPR finding
    requirement: Optional[str] = None          # What regulation applies and why it matters
    detected_evidence: Optional[str] = None    # What was found in the code (populated per-finding)
    recommended_action: Optional[str] = None   # What needs to be verified or changed
    human_review_required: Optional[str] = None  # Whether legal/human review is needed
    
    def __init__(
        self, category: str, severity: str, file: Optional[str], line: Optional[int], 
        message: str, rule_id: str, detected_by: List[str] = None, confidence: Optional[str] = None,
        finding_id: Optional[str] = None, priority: str = "P3", code_context: Optional[str] = None,
        merge_blocking: bool = False, ai_fields: Optional[AIFutureFields] = None,
        status: str = "OPEN", title: Optional[str] = None, description: Optional[str] = None,
        location: Optional[FindingLocation] = None, evidence: Optional[FindingEvidence] = None,
        gdpr_references: Optional[List[str]] = None,
        compliance_finding_type: Optional['ComplianceFindingType'] = None,
        requirement: Optional[str] = None,
        detected_evidence: Optional[str] = None,
        recommended_action: Optional[str] = None,
        human_review_required: Optional[str] = None,
    ):
        self.finding_id = finding_id or str(uuid.uuid4())
        self.status = status
        self.category = category
        self.severity = severity
        self.priority = priority
        self.title = title if title else rule_id
        self.description = description if description else message
        
        if location:
            self.location = location
        else:
            clean_line = line if line not in (0, -1, None) else None
            self.location = FindingLocation(file=file, line=clean_line)
            
        self.detected_by = detected_by or []
        self.rule_id = rule_id
        
        if evidence:
            self.evidence = evidence
        else:
            self.evidence = FindingEvidence(code_context=code_context)
            
        self.merge_blocking = merge_blocking
        self.confidence = confidence
        self.ai_fields = ai_fields
        self.gdpr_references = gdpr_references or []
        self.compliance_finding_type = compliance_finding_type
        self.requirement = requirement
        self.detected_evidence = detected_evidence
        self.recommended_action = recommended_action
        self.human_review_required = human_review_required

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
    data_flow: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        import dataclasses
        
        def dict_factory(data):
            return {k: v for k, v in data if v is not None}
            
        # Standard asdict converts enums to their string values if they inherit from str
        raw_dict = dataclasses.asdict(self, dict_factory=dict_factory)
        
        # We need to manually clean up nested enums if standard asdict doesn't do it perfectly
        # But since our enums inherit from str, json.dumps will handle them natively.
        return raw_dict

    @classmethod
    def from_dict(cls, data: dict) -> 'Report':
        summary_dict = {}
        for k, v in data.get("summary", {}).items():
            metrics_data = v.get("metrics")
            tools_data = v.get("tools", {})
            summary_dict[k] = CategorySummary(
                status=CategoryStatus(v.get("status")),
                count=v.get("count", 0),
                tools=tools_data,
                metrics=metrics_data
            )
            
        findings_list = []
        for fd in data.get("findings", []):
            loc_data = fd.get("location")
            loc = FindingLocation(**loc_data) if loc_data else None
            
            ev_data = fd.get("evidence")
            ev = FindingEvidence(**ev_data) if ev_data else None
            
            ai_data = fd.get("ai_fields")
            ai_fields = AIFutureFields(**ai_data) if ai_data else None
            
            f = Finding(
                finding_id=fd.get("finding_id"),
                status=fd.get("status", "OPEN"),
                category=fd.get("category"),
                severity=fd.get("severity"),
                priority=fd.get("priority", "P3"),
                title=fd.get("title"),
                description=fd.get("description", ""),
                location=loc,
                evidence=ev,
                detected_by=fd.get("detected_by", []),
                rule_id=fd.get("rule_id", ""),
                merge_blocking=fd.get("merge_blocking", False),
                confidence=fd.get("confidence"),
                ai_fields=ai_fields,
                gdpr_references=fd.get("gdpr_references", []),
                compliance_finding_type=ComplianceFindingType(fd["compliance_finding_type"]) if fd.get("compliance_finding_type") else None,
                requirement=fd.get("requirement"),
                detected_evidence=fd.get("detected_evidence"),
                recommended_action=fd.get("recommended_action"),
                human_review_required=fd.get("human_review_required"),
                file=None,  # Legacy args
                line=None,
                message=""
            )
            findings_list.append(f)
            
        return cls(
            repo=data.get("repo", ""),
            timestamp=data.get("timestamp", ""),
            summary=summary_dict,
            findings=findings_list,
            data_flow=data.get("data_flow")
        )
