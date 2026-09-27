from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TrustLevel(Enum):
    TRUSTED_SYSTEM = 0
    AUTHENTICATED_USER = 1
    UNTRUSTED_EXTERNAL = 2  # F.eks. web-scrapes, e-poster, PDF-er, API-payloads


class ThreatCategory(Enum):
    HOMOGLYPH_OBFUSCATION = "HOMOGLYPH_OBFUSCATION"
    INDIRECT_ROLE_HIJACK = "INDIRECT_ROLE_HIJACK"
    SPECIAL_TOKEN_INJECTION = "SPECIAL_TOKEN_INJECTION"
    MARKDOWN_EXFILTRATION = "MARKDOWN_EXFILTRATION"
    UNSAFE_CODE_EXECUTION = "UNSAFE_CODE_EXECUTION"
    TOOL_ARGUMENT_POISONING = "TOOL_ARGUMENT_POISONING"
    SEMANTIC_JAILBREAK = "SEMANTIC_JAILBREAK"


class EnforcementAction(Enum):
    ALLOW = "ALLOW"
    SANITIZE_AND_WRAP = "SANITIZE_AND_WRAP"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class SecurityViolation:
    category: ThreatCategory
    rule_id: str
    risk_score: float
    description: str
    extracted_sample: str


@dataclass
class TaintReport:
    is_safe: bool
    action: EnforcementAction
    sanitized_text: str
    boundary_token: str
    max_risk: float
    trust_level: TrustLevel
    violations: List[SecurityViolation] = field(default_factory=list)


@dataclass
class ToolCallEvaluation:
    is_valid: bool
    tool_name: str
    sanitized_arguments: Dict[str, Any]
    violations: List[SecurityViolation] = field(default_factory=list)
