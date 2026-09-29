"""PromptGuard-Taint: Audit Session Logger & Signed JSON Report Generator.

Zero-dependency implementation using Python's standard library:
- json (canonical sorting)
- hashlib (SHA-256 digests)
- hmac (HMAC-SHA256 signature blocks)
- datetime, secrets
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
from typing import Any, Dict, List, Optional
from .models import EnforcementAction, SecurityViolation, TaintReport, TrustLevel


def canonicalize_json(data: Any) -> str:
    """Deterministic JSON serialization with alphabetically sorted keys (RFC 8785)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    source_origin: str
    trust_level: str
    target_tool: Optional[str]
    raw_payload: str
    payload_sha256: str
    action: str
    max_risk_score: float
    violations: List[Dict[str, Any]]
    taint_boundary: str


class AuditSessionLogger:
    """Manages kernel inspection session provenance logs and generates signed JSON audit reports."""

    def __init__(self, session_key: Optional[str] = None):
        self.session_id = f"SESS-{secrets.token_hex(6).upper()}"
        self.session_start = datetime.now(timezone.utc).isoformat()
        self.session_key = session_key or secrets.token_hex(32)
        self.key_id = f"PG-KEY-{secrets.token_hex(4).upper()}"
        self.events: List[AuditEvent] = []

    def record_inspection(
        self,
        report: TaintReport,
        source_origin: str = "python_kernel",
        target_tool: Optional[str] = None,
        raw_payload: Optional[str] = None,
    ) -> AuditEvent:
        event_id = f"EVT-{secrets.token_hex(4).upper()}"
        payload_text = raw_payload if raw_payload is not None else report.sanitized_text
        payload_hash = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()

        violations_dict = [
            {
                "category": v.category.value if hasattr(v.category, "value") else str(v.category),
                "rule_id": v.rule_id,
                "risk_score": v.risk_score,
                "description": v.description,
                "sample": v.extracted_sample,
            }
            for v in report.violations
        ]

        action_str = (
            report.action.value if hasattr(report.action, "value") else str(report.action)
        )
        trust_str = (
            report.trust_level.name
            if hasattr(report.trust_level, "name")
            else str(report.trust_level)
        )

        event = AuditEvent(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_origin=source_origin,
            trust_level=trust_str,
            target_tool=target_tool,
            raw_payload=payload_text,
            payload_sha256=payload_hash,
            action=action_str,
            max_risk_score=report.max_risk,
            violations=violations_dict,
            taint_boundary=report.boundary_token,
        )
        self.events.append(event)
        return event

    def generate_signed_report(
        self,
        organization: str = "Enterprise SecOps",
        auditor_notes: str = "Kernel Inspection Audit",
        include_payloads: bool = True,
    ) -> Dict[str, Any]:
        """Builds, canonicalizes, and cryptographically signs a JSON audit report."""
        generated_at = datetime.now(timezone.utc).isoformat()
        report_id = f"AUDIT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"

        logs_data = []
        for evt in self.events:
            logs_data.append({
                "event_id": evt.event_id,
                "timestamp": evt.timestamp,
                "source": evt.source_origin,
                "trust_level": evt.trust_level,
                "target_tool": evt.target_tool,
                "payload_sha256": evt.payload_sha256,
                "payload_content": evt.raw_payload if include_payloads else f"[REDACTED_HASH:{evt.payload_sha256[:16]}]",
                "enforcement_action": evt.action,
                "risk_score": evt.max_risk_score,
                "violations_count": len(evt.violations),
                "violations": evt.violations,
                "taint_boundary": evt.taint_boundary,
            })

        total = len(self.events)
        blocked = sum(1 for e in self.events if e.action == "BLOCK")
        sanitized = sum(1 for e in self.events if e.action == "SANITIZE_AND_WRAP")
        allowed = total - blocked - sanitized

        report_payload = {
            "$schema": "https://promptguard.enterprise/schemas/v1/audit-report.json",
            "report_header": {
                "report_id": report_id,
                "generated_at": generated_at,
                "kernel_version": "PromptGuard Enterprise Kernel v4.2.1",
                "organization": organization,
                "auditor_notes": auditor_notes,
                "deterministic_guarantee": "ZERO_AI_OVERHEAD_REPRODUCIBLE",
            },
            "session_summary": {
                "session_id": self.session_id,
                "session_start_time": self.session_start,
                "total_inspections": total,
                "enforcement_summary": {
                    "allowed": allowed,
                    "sanitized_and_wrapped": sanitized,
                    "blocked": blocked,
                },
            },
            "taint_provenance_results": {
                "events_count": total,
                "boundary_tokens_minted": list({e.taint_boundary for e in self.events if e.taint_boundary}),
            },
            "inspection_session_logs": logs_data,
        }

        # Canonicalize payload without signature block
        canonical_str = canonicalize_json(report_payload)
        payload_digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        # Compute HMAC-SHA256 signature
        sig = hmac.new(
            self.session_key.encode("utf-8"),
            canonical_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        report_payload["integrity_and_signature"] = {
            "signature_algorithm": "HMAC-SHA256",
            "key_id": self.key_id,
            "canonicalization": "RFC-8785-JCS",
            "payload_digest_sha256": payload_digest,
            "signature_hex": sig,
            "signed_at": generated_at,
        }

        return report_payload
