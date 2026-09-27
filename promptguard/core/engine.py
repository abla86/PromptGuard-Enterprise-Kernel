import html
import re
import secrets
from typing import List, Tuple, Optional
from promptguard.core.models import (
    TrustLevel, ThreatCategory, EnforcementAction, SecurityViolation, TaintReport
)
from promptguard.core.normalizer import AdvancedNormalizer
from promptguard.core.rules import ThreatPatterns


class PromptGuardEngine:
    """Deterministisk kjerne for leksikalsk inspeksjon, sanering og taint-innkapsling."""

    def __init__(self, block_risk_threshold: float = 0.85):
        self.block_threshold = block_risk_threshold

    def inspect_and_contain(
        self,
        raw_text: str,
        trust_level: TrustLevel = TrustLevel.UNTRUSTED_EXTERNAL
    ) -> TaintReport:
        if not raw_text:
            return TaintReport(
                is_safe=True,
                action=EnforcementAction.ALLOW,
                sanitized_text="",
                boundary_token="",
                max_risk=0.0,
                trust_level=trust_level,
                violations=[]
            )

        violations: List[SecurityViolation] = []

        # 1. Normalisering & De-cloaking
        cleaned, had_zw = AdvancedNormalizer.strip_evil_unicode(raw_text)
        if had_zw:
            violations.append(
                SecurityViolation(
                    category=ThreatCategory.HOMOGLYPH_OBFUSCATION,
                    rule_id="NORM-001",
                    risk_score=0.80,
                    description="Usynlige Zero-width/BiDi-kontrolltegn strippet.",
                    extracted_sample="[HIDDEN_UNICODE]"
                )
            )

        normalized_homo, had_homo = AdvancedNormalizer.normalize_homoglyphs(cleaned)
        if had_homo:
            violations.append(
                SecurityViolation(
                    category=ThreatCategory.HOMOGLYPH_OBFUSCATION,
                    rule_id="NORM-002",
                    risk_score=0.85,
                    description="Homoglyfer normalisert til latinske tegn.",
                    extracted_sample="[HOMOGLYPH_SUBSTITUTION]"
                )
            )

        # 2. Rekursiv utpakking
        all_layers = [("raw", normalized_homo)] + AdvancedNormalizer.recursive_decode(normalized_homo)

        # 3. Mønstergjenkjenning
        for layer_name, text_layer in all_layers:
            for pat in ThreatPatterns.DELIMITER_TOKENS:
                for match in re.finditer(pat, text_layer, re.IGNORECASE):
                    violations.append(
                        SecurityViolation(
                            category=ThreatCategory.SPECIAL_TOKEN_INJECTION,
                            rule_id="DELIM-001",
                            risk_score=1.0,
                            description=f"Fluktforsøk mot LLM-delimiter påvist ({layer_name}).",
                            extracted_sample=match.group(0)
                        )
                    )

            for pat in ThreatPatterns.ROLE_OVERRIDE:
                for match in re.finditer(pat, text_layer, re.IGNORECASE):
                    violations.append(
                        SecurityViolation(
                            category=ThreatCategory.INDIRECT_ROLE_HIJACK,
                            rule_id="HIJACK-001",
                            risk_score=0.95,
                            description=f"Instruksjonsoverstyring detektert ({layer_name}).",
                            extracted_sample=match.group(0)
                        )
                    )

            for pat in ThreatPatterns.EXFILTRATION:
                for match in re.finditer(pat, text_layer, re.IGNORECASE):
                    violations.append(
                        SecurityViolation(
                            category=ThreatCategory.MARKDOWN_EXFILTRATION,
                            rule_id="EXFIL-001",
                            risk_score=0.90,
                            description=f"Forsøk på datalekkasje ({layer_name}).",
                            extracted_sample=match.group(0)[:50]
                        )
                    )

        # 4. Beslutning
        max_risk = max([v.risk_score for v in violations], default=0.0)

        if max_risk >= self.block_threshold and trust_level == TrustLevel.UNTRUSTED_EXTERNAL:
            action = EnforcementAction.BLOCK
            is_safe = False
        elif max_risk > 0.3 or trust_level == TrustLevel.UNTRUSTED_EXTERNAL:
            action = EnforcementAction.SANITIZE_AND_WRAP
            is_safe = False
        else:
            action = EnforcementAction.ALLOW
            is_safe = True

        boundary = f"DATA_CONTAINER_{secrets.token_hex(6).upper()}"
        escaped_text = html.escape(normalized_homo)

        wrapped_payload = (
            f"<{boundary} trust_level=\"{trust_level.name}\" action=\"{action.value}\">\n"
            f"{escaped_text}\n"
            f"</{boundary}>"
        )

        return TaintReport(
            is_safe=is_safe,
            action=action,
            sanitized_text=wrapped_payload,
            boundary_token=boundary,
            max_risk=max_risk,
            trust_level=trust_level,
            violations=violations
        )
