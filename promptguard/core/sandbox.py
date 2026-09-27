import ast
import re
from typing import Any, Dict, List
from promptguard.core.models import SecurityViolation, ThreatCategory, ToolCallEvaluation
from promptguard.core.engine import PromptGuardEngine


class ToolCallSandbox:
    """Deterministisk kodesandbox og argumentvaliderer for verktøykall."""

    FORBIDDEN_PYTHON_CALLS = {"eval", "exec", "compile", "__import__", "open", "system", "popen", "spawn"}
    FORBIDDEN_PYTHON_MODULES = {"os", "sys", "subprocess", "socket", "shutil", "requests", "urllib", "pty"}

    def __init__(self, engine: PromptGuardEngine):
        self.engine = engine

    def audit_python_code(self, code_str: str) -> List[SecurityViolation]:
        violations = []
        try:
            tree = ast.parse(code_str)
        except SyntaxError:
            return violations

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                
                if func_name in self.FORBIDDEN_PYTHON_CALLS:
                    violations.append(
                        SecurityViolation(
                            category=ThreatCategory.UNSAFE_CODE_EXECUTION,
                            rule_id="AST-PY-001",
                            risk_score=1.0,
                            description=f"Uautorisert systemfunksjonskall '{func_name}' detektert.",
                            extracted_sample=f"{func_name}()"
                        )
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.FORBIDDEN_PYTHON_MODULES:
                        violations.append(
                            SecurityViolation(
                                category=ThreatCategory.UNSAFE_CODE_EXECUTION,
                                rule_id="AST-PY-002",
                                risk_score=1.0,
                                description=f"Import av forbudt modul '{alias.name}'.",
                                extracted_sample=f"import {alias.name}"
                            )
                        )
        return violations

    def validate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> ToolCallEvaluation:
        violations: List[SecurityViolation] = []
        sanitized_args: Dict[str, Any] = {}

        for key, value in arguments.items():
            if isinstance(value, str):
                report = self.engine.inspect_and_contain(value)
                if not report.is_safe:
                    violations.extend(report.violations)

                # Kjør AST-sjekk dersom argumentet inneholder kode
                if tool_name in ["run_python", "execute_code"]:
                    violations.extend(self.audit_python_code(value))

                sanitized_args[key] = value
            else:
                sanitized_args[key] = value

        return ToolCallEvaluation(
            is_valid=len(violations) == 0,
            tool_name=tool_name,
            sanitized_arguments=sanitized_args,
            violations=violations
        )
