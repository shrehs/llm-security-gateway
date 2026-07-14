from pathlib import Path

import yaml
from pydantic import BaseModel

from app.core.config import settings
from app.models.finding import Finding
from app.models.request import ChatRequest
from app.services.risk_engine import RiskResult


class PolicyDecision(BaseModel):
    action: str
    reason: str


class PolicyEngine:
    def __init__(self, policy_file: Path = settings.policy_file) -> None:
        self.policy_file = policy_file
        self.config = self._load_config()

    def decide(
        self,
        risk: RiskResult,
        findings: list[Finding],
        request: ChatRequest | None = None,
    ) -> PolicyDecision:
        finding_decisions = [self._decision_for_finding(finding) for finding in findings]
        threshold_decision = self._decision_for_score(risk.score)
        base_action = max([threshold_decision, *finding_decisions], key=self._priority)
        action = self._apply_context(base_action, request)
        role = getattr(request, "role", "unknown")
        reason = (
            f"risk={risk.level}; "
            f"score={risk.score}; "
            f"base={base_action}; "
            f"role={role}"
        )
        return PolicyDecision(action=action, reason=reason)

    def _load_config(self) -> dict:
        if not self.policy_file.exists():
            return {
                "policies": {},
                "thresholds": {"warn": 30, "redact": 60, "block": 80},
            }
        return yaml.safe_load(self.policy_file.read_text(encoding="utf-8")) or {}

    def _decision_for_finding(self, finding: Finding) -> str:
        scanner_key = self._scanner_key(finding.scanner)
        policies = self.config.get("policies", {})
        scanner_policy = policies.get(scanner_key, {})

        decision = scanner_policy.get(finding.severity, "ALLOW")

        assert isinstance(decision, str)

        return decision

    def _decision_for_score(self, score: int) -> str:
        thresholds = self.config.get("thresholds", {})
        if score >= int(thresholds.get("block", 80)):
            return "BLOCK"
        if score >= int(thresholds.get("redact", 60)):
            return "REDACT"
        if score >= int(thresholds.get("warn", 30)):
            return "WARN"
        return "ALLOW"

    def _apply_context(self, action: str, request: ChatRequest | None) -> str:
        if request is None:
            return action
        role_overrides = self.config.get("role_overrides", {})
        role_config = role_overrides.get(request.role, {})

        role_action = role_config.get(action, action)
        assert isinstance(role_action, str)

        clearance_overrides = self.config.get("clearance_overrides", {})
        clearance_config = clearance_overrides.get(request.clearance, {})

        final_action = clearance_config.get(role_action, role_action)
        assert isinstance(final_action, str)

        return final_action

    def _scanner_key(self, scanner: str) -> str:
        return {
            "SecretScanner": "SECRET",
            "PIIScanner": "PII",
            "PromptInjectionScanner": "PROMPT_INJECTION",
            "URLScanner": "URL",
            "MalwareURLScanner": "URL",
        }.get(scanner, scanner.upper())

    def _priority(self, decision: str) -> int:
        return {"ALLOW": 0, "WARN": 1, "REDACT": 2, "BLOCK": 3}.get(decision, 0)
