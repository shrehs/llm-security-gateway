from app.core.security import normalize_prompt
from app.models.finding import Finding
from app.services.base_scanner import BaseScanner
from app.services.owasp import categories_for


class PromptInjectionScanner(BaseScanner):
    name = "PromptInjectionScanner"
    rules: tuple[tuple[str, str], ...] = (
        ("IGNORE_PREVIOUS_INSTRUCTIONS", "ignore previous instructions"),
        ("FORGET_ALL_PREVIOUS", "forget all previous"),
        ("SYSTEM_PROMPT", "system prompt"),
        ("DEVELOPER_MODE", "developer mode"),
        ("REVEAL_HIDDEN", "reveal hidden"),
        ("ACT_AS_ROOT", "act as root"),
        ("BYPASS_SAFETY", "bypass safety"),
        ("EXECUTE_SHELL", "execute shell"),
        ("IGNORE_POLICY", "ignore policy"),
    )

    async def scan(self, text: str) -> list[Finding]:
        normalized = normalize_prompt(text).lower()
        findings: list[Finding] = []
        for finding_type, phrase in self.rules:
            if phrase in normalized:
                findings.append(
                    Finding(
                        scanner=self.name,
                        type=finding_type,
                        severity="MEDIUM",
                        value=phrase,
                        owasp=categories_for(self.name),
                    )
                )
        if len(findings) >= 5:
            return [finding.model_copy(update={"severity": "HIGH"}) for finding in findings]
        return findings
