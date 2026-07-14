import re

from app.models.finding import Finding
from app.services.base_scanner import BaseScanner
from app.services.owasp import categories_for


class SecretScanner(BaseScanner):
    name = "SecretScanner"
    patterns: dict[str, str] = {
        "OPENAI_KEY": r"\bsk-[A-Za-z0-9_-]{20,}\b",
        "AWS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
        "GITHUB_TOKEN": r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b",
        "BEARER_TOKEN": r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b",
        "JWT": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "SLACK_TOKEN": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    }

    async def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for secret_type, pattern in self.patterns.items():
            for match in re.finditer(pattern, text):
                raw = match.group(0)
                findings.append(
                    Finding(
                        scanner=self.name,
                        type=secret_type,
                        severity="HIGH",
                        value=self._mask(raw),
                        raw_value=raw,
                        owasp=categories_for(self.name),
                    )
                )
        return findings

    def _mask(self, value: str) -> str:
        if value.startswith("Bearer "):
            return f"Bearer {self._mask(value.split(' ', 1)[1])}"
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}{'*' * max(len(value) - 8, 4)}{value[-4:]}"
