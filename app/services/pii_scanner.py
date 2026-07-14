import re

from app.models.finding import Finding
from app.services.base_scanner import BaseScanner
from app.services.owasp import categories_for


class PIIScanner(BaseScanner):
    name = "PIIScanner"
    patterns: dict[str, str] = {
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "PHONE": r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b",
        "AADHAAR": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "CREDIT_CARD": r"\b(?:\d[ -]*?){13,19}\b",
        "IP_ADDRESS": (
            r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
        ),
    }

    async def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for entity, pattern in self.patterns.items():
            for match in re.finditer(pattern, text):
                raw = match.group(0)
                findings.append(
                    Finding(
                        scanner=self.name,
                        type=entity,
                        severity="LOW",
                        value=self._mask(raw),
                        raw_value=raw,
                        owasp=categories_for(self.name),
                    )
                )
        return findings

    def _mask(self, value: str) -> str:
        if "@" in value:
            name, domain = value.split("@", 1)
            return f"{name[:2]}***@{domain}"
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}{'*' * max(len(value) - 4, 4)}{value[-2:]}"


PiiScanner = PIIScanner
