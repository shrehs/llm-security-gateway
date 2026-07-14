from app.models.finding import Finding


class RedactionService:
    def redact(self, text: str, findings: list[Finding]) -> str:
        redacted = text
        values = [finding.raw_value or finding.value for finding in findings]
        for value in sorted(values, key=len, reverse=True):
            if value and value in redacted:
                redacted = redacted.replace(value, "[REDACTED]")
        return redacted
