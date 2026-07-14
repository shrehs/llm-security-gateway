from pydantic import BaseModel

from app.models.finding import Finding


class RiskResult(BaseModel):
    score: int
    level: str


class RiskEngine:
    weights: dict[str, int] = {
        "SecretScanner": 40,
        "PIIScanner": 20,
        "PromptInjectionScanner": 35,
        "URLScanner": 5,
        "MalwareURLScanner": 50,
    }

    def calculate(self, findings: list[Finding]) -> RiskResult:
        score = sum(self.weights.get(finding.scanner, 10) for finding in findings)
        return RiskResult(score=score, level=self._level(score))

    def _level(self, score: int) -> str:
        if score >= 80:
            return "HIGH"
        if score >= 60:
            return "MEDIUM"
        if score >= 30:
            return "LOW"
        return "NONE"
