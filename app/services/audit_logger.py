from datetime import UTC, datetime

from app.models.finding import Finding
from app.services.risk_engine import RiskResult


class AuditLogger:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def log(
        self,
        request_id: str,
        user: str,
        prompt: str,
        model: str,
        decision: str,
        risk: RiskResult,
        findings: list[Finding],
        latency_ms: float,
    ) -> None:
        self.events.append(
            {
                "request_id": request_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "user": user,
                "model": model,
                "decision": decision,
                "risk_score": risk.score,
                "risk_level": risk.level,
                "latency_ms": round(latency_ms, 2),
                "violations": [finding.model_dump(exclude={"value"}) for finding in findings],
                "prompt_length": len(prompt),
            }
        )
