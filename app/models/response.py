from pydantic import BaseModel, Field

from app.models.finding import Finding


class ScannerMetric(BaseModel):
    scanner: str
    execution_time_ms: float
    detections: int


class GatewayChatResponse(BaseModel):
    request_id: str
    decision: str
    risk_score: int
    risk_level: str
    violations: list[Finding]
    owasp: list[str] = Field(default_factory=list)
    scanner_metrics: list[ScannerMetric] = Field(default_factory=list)
    llm_response: str | None = None
