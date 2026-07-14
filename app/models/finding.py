from pydantic import BaseModel, Field


class Finding(BaseModel):
    scanner: str
    type: str
    severity: str
    value: str
    redacted_value: str = "[REDACTED]"
    owasp: list[str] = Field(default_factory=list)
    raw_value: str | None = Field(default=None, exclude=True)
