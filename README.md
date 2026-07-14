# LLM Security Gateway

A FastAPI gateway that evaluates prompts and model responses through a modular, policy-driven security pipeline before returning output to clients.

## Architecture

```text
API Layer
  -> Request Validation
  -> Gateway Orchestrator
  -> Scanner Registry
  -> Async Security Scanners
  -> Risk Engine
  -> YAML Policy Engine
  -> LLM Provider Registry
  -> Response Scanner
  -> Redaction Stage
  -> Structured Audit Log
  -> Response
```

## Enterprise Features

- Pluggable scanner framework through a shared `BaseScanner` interface
- Scanner enablement through `configs/policies.yaml`
- Policy-as-code with `ALLOW`, `WARN`, `REDACT`, and `BLOCK`
- RBAC-aware decisions using `user_id`, `role`, `department`, and `clearance`
- Request tracing with `X-Request-ID`
- Structured audit events with latency and violation metadata
- Per-scanner execution metrics in each gateway response
- OWASP LLM Top 10 category mapping
- Mock streaming endpoint for server-sent event inspection
- Response redaction for sensitive model output

## Current Scanners

- `SecretScanner`
- `PIIScanner`
- `PromptInjectionScanner`
- `URLScanner`
- `MalwareURLScanner`

Each scanner implements:

```python
async def scan(self, text: str) -> list[Finding]:
    ...
```

## Policy Configuration

Policies live in `configs/policies.yaml`.

```yaml
scanners:
  enabled:
    - secret
    - pii
    - injection
    - url
    - malware_url

policies:
  PII:
    HIGH: BLOCK
    MEDIUM: REDACT
    LOW: WARN

thresholds:
  warn: 30
  redact: 60
  block: 80
```

## Endpoints

### GET /health

Returns service health metadata.

### POST /gateway/chat

Accepts an optional `X-Request-ID` header. If omitted, the gateway creates a UUID and returns it in both the response body and response header.

```json
{
  "prompt": "Hello, how are you?",
  "model": "llama3",
  "user_id": "demo-user",
  "role": "employee",
  "department": "general",
  "clearance": "public"
}
```

Example response:

```json
{
  "request_id": "req-123",
  "decision": "ALLOW",
  "risk_score": 0,
  "risk_level": "NONE",
  "violations": [],
  "owasp": [],
  "scanner_metrics": [],
  "llm_response": "Mock response from llama3."
}
```

### POST /gateway/chat/stream

Returns server-sent events with gateway metadata followed by safe model output.

## Run

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```