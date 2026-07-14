import pytest

from app.models.request import ChatRequest
from app.services.pii_scanner import PIIScanner
from app.services.policy_engine import PolicyEngine
from app.services.prompt_injection import PromptInjectionScanner
from app.services.redaction import RedactionService
from app.services.risk_engine import RiskEngine
from app.services.scanner_registry import ScannerRegistry
from app.services.secret_scanner import SecretScanner


@pytest.mark.asyncio
async def test_secret_scanner_returns_structured_masked_findings() -> None:
    findings = await SecretScanner().scan("AWS key AKIAABCDEFGHIJKLMNOP")

    assert findings[0].scanner == "SecretScanner"
    assert findings[0].type == "AWS_KEY"
    assert findings[0].severity == "HIGH"
    assert findings[0].owasp == ["LLM02"]
    assert "AKIA" in findings[0].value
    assert "ABCDEFGHIJKLMNOP" not in findings[0].value


@pytest.mark.asyncio
async def test_pii_scanner_detects_requested_entities() -> None:
    findings = await PIIScanner().scan("abc@gmail.com 192.168.1.1 ABCDE1234F")
    types = {finding.type for finding in findings}

    assert {"EMAIL", "IP_ADDRESS", "PAN"} <= types


@pytest.mark.asyncio
async def test_prompt_injection_scanner_matches_rules() -> None:
    findings = await PromptInjectionScanner().scan("developer mode and bypass safety")
    types = {finding.type for finding in findings}

    assert {"DEVELOPER_MODE", "BYPASS_SAFETY"} <= types
    assert findings[0].owasp == ["LLM01"]


@pytest.mark.asyncio
async def test_risk_and_policy_engines_use_yaml_policy_and_rbac() -> None:
    findings = [
        *await SecretScanner().scan("AKIAABCDEFGHIJKLMNOP"),
        *await PIIScanner().scan("abc@gmail.com"),
    ]
    risk = RiskEngine().calculate(findings)

    assert risk.score == 60
    assert risk.level == "MEDIUM"
    assert (
        PolicyEngine().decide(risk, findings, ChatRequest(prompt="x", role="employee")).action
        == "BLOCK"
    )
    assert (
        PolicyEngine().decide(risk, findings, ChatRequest(prompt="x", role="admin")).action
        == "WARN"
    )


def test_scanner_registry_uses_configured_plugins() -> None:
    scanner_names = {scanner.name for scanner in ScannerRegistry().scanners}

    assert {
        "SecretScanner",
        "PIIScanner",
        "PromptInjectionScanner",
        "URLScanner",
        "MalwareURLScanner",
    } <= scanner_names


def test_redaction_service_replaces_sensitive_values() -> None:
    from app.models.finding import Finding

    finding = Finding(
        scanner="SecretScanner",
        type="AWS_KEY",
        severity="HIGH",
        value="AKIA************MNOP",
    )
    redacted = RedactionService().redact("AWS key AKIA************MNOP", [finding])

    assert redacted == "AWS key [REDACTED]"
