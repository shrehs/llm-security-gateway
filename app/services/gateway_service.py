import asyncio
import time
from uuid import uuid4

from app.models.finding import Finding
from app.models.request import ChatRequest
from app.models.response import GatewayChatResponse, ScannerMetric
from app.providers.base import LLMProvider
from app.services.audit_logger import AuditLogger
from app.services.base_scanner import BaseScanner
from app.services.metrics import MetricsCollector
from app.services.policy_engine import PolicyEngine
from app.services.redaction import RedactionService
from app.services.response_scanner import ResponseScanner
from app.services.risk_engine import RiskEngine


class GatewayService:
    def __init__(
        self,
        scanners: list[BaseScanner],
        risk_engine: RiskEngine,
        policy_engine: PolicyEngine,
        llm_provider: LLMProvider,
        response_scanner: ResponseScanner,
        audit_logger: AuditLogger,
        metrics: MetricsCollector,
        redaction: RedactionService,
    ) -> None:
        self.scanners = scanners
        self.risk_engine = risk_engine
        self.policy_engine = policy_engine
        self.llm_provider = llm_provider
        self.response_scanner = response_scanner
        self.audit_logger = audit_logger
        self.metrics = metrics
        self.redaction = redaction

    async def process(
        self, request: ChatRequest, request_id: str | None = None
    ) -> GatewayChatResponse:
        started = time.perf_counter()
        request_id = request_id or str(uuid4())
        scanner_metrics: list[ScannerMetric] = []

        findings = await self._scan(request.prompt, self.scanners, scanner_metrics)
        risk = self.risk_engine.calculate(findings)
        policy = self.policy_engine.decide(risk, findings, request)
        decision = policy.action

        llm_response = None
        if decision != "BLOCK":
            prompt = (
                self.redaction.redact(request.prompt, findings)
                if decision == "REDACT"
                else request.prompt
            )
            llm_response = await self.llm_provider.generate(prompt, request.model)
            response_findings = await self.response_scanner.scan(llm_response, scanner_metrics)
            findings.extend(response_findings)
            if response_findings:
                risk = self.risk_engine.calculate(findings)
                policy = self.policy_engine.decide(risk, findings, request)
                decision = policy.action
                if decision == "REDACT":
                    llm_response = self.redaction.redact(llm_response, response_findings)
                elif decision == "BLOCK":
                    llm_response = None

        latency_ms = (time.perf_counter() - started) * 1000
        self.metrics.record_request(decision, latency_ms)
        self.audit_logger.log(
            request_id,
            request.user_id,
            request.prompt,
            request.model,
            decision,
            risk,
            findings,
            latency_ms,
        )

        return GatewayChatResponse(
            request_id=request_id,
            decision=decision,
            risk_score=risk.score,
            risk_level=risk.level,
            violations=findings,
            owasp=sorted({category for finding in findings for category in finding.owasp}),
            scanner_metrics=scanner_metrics,
            llm_response=llm_response,
        )

    async def stream(self, request: ChatRequest, request_id: str | None = None):
        result = await self.process(request, request_id=request_id)
        if result.decision == "BLOCK":
            yield f"event: blocked\ndata: {result.model_dump_json()}\n\n"
            return
        yield f"event: metadata\ndata: {result.model_dump_json(exclude={'llm_response'})}\n\n"
        if result.llm_response:
            yield f"data: {result.llm_response}\n\n"

    async def _scan(
        self,
        text: str,
        scanners: list[BaseScanner],
        scanner_metrics: list[ScannerMetric],
    ) -> list[Finding]:
        async def run(scanner: BaseScanner) -> list[Finding]:
            started = time.perf_counter()
            findings = await scanner.scan(text)
            elapsed_ms = (time.perf_counter() - started) * 1000
            self.metrics.record_scanner(scanner.name, elapsed_ms, len(findings))
            scanner_metrics.append(
                ScannerMetric(
                    scanner=scanner.name,
                    execution_time_ms=round(elapsed_ms, 2),
                    detections=len(findings),
                )
            )
            return findings

        results = await asyncio.gather(*(run(scanner) for scanner in scanners))
        return [finding for scanner_findings in results for finding in scanner_findings]
