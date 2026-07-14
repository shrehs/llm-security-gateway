from fastapi import APIRouter, Header, Response
from fastapi.responses import StreamingResponse

from app.models.request import ChatRequest
from app.models.response import GatewayChatResponse
from app.providers.registry import ProviderRegistry
from app.services.audit_logger import AuditLogger
from app.services.gateway_service import GatewayService
from app.services.metrics import MetricsCollector
from app.services.policy_engine import PolicyEngine
from app.services.redaction import RedactionService
from app.services.response_scanner import ResponseScanner
from app.services.risk_engine import RiskEngine
from app.services.scanner_registry import ScannerRegistry

router = APIRouter(prefix="/gateway", tags=["gateway"])

scanner_registry = ScannerRegistry()
metrics = MetricsCollector()

gateway_service = GatewayService(
    scanners=scanner_registry.scanners,
    risk_engine=RiskEngine(),
    policy_engine=PolicyEngine(),
    llm_provider=ProviderRegistry().get_active(),
    response_scanner=ResponseScanner(scanner_registry.scanners),
    audit_logger=AuditLogger(),
    metrics=metrics,
    redaction=RedactionService(),
)


@router.post("/chat", response_model=GatewayChatResponse)
async def chat(
    request: ChatRequest,
    response: Response,
    x_request_id: str | None = Header(default=None, alias="X-Request-ID"),
) -> GatewayChatResponse:
    result = await gateway_service.process(request, request_id=x_request_id)
    response.headers["X-Request-ID"] = result.request_id
    return result


@router.post("/chat/stream")
async def stream_chat(
    request: ChatRequest,
    x_request_id: str | None = Header(default=None, alias="X-Request-ID"),
) -> StreamingResponse:
    return StreamingResponse(
        gateway_service.stream(request, request_id=x_request_id),
        media_type="text/event-stream",
    )
