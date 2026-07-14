import asyncio
import time

from app.models.finding import Finding
from app.models.response import ScannerMetric
from app.services.base_scanner import BaseScanner


class ResponseScanner:
    def __init__(self, scanners: list[BaseScanner]) -> None:
        self.scanners = scanners

    async def scan(
        self, response: str, scanner_metrics: list[ScannerMetric] | None = None
    ) -> list[Finding]:
        async def run(scanner: BaseScanner) -> list[Finding]:
            started = time.perf_counter()
            findings = await scanner.scan(response)
            elapsed_ms = (time.perf_counter() - started) * 1000
            if scanner_metrics is not None:
                scanner_metrics.append(
                    ScannerMetric(
                        scanner=f"Response{scanner.name}",
                        execution_time_ms=round(elapsed_ms, 2),
                        detections=len(findings),
                    )
                )
            return findings

        results = await asyncio.gather(*(run(scanner) for scanner in self.scanners))
        return [finding for scanner_findings in results for finding in scanner_findings]
