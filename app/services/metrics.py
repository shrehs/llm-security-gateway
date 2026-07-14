from collections import Counter


class MetricsCollector:
    def __init__(self) -> None:
        self.total_requests = 0
        self.decisions: Counter[str] = Counter()
        self.detections_by_scanner: Counter[str] = Counter()
        self.scanner_execution_time_ms: dict[str, float] = {}
        self.total_latency_ms = 0.0

    def record_request(self, decision: str, latency_ms: float) -> None:
        self.total_requests += 1
        self.decisions[decision] += 1
        self.total_latency_ms += latency_ms

    def record_scanner(self, scanner: str, elapsed_ms: float, detections: int) -> None:
        self.scanner_execution_time_ms[scanner] = (
            self.scanner_execution_time_ms.get(scanner, 0.0) + elapsed_ms
        )
        self.detections_by_scanner[scanner] += detections

    @property
    def average_latency_ms(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_latency_ms / self.total_requests
