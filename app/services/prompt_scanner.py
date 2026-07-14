from app.models.finding import Finding
from app.services.prompt_injection import PromptInjectionScanner


class PromptScanner:
    def __init__(self) -> None:
        self.injection_scanner = PromptInjectionScanner()

    async def scan(self, text: str) -> list[Finding]:
        return await self.injection_scanner.scan(text)
