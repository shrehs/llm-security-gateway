from app.providers.base import LLMProvider
from app.providers.mock import MockProvider


class ProviderRegistry:
    def __init__(self, providers: list[LLMProvider] | None = None, active: str = "mock") -> None:
        self.providers = {provider.name: provider for provider in providers or [MockProvider()]}
        self.active = active

    def get_active(self) -> LLMProvider:
        return self.providers.get(self.active, self.providers["mock"])
