from abc import ABC, abstractmethod
from collections.abc import AsyncIterator


class LLMProvider(ABC):
    name: str

    @abstractmethod
    async def generate(self, prompt: str, model: str) -> str:
        raise NotImplementedError

    async def stream(self, prompt: str, model: str) -> AsyncIterator[str]:
        yield await self.generate(prompt, model)
