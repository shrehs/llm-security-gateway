from collections.abc import AsyncIterator

from app.providers.base import LLMProvider


class MockProvider(LLMProvider):
    name = "mock"

    async def generate(self, prompt: str, model: str) -> str:
        if "leak_response_secret" in prompt:
            return "Mock response contains AWS key AKIAABCDEFGHIJKLMNOP."
        if "leak_response_email" in prompt:
            return "Mock response contains email abc@gmail.com."
        return f"Mock response from {model}."

    async def stream(self, prompt: str, model: str) -> AsyncIterator[str]:
        response = await self.generate(prompt, model)
        for chunk in response.split(" "):
            yield f"{chunk} "
