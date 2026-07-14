from app.providers.base import LLMProvider


class OpenAIProvider(LLMProvider):
    name = "openai"

    async def generate(self, prompt: str, model: str) -> str:
        raise NotImplementedError("OpenAI provider is not configured yet.")
