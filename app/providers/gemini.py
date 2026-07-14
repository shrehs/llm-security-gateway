from app.providers.base import LLMProvider


class GeminiProvider(LLMProvider):
    name = "gemini"

    async def generate(self, prompt: str, model: str) -> str:
        raise NotImplementedError("Gemini provider is not configured yet.")
