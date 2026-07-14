from app.providers.base import LLMProvider


class OllamaProvider(LLMProvider):
    name = "ollama"

    async def generate(self, prompt: str, model: str) -> str:
        raise NotImplementedError("Ollama provider is not configured yet.")
