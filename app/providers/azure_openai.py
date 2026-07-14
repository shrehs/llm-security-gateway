from app.providers.base import LLMProvider


class AzureOpenAIProvider(LLMProvider):
    name = "azure_openai"

    async def generate(self, prompt: str, model: str) -> str:
        raise NotImplementedError("Azure OpenAI provider is not configured yet.")
