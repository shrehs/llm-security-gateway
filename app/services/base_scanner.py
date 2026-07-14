from abc import ABC, abstractmethod

from app.models.finding import Finding


class BaseScanner(ABC):
    name: str

    @abstractmethod
    async def scan(self, text: str) -> list[Finding]:
        raise NotImplementedError
