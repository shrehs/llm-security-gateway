import re

from app.models.finding import Finding
from app.services.base_scanner import BaseScanner
from app.services.owasp import categories_for


class URLScanner(BaseScanner):
    name = "URLScanner"
    pattern = r"https?://[^\s]+"

    async def scan(self, text: str) -> list[Finding]:
        return [
            Finding(
                scanner=self.name,
                type="URL",
                severity="LOW",
                value=match.group(0),
                owasp=categories_for(self.name),
            )
            for match in re.finditer(self.pattern, text, flags=re.IGNORECASE)
        ]
