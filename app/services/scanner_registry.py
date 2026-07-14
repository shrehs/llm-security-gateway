import yaml

from app.core.config import settings
from app.services.base_scanner import BaseScanner
from app.services.malware_url_scanner import MalwareURLScanner
from app.services.pii_scanner import PIIScanner
from app.services.prompt_injection import PromptInjectionScanner
from app.services.secret_scanner import SecretScanner
from app.services.url_scanner import URLScanner


class ScannerRegistry:
    available: dict[str, type[BaseScanner]] = {
        "secret": SecretScanner,
        "pii": PIIScanner,
        "injection": PromptInjectionScanner,
        "url": URLScanner,
        "malware_url": MalwareURLScanner,
    }

    def __init__(self, enabled: list[str] | None = None) -> None:
        enabled_scanners = enabled or self._enabled_from_config()
        self._scanners = [
            self.available[name]() for name in enabled_scanners if name in self.available
        ]

    @property
    def scanners(self) -> list[BaseScanner]:
        return self._scanners

    def register(self, name: str, scanner: type[BaseScanner]) -> None:
        self.available[name] = scanner

    def _enabled_from_config(self) -> list[str]:
        if not settings.policy_file.exists():
            return list(self.available.keys())
        config = yaml.safe_load(
            settings.policy_file.read_text(encoding="utf-8")
        ) or {}

        enabled = config.get(
            "scanners",
            {},
        ).get(
            "enabled",
            list(self.available.keys()),
        )

        assert isinstance(enabled, list)

        return enabled
