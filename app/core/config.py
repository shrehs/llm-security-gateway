from pathlib import Path

from pydantic import BaseModel


class Settings(BaseModel):
    service_name: str = "LLM Security Gateway"
    version: str = "0.1.0"
    policy_file: Path = Path("configs/policies.yaml")
    default_user: str = "demo-user"


settings = Settings()
