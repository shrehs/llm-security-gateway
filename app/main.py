from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import settings

app = FastAPI(
    title=settings.service_name,
    version=settings.version,
)

app.include_router(api_router)
