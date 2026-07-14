FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY configs ./configs
COPY requirements.txt .
COPY README.md .

LABEL org.opencontainers.image.title="LLM Security Gateway"
LABEL org.opencontainers.image.description="Enterprise LLM Security Middleware"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]