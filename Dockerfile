FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /workspace

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock requirements.txt README.md ./
RUN uv sync --frozen

COPY . .

EXPOSE 4173

CMD ["python", "-m", "http.server", "4173", "-d", "frontend"]