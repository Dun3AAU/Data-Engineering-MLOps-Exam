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

# Default container command: run the full collect_artifacts pipeline.
# You can override this at runtime to serve files or run other commands.
CMD ["python", "backend/API/scripts/collect_artifacts.py", "--nvd-sleep-seconds", "7", "--reasoning-limit", "50"]