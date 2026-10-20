FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

# Dependencies first, so code changes don't reinstall them.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project

COPY src ./src
COPY alembic.ini ./
COPY migrations ./migrations
RUN uv sync --locked --no-dev

RUN useradd --system --no-create-home app && mkdir logs && chown app logs
USER app

EXPOSE 8000
# Migrating on start is fine for a single instance; with replicas, run it as a separate job.
CMD ["sh", "-c", "alembic upgrade head && uvicorn ai_alert_triage.main:app --host 0.0.0.0 --port 8000"]
