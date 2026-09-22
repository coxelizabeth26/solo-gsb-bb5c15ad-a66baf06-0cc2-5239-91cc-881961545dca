FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DR_DB_PATH=/data/sss.db

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Persistent SQLite location; initialised automatically on first startup.
RUN mkdir -p /data && \
    useradd --create-home --uid 10001 appuser && \
    chown -R appuser:appuser /data /app
USER appuser

VOLUME ["/data"]

EXPOSE 8000

# Container-local healthcheck (no external tooling/accounts required).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

ENTRYPOINT ["/entrypoint.sh"]
