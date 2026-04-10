# =============================================================================
# CloudOps Intelligence Environment — production Dockerfile
#
# Build context : fire_swarm_simulator/  (repo root — this file)
# Exposed port  : 7860  (HF Spaces standard)
# Runtime user  : appuser (non-root, required by HF Spaces sandbox)
#
# Build:
#   docker build -t cloudops-intelligence .
#
# Run:
#   docker run -p 7860:7860 \
#     -e API_BASE_URL=https://api.openai.com/v1 \
#     -e MODEL_NAME=gpt-4o-mini               \
#     -e HF_TOKEN=<your-api-key>              \
#     cloudops-intelligence
# =============================================================================

FROM python:3.10-slim

RUN useradd --create-home --shell /bin/bash --uid 1000 appuser

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gcc && \
    rm -rf /var/lib/apt/lists/*

COPY --chown=appuser:appuser requirements.txt ./requirements.txt

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . .

# Pre-fetch real-world datasets (Spamhaus DROP, CIC-IDS2018, AWS Pricing,
# MITRE ATT&CK) and bake them into the image so the environment uses
# authentic data without needing external network access at runtime.
# Runs as appuser with /app as cwd; output goes to data/ directory.
# Failures are non-fatal — environment falls back to hardcoded baselines.
RUN python data_fetcher.py || echo "[WARN] data_fetcher.py failed — using fallback data"

EXPOSE 7860

USER appuser

HEALTHCHECK \
    --interval=15s  \
    --timeout=10s   \
    --start-period=60s \
    --retries=5     \
    CMD python3 /app/healthcheck.py || exit 1

ENV WORKERS=1
ENV PYTHONPATH=/app

CMD ["sh", "-c", "uvicorn server.app:app --host 0.0.0.0 --port 7860 --workers ${WORKERS} --log-level info"]
