# SignalForge-Commotai | Causal OSINT Tier 1 Agent
# Cloud Run / Fly.io / Docker-compatible

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for sentence-transformers
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy shared modules first (they're imported by the agent)
COPY shared/ /app/shared/

# Copy agent code
COPY agents/causal_osint/ /app/agents/causal_osint/

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/agents/causal_osint/requirements.txt

# Download sentence-transformers model at build time (cache in image)
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

ENV PORT=8080
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "-m", "agents.causal_osint.agent"]