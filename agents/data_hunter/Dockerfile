FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy agent code + shared modules
COPY agents/data_hunter/requirements.txt /app/agent_requirements.txt
RUN pip install --no-cache-dir -r /app/agent_requirements.txt

COPY shared/ /app/shared/
COPY agents/data_hunter/agent.py /app/agent.py

ENV PORT=8080
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

EXPOSE 8080

CMD ["python", "-u", "agent.py"]