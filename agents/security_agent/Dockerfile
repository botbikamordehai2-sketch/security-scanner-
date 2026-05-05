FROM python:3.11-slim

WORKDIR /app

# Copy shared modules from project root
COPY shared/ /app/shared/
COPY agents/security_agent/requirements.txt /app/agent/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r /app/agent/requirements.txt

# Copy the agent code
COPY agents/security_agent/agent.py /app/agent/agent.py

# Cloud Run sets PORT, default 8080 for agents
ENV PORT=8080
EXPOSE ${PORT}

# Run agent as Pub/Sub push handler
CMD ["python", "/app/agent/agent.py"]