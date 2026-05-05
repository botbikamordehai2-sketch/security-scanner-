FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules (event schemas, pubsub utils, db)
COPY shared/ /app/shared/

# Copy the orchestrator + dashboard
COPY orchestrator/main.py /app/orchestrator/main.py
COPY backend_core.py /app/backend_core.py
COPY templates/ /app/templates/

# Cloud Run sets PORT env var, default 8000
ENV PORT=8000

EXPOSE ${PORT}

# Run the new orchestrator (maintains 100% backward compatibility)
CMD ["python", "/app/orchestrator/main.py"]
