FROM python:3.11-slim

WORKDIR /app

# Install system dependencies 
# - build-essential: for compiling Python packages with C extensions (bcrypt, etc.)
# - git: sqlmap needs it for some operations
# - curl: health checks
# - nmap: required by sqlmap for port scanning
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install sqlmap via pip
RUN pip install --no-cache-dir sqlmap

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create the persistent storage directory for vault/reports
RUN mkdir -p /app/vault_storage

# Expose the port FastAPI listens on
EXPOSE 8000


# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the app with Gunicorn + Uvicorn worker
# Railway provides the PORT env var automatically; if not set, default to 8000
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:$PORT app:app -k uvicorn.workers.UvicornWorker"]