FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required for psycopg2 and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
 && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose default port (Render will override PORT at runtime)
EXPOSE 8091

# Start the Starlette MCP Server with Uvicorn
CMD ["python", "-m", "mcp_server.http_server"]
