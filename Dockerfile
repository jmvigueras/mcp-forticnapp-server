# Use Python 3.13 slim image as base
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install uv and curl (for health checks)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_CACHE_DIR=/tmp/.uv-cache
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Create non-root user for security
RUN groupadd -r mcpuser && useradd -r -g mcpuser -d /app -s /bin/bash mcpuser

# Copy project files and set ownership
COPY --chown=mcpuser:mcpuser pyproject.toml uv.lock ./

# Install dependencies as root (needed for system packages)
RUN uv sync --frozen --no-cache

# Copy application code and set ownership
COPY --chown=mcpuser:mcpuser . .

# Change ownership of the entire app directory
RUN chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Expose port (default for FastMCP/Starlette)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the server using uvicorn directly (avoids uv.lock writes with readOnlyRootFilesystem)
CMD [".venv/bin/uvicorn", "app.server:app", "--host", "0.0.0.0", "--port", "8000"]
