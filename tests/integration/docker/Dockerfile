FROM python:3.12-slim

# Environment hygiene
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create non-root user first
RUN useradd -m -u 1000 runtime

# Set up virtual environment
ENV VIRTUAL_ENV=/home/runtime/venv
RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Change ownership of venv to runtime user
RUN chown -R runtime:runtime $VIRTUAL_ENV

WORKDIR /app

# Install Poetry as root first (cache this layer)
RUN pip install poetry

# Copy dependency files first for better Docker layer caching
COPY pyproject.toml poetry.lock ./

# Switch to non-root user for dependency installation
USER runtime

# Install only dependencies first (not the project itself)
RUN poetry install --only=main,observability --no-root

# Switch back to root to copy source code and fix permissions
USER root

# Copy the source code (this layer changes when code changes)
COPY src/ ./src/
COPY README.md ./

# Fix ownership of all files
RUN chown -R runtime:runtime /app

# Switch back to runtime user for final setup
USER runtime

# Now install the project itself
RUN poetry install --only=main,observability

# Expose port
EXPOSE 8000

# Add health check endpoint for testing
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 8000)); s.close()"

# Default command - can be overridden by docker-compose
CMD ["python", "--version"]
