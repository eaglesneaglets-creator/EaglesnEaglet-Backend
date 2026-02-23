# =============================================================================
# Eagles & Eaglets Backend Dockerfile
# =============================================================================
# This file tells Docker how to build an image of our Django application.
# Think of a Docker image as a "snapshot" of your app with everything it needs.
# =============================================================================

# -----------------------------------------------------------------------------
# STAGE 1: Base Image
# -----------------------------------------------------------------------------
# We start with an official Python image. "slim" means it's a smaller version
# without extra tools we don't need, making our final image smaller and faster.
FROM python:3.12-slim as base

# Set environment variables
# PYTHONDONTWRITEBYTECODE: Prevents Python from creating .pyc files
# PYTHONUNBUFFERED: Ensures our logs appear in real-time in Docker
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Poetry settings (if you switch to poetry later)
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set the working directory inside the container
# All subsequent commands will run from this directory
WORKDIR /app

# -----------------------------------------------------------------------------
# STAGE 2: Builder Stage
# -----------------------------------------------------------------------------
# This stage installs dependencies. We use a multi-stage build to keep
# the final image small by only copying what we need.
FROM base as builder

# Install system dependencies needed to build Python packages
# These are temporary - we won't include them in the final image
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements file first
# This is a Docker optimization - if requirements don't change,
# Docker can reuse this cached layer, making builds faster
COPY requirements.txt .

# Create a virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# -----------------------------------------------------------------------------
# STAGE 3: Production Image
# -----------------------------------------------------------------------------
# This is our final, lean production image
FROM base as production

# Install only runtime dependencies (not build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create a non-root user for security
# Running as root inside containers is a security risk
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=appuser:appgroup . .

# Create necessary directories
RUN mkdir -p /app/staticfiles /app/media /app/logs && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Collect static files (CSS, JS, images)
# This command gathers all static files into one location
RUN python manage.py collectstatic --noinput --settings=eaglesneagletsbackend.settings.production || true

# Expose port 8000 - this is the port our app will listen on
EXPOSE 8000

# Health check - Docker will periodically check if our app is healthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/ || exit 1

# Default command to run the application
# Gunicorn is a production-grade WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--threads", "2", \
     "--worker-class", "gthread", "--worker-tmp-dir", "/dev/shm", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "--capture-output", "--enable-stdio-inheritance", \
     "eaglesneagletsbackend.wsgi:application"]

# -----------------------------------------------------------------------------
# STAGE 4: Development Image (optional - for local development)
# -----------------------------------------------------------------------------
FROM base as development

# Install all dependencies including dev tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

# Install development dependencies
RUN pip install debugpy watchdog

EXPOSE 8000

# Run Django development server with auto-reload
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
