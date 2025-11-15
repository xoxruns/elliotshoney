# Use a Python image with uv pre-installed
# 
# NOTE: This Dockerfile requires BuildKit to be enabled for --mount cache support.
# Enable BuildKit by running:
#   export DOCKER_BUILDKIT=1
#   docker build -t <image-name> .
# Or use:
#   DOCKER_BUILDKIT=1 docker build -t <image-name> .
# Or permanently enable it in ~/.docker/config.json:
#   { "features": { "buildkit": true } }
#
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# Install system dependencies (curl for healthcheck)
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install the project into `/app`
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Copy project files needed for dependency installation
COPY pyproject.toml ./
COPY README.md ./

# Install the project's dependencies using the lockfile and settings
RUN uv sync 

# Then, add the rest of the project source code and install it
ADD . /app
RUN uv sync 

# Create .env file from template if it doesn't exist
# Note: For production, pass environment variables at runtime using:
#   - docker run: docker run --env-file .env <image>
#   - docker-compose: Use env_file directive in docker-compose.yml
# Do NOT copy .env into the image for security reasons
RUN if [ ! -f .env ]; then cp env_template.txt .env 2>/dev/null || true; fi

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Expose Streamlit port
# Note: EXPOSE is documentation only. To actually expose the port to the host,
# use: docker run -p 8080:8080 <image> or use docker-compose.yml
EXPOSE 8080

# Set environment variables for Streamlit
ENV STREAMLIT_SERVER_PORT=8080
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8080/_stcore/health || exit 1

# Reset the entrypoint, don't invoke `uv`
ENTRYPOINT []

# Run Streamlit app
CMD ["streamlit", "run", "app.py", "--server.port=8080", "--server.address=0.0.0.0"]
