# Use Python 3.12 slim image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files first
COPY pyproject.toml ./
COPY README.md ./

# Install Python dependencies directly with pip
RUN pip install --no-cache-dir \
    langgraph>=1.0.3 \
    langchain-core>=0.3.0 \
    langchain-community>=0.3.0 \
    langchain-google-genai>=3.0.0 \
    langchain-openai>=0.2.0 \
    langchain>=0.3.0 \
    langchain-mistralai>=1.0.1 \
    python-dotenv>=1.0.0 \
    httpx>=0.27.0 \
    streamlit>=1.29.0

# Copy application code
COPY . .

# Create .env file from template if it doesn't exist
RUN if [ ! -f .env ]; then cp env_template.txt .env 2>/dev/null || true; fi

# Expose Streamlit port
EXPOSE 8501

# Set environment variables for Streamlit
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Run Streamlit app
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
