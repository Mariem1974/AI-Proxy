# ─── Stage 1: Build the React / TypeScript frontend ──────────────────────────
FROM node:20-slim AS frontend-builder

WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci --silent
COPY frontend/ ./
RUN npm run build

# ─── Stage 2: Python runtime ──────────────────────────────────────────────────
FROM python:3.10-slim

# System packages needed by PyTorch, OpenCV, and python-doctr
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ \
        libgl1 libglib2.0-0 \
        libgomp1 \
        curl \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies before copying source (maximises layer caching)
COPY requirements.txt ./
# --extra-index-url lets pip find the +cpu torch wheels from PyTorch's own index,
# avoiding the default CUDA builds (~3 GB) that PyPI serves for Linux.
RUN pip install --no-cache-dir \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        --timeout 300 \
        --retries 10 \
        -r requirements.txt

# Bake the spaCy English model into the image (~15 MB)
RUN python -m spacy download en_core_web_sm

# Pre-download the sentence-transformers embedding model used by ChromaDB/RAG
# so the container works fully offline (HF_HUB_OFFLINE=1)
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"

# Copy application source (see .dockerignore for exclusions)
COPY . .

# Overlay the pre-built frontend from Stage 1
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

# Directory for the SQLite database and security-log JSON
# Mounted as a named volume in docker-compose so data survives restarts
RUN mkdir -p /app/data

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Override these at compose level if your paths differ
    OLLAMA_URL=http://ollama:11434/api/chat \
    HF_HUB_OFFLINE=1 \
    DB_PATH=/app/data/users.db \
    LOGS_PATH=/app/data/security_logs.json \
    MODERNBERT_MODEL_DIR=/app/models/modernbert \
    GLINER_MODEL_PATH=/app/models/gretel-gliner/hub/models--gretelai--gretel-gliner-bi-large-v1.0/snapshots/f96d1da43b97bd1846b14a7068a57e1ab15f226e

EXPOSE 5000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
