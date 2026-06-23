# Running AI-Proxy v2 Locally (without Docker)

This guide walks through setting up and running the full stack directly on your machine — no Docker required.

---

## Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.10 (exact) | https://www.python.org/downloads/ |
| Node.js | 18 or 20 LTS | https://nodejs.org/ |
| Ollama | Latest | https://ollama.com/ |
| Git | Any | https://git-scm.com/ |
| Conda (recommended) | Any | https://docs.conda.io/en/latest/miniconda.html |

Minimum hardware: **8 GB RAM**, ~**15 GB free disk space**.

---

## Step 1 — Create a Python virtual environment

### With Conda (recommended)

```bash
conda create -n ai_proxy python=3.10 -y
conda activate ai_proxy
```

### With venv

```bash
python3.10 -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

---

## Step 2 — Install Python dependencies

```bash
pip install -r requirements.txt
```

> This installs PyTorch, TensorFlow, Transformers, spaCy, ChromaDB, and more.  
> Expect **5–20 minutes** depending on your internet speed.

---

## Step 3 — Download the spaCy language model

```bash
python -m spacy download en_core_web_sm
```

---

## Step 4 — Download ML model weights

### GLiNER (PII detection)

If the `models/gretel-gliner/` directory is empty, download the snapshot:

```bash
python -c "
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id='gretelai/gretel-gliner-bi-large-v1.0',
    local_dir='./models/gretel-gliner'
)
"
```

### ModernBERT (jailbreak classifier)

Point `MODERNBERT_MODEL_DIR` in your `.env` to your fine-tuned checkpoint directory (see Step 5).

### Ollama LLM models

Make sure Ollama is running, then pull the two required models:

```bash
ollama pull qwen2.5:1.5b
ollama pull llama3.2
```

Each model is downloaded once and cached in `~/.ollama/models`.

---

## Step 5 — Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and set the required values:

```dotenv
# ── Model paths ────────────────────────────────────────────────────────
# Directory that contains config.json, model.safetensors, tokenizer, etc.
MODERNBERT_MODEL_DIR=../prompt_injection_modernbert_v1/prompt_injection_modernbert_v1/checkpoint-65355

# Legacy DistilBERT fallback (optional)
DISTILBERT_MODEL_DIR=./fine-tune3

# GLiNER snapshot (the long path from huggingface_hub)
GLINER_MODEL_PATH=./models/gretel-gliner/hub/models--gretelai--gretel-gliner-bi-large-v1.0/snapshots/f96d1da43b97bd1846b14a7068a57e1ab15f226e

# ── HuggingFace — disable outbound model downloads ─────────────────────
HF_HUB_OFFLINE=1

# ── Admin credentials ──────────────────────────────────────────────────
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123

# ── Ollama ─────────────────────────────────────────────────────────────
OLLAMA_URL=http://localhost:11434/api/chat

# ── Optional alerting ──────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN=
SMTP_USER=
SMTP_PASS=
```

---

## Step 6 — Build the frontend

```bash
cd frontend
npm install
npm run build
cd ..
```

The compiled files land in `frontend/dist/` and are served automatically by the FastAPI app.

---

## Step 7 — Start Ollama

Ollama must be running before you start the backend.

```bash
# It runs as a background service on port 11434
ollama serve
```

On Windows, Ollama often starts automatically on login. Check with:
```bash
ollama list
```

If you see your models listed, Ollama is up.

---

## Step 8 — Start the backend

From the `AI_proxy/` directory (with your virtual environment active):

```bash
python -m uvicorn app:app --host 127.0.0.1 --port 5000 --reload
```

Open **http://localhost:5000** in your browser.

---

## Development workflow

### Running the frontend dev server (hot reload)

When actively working on the React frontend, run the Vite dev server instead of using the built files:

```bash
# Terminal 1 — backend
python -m uvicorn app:app --host 127.0.0.1 --port 5000 --reload

# Terminal 2 — frontend dev server
cd frontend
npm run dev         # runs on http://localhost:5173
```

The dev server proxies `/api` requests to `localhost:5000` (configured in `vite.config.ts`).

After making frontend changes for production, rebuild:
```bash
cd frontend && npm run build
```

### Running the test suite

```bash
# Full suite (requires the server to be running on port 5000)
python -m pytest tests/e2e_test_suite.py -v

# Single test or group
python -m pytest tests/e2e_test_suite.py -k "TestAuth" -v
```

---

## Troubleshooting

### `ModuleNotFoundError` on startup
Your virtual environment is not activated, or `pip install -r requirements.txt` was not run inside it.

### "Connection refused" to Ollama
Ollama is not running. Start it with `ollama serve` or via the Ollama desktop app.

### Frontend shows "503 — Frontend not built"
Run `cd frontend && npm run build`.

### BERT model path errors
Check that `MODERNBERT_MODEL_DIR` in `.env` points to a directory that contains `config.json`.  
If you do not have the checkpoint, set `MODERNBERT_MODEL_DIR=` (blank) — the BERT filter will be disabled.

### spaCy model missing
```bash
python -m spacy download en_core_web_sm
```

### Port 5000 already in use
Change the port:
```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8080 --reload
```

---

## Project structure (quick reference)

```
AI_proxy/
├── app.py                  # FastAPI entry point + middleware
├── auth.py                 # Auth, sessions, security logging
├── schemas.py              # Pydantic request/response models
├── state.py                # Feature-flag state
├── requirements.txt        # Python dependencies
├── routers/
│   ├── auth_routes.py      # /api/auth/*
│   ├── chat_routes.py      # /api/chat, /api/features, /api/reset
│   └── admin_routes.py     # /api/toggle/*, /api/users, /api/alert-settings
├── core/
│   ├── llm.py              # Ollama integration + per-user memory
│   ├── pipeline.py         # Filter singletons
│   ├── dependencies.py     # require_admin, handle_violation
│   └── vector_db.py        # ChromaDB RAG
├── filters/                # 9-stage security pipeline filters
├── models/
│   ├── modernbert/         # Fine-tuned ModernBERT checkpoint
│   └── gretel-gliner/      # GLiNER PII model snapshot
├── context_vectorstore/    # ChromaDB persistence
└── frontend/
    ├── src/
    │   ├── pages/          # Login, Register, Chat, Admin
    │   ├── services/api.ts # Typed API client
    │   └── lib/schemas.ts  # Zod validation schemas
    └── dist/               # Built assets (served by FastAPI)
```
