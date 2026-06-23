# AI-Proxy v2 — Secure Finance LLM Gateway

A security-hardened AI proxy that intercepts every message between users and a local LLM, enforcing a 9-stage filtering pipeline to block prompt injection, PII leakage, jailbreaks, Unicode steganography, and data exfiltration. Includes an admin dashboard, analytics, SOC alerting, and document upload with OCR scanning.

**Only prerequisite: Docker Desktop.**

---

## Quick Start

```bash
# 1. Clone the repo
git clone <repo-url>
cd AI_proxy

# 2. (Optional) configure alerts — skip this step to run without email/Telegram
cp .env.example .env
# Edit .env and fill in TELEGRAM_BOT_TOKEN and/or SMTP_USER / SMTP_PASS

# 3. Start everything
docker compose up --build
```

On first run Docker will:
- Build the application image (installs all Python/Node dependencies, ~10 min)
- Pull `qwen2.5:1.5b` and `llama3.2` from Ollama (~2 GB, one-time)
- Start PostgreSQL + TimescaleDB, ChromaDB, Ollama, and the app

**Open `http://localhost:5000` — log in with `admin` / `admin123`.**

> The app is ready when you see `Application startup complete` in the logs.
> First startup takes longer because Ollama downloads the LLM models.

---

## Architecture

```
Browser
  └── React SPA (served from FastAPI at :5000)
        │
        └── FastAPI Backend (:5000)
              │  9-stage security pipeline
              ├── Input:  Unicode Firewall → spaCy Rules → ModernBERT
              │           → GLiNER PII → Context Relevance
              ├──  LLM:   Ollama (qwen2.5:1.5b) (:11434)
              └── Output: spaCy Rules → GLiNER PII → Context Relevance
                    │
                    ├── PostgreSQL + TimescaleDB (:5432)
                    │   users, sessions, security_logs hypertable, settings
                    ├── ChromaDB (:8001)
                    │   finance-domain embeddings for context relevance
                    └── SOC Alerts → Telegram Bot / Gmail SMTP
```

### Docker Compose Services

| Container | Image | Purpose |
|-----------|-------|---------|
| `ai_proxy_app` | built locally | FastAPI backend + React frontend |
| `ai_proxy_postgres` | timescale/timescaledb:latest-pg16 | Relational + time-series DB |
| `ai_proxy_chromadb` | chromadb/chroma:latest | Vector store for RAG |
| `ai_proxy_ollama` | ollama/ollama:latest | Local LLM inference |
| `ai_proxy_ollama_init` | ollama/ollama:latest | One-shot model pull (exits after) |

---

## Security Pipeline

### Input (5 stages)

| # | Stage | What it catches |
|---|-------|-----------------|
| 1 | Unicode Firewall | Homoglyphs, zero-width chars, BiDi overrides, emoji steganography |
| 2 | spaCy Rule Engine | Prompt injection, SQLi, XSS, CMDi, path traversal, delimiter attacks |
| 3 | ModernBERT Classifier | Fine-tuned ML injection / jailbreak detector (8k token context) |
| 4 | GLiNER PII Detector | 22 PII entity types masked before reaching the LLM |
| 5 | Context Relevance | Blocks off-topic queries via ChromaDB cosine similarity |

### Output (3 stages)

| # | Stage | What it catches |
|---|-------|-----------------|
| 6 | spaCy Output Engine | Redacts secrets, credentials, attack-tool references in LLM replies |
| 7 | GLiNER Output PII | Masks PII that the LLM might have generated |
| 8 | Context Relevance | Validates response stays within the finance domain |

### Document pipeline

Uploaded files (PDF / DOCX / TXT / PNG / JPG) pass through:
**FileGate** (magic-bytes, spoofing, active-PDF checks) →
**Extractor** (PyMuPDF / docTR OCR) →
**Normaliser** (zero-width strip, NFKC) →
**Parallel chunk scan** (full 9-stage pipeline per chunk, early-abort on first hit)

---

## Feature Flags (Admin Panel)

All pipeline stages can be toggled live without restarting.

| Feature | Default | Notes |
|---------|---------|-------|
| Unicode Firewall | **ON** | Fast deterministic, near-zero false positives |
| spaCy Input Rules | **ON** | Rule-based injection/SQLi/XSS/CMDi |
| ModernBERT | OFF | Enable for ML-based injection detection |
| GLiNER PII (input) | OFF | Enable to mask user-submitted PII |
| Context Relevance (input) | OFF | Requires domain PDF uploaded first |
| spaCy Output Rules | **ON** | Redacts LLM output secrets |
| GLiNER PII (output) | OFF | Enable to mask PII in LLM responses |
| Context Relevance (output) | OFF | Requires domain PDF uploaded first |
| Document Processing | OFF | Enable to allow file uploads |

---

## Default Credentials

| Account | Username | Password |
|---------|----------|----------|
| Admin | `admin` | `admin123` |

Change via the Users tab in the admin panel or set `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `.env` before first run.

---

## Alerts Configuration

Alerts are sent for HIGH and CRITICAL severity violations (temp block, permanent block).

1. Open the admin panel → **Alerts** tab
2. Set your Telegram Chat ID and/or email address
3. Toggle **Enable Telegram** and/or **Enable Email**

Or pre-configure via `.env`:

```env
TELEGRAM_BOT_TOKEN=your_bot_token_from_botfather
SMTP_USER=your@gmail.com
SMTP_PASS=your_16char_app_password
```

---

## Running the E2E Test Suite

With the stack running (`docker compose up`):

```bash
# Install test dependencies on the host (requests + pytest only)
pip install requests pytest

# Run all 82 tests
cd AI_proxy
python -m pytest tests/e2e_test_suite.py -v

# Fast subset (no Ollama calls, ~30 seconds)
python -m pytest tests/e2e_test_suite.py -k "not ChatPipeline" -v
```

Expected result: **75 passed, 7 skipped, 0 failed**
(7 skips = BERT guardrail tests that skip when ModernBERT weights are absent)

---

## Loading ML Models (Optional)

The pipeline works without ModernBERT and GLiNER weight files — those stages gracefully fall back or are skipped. To enable full ML detection:

### GLiNER (PII detection)
Place the snapshot at:
```
AI_proxy/models/gretel-gliner/hub/models--gretelai--gretel-gliner-bi-large-v1.0/
    snapshots/f96d1da43b97bd1846b14a7068a57e1ab15f226e/
```

### ModernBERT (injection classifier)
Place the checkpoint at:
```
AI_proxy/models/modernbert/
```
The `models/` directory is bind-mounted read-only into the container at `/app/models`.

---

## Seeding Demo Data

To populate the analytics dashboard with sample users and security events:

```bash
docker exec -i ai_proxy_postgres psql -U ai_proxy -d ai_proxy < seed_demo.sql
```

This creates 5 demo users (`alice`, `bob`, `charlie`, `diana`, `eve`) with password `password123` and 110 security log entries for dashboard visualisation.

---

## Project Structure

```
AI_proxy/
├── app.py                      # FastAPI entry point, lifespan, routers
├── auth.py                     # Async user CRUD, JWT sessions, blocking, logs
├── auth_utils.py               # bcrypt hashing, JWT create/decode (jti-unique)
├── db.py                       # SQLAlchemy models, TimescaleDB hypertable init
├── state.py                    # In-memory feature flags and BERT thresholds
├── schemas.py                  # Pydantic request/response models
├── docker-compose.yml          # 4-container orchestration
├── Dockerfile                  # Multi-stage: Node (React build) + Python
├── .env.example                # Environment variable template
├── seed_demo.sql               # Demo users + analytics log entries
├── requirements.txt
├── core/
│   ├── llm.py                  # Async Ollama integration, per-user memory
│   ├── vector_db.py            # ChromaDB context relevance
│   ├── rephrase_engine.py      # Llama3.2-based input rewriter
│   └── dependencies.py        # require_admin guard, handle_violation escalation
├── filters/
│   ├── input/
│   │   ├── unicode_firewall.py # Stage 1 — emoji stego, homoglyphs, BiDi
│   │   ├── spacy_engine.py     # Stage 2 — injection/SQLi/XSS rules
│   │   ├── bert_classifier.py  # Stage 3 — ModernBERT/DistilBERT
│   │   └── pii_detector.py     # Stage 4 — GLiNER zero-shot NER
│   └── output/
│       └── spacy_engine.py     # Stage 6 — output redaction
├── routers/
│   ├── auth_routes.py          # /api/auth/* — register, login, me, logout
│   ├── chat_routes.py          # /api/chat, /api/upload-document, /api/reset
│   └── admin_routes.py         # /api/toggle/*, /api/users, /api/analytics, ...
├── document/
│   ├── doc_pipeline.py         # Orchestrates the document security pipeline
│   ├── file_gate.py            # Magic-bytes, spoofing, active-PDF detection
│   └── extractor.py            # TXT/DOCX/PDF/OCR routing
├── alerts/
│   └── soc_alerter.py          # Telegram + Gmail alert dispatcher
├── diagrams/                   # PlantUML source + rendered PNGs
├── tests/
│   └── e2e_test_suite.py       # 82 end-to-end API tests
└── frontend/
    └── src/
        ├── pages/
        │   ├── Chat.tsx
        │   ├── Admin.tsx        # Feature toggles, users, alerts, analytics
        │   ├── Login.tsx
        │   └── Register.tsx
        └── services/
            └── api.ts
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10, FastAPI, Uvicorn |
| Frontend | React 18, TypeScript, Vite, TailwindCSS, Recharts |
| LLM | Ollama — `qwen2.5:1.5b` (chat), `llama3.2` (rewriter) |
| ML Models | ModernBERT (fine-tuned), DistilBERT (fallback), GLiNER (PII), docTR (OCR), spaCy 3.8 |
| Vector DB | ChromaDB (standalone container) |
| Database | PostgreSQL 16 + TimescaleDB (`security_logs` hypertable) |
| Auth | JWT (`python-jose`) with `jti` UUID claim |
| Alerting | Telegram Bot API + Gmail SMTP |
| Deployment | Docker Compose (4 containers) |
