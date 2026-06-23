# Running AI-Proxy v2 with Docker

This guide assumes you have **Docker Desktop** (or Docker Engine + Compose plugin) installed.  
No Python, Node.js, or Ollama installation is required on your machine.

---

## Prerequisites

| Tool | Minimum version | Check |
|------|----------------|-------|
| Docker Desktop | 4.x (includes Compose v2) | `docker --version` |
| Free disk space | ~25 GB | for image layers + model weights |
| RAM | 8 GB (16 GB recommended) | |

---

## 1 — Prepare your model files

The ML models are too large to ship inside the Docker image. You must make them available as a bind mount before the first build.

### GLiNER (PII detection)
The model files should already be at `./models/gretel-gliner/` inside this directory (they are downloaded once and committed to the models folder).  
If the folder is empty, download the snapshot:

```bash
# inside the AI_proxy directory
python -c "
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id='gretelai/gretel-gliner-bi-large-v1.0',
    local_dir='./models/gretel-gliner'
)
"
```

### ModernBERT (jailbreak classifier)
Copy or symlink your fine-tuned checkpoint into the `models/` directory:

```bash
# Windows (PowerShell)
Copy-Item -Recurse "C:\path\to\prompt_injection_modernbert_v1\checkpoint-65355" `
    ".\models\modernbert"

# Linux / macOS
cp -r /path/to/checkpoint-65355 ./models/modernbert
# or symlink
ln -s /absolute/path/to/checkpoint-65355 ./models/modernbert
```

After this step your models folder should look like:

```
models/
├── modernbert/          ← ModernBERT checkpoint (config.json, model.safetensors, …)
└── gretel-gliner/
    └── hub/
        └── models--gretelai--gretel-gliner-bi-large-v1.0/
            └── snapshots/
                └── f96d1da…/
```

---

## 2 — Create your `.env` file

```bash
cp .env.example .env
```

Open `.env` and fill in at minimum:

```dotenv
# Admin credentials (change these!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123

# Optional alerting — leave blank to disable
TELEGRAM_BOT_TOKEN=
SMTP_USER=
SMTP_PASS=
```

> The Docker Compose file automatically overrides `OLLAMA_URL`, `DB_PATH`, `LOGS_PATH`,
> and the model paths for the container, so you do **not** need to set those in `.env`.

---

## 3 — Build and start the stack

```bash
docker compose up --build
```

The first build downloads and compiles all Python and Node dependencies — expect **15–30 minutes** on a first run.  
Subsequent starts (without `--build`) take a few seconds.

You will see both services start:

```
ai_proxy_ollama  | Listening on 11434
ai_proxy_app     | Uvicorn running on http://0.0.0.0:5000
```

---

## 4 — Pull Ollama models (first run only)

While the services are running, open a second terminal and pull the two LLM models:

```bash
docker compose exec ollama ollama pull qwen2.5:1.5b
docker compose exec ollama ollama pull llama3.2
```

`qwen2.5:1.5b` is ~1 GB and `llama3.2` is ~2 GB. They are cached in the `ollama_data` volume and do not need to be re-downloaded on subsequent starts.

---

## 5 — Open the application

Navigate to **http://localhost:5000** in your browser.

Default admin credentials: whatever you set in `.env` (default `admin` / `admin123`).

---

## Common commands

| Task | Command |
|------|---------|
| Start in background | `docker compose up -d` |
| Stop | `docker compose down` |
| View logs | `docker compose logs -f app` |
| View Ollama logs | `docker compose logs -f ollama` |
| Rebuild after code change | `docker compose up --build` |
| Open a shell in the app container | `docker compose exec app bash` |
| Remove all data (reset DB, logs, Ollama models) | `docker compose down -v` |

---

## Troubleshooting

### App crashes with "model not found"
You skipped step 4. Run the `ollama pull` commands and then restart the app:
```bash
docker compose restart app
```

### Build fails with `libGL.so` error
The base image already installs `libgl1`. If you are on a custom host, try switching the Dockerfile base to `python:3.10` (full, not slim).

### Port 5000 is already in use
Change the host port in `docker-compose.yml`:
```yaml
ports:
  - "8080:5000"   # access via http://localhost:8080
```

### ModernBERT filter not loading
Check that `./models/modernbert/config.json` exists. If you are not using ModernBERT, the BERT filter will fall back to DistilBERT (if `DISTILBERT_MODEL_DIR` is set) or be disabled.

---

## GPU acceleration (optional)

To run Ollama with an NVIDIA GPU, add a `deploy` section to the `ollama` service in `docker-compose.yml`:

```yaml
ollama:
  image: ollama/ollama:latest
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: all
            capabilities: [gpu]
```

Requires the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html) installed on the host.
