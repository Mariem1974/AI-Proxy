# AI-Proxy v2 — Project Structure

```
Chatbot/
│
├── app.py                          ← FastAPI app — full pipeline orchestration
├── state.py                        ← Central feature flags & settings (shared state)
├── auth.py                         ← User management, blocking, security logging + JSON export
├── requirements.txt
├── .env.example
├── security_logs.json              ← Auto-generated: all security events in JSON
├── users.db                        ← SQLite database
│
├── core/                           ← Core infrastructure
│   ├── llm.py                      ← Ollama LLM integration + conversation memory
│   ├── vector_db.py                ← ChromaDB vector store for context relevance
│   └── rephrase_engine.py          ← InputRewriter + OutputRewriter (Llama3.2)
│
├── filters/
│   ├── input/                      ← Input pipeline filters
│   │   ├── unicode_firewall.py     ← NEW: Emoji stego + homoglyph attack detection
│   │   ├── spacy_engine.py         ← UPGRADED: spaCy rules v2 (more patterns)
│   │   ├── bert_classifier.py      ← UPGRADED: ModernBERT + DistilBERT fallback
│   │   └── pii_detector.py         ← GLiNER PII detection + masking
│   │
│   └── output/                     ← Output pipeline filters
│       └── spacy_engine.py         ← UPGRADED: secrets, toxic content, PII redaction
│
├── document/                       ← NEW: Document processing pipeline (DOC_Guard)
│   ├── file_gate.py                ← Step 1+2: type check, magic bytes, spoofing, PDF markers
│   ├── extractor.py                ← Step 3: smart router (TXT/DOCX/digital-PDF/OCR)
│   └── doc_pipeline.py             ← Steps 3–7: full chunked document security pipeline
│
├── alerts/
│   └── soc_alerter.py              ← SOC alerts via Telegram + Gmail SMTP
│
└── frontend/
    └── src/
        ├── pages/
        │   ├── Admin.tsx            ← UPGRADED: new toggles, model selector, doc tab, log download
        │   ├── Chat.tsx             ← UPGRADED: document upload button
        │   ├── Login.tsx
        │   └── Register.tsx
        ├── services/
        │   └── api.ts              ← UPGRADED: all new endpoints
        └── types/
            └── api.ts              ← UPGRADED: new types
```

## Full Input Pipeline (in order)

| # | Filter | Module | What it catches |
|---|--------|--------|-----------------|
| ① | Unicode Firewall | `filters/input/unicode_firewall.py` | Emoji steganography, ZW binary encoding, homoglyphs, Bidi overrides |
| ② | spaCy Rules v2 | `filters/input/spacy_engine.py` | Prompt injection, SQLi, XSS, CMDi, SSTI, path traversal, Base64/32 obfuscation |
| ③ | ModernBERT | `filters/input/bert_classifier.py` | Semantic injection attempts (with rephrase loop) |
| ④ | GLiNER PII | `filters/input/pii_detector.py` | 41 PII types — redact before sending to LLM |
| ⑤ | Context Relevance | `core/vector_db.py` | Off-domain questions |

## Full Output Pipeline (in order)

| # | Filter | Module | What it catches |
|---|--------|--------|-----------------|
| ⑥ | spaCy Rules v2 | `filters/output/spacy_engine.py` | Leaked secrets, Egyptian PII, toxic content, attack tools |
| ⑦ | GLiNER + Llama3.2 | `filters/input/pii_detector.py` + `core/rephrase_engine.py` | PII in LLM response |
| ⑧ | Context Relevance | `core/vector_db.py` | Off-domain LLM hallucinations |

## Document Pipeline (per uploaded file)

```
Upload → FileGate (type/size/markers) → Extract (docTR OCR / PyMuPDF / python-docx)
       → Chunk (200 words, 50 overlap) → Normalize → Unicode scan → spaCy → BERT → PII
       → Final decision: ALLOW (safe_context) or BLOCK
```

## Adding new filters

Each filter is a standalone class. To add a new input filter:
1. Create `filters/input/my_filter.py` with a class that has an `analyze(text)` method
2. Add a feature flag to `state.py`
3. Instantiate in `app.py` at startup
4. Add the check to the `@app.post("/api/chat")` handler
5. Add a toggle endpoint + Admin panel toggle

## Security logs

- Stored in SQLite (`users.db` → `security_logs` table)
- Auto-exported to `security_logs.json` in the project root on every new event
- Downloadable via `GET /api/security-logs/download`
- Visible in the Admin panel → Logs tab with filtering
