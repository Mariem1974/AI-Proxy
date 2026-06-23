# Session Summary

## UI & Branding
- Added **light / dark mode** toggle (CSS custom properties + localStorage persistence)
- Rewrote `frontend/src/index.css` with full theme system (`[data-theme="light"]`)
- Renamed the app: Essam → AegisAI → Horus → **Security Booster**
- New shield SVG avatar, gradient send button, cleaner card/button styles
- Added theme toggle to Chat, Admin, Login, and Register pages

## Markdown & LaTeX Rendering
- Installed `react-markdown`, `remark-gfm`, `remark-math`, `rehype-katex`, `katex`
- Assistant chat bubbles now render formatted text, tables, code blocks, and math

## SOC Alerting (Telegram + Email)
- Fixed `SOCAlerter` reading `TELEGRAM_BOT_TOKEN` at startup (missed `.env` changes)
  - Now reads token fresh on every call via `os.getenv()`
- Debugged Gmail App Password — spaces in the password were breaking SMTP auth
- Used Bot API `getUpdates` to find real Telegram chat ID
- Added skip-with-print when credentials are not set

## Context Relevance Fix
- Problem: "give me an example" was blocked because it scored low without context
- Fix: added `_FOLLOWUP_RE` regex in `chat_routes.py` to detect continuation messages
- Follow-up messages (≤ 10 words + matching pattern) get enriched with last conversation turn before the similarity check
- Generic off-topic messages ("tell me a joke") are still checked standalone and blocked

## Token Isolation Explained
- **`auth.py`** — `create_session()` generates `secrets.token_hex(32)`, stored in SQLite `sessions` table with `user_id` + 24 h expiry
- **`auth.py`** — `verify_session()` validates token and returns linked user
- **`core/dependencies.py`** — `require_admin` extracts Bearer token and enforces admin role
- **`core/llm.py`** — `_memories: dict[int, list]` keeps each user's conversation fully isolated by `user_id`

## Bug Fix — Permanent Block on First Offense
- **File:** `auth.py` line 270, function `block_user_temp`
- **Bug:** condition was `temp_count >= max_temp`
  - With `max_temp_blocks = 1`: first offense gave temp_count=1, `1 >= 1` = True → permanent immediately
- **Fix:** changed to `temp_count > max_temp`
  - Now: 1st offense = temp block, 2nd offense = permanent block (as intended)
