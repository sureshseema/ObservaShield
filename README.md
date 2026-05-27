# ObservaShield

ObservaShield is an AI-assisted security and observability product: correlate metrics, logs, traces, and cloud security findings into prioritized incidents.

- **Landing site:** `index.html` (static marketing page)
- **MVP dashboard + API:** run the backend, then open **http://127.0.0.1:8080/dashboard** (lists incidents, acknowledge/resolve)
- **Backend:** `backend/` — FastAPI, SQLite persistence under `data/observashield.db` (override with `OBSERVASHIELD_DB`)
- **Agent prompt (LLM behavior):** `prompt.txt`
