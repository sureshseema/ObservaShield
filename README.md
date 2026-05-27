# ObservaShield

ObservaShield is a single-agent security and observability platform: deploy one Universal Agent in Kubernetes or on a VM, then view logs, metrics, traces, events, vulnerabilities, CWP signals, alerts, and incidents in one place.

- **MVP blueprint:** `docs/observashield-mvp.md` - Universal Agent, MVP scope, architecture, deployment models, roadmap
- **Technology stack:** `docs/tech-stack.md` - concrete MVP and production stack choices
- **Landing site:** `index.html` (static marketing page)
- **MVP dashboard + API:** run the backend, then open **http://127.0.0.1:8080/dashboard** (lists incidents, acknowledge/resolve)
- **Master stack:** `master-stack/` — ObservaAgent (Grafana Alloy) + Mimir + Loki + Tempo + Grafana + CWP simulator
- **Backend:** `backend/` — FastAPI, SQLite persistence under `data/observashield.db` (override with `OBSERVASHIELD_DB`)
- **Agent prompt (LLM behavior):** `prompt.txt`, `observashield_full_prompt_v2.html`

## Master stack quick start

```bash
# Terminal 1 — LGTM backends + ObservaAgent
cd master-stack && docker compose up -d

# Terminal 2 — ObservaShield API
cd backend && source .venv/bin/activate && uvicorn app.main:app --reload --port 8080

# Seed metrics, logs, traces, and CWP data
cd master-stack && ./scripts/seed.sh
```

- Grafana: http://localhost:3000 (admin / observashield)
- Stack status: http://127.0.0.1:8080/stack/status
- Incidents: http://127.0.0.1:8080/incidents

See `master-stack/README.md` for full architecture and configuration.
