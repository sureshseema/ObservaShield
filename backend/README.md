# ObservaShield — backend (MVP)

ObservaShield API correlates:

- Observability signals: metrics, logs, traces, profiles, events
- Security signals: CWP runtime, CSPM, vulnerability, AI-SPM findings

into prioritized incidents with **stable IDs**, **SQLite persistence**, and **lifecycle status** (`open` → `acknowledged` → `resolved`).

The **master stack** (`../master-stack/`) provides Mimir, Loki, Tempo, and ObservaAgent (Grafana Alloy) for raw telemetry storage. ObservaShield ingests normalized correlation events via `/ingest/unified`.

## Quick start

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

- **Swagger UI:** http://127.0.0.1:8080/docs  
- **Incident UI:** http://127.0.0.1:8080/dashboard  

**Database:** JSON rows for signals + `incident_meta` for status/timestamps. Default path: `../data/observashield.db` (created automatically). Set **`OBSERVASHIELD_DB`** to use a different file.

ObservaShield agent prompt (for LLM integrations) lives at the repo root: `../prompt.txt`.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness |
| GET | `/stack/status` | Master stack health (Mimir, Loki, Tempo, Grafana, ObservaAgent) + signal inventory |
| POST | `/ingest/telemetry` | Append telemetry events |
| POST | `/ingest/security` | Append security findings |
| POST | `/ingest/unified` | ObservaAgent batch ingest (metrics, logs, traces + CWP) |
| GET | `/incidents` | List incidents (sorted by priority) |
| GET | `/incidents/{id}` | Incident detail |
| PATCH | `/incidents/{id}` | Body: `{"status":"open"\|"acknowledged"\|"resolved"}` |

## Sample telemetry payload

```json
{
  "events": [
    {
      "signal_type": "metric",
      "severity": "high",
      "source": "prometheus",
      "title": "5xx error spike",
      "details": "checkout-api 5xx crossed 10% threshold",
      "context": {
        "cloud_account": "prod-aws",
        "region": "eu-west-1",
        "cluster": "eks-prod",
        "namespace": "payments",
        "service": "checkout-api",
        "identity": "svc-checkout",
        "resource_id": "deploy/checkout-api"
      },
      "metrics": {
        "error_rate": 0.14,
        "latency_p95_ms": 2400
      }
    }
  ]
}
```

## Sample security payload

```json
{
  "findings": [
    {
      "domain": "cspm",
      "severity": "critical",
      "source": "wiz",
      "title": "Publicly exposed workload path",
      "details": "Security group allows 0.0.0.0/0 on sensitive endpoint",
      "exploitability": 0.9,
      "context": {
        "cloud_account": "prod-aws",
        "region": "eu-west-1",
        "cluster": "eks-prod",
        "namespace": "payments",
        "service": "checkout-api",
        "identity": "svc-checkout",
        "resource_id": "sg-0123abcd"
      },
      "tags": ["internet-exposed", "attack-path"]
    }
  ]
}
```

## Seed sample data (curl)

```bash
curl -s -X POST http://127.0.0.1:8080/ingest/telemetry -H 'Content-Type: application/json' -d @- <<'EOF'
{"events":[{"signal_type":"metric","severity":"high","source":"prometheus","title":"5xx spike","details":"errors","context":{"cloud_account":"demo","region":"eu-west-1","cluster":"eks","namespace":"pay","service":"checkout-api"},"metrics":{"error_rate":0.14,"latency_p95_ms":2400}}]}
EOF
curl -s -X POST http://127.0.0.1:8080/ingest/security -H 'Content-Type: application/json' -d @- <<'EOF'
{"findings":[{"domain":"cspm","severity":"critical","source":"wiz","title":"Exposure","details":"0.0.0.0/0","exploitability":0.9,"context":{"cloud_account":"demo","region":"eu-west-1","cluster":"eks","namespace":"pay","service":"checkout-api"},"tags":[]}]}
EOF
```

## What to build next

1. Collectors (Grafana Alertmanager webhooks, Wiz API/export) pushing into `/ingest/*`.
2. Postgres for multi-instance / HA; optional tenant column for SaaS.
3. Deduping signals and noise controls (SLO-aware suppression).
4. LLM narrative layer using `prompt.txt` on top of structured incidents only.
