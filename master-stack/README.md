# ObservaShield Master Stack

Unified data plane for **ObservaAgent** — collects and stores all four signal planes:

| Plane | Backend | ObservaAgent path |
|-------|---------|-------------------|
| **Metrics** | Mimir | OTLP + Prometheus remote_write |
| **Logs** | Loki | OTLP log exporter |
| **Traces** | Tempo | OTLP trace exporter |
| **CWP** | ObservaShield API | Wiz webhook / `cwp-simulator` → `/ingest/unified` |

ObservaShield correlates normalized events from all planes into prioritized incidents.

## Architecture

```
 Apps / K8s / Cloud
        │
        ▼
  ObservaAgent (Grafana Alloy)
   ├── OTLP receiver (:4318 HTTP, :4317 gRPC internal)
   ├── batch + enrich processors
   └── exporters ──┬──► Mimir  (metrics)
                   ├──► Loki   (logs)
                   └──► Tempo  (traces)

 CWP sensor / Wiz / simulator
        │
        └──► ObservaShield API (/ingest/unified)
                    │
                    ▼
             Correlation engine → Incidents
                    │
                    ▼
             Grafana (Explore: Mimir + Loki + Tempo)
```

## Quick start

### 1. Start the master stack

```bash
cd master-stack
docker compose up -d
```

Wait ~30s for backends to become ready.

### 2. Start ObservaShield API (separate terminal)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

### 3. Seed sample data

```bash
chmod +x scripts/seed.sh
./scripts/seed.sh
```

The CWP simulator runs automatically inside Docker and pushes correlated runtime + posture scenarios every 30s.

### 4. Verify

| Endpoint | Purpose |
|----------|---------|
| http://localhost:3000 | Grafana (admin / observashield) |
| http://localhost:12345 | ObservaAgent UI |
| http://localhost:8080/stack/status | Master stack health + signal inventory |
| http://localhost:8080/incidents | Correlated incidents |
| http://localhost:8080/docs | API Swagger |

## ObservaAgent ingest

### Unified batch (all planes → ObservaShield)

```bash
POST /ingest/unified
{
  "events": [ /* TelemetryEvent: metric|log|trace|profile|event */ ],
  "findings": [ /* SecurityFinding: cwp_runtime|cspm|vuln|ai_spm */ ]
}
```

### OTLP push (raw telemetry → master stack backends)

```bash
# Metrics, logs, traces via ObservaAgent
curl -X POST http://localhost:4318/v1/metrics -H 'Content-Type: application/json' -d '...'
curl -X POST http://localhost:4318/v1/logs    -H 'Content-Type: application/json' -d '...'
curl -X POST http://localhost:4318/v1/traces  -H 'Content-Type: application/json' -d '...'
```

Query raw data in Grafana Explore using the pre-provisioned Mimir, Loki, and Tempo datasources.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `OBSERVASHIELD_MIMIR_URL` | `http://127.0.0.1:9009/prometheus/api/v1/status/buildinfo` | Mimir health probe |
| `OBSERVASHIELD_LOKI_URL` | `http://127.0.0.1:3100/ready` | Loki health probe |
| `OBSERVASHIELD_TEMPO_URL` | `http://127.0.0.1:3200/ready` | Tempo health probe |
| `OBSERVASHIELD_GRAFANA_URL` | `http://127.0.0.1:3000/api/health` | Grafana health probe |
| `OBSERVASHIELD_AGENT_URL` | `http://127.0.0.1:12345/-/ready` | ObservaAgent health probe |

Edit `observaagent/config.alloy` to add Kubernetes discovery, tail sampling, or additional scrape targets.

## Production next steps

1. Deploy ObservaAgent as a DaemonSet in Kubernetes with `discovery.kubernetes` enabled.
2. Replace `cwp-simulator` with Wiz Defend / Runtime Sensor webhooks → `/ingest/unified`.
3. Add Alertmanager → ObservaShield webhook for SLO-based metric alerts.
4. Point long-term storage to object storage (S3/GCS) in Mimir/Loki/Tempo configs.
