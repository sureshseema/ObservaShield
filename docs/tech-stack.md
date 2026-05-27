# ObservaShield Technology Stack

## Stack principle

ObservaShield is built around one operating principle:

> One Universal Agent collects observability and security signals. One platform stores, correlates, alerts, and investigates them.

The stack should avoid forcing customers to deploy separate agents for metrics, logs, traces, Kubernetes events, vulnerability scanning, and CWP signals.

## Recommended MVP stack

| Layer | MVP choice | Why |
|-------|------------|-----|
| Universal Agent core | Grafana Alloy | Single collector for metrics, logs, traces, and profiles with Prometheus and OpenTelemetry support |
| Telemetry protocol | OpenTelemetry OTLP | Open standard for metrics, logs, and traces; avoids vendor lock-in |
| Metrics backend | Mimir now, VictoriaMetrics optional | Mimir matches the current repo stack; VictoriaMetrics is a strong simpler option later |
| Logs backend | Loki | Native label-based log storage and good fit with Grafana/Alloy |
| Traces backend | Tempo | Low-cost trace backend that fits OTLP and Grafana workflows |
| Dashboard/explore | Grafana for raw telemetry, ObservaShield UI for product workflow | Grafana is excellent for exploration; ObservaShield UI owns incidents, assets, risk, and workflows |
| Backend API | FastAPI for MVP | Already in repo, fast to iterate, good OpenAPI support |
| Production backend services | Go for high-throughput ingestion/correlation later | Better fit when ingestion volume and concurrency increase |
| Metadata store | SQLite for local MVP, PostgreSQL for production | SQLite keeps demos simple; PostgreSQL supports tenants, HA, and relational asset models |
| Queue/stream | In-process for MVP, NATS or Kafka later | Start simple; add durable async pipelines when ingestion grows |
| Cache | None for MVP, Redis later | Useful for rate limits, sessions, rule state, and hot metadata |
| Vulnerability scanning | Trivy | Container image, filesystem, SBOM, and misconfiguration scanning |
| Kubernetes posture | Custom checks first, OPA/Rego later | Start with critical checks; add policy-as-code once requirements settle |
| Cloud posture | Cloud provider SDKs | Direct AWS/Azure/GCP inventory and checks |
| AI service | Python worker using OpenAI API | Keeps LLM workflows separate from ingestion path |
| Auth | Static token for local MVP, OIDC/Keycloak later | Simple developer onboarding now; enterprise auth later |
| Deployment | Docker Compose locally, Helm for Kubernetes | Compose for demo/dev; Helm for real clusters |
| GitOps | Argo CD optional | Good fit for self-hosted enterprise installs |

## Universal Agent stack

The Universal Agent should be packaged as one deployable unit, even if it contains multiple internal modules.

### Kubernetes deployment

Deploy as:

- `observashield-agent` DaemonSet on every node
- Optional `observashield-cluster-scanner` Deployment for cluster-wide scans
- Optional admission controller later

MVP internal modules:

| Module | Technology |
|--------|------------|
| Metrics collection | Grafana Alloy / OpenTelemetry Collector + Prometheus receiver |
| Log collection | Alloy log components or OTEL filelog receiver |
| Trace collection | OTLP receiver |
| Kubernetes metadata | Kubernetes API watcher |
| Kubernetes events | Kubernetes API watcher |
| Host inventory | Agent host module |
| Container inventory | Kubernetes API + container runtime metadata |
| Vulnerability scan | Trivy library or sidecar-style scanner module |
| Posture scan | Built-in checks for CIS-style Kubernetes risk |
| Local buffer | Disk-backed queue later; memory retry for MVP |
| Exporter | OTLP for telemetry, `/ingest/unified` for normalized security findings |

### VM deployment

Deploy as:

- `observashield-agent` binary or container
- `systemd` service
- Config file at `/etc/observashield/agent.yaml`

MVP collection:

- Host CPU, memory, disk, network
- Syslog or configured log files
- OTLP traces from local apps
- OS package inventory
- Listening ports
- Running processes
- Host vulnerability scan

### Agent output paths

| Signal | Export path |
|--------|-------------|
| Metrics | OTLP or remote write to ingestion |
| Logs | OTLP logs to ingestion |
| Traces | OTLP traces to ingestion |
| Kubernetes events | Normalized event payload to `/ingest/unified` |
| Vulnerabilities | Normalized security finding to `/ingest/unified` |
| CWP/runtime events | Normalized security finding to `/ingest/unified` |
| Asset inventory | Asset payload to metadata API |

## Control plane stack

### MVP control plane

```text
ObservaShield UI
        |
FastAPI backend
        |
SQLite metadata store
        |
Correlation engine
        |
Incidents / stack status / OpenAPI
```

Use the current repo implementation for:

- `/ingest/telemetry`
- `/ingest/security`
- `/ingest/unified`
- `/incidents`
- `/stack/status`
- Static dashboard

### Production control plane

```text
API Gateway
        |
Auth / RBAC / Tenant service
        |
Ingestion services
        |
NATS or Kafka
        |
Normalizer workers
        |
PostgreSQL + telemetry backends + object storage
        |
Correlation engine + alert engine + AI worker
        |
ObservaShield UI
```

Recommended service split:

| Service | Responsibility | Suggested language |
|---------|----------------|--------------------|
| API Gateway | Routing, auth handoff, rate limits | Envoy/Kong/Traefik |
| Ingestion API | Accept OTLP and security payloads | Go |
| Metadata API | Assets, tenants, config, agents | Go or Python |
| Correlation engine | Build incidents from signals | Python now, Go later |
| Alert engine | Evaluate thresholds and security rules | Go |
| AI worker | Summaries, RCA hints, runbook suggestions | Python |
| Notification worker | Slack, email, webhooks | Go or Python |
| UI backend | Product API aggregation | Go or Python |

## Storage stack

### MVP

| Data | Store |
|------|-------|
| Incident metadata | SQLite |
| Normalized telemetry events | SQLite JSON rows |
| Normalized security findings | SQLite JSON rows |
| Raw metrics | Mimir |
| Raw logs | Loki |
| Raw traces | Tempo |

### Production

| Data | Store |
|------|-------|
| Tenants, users, agents, assets, incidents | PostgreSQL |
| Raw metrics | Mimir or VictoriaMetrics |
| Raw logs | Loki |
| Raw traces | Tempo |
| Long-term backend blocks | S3/GCS/Azure Blob/MinIO |
| Queue events | NATS JetStream or Kafka |
| Cache and short-lived state | Redis |
| Searchable findings | PostgreSQL first; OpenSearch later only if needed |

## UI stack

MVP:

- Current static dashboard is acceptable for local proof.
- Keep Grafana for raw metrics/logs/traces exploration.
- Build ObservaShield product views around incidents, assets, posture, vulnerabilities, and agent health.

Production:

- React + Next.js
- TypeScript
- TanStack Query
- Tailwind or a small internal design system
- Recharts/ECharts for product charts
- Monaco editor later for PromQL/LogQL/policy editing

Important UX rule:

Grafana is an exploration tool. ObservaShield is the single operational workspace. Users should not need to open Grafana to understand the current incident, affected service, security risk, or recommended next action.

## AI stack

MVP:

- Python AI worker
- OpenAI API
- Prompt uses only structured incident JSON
- AI output stored as incident summary fields

Later:

- LangGraph for multi-step investigations
- Retrieval over runbooks and past incidents
- Human approval workflow for remediation
- No automatic production mutations without explicit policy and audit trail

AI input:

- Incident summary
- Correlated telemetry event titles/details
- Security findings
- Asset context
- Recent deployment metadata later
- Runbook snippets later

AI output:

- Short incident summary
- Likely contributing factors
- Next checks
- Suggested PromQL/LogQL queries
- Remediation draft

## Security stack

MVP:

- Agent enrollment token
- Tenant ID on ingest
- HTTPS transport
- Least-privilege Kubernetes RBAC
- Local secret redaction rules
- Signed release artifacts later in MVP hardening

Production:

- mTLS agent identity
- OIDC/SAML SSO
- RBAC and audit logs
- Per-tenant encryption boundaries
- Secrets in Vault, cloud secret managers, or Kubernetes Secrets
- SBOM for agent and backend images
- Image signing with cosign
- Policy checks in CI/CD

## Deployment stack

### Local developer stack

Use the current repo:

- `docker compose` in `master-stack/`
- FastAPI backend on port `8080`
- Mimir, Loki, Tempo, Grafana, Alloy
- CWP simulator

### Kubernetes self-hosted stack

Package as Helm charts:

- `observashield-control-plane`
- `observashield-agent`
- `observashield-storage`

Self-hosted dependencies:

- PostgreSQL
- Redis
- NATS or Kafka
- Mimir/VictoriaMetrics
- Loki
- Tempo
- Grafana optional
- MinIO or cloud object storage for long-term retention

### SaaS stack

Customer installs:

- `observashield-agent`

ObservaShield operates:

- Ingestion edge
- Tenant control plane
- Telemetry storage
- Incident engine
- AI worker
- UI

### Hybrid stack

Customer keeps:

- Raw logs
- Raw metrics
- Raw traces
- Long-term object storage

ObservaShield SaaS receives:

- Asset metadata
- Security findings
- Alert summaries
- Incident objects
- Optional links back to customer telemetry stores

## MVP build order

1. Keep current FastAPI + SQLite control plane.
2. Keep current Mimir/Loki/Tempo/Grafana/Alloy local stack.
3. Formalize `/ingest/unified` as the primary normalized event API.
4. Add an agent config schema for Kubernetes and VM modes.
5. Package the Universal Agent as a Kubernetes DaemonSet.
6. Add VM `systemd` packaging.
7. Add Trivy-based vulnerability scan output into `/ingest/unified`.
8. Add Kubernetes event and posture scan output.
9. Add Slack/email/webhook notifications.
10. Add AI summaries after incident objects are stable.

## Final recommended architecture

```text
Kubernetes / VM / On-Prem
        |
        v
ObservaShield Universal Agent
  - Alloy / OTel collector
  - Prometheus scrape
  - Log tailing
  - OTLP traces
  - K8s metadata/events
  - Host/container inventory
  - Trivy vulnerability scans
  - Posture checks
        |
        | OTLP + HTTPS unified ingest
        v
ObservaShield Ingestion
        |
        +--> Mimir or VictoriaMetrics for metrics
        +--> Loki for logs
        +--> Tempo for traces
        +--> PostgreSQL for assets, findings, incidents
        +--> NATS/Kafka for async processing
        |
        v
Correlation + Alert + AI engines
        |
        v
ObservaShield UI
  - Dashboards
  - Assets
  - Vulnerabilities
  - CWP events
  - Alerts
  - Incidents
  - AI summaries
```

## References

- Grafana Alloy is an OpenTelemetry Collector distribution with Prometheus pipelines and support for metrics, logs, traces, and profiles: https://grafana.com/docs/alloy/latest/introduction/
- OpenTelemetry Collector is structured around receivers, processors, exporters, connectors, and extensions: https://opentelemetry.io/docs/collector/components/
- Trivy supports container image vulnerability scanning, SBOM use, and misconfiguration scanning: https://trivy.dev/docs/dev/guide/target/container_image/
- The current repo already contains a local Mimir, Loki, Tempo, Grafana, and Alloy stack in `master-stack/`.

