# ObservaShield MVP Blueprint

## Product vision

ObservaShield is a unified Security, Observability, and AI Operations platform for Kubernetes, cloud VMs, and on-prem environments.

The product goal is intentionally simple: customers should not need to deploy multiple agents in Kubernetes, then jump across separate tools to see logs, metrics, traces, events, vulnerabilities, CWP findings, and incidents. ObservaShield should collect these signals through one Universal Agent and present them in one operational workspace.

The MVP proves one promise:

> One Universal Agent. One platform. One place to observe, secure, and triage Kubernetes and VM workloads.

## MVP positioning

ObservaShield MVP is a Kubernetes and VM observability platform with cloud and workload security posture built in from day one.

Primary wedge:

- One agent instead of separate observability, logging, security, and CWP agents
- One dashboard instead of separate tools for logs, metrics, events, vulnerabilities, and incidents
- Kubernetes observability
- VM/host observability
- CSPM checks
- IaC and image security signals
- Alerting and incident creation
- Single Universal Agent

Out of scope for MVP:

- Full ASPM
- Full CIEM
- Full DSPM
- Advanced eBPF runtime protection
- Auto-remediation
- Enterprise on-call scheduling
- Deep AI agents that can mutate production

## Target users

| User | Jobs to be done |
|------|------------------|
| SRE / Platform engineer | Monitor clusters, reduce alert noise, triage incidents faster |
| DevOps engineer | Deploy one agent, collect telemetry, connect CI/CD and IaC findings |
| Cloud security engineer | Find exposed resources, vulnerable workloads, weak posture |
| Security operations engineer | Prioritize security findings by runtime and service impact |
| Engineering manager | See reliability and security risk in one operational view |

## Core MVP modules

### 1. ObservaShield Universal Agent

Runs as:

- Kubernetes DaemonSet
- VM or bare-metal `systemd` service
- On-prem server process

MVP capabilities:

| Capability | MVP |
|------------|-----|
| Metrics collection | Yes |
| Logs collection | Yes |
| Traces collection | Yes |
| Kubernetes metadata | Yes |
| Host inventory | Yes |
| Container inventory | Yes |
| Image vulnerability scan | Yes |
| Host package scan | Yes |
| Secure export | Yes |
| Runtime eBPF sensor | Later |
| Admission controller | Later |
| Auto-remediation | Later |

Recommended implementation:

- OpenTelemetry Collector or Grafana Alloy as the collector core
- Prometheus receiver for `/metrics`
- OTEL filelog receiver or Fluent Bit-style tailing for logs
- OTLP receiver/exporter for traces
- Trivy for image and host package scanning
- Kubernetes watcher for pod, node, deployment, service, namespace metadata
- Local retry queue for temporary network loss
- OTLP over HTTP/gRPC plus ObservaShield unified ingest for normalized security events

### 2. Observability MVP

Metrics:

- Node metrics
- Kubernetes metrics
- Application metrics
- Prometheus scrape targets
- Custom service metrics

Logs:

- Kubernetes pod logs
- Container logs
- VM logs
- Label-based search
- Correlation by service, namespace, pod, host, trace ID

Traces:

- OTLP ingestion
- Service latency
- Error spans
- Trace-to-log linking by trace ID

Backends:

- VictoriaMetrics or Mimir for metrics
- Loki for logs
- Tempo for traces

The current local stack uses Mimir, Loki, Tempo, Grafana, and Grafana Alloy.

### 3. Security MVP

Kubernetes posture:

- CIS-style checks
- Privileged containers
- HostPath mounts
- Public service exposure
- Risky RBAC bindings
- Missing resource limits
- Insecure image settings

Vulnerability scanning:

- Container image scan
- Host package scan
- CVE severity
- EPSS field support
- Runtime/service context when available

Basic CSPM:

- Public buckets
- Open security groups
- Public IP exposure
- Overly broad IAM permissions
- Unencrypted storage

Supported first:

- AWS
- Azure
- GCP

### 4. Unified incident engine

Correlates:

- Metrics, logs, traces
- Kubernetes metadata
- Cloud account, region, cluster, namespace, service
- Vulnerabilities
- CSPM findings
- Runtime/security events

MVP scoring inputs:

- Security severity
- Exploitability
- Service criticality
- Error rate or latency impact
- Active telemetry severity

Outputs:

- Stable incident ID
- Priority P0/P1/P2
- Summary
- Correlated telemetry and security findings
- Recommended actions
- Lifecycle status: `open`, `acknowledged`, `resolved`

### 5. Dashboard MVP

Views:

| View | Purpose |
|------|---------|
| Cluster dashboard | CPU, memory, nodes, pods, restarts |
| Application dashboard | Logs, traces, metrics by service |
| Security dashboard | Vulnerabilities, posture, exposures |
| Asset inventory | Clusters, VMs, containers, services |
| Alerts dashboard | Active threshold and security alerts |
| Incident dashboard | Correlated incidents and status |
| Stack status | Agent and backend health |

### 6. Alerting and incident MVP

MVP features:

- Threshold alerts
- Security finding alerts
- Incident creation
- Slack notification
- Email notification
- Webhook notification
- Basic acknowledgement and resolution

Later:

- Escalation policies
- Full on-call rotations
- Maintenance windows
- Noise suppression
- SLO-aware paging

### 7. AI MVP

MVP features:

- Alert summarization
- Incident summarization
- Basic root-cause hints from structured incident context
- Suggested next checks

Guardrails:

- AI reads structured signals only
- AI does not invent telemetry
- AI does not execute remediation in MVP
- Every recommendation links back to correlated signals

Suggested stack:

- OpenAI API
- LangGraph for future multi-step investigation flows
- Deterministic correlation engine before LLM summarization

## High-level architecture

```text
Customer Kubernetes / VM / On-Prem
        |
        v
ObservaShield Universal Agent
        |
        | OTLP / HTTPS / mTLS
        v
ObservaShield Ingestion
        |
        +--> Metrics store
        +--> Logs store
        +--> Trace store
        +--> Security finding store
        +--> Metadata store
        |
        v
Unified Risk and Ops Graph
        |
        v
Correlation and Incident Engine
        |
        v
API Gateway + UI + AI Insights
```

## Control plane and data plane

### Control plane

Responsibilities:

- Tenant management
- Auth and RBAC
- Agent enrollment
- Ingestion routing
- Incident correlation
- Alert rules
- Dashboard API
- AI summary API
- Audit logs

MVP components:

- FastAPI backend
- SQLite for local MVP, PostgreSQL for production
- Incident correlation engine
- Stack health endpoint
- Static dashboard
- OpenAPI docs

Production components:

- API gateway
- PostgreSQL
- Redis
- NATS or Kafka
- OIDC/Keycloak
- Object storage for long-term telemetry backends

### Data plane

Responsibilities:

- Collect host, Kubernetes, app, and security signals
- Enrich signals with metadata
- Batch, compress, and retry
- Export securely to control plane or self-hosted backend
- Minimize privileges by capability

Kubernetes mode:

- Agent DaemonSet on every node
- Optional cluster scanner Deployment
- Optional admission controller later

VM mode:

- Single binary or package
- Runs as `observashield-agent.service`
- Collects host metrics, logs, package inventory, process inventory

## Deployment models

### SaaS

Customer deploys only the Universal Agent.

```text
Customer environment -> ObservaShield SaaS ingestion -> ObservaShield SaaS UI
```

Best for:

- Fast onboarding
- Managed storage
- Managed upgrades

### Self-hosted

Customer deploys:

- ObservaShield backend
- Observability backends
- Universal Agent
- Database and queue

Best for:

- Regulated environments
- Air-gapped or private networks
- Data residency needs

### Hybrid

Customer keeps raw telemetry in their environment, while ObservaShield SaaS receives metadata, findings, summaries, and incident objects.

Best for:

- Enterprises with strict telemetry residency
- Lower SaaS ingestion cost
- Centralized risk operations without moving all logs

## Recommended MVP technology stack

| Layer | Technology |
|-------|------------|
| Frontend | Static dashboard now; React/Next.js later |
| Backend API | Python FastAPI now; Go services later where high-throughput needed |
| Agent | Grafana Alloy or OpenTelemetry Collector distribution |
| Metrics | Mimir or VictoriaMetrics |
| Logs | Loki |
| Traces | Tempo |
| Vulnerability scan | Trivy |
| Policy | OPA/Rego later |
| Metadata | SQLite for local MVP; PostgreSQL for production |
| Cache/queue | Redis/NATS later |
| Auth | OIDC/Keycloak later |
| Deployment | Docker Compose for local; Helm for Kubernetes |

## MVP delivery phases

### Phase 1: Local proof

Duration: 2-3 weeks

- Local control plane
- Unified ingest API
- SQLite persistence
- Incident correlation
- Static incident dashboard
- Docker Compose master stack

Success criteria:

- Demo can ingest metric, log, trace, and security signals
- Incidents are generated with stable IDs and status changes

### Phase 2: Universal Agent v1

Duration: 3-4 weeks

- Kubernetes DaemonSet packaging
- VM/systemd packaging
- Metrics, logs, traces
- Kubernetes metadata enrichment
- Host inventory
- Secure config file
- Retry and batching

Success criteria:

- One install command starts signal collection in Kubernetes
- One service install starts signal collection on a VM

### Phase 3: Security signal MVP

Duration: 3-4 weeks

- Trivy image and host scanning
- Basic Kubernetes posture checks
- Basic cloud inventory and CSPM checks for AWS first
- Normalize findings into `/ingest/unified`

Success criteria:

- Security findings correlate with running services and incidents

### Phase 4: Dashboard and alerting

Duration: 3-4 weeks

- Cluster dashboard
- Asset inventory
- Security dashboard
- Alert rules
- Slack/email/webhook notifications
- Incident detail page

Success criteria:

- User can go from alert to service to correlated security and telemetry context

### Phase 5: AI summary

Duration: 2 weeks

- Incident summary
- Root-cause hints
- Suggested next checks
- Prompt guardrails

Success criteria:

- AI output is grounded in incident fields and does not fabricate data

### Phase 6: Hardening

Duration: 3 weeks

- Tenant model
- Auth
- TLS/mTLS
- Rate limits
- Helm chart
- Upgrade path
- Documentation

Success criteria:

- Pilot customer can deploy safely in a non-production cluster

## Differentiators

- One agent for observability and security signals
- Correlation by service, workload, host, identity, and cloud resource
- Incident-first UX instead of separate metrics/logs/security silos
- Runtime-aware vulnerability prioritization
- Hybrid deployment path for telemetry residency
- AI summaries grounded in structured evidence

## Example MVP workflows

### Workflow 1: Kubernetes incident triage

1. Error rate alert fires for `checkout-api`.
2. ObservaShield correlates metric spike, trace latency, pod restarts, and recent image vulnerability.
3. Incident is scored as P0 or P1.
4. SRE opens incident dashboard.
5. Dashboard shows impacted service, cluster, namespace, related logs/traces, and recommended checks.
6. SRE acknowledges incident and resolves after mitigation.

### Workflow 2: Cloud exposure finding

1. CSPM check detects a public security group or bucket.
2. ObservaShield maps it to cloud account, region, and service.
3. If service also has active telemetry impact, priority is raised.
4. Security engineer gets recommended remediation steps and affected assets.

### Workflow 3: Vulnerable image in production

1. Agent scans a container image with Trivy.
2. Critical CVE is found.
3. Agent enriches finding with namespace, pod, service, image digest, and cluster.
4. ObservaShield correlates with live traffic and service criticality.
5. Security team prioritizes patching based on runtime context.

## Security and compliance considerations

MVP must include:

- TLS for all network transport
- Tenant ID on ingest
- API keys or enrollment tokens
- Least-privilege Kubernetes RBAC
- Redaction rules for sensitive log fields
- Local buffering with bounded disk usage
- Audit log for status changes and configuration changes
- No automatic remediation by default

Production must add:

- mTLS for agent enrollment and export
- OIDC/SAML SSO
- Role-based access control
- Per-tenant encryption boundaries
- Data retention policies
- SOC 2 control evidence
- PCI/HIPAA-ready log redaction options where needed
- Signed agent releases and SBOM

## Definition of done for MVP

The MVP is done when a user can:

1. Deploy the Universal Agent to Kubernetes or a VM.
2. See metrics, logs, traces, assets, and security findings in ObservaShield.
3. Receive a threshold or security alert.
4. See a correlated incident with priority and recommended actions.
5. Acknowledge or resolve the incident.
6. Run the same basic experience in SaaS-style or self-hosted local mode.
