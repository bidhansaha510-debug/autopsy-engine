# INFRASTRUCTURE AUTOPSY

<p align="center">
  <strong>"Give it the evidence. It reconstructs the incident."</strong>
</p>

<p align="center">
  <em>A deterministic, evidence-backed digital incident forensics platform for complex distributed systems.</em>
</p>

---

## Table of Contents
1. [Core Mandate & Philosophy](#1-core-mandate--philosophy)
2. [Forensic Workflow (End-to-End)](#2-forensic-workflow-end-to-end)
3. [The Canonical Incident Benchmark](#3-the-canonical-incident-benchmark)
4. [Pluggable Ingestion Adapters & Provenance](#4-pluggable-ingestion-adapters--provenance)
5. [Database Schema & Domain Models (22 Relational Entities)](#5-database-schema--domain-models-22-relational-entities)
6. [Forensic Analytical Engines](#6-forensic-analytical-engines)
   - [Robust Baselines & Anomaly Detection (MAD / Non-Parametric)](#robust-baselines--anomaly-detection-mad--non-parametric)
   - [Deterministic Correlation Engine](#deterministic-correlation-engine)
   - [Distributed Tracing & Critical Path Analysis](#distributed-tracing--critical-path-analysis)
   - [Competing Hypotheses & "Prove Me Wrong" Engine](#competing-hypotheses--prove-me-wrong-engine)
   - [Topology & Blast Radius Engine](#topology--blast-radius-engine)
7. [AI Forensic Investigator (Local Ollama Tool Loop)](#7-ai-forensic-investigator-local-ollama-tool-loop)
8. [Codebase & Telemetry Folder Ingestion](#8-codebase--telemetry-folder-ingestion)
9. [Forensic Workspace UI & Replay Controller](#9-forensic-workspace-ui--replay-controller)
10. [Safety & Security Guardrails](#10-safety--security-guardrails)
11. [Complete REST API Reference](#11-complete-rest-api-reference)
12. [Quickstart & Verification](#12-quickstart--verification)

---

## 1. Core Mandate & Philosophy

**Infrastructure Autopsy is NOT:**
- A generic real-time telemetry dashboard (like Grafana or Datadog).
- A simple text log search viewer (like Kibana or Graylog).
- An ungrounded conversational AI chatbot or fake telemetry generator.

**Infrastructure Autopsy IS:**
- **A digital incident forensics workstation**: When a production failure strikes, engineers ingest system telemetry, deployment logs, and configuration history. The engine reconstructs the timeline, correlates multi-service symptoms, formulates competing root-cause hypotheses, rigorously tests them against raw evidence using counterevidence rules, calculates the failure blast radius, and outputs an evidence-backed postmortem.
- **Strictly Evidence-Backed**: Every conclusion possesses cryptographic provenance (SHA-256 fingerprinting) and cites indelible Evidence IDs (`[EVID-XXX]`).
- **Zero Hallucination Guarantee**: AI operates strictly as an autonomous read-only tool-using investigator. It is never allowed to fabricate data or act as the source of truth.

---

## 2. Forensic Workflow (End-to-End)

The forensic engine processes evidence through 14 deterministic stages:

```
DATA SOURCES
     │
     ▼
 INGESTION  ──► (JSON logs, OpenTelemetry spans, Prometheus metrics, K8s events, Git diffs)
     │
     ▼
NORMALIZATION ──► (UTC timestamp translation, timezone retention, SHA-256 fingerprinting)
     │
     ▼
  STORAGE   ──► (PostgreSQL / SQLAlchemy 2.0 normalized relational tables)
     │
     ▼
 BASELINES  ──► (Non-parametric historical windows: Median, MAD, p50, p95, p99)
     │
     ▼
ANOMALY DET ──► (Robust deviation z-scores and severity classification)
     │
     ▼
CORRELATION ──► (Deterministic temporal, causal, topological, and trace-ID linking)
     │
     ▼
DEPENDENCY  ──► (NetworkX microservice DAG traversal)
     │
     ▼
HYPOTHESES  ──► (Competing rival root-cause candidates generation)
     │
     ▼
EVIDENCE GR ──► (Indelible chain-of-custody register)
     │
     ▼
PROVE WRONG ──► (Counterevidence search, rival hypothesis penalties, support scoring)
     │
     ▼
AI INVEST   ──► (Local Ollama tool-calling loop with mandatory evidence citations)
     │
     ▼
BLAST RADIUS──► (Direct origin vs indirect upstream caller propagation paths)
     │
     ▼
RECOVERY    ──► (Intervention rollback verification and metric stabilization)
     │
     ▼
POSTMORTEM  ──► (Formal evidence-backed Markdown & JSON report export)
```

---

## 3. The Canonical Incident Benchmark

The platform includes automated reconstruction and replay for canonical distributed failure scenarios:

| Timestamp (UTC) | Forensic Event Observed | Telemetry Type | Evidence Record |
|---|---|---|---|
| **02:47:00** | Parameter `database.pool.max_connections` reduced from `50` to `5` on `payment-service` by `infra-ops-script`. | `CONFIG` | `[EVID-CFG-0001]` |
| **02:48:00** | DB connection pool utilization on `payment-service` saturated from baseline 18.5% to **100%**. Connection queue backlogged. | `METRIC` / `LOG` | `[EVID-ANOM-0001]` `[EVID-LOG-0001]` |
| **02:49:00** | `api-gateway` p99 latency surged from 32ms to **1280ms** due to blocking downstream calls. | `METRIC` | `[EVID-ANOM-0003]` |
| **02:50:00** | `checkout-service` RPC calls timed out waiting for `payment-service:AuthorizePayment`. Distributed trace waterfall recorded 3050ms latency with 503 error. | `TRACE` / `LOG` | `[EVID-TRACE-0001]` |
| **02:51:00** | API Gateway 5xx rate surged to **42.8%**, triggering critical alert `HighHTTP5xxErrorRate`. | `ALERT` | `[EVID-ALT-0001]` |
| **02:52:00** | Emergency operator rollback executed: restored `database.pool.max_connections` back to `50`. | `CONFIG` / `INTERVENTION` | `[EVID-CFG-0002]` |
| **02:53:00** | Connection pool utilization normalized to **22%**, p99 latency dropped to **35ms**, and error rate returned to baseline. | `METRIC` / `RECOVERY` | `[EVID-RECOVERY-0001]` |

**Analytical Conclusion**: The configuration change is proven as the root cause because the evidence strictly satisfies temporal precedence, topological dependency, trace critical path, and recovery timing.

---

## 4. Pluggable Ingestion Adapters & Provenance

Infrastructure Autopsy supports pluggable adapters for structured and unstructured operational telemetry:

- **Application & Infrastructure Logs**: Parses JSON logs, syslog, logcat, and plain text. Automatically extracts `request_id`, `trace_id`, `span_id`, service, and log level.
- **Prometheus Metrics**: Ingests timeseries samples, counters, gauges, and histograms with label sets.
- **OpenTelemetry Traces**: Reconstructs parent-child span hierarchy trees, durations, status codes, and span attributes.
- **Configuration & IaC**: Ingests `.env`, `.yaml`, `.json`, Kubernetes ConfigMaps, and feature flags.
- **CI/CD & Git Deployments**: Ingests commit hashes, changelogs, authors, and deployment statuses.
- **Kubernetes Events & Alerts**: Ingests `OOMKilled`, `CrashLoopBackOff`, `PodEviction`, and Prometheus Alertmanager alerts.

### Cryptographic Provenance Model
Every ingested record preserves:
- `event_time`: Original observation time in UTC.
- `ingested_at`: UTC ingest timestamp.
- `source`: Source file, collector, or endpoint URI.
- `source_type`: `LOG`, `METRIC`, `TRACE`, `CONFIG`, `DEPLOYMENT`, `ALERT`, `K8S`.
- `environment`: `production`, `staging`, `dev`.
- `service` and `host`.
- `raw_data`: Complete raw payload.
- `normalized_data`: Standardized key-value model.
- `provenance`: Dict containing the original timezone offset, collector identity, and SHA-256 fingerprint (`hashlib.sha256(raw_payload)`).

---

## 5. Database Schema & Domain Models (22 Relational Entities)

Implemented with **SQLAlchemy 2.0** declarative models. Fully compatible with PostgreSQL and SQLite:

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│     Service     │◄──────┤ServiceDependency│──────►│     Service     │
└────────┬────────┘       └─────────────────┘       └────────┬────────┘
         │                                                   │
         ▼                                                   ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│   Deployment    │       │  ConfigChange   │       │     Metric      │
└─────────────────┘       └─────────────────┘       └────────┬────────┘
                                                             │
┌─────────────────┐       ┌─────────────────┐                ▼
│    Incident     │◄──────┤      Event      │       ┌─────────────────┐
└────────┬────────┘       └────────┬────────┘       │  MetricSample   │
         │                         │                └─────────────────┘
         ├─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│    Evidence     │◄──────┤HypothesisEvidence├──────►│   Hypothesis    │
└─────────────────┘       └─────────────────┘       └─────────────────┘
         │                                                   │
         ▼                                                   ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│     Anomaly     │       │  Investigation  │       │     Report      │
└─────────────────┘       └────────┬────────┘       └─────────────────┘
                                   │
                                   ▼
                          ┌─────────────────┐
                          │InvestigationStep│
                          └─────────────────┘
```

1. **`Service`**: Service identity, tier (tier-1/tier-2/tier-3), repo URL, on-call team, active status.
2. **`ServiceDependency`**: Directed caller-to-callee dependencies, protocol (RPC/DB/CACHE/QUEUE), criticality flag, baseline latency.
3. **`Incident`**: Incident case file, severity (SEV1-SEV4), status (ACTIVE/MITIGATED/RESOLVED), lifecycle timestamps, simulation flag.
4. **`Event`**: Base observation with raw payload, normalized data, and SHA-256 provenance.
5. **`EventRelationship`**: Directed causal and temporal links between events with relationship type and reason.
6. **`LogEntry`**: Parsed log entries linked to request and distributed trace IDs.
7. **`Metric`**: Timeseries definition, unit, and label metadata.
8. **`MetricSample`**: Timestamped numerical observations.
9. **`Trace`**: Root-span distributed request metadata, duration, error flag, status code.
10. **`Span`**: Span execution node, parent span ID, start time, duration, attributes, events.
11. **`Deployment`**: CI/CD deployment event with version, commit SHA, deployed by, changelog.
12. **`ConfigChange`**: Configuration key update, previous value, new value, operator, reason.
13. **`Alert`**: Alertmanager or monitoring trigger, threshold, query, and trigger conditions.
14. **`Anomaly`**: Statistical anomaly record with actual value, expected baseline, deviation, severity, and anomaly score.
15. **`Evidence`**: Indelible forensic evidence item with human-readable ID (`EVID-XXX`), confidence, entity, and provenance.
16. **`Hypothesis`**: Competing root-cause hypothesis, support score, status, expected and actual signals.
17. **`HypothesisEvidence`**: M:N association table linking evidence to hypotheses with relationship type (`SUPPORTS`, `CONTRADICTS`, `NEUTRAL`) and weights.
18. **`Intervention`**: Corrective action executed by operators (rollback, scale-up, restart).
19. **`RecoveryEvent`**: Verified recovery telemetry indicating return to historical baseline.
20. **`Investigation`**: AI forensic investigation session record and current status.
21. **`InvestigationStep`**: Step-by-step tool-execution log with forensic question, tool called, parameters, raw result, and findings narrative.
22. **`Report`**: Formal evidence-backed postmortem report in Markdown and structured JSON.

---

## 6. Forensic Analytical Engines

### Robust Baselines & Anomaly Detection (MAD / Non-Parametric)
Standard deviation and mean are sensitive to extreme outage spikes. Infrastructure Autopsy computes non-parametric robust statistics:
- **Median ($M$)**: Unaffected by skewed distributions.
- **Median Absolute Deviation (MAD)**:
  $$\text{MAD} = \text{median}(|x_i - M|)$$
- **Robust Scale Parameter**:
  $$\hat{\sigma} = 1.4826 \times \text{MAD}$$
- **Robust Anomaly Score**:
  $$\text{Score} = \frac{|x_{\text{observed}} - M|}{\hat{\sigma} + \epsilon}$$
- **Severity Classification**:
  - `Score >= 6.0`: **CRITICAL**
  - `4.5 <= Score < 6.0`: **HIGH**
  - `3.0 <= Score < 4.5`: **MEDIUM**
  - `2.0 <= Score < 3.0`: **LOW**
  - `Score < 2.0`: **NORMAL**

### Deterministic Correlation Engine
Avoids false causality by requiring structural, temporal, and topological proof:
1. **Shared Distributed Tracing Context**: Exact match on `trace_id` or `request_id` across microservices (`score: 0.95 - 0.98`).
2. **Causal Precedence**: Changes (`CONFIG`, `DEPLOYMENT`) preceding symptoms on the same service or its callers within causal time windows (`score: 0.88 - 0.92`).
3. **Topological Dependency Propagation**: Failures propagating upstream from callee to caller along dependency graph edges (`score: 0.84`).
4. **Recovery Timing**: Stabilization following an intervention event within stabilization windows (`score: 0.94`).
5. **Host Proximity**: Sequential errors occurring on identical compute nodes (`score: 0.70`).

### Distributed Tracing & Critical Path Analysis
- Reconstructs parent-child trees from OpenTelemetry spans.
- **Self-Time Latency Contribution**:
  $$\text{SelfTime}(S) = \text{Duration}(S) - \sum_{C \in \text{Children}(S)} \text{Duration}(C)$$
- **Critical Path Calculation**: Traverses the heaviest child subtree to identify the true bottlenecks.
- **Root Failure Leaf Isolation**: Pinpoints the deepest failing span without failing children (e.g. `payment-db:SELECT FOR UPDATE`) to distinguish the origin error from caller timeout cascades.

### Competing Hypotheses & "Prove Me Wrong" Engine
Rather than merely matching positive symptoms, the engine formulates multiple rival hypotheses and searches for counterevidence:
1. **Define Expected Observations**: What telemetry MUST be visible if the hypothesis is true.
2. **Search Positive Telemetry**: Ingest supporting logs, metrics, traces.
3. **Actively Search for Counterevidence**:
   - *Example*: If Database Pool Exhaustion is claimed, check if pool utilization ever exceeded 80%. If utilization remained low, counterevidence heavily penalizes the hypothesis.
   - *Example*: If External Network Outage is claimed, check if packet loss was 0%.
   - *Example*: If Application Release Bug is claimed, check if any deployments occurred in the preceding 3 hours.
4. **Calibrated Support Score Formula**:
   $$S(H) = \max\left(0.05, \min\left(0.98, \frac{\sum w_{\text{sup}} \cdot C_{\text{sup}} - 1.5 \sum w_{\text{contra}} \cdot C_{\text{contra}}}{\sum w_{\text{expected}}}\right)\right)$$

### Topology & Blast Radius Engine
- Constructs directed graph $G = (V, E)$ using NetworkX.
- Traces propagation from patient-zero callee upstream to callers.
- Categorizes all nodes:
  - `DIRECTLY_AFFECTED`: Root cause origin.
  - `INDIRECTLY_AFFECTED`: Upstream callers experiencing cascading degradation.
  - `CUSTOMER_FACING`: Ingress tier-1 services exposed to end users.
  - `HEALTHY`: Services unaffected by the incident.
- Determines the exact propagation path vector (e.g. `payment-db → payment-service → checkout-service → api-gateway`).

---

## 7. AI Forensic Investigator (Local Ollama Tool Loop)

The AI Forensic Investigator uses local Ollama (`qwen2.5:7b` / `llama3:latest`) in a tool-calling loop. If Ollama is offline or busy, the system executes the tool loop deterministically.

```
AI Forensic Investigator
         │
         ▼
 Formulate Investigation Step
         │
         ▼
 Execute Read-Only Forensic Tool
 (get_logs, inspect_trace, compare_baseline, inspect_config_change)
         │
         ▼
 Inspect Indelible Evidence Returned
         │
         ▼
 Synthesize Chain-of-Custody Narrative
 (Mandatory citations: [EVID-CFG-0001], [EVID-ANOM-0002])
```

### Available Read-Only Forensic Tools:
- `get_logs(incident_id, service, query, level, limit)`
- `query_metrics(service, metric_name, incident_id)`
- `inspect_trace(trace_id)`
- `inspect_deployment(service)`
- `inspect_config_change(service)`
- `compare_baseline(metric_name, service)`
- `find_related_events(incident_id, event_id)`
- `get_dependencies(service)`
- `test_hypothesis(hypothesis_id)`
- `get_recovery_events(incident_id)`

**Rule**: Every assertion made by the investigator must cite an evidence ID (`[EVID-XXX]`). If evidence is insufficient, it outputs: *"Insufficient evidence to determine root cause."*

---

## 8. Codebase & Telemetry Folder Ingestion

Infrastructure Autopsy allows uploading or pointing to arbitrary codebases, microservice folders, or telemetry directories:

### How to Ingest:
1. **Interactive UI Folder Upload**: Click **`📁 Ingest Codebase / Folder`** in the top navigation bar. Choose any folder from your machine via browser folder picker (`webkitdirectory`) or drag-and-drop a `.zip` archive.
2. **Local Directory Scanner**: Provide any local directory path on disk (e.g. `D:/projects/microservices` or `./my-app`).

### What is Extracted:
- **Microservice Services**: Discovered from folder structures, Dockerfiles, `package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `Cargo.toml`.
- **Inter-Service Dependencies**: Extracted from `docker-compose.yml`, service links, and environment variables (`_URL`, `_HOST`, `_ADDR`).
- **Configuration Keys**: Parsed from `.yaml`, `.json`, `.env`, `.properties`, `.conf` (e.g. connection pool sizes, timeouts, worker limits).
- **Logs & Telemetry**: Automatically ingests `.log`, `.jsonl`, `.ndjson` files into the incident timeline.

---

## 9. Forensic Workspace UI & Replay Controller

The frontend is a dark-mode workstation featuring:

1. **Incident Cockpit**: Case file switcher, severity badge (SEV1-SEV4), status badge (RESOLVED/ACTIVE), mode tag (`SIMULATION`/`LIVE`), MTTR duration, and leading hypothesis support score meter.
2. **Chronological Timeline**: Filterable event stream by event type (`CONFIG`, `METRIC`, `LOG`, `TRACE`, `ALERT`), service, and severity with timestamps and SHA-256 provenance hashes.
3. **Topology & Blast Radius Visualizer**: Interactive SVG node-link graph showing real-time service health, failure origin (pulsing red), indirect cascades (amber), healthy nodes (slate), and animated propagation paths.
4. **Metric Anomalies & Baselines**: Telemetry deviation cards comparing observed values against historical baseline medians with MAD anomaly scores.
5. **Distributed Trace Waterfall**: Interactive span tree displaying latency contribution %, error badges, self-time, and critical path highlights.
6. **Hypotheses & Counterevidence Matrix**: Competing hypothesis cards with investigation support score meters, supporting evidence chips, counterevidence callouts, and missing evidence checklists.
7. **Evidence Locker**: Indelible chain-of-custody register with copyable citation badges (`[EVID-XXX]`), timestamps, entities, confidence scores, and raw JSON inspectors.
8. **AI Investigator Terminal**: Live audit trail of questions, tool executions, parameters, and forensic synthesis.
9. **Postmortem Report Generator**: Formal evidence-backed incident report with one-click Markdown export.
10. **Replay Controller**: Time-travel scrubber dock (Play, Pause, Step Forward, Step Backward, Jump) allowing engineers to step through the incident timeline.

---

## 10. Safety & Security Guardrails

- **Read-Only by Default**: The forensic engine cannot execute destructive cluster mutations, database drops, or network modifications.
- **SSRF Protection**: URL validators reject cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- **Command Injection Guard**: Arbitrary shell execution is disabled.
- **Sanitized Outputs**: HTML and script tags are stripped from telemetry attributes to protect against stored XSS.

---

## 11. Complete REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health status and local Ollama connectivity |
| `GET` | `/api/incidents` | List all reconstructed incident case files |
| `GET` | `/api/incidents/{id}` | Get detailed incident record |
| `POST` | `/api/incidents` | Create a new incident case file |
| `POST` | `/api/incidents/bootstrap-canonical` | Seed the canonical 02:47 benchmark incident |
| `POST` | `/api/codebase/upload-folder` | Upload folder tree or `.zip` archive for automated ingestion |
| `POST` | `/api/codebase/scan-local-path` | Scan an existing directory path on disk |
| `POST` | `/api/ingest/log` | Ingest application/infra log entry |
| `POST` | `/api/ingest/metric` | Ingest Prometheus timeseries metric samples |
| `POST` | `/api/ingest/trace` | Ingest OpenTelemetry trace span batch |
| `POST` | `/api/ingest/deployment` | Ingest deployment and Git commit record |
| `POST` | `/api/ingest/config` | Ingest configuration change event |
| `POST` | `/api/ingest/alert` | Ingest monitoring alert event |
| `GET` | `/api/telemetry/logs` | Query logs with service, level, and text filters |
| `GET` | `/api/telemetry/metrics` | Query timeseries metric samples |
| `GET` | `/api/telemetry/traces` | List distributed traces |
| `GET` | `/api/telemetry/traces/{trace_id}` | Detailed trace analysis, self-time, and critical path |
| `GET` | `/api/telemetry/events` | Chronological event stream |
| `GET` | `/api/telemetry/correlations` | Event relationships and causal links |
| `GET` | `/api/topology/services` | Microservices and dependency topology |
| `GET` | `/api/topology/blast-radius/{incident_id}`| NetworkX DAG blast radius and propagation path |
| `GET` | `/api/forensics/anomalies/{incident_id}` | Detected metric baseline anomalies |
| `GET` | `/api/forensics/evidence/{incident_id}` | Indelible evidence locker records |
| `GET` | `/api/forensics/hypotheses/{incident_id}` | Competing hypotheses and support scores |
| `POST`| `/api/forensics/hypotheses/recalculate/{id}`| Re-evaluate Prove Me Wrong counterevidence |
| `GET` | `/api/investigation/{incident_id}` | AI investigation session and step audit trail |
| `POST`| `/api/investigation/run/{incident_id}` | Trigger AI forensic investigation tool loop |
| `POST`| `/api/investigation/tool-call` | Execute individual read-only forensic tool |
| `GET` | `/api/replay/{incident_id}/slice` | Get state slice at specific cursor timestamp |
| `GET` | `/api/replay/{incident_id}/timestamps` | List all discrete event timestamps for stepping |
| `GET` | `/api/reports/{incident_id}` | Get formal evidence-backed postmortem report |
| `POST`| `/api/reports/generate/{incident_id}` | Generate fresh postmortem report |
| `GET` | `/api/reports/export/{report_id}` | Download postmortem report as Markdown |

---

## 12. Quickstart & Verification

### 1. Prerequisites
- Python 3.10+
- Node.js (optional, for tooling)
- Local Ollama running on `http://localhost:11434` (optional: platform falls back to deterministic analysis if Ollama is paused)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Automated Tests
```bash
pytest -v
```
All 9 unit and integration tests run in under 8 seconds:
```
backend/tests/test_ai_investigator.py::test_ai_investigator_tool_loop PASSED
backend/tests/test_baselines.py::test_baseline_stats_calculation PASSED
backend/tests/test_baselines.py::test_anomaly_scoring_normal PASSED
backend/tests/test_baselines.py::test_anomaly_scoring_critical_deviation PASSED
backend/tests/test_blast_radius.py::test_blast_radius_calculation PASSED
backend/tests/test_codebase_scanner.py::test_codebase_folder_scan PASSED
backend/tests/test_codebase_scanner.py::test_codebase_scanner_with_many_error_logs PASSED
backend/tests/test_correlation_and_hypotheses.py::test_canonical_incident_forensics PASSED
backend/tests/test_tracing.py::test_distributed_trace_critical_path_and_failure PASSED
```

### 4. Start the Forensic Server
```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser to:
```
http://localhost:8000
```

---

## License & Operational Notice
Infrastructure Autopsy is built for incident commanders, site reliability engineers, and distributed systems architects.

*"Every analytical conclusion must have provenance. AI must never be treated as the source of truth."*
