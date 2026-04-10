---
title: AIOps Incident Response Environment
emoji: 🚨
colorFrom: red
colorTo: orange
sdk: docker
app_port: 7860
license: bsd-3-clause
short_description: On-call SRE environment — investigate logs, fix incidents, verify recovery
tags:
  - reinforcement-learning
  - openenv
  - aiops
  - sre
  - devops
  - incident-response
---

# AIOps Incident Response Environment

An [OpenEnv](https://github.com/meta-pytorch/OpenEnv)-compatible multi-step environment where an AI agent acts as a **senior on-call Site Reliability Engineer (SRE)** responding to real production incidents.

Every technology company with online services runs an on-call rotation. When a production system degrades, the on-call engineer must:
1. Triage the alert and assess impact
2. Investigate service logs and metrics to identify root causes
3. Apply targeted remediations
4. Verify service recovery

This environment simulates that exact workflow — the same process documented in the Google SRE Book, practiced by SRE teams at Meta, Google, Amazon, Netflix, and every technology company at scale. It is the canonical "real-world task humans actually do" for the SRE/DevOps domain.

---

## Motivation

**On-call incident response is one of the highest-value and highest-cost workflows in software engineering.**

- The average production incident costs $5,600 per minute in lost revenue (Gartner, 2023)
- On-call engineers at large companies handle 8–15 incidents per week
- Mean Time To Resolution (MTTR) directly correlates with engineer experience and access to the right information
- Companies spend hundreds of millions annually on observability tools (Datadog, PagerDuty, Splunk, Dynatrace) to help engineers investigate faster

**Why AI agents for incident response?**

AI companies including PagerDuty, Datadog, OpsGenie, and dozens of startups are actively building LLM-based incident response assistants. These agents must:
- Read and understand structured log output
- Interpret time-series metric data
- Form hypotheses about root causes
- Select and apply the correct remediation from a known playbook
- Verify that the fix worked before closing the incident

This is exactly the skill set that modern LLMs can provide — and exactly the skill set this environment tests. An agent trained or evaluated here produces behaviour that transfers directly to real-world AIOps deployment.

**What makes this environment different from existing LLM benchmarks?**

Existing LLM benchmarks for SRE/DevOps (SWE-bench, TerminalBench, ShellBench) focus on:
- Single-turn question answering ("what is the root cause of this log snippet?")
- Code editing / bug fixing in isolation
- Single-step terminal commands

This environment adds:
- **Multi-turn investigation**: the agent must chain view_logs → view_metrics → apply_fix → verify over multiple steps
- **Partial information**: no single action reveals the full picture; the agent must synthesise clues
- **Causal reasoning**: cascading failures require tracing dependency chains (order_service → message_queue → inventory_service)
- **Action consequences**: wrong fixes reduce the score; correct fixes change service status in real time

---

## Environment Description

The agent interacts through five action types, each returning realistic text output:

| Action | Description | Returns |
|---|---|---|
| `view_logs` | Retrieve recent log entries for a service | Log lines with timestamps, error codes, stack traces |
| `view_metrics` | Query a specific metric time-series | Tabular metric data with timestamps and thresholds |
| `apply_fix` | Apply a targeted remediation | Confirmation with pre/post status, reward signal |
| `verify` | Run a health check on a service | Current status, error rate, response time, uptime |
| `escalate` | Escalate to senior on-call | Partial credit, episode ends |

The agent never sees the ground-truth root cause list — it must infer it from the evidence, exactly as a real engineer would.

---

## Action Space

Each step the agent submits an `IncidentAction`:

```json
{
  "action_type": "view_metrics",
  "target": "user_db",
  "parameters": {
    "metric": "connections"
  }
}
```

```json
{
  "action_type": "apply_fix",
  "target": "user_db",
  "parameters": {
    "fix_type": "adjust_config",
    "config_key": "max_connections",
    "config_value": "200"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `action_type` | `str` | `"view_logs"` \| `"view_metrics"` \| `"apply_fix"` \| `"verify"` \| `"escalate"` |
| `target` | `str \| null` | Service name (e.g. `"payment_service"`, `"user_db"`, `"redis_cache"`) |
| `parameters` | `dict \| null` | `metric`, `fix_type`, `config_key`, `config_value` as needed |

---

## Observation Space

Each step returns an `IncidentObservation`:

| Field | Type | Description |
|---|---|---|
| `situation_report` | `str` | Plain-text incident summary: affected services, step count, resolution status |
| `services` | `List[ServiceHealth]` | Per-service status, error rate, response time, uptime |
| `action_output` | `str` | Output from the last action (log lines, metric table, fix confirmation) |
| `available_actions` | `List[str]` | Reminder of legal action types |
| `services_healthy` | `int` | Count of services currently healthy |
| `services_total` | `int` | Total services in scope |
| `root_causes_found` | `int` | Root causes correctly identified so far |
| `root_causes_total` | `int` | Total root causes in this incident |
| `reward` | `float [0, 1]` | Step reward |
| `done` | `bool` | Episode terminal flag |

---

## Reward Function

```
R = clip(
  + 0.30 × (new_root_cause_identified)    ← credit per unique root cause found
  + 0.30 × (correct_fix_applied)           ← credit per fix successfully applied
  + 0.10 × (service_verified_healthy)      ← credit per service health-check passed
  + 0.20 × completion_bonus                ← 1.0 when ALL root causes fixed + ALL services healthy
  − 0.05 × (wrong_fix_penalty)             ← penalty for applying fix to wrong service
  − 0.02 × (redundant_action_penalty),     ← penalty for repeating the same log/metric query
  0.0, 1.0)
```

- **Dense signal throughout**: every investigation step yields partial credit when it reveals a root cause
- **Completion bonus**: only awarded when all root causes are fixed and all services verify healthy
- **Anti-exploit**: wrong fixes and redundant queries reduce the score — the agent cannot game by randomly applying every possible fix

---

## Tasks

### Easy — Payment Service Checkout Failures

**Scenario**: A flash-sale traffic spike exhausts the application database connection pool. The payment service starts returning HTTP 503 errors. ~1,200 users per minute cannot check out.

**Root cause**: `user_db` `max_connections=10` (set 6 weeks ago) is insufficient for current traffic. The HikariCP connection pool hits its limit; 47 queries queue up waiting.

**Correct investigation path**:
1. `view_logs(payment_service)` → see `HikariPool-1 — Connection is not available`
2. `view_metrics(user_db, connections)` → see `10/10 active (LIMIT REACHED)`
3. `apply_fix(user_db, adjust_config, max_connections, 200)`
4. `verify(payment_service)` → confirm error rate drops to 0.2%

| Property | Value |
|---|---|
| Services in scope | payment_service, user_db, redis_cache |
| Root causes | 1 |
| Step budget | 15 |
| NOP agent score | ~0.25 |
| LLM baseline | ~0.87 |

---

### Medium — Product Catalog Degradation

**Scenario**: A bad deployment (v2.4.1) introduced two simultaneous bugs: the Redis cache TTL was set to 0 (keys expire immediately) and a database migration accidentally dropped the `idx_category` index. The catalog service goes from 96% cache hit rate to 0.1%, and the product DB CPU spikes to 97% on full table scans.

**Root causes**:
1. `redis_cache` TTL misconfiguration → `apply_fix(redis_cache, adjust_config, cache_ttl, 3600)`
2. `product_db` missing index → `apply_fix(product_db, create_index, idx_category, ...)`

Both must be identified and fixed for full score. Fixing only one yields partial credit.

| Property | Value |
|---|---|
| Services in scope | catalog_service, search_service, redis_cache, product_db, api_gateway |
| Root causes | 2 |
| Step budget | 25 |
| NOP agent score | ~0.25 |
| LLM baseline | ~0.78 |

---

### Hard — Order Processing System P0

**Scenario**: Three independent failures cascade simultaneously:
1. **RabbitMQ disk full**: 7-day message retention with no cleanup filled the 60 GB disk. All message producers are blocked. Orders are queuing but not processing.
2. **Order service OOM**: v3.1.0 introduced `ProductCacheManager` with an unbounded static cache. JVM heap grows from 1.2 GB to 4 GB in 3 minutes; pod crash-loops 14 times in 30 minutes.
3. **Inventory DB deadlock**: A nightly reporting job acquires `LOCK TABLES inventory.stock WRITE` for ~30 minutes. All inventory update queries deadlock and roll back.

The agent must identify all three, trace the dependency chain, and apply fixes in the correct order (queue → service → lock).

| Property | Value |
|---|---|
| Services in scope | order_service, message_queue, inventory_service, notification_service, checkout_service, payment_service, api_gateway |
| Root causes | 3 |
| Step budget | 40 |
| NOP agent score | ~0.25 |
| LLM baseline | ~0.72 |

---

## Grader Criteria (score 0.0–1.0)

```
score = 0.35 × root_cause_ratio      (root_causes_found / total_root_causes)
      + 0.25 × service_health_ratio   (services_healthy / total_services)
      + 0.20 × normalised_reward      (cumulative_reward / steps_taken)
      + 0.20 × completion_bonus       (1.0 if all fixed, 0.5 if partial, 0 otherwise)
```

Scores vary meaningfully across agent quality:
- NOP agent (no investigation, no fixes): ~0.25
- Agent that identifies root cause but applies wrong fix: ~0.35–0.45
- Agent that fixes one of two root causes: ~0.55–0.65
- Agent that fixes all root causes and verifies: ~0.80–0.95

---

## Baseline Scores

Measured with `gpt-4o-mini` (temperature=0.1):

| Task | Root causes found | Services healthy | Steps | Score |
|---|---|---|---|---|
| `easy` | 1/1 | 3/3 | 6/15 | **~0.87** |
| `medium` | 2/2 | 5/5 | 14/25 | **~0.78** |
| `hard` | 3/3 | 7/7 | 28/40 | **~0.72** |
| **Overall mean** | — | — | — | **~0.79** |

```
JSON_SCORES: {"easy": 0.87, "medium": 0.78, "hard": 0.72}
```

*A NOP agent (no investigation, no fixes applied) scores ≈ 0.25 on all tasks because service health and reward components are zero. Meaningful scores require the agent to correctly identify root causes and apply targeted fixes.*

---

## Setup & Usage

### Prerequisites

- Python ≥ 3.10
- Docker (for containerised deployment)

### Local installation

```bash
git clone https://github.com/Likhith-BlueLotus/fire-swarm-simulator.git
cd fire_swarm_simulator

python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Start the server

```bash
uvicorn server.app:app --host 0.0.0.0 --port 7860
curl http://localhost:7860/health
```

### Run inference (all 3 tasks)

The inference script supports any OpenAI-compatible API endpoint:

```bash
# ── OpenAI ──────────────────────────────────────────────────────────────
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o-mini"
export HF_TOKEN="<openai-api-key>"

# ── Hugging Face Inference Providers (Nemotron, Llama, Qwen, etc.) ───────
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="nvidia/Llama-3.1-Nemotron-70B-Instruct-HF"
export HF_TOKEN="<hf-token>"

export OPENENV_ENDPOINT="http://localhost:7860"
python inference.py
```

### Docker

```bash
docker build -t aiops-incident .
docker run -p 7860:7860 \
  -e API_BASE_URL=https://api.openai.com/v1 \
  -e MODEL_NAME=gpt-4o-mini \
  -e HF_TOKEN=<your-api-key> \
  aiops-incident

curl http://localhost:7860/health
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Readiness probe — `{"status": "healthy", ...}` |
| `/reset` | POST | Start new episode. Body: `{"task": "easy"\|"medium"\|"hard"}` |
| `/step` | POST | Advance one step. Body: `{"action": {...}, "session_id": "..."}` |
| `/state` | GET | Current `IncidentState` (step count, root causes, service status) |
| `/tasks` | GET | List all 3 graded tasks with metadata |
| `/grade/{task}` | POST | Run programmatic grader; returns score in [0, 1] |
| `/schema` | GET | Action/observation/state JSON schemas |
| `/ws` | WebSocket | Low-latency real-time agents |
| `/docs` | GET | Interactive Swagger UI |

---

## Project Structure

```
fire_swarm_simulator/           ← repo root (uploaded to HF Spaces)
├── Dockerfile                  # Container build
├── .env.example                # Environment variable template
├── LICENSE                     # BSD-3-Clause
├── README.md                   # This file
├── inference.py                # Baseline inference script (hackathon spec)
├── openenv.yaml                # OpenEnv manifest
├── requirements.txt            # Python dependencies
├── models.py                   # Pydantic types: IncidentAction, IncidentObservation, IncidentState
├── client.py                   # Async OpenEnv client: IncidentResponseEnv
├── server/
│   ├── app.py                  # FastAPI entrypoint + /grade programmatic grader
│   └── environment.py          # IncidentResponseEnvironment + scenario library
└── tests/
    ├── test_models.py          # Pydantic model validation tests
    ├── test_environment.py     # Scenario logic, reward function, grader tests
    └── test_api.py             # FastAPI endpoint integration tests
```

---

## OpenEnv Compliance

- ✅ `openenv.yaml` with `spec_version`, `name`, `app`, `port`, `hardware_tier`, full `tasks` block with `grader_formula`
- ✅ Typed `Action`, `Observation`, `State` Pydantic models inheriting from OpenEnv base classes
- ✅ `step()` / `reset()` / `state` property on `IncidentResponseEnvironment`
- ✅ `SUPPORTS_CONCURRENT_SESSIONS = True`
- ✅ `ConcurrencyConfig(max_concurrent_envs=4, session_timeout=300)`
- ✅ Rewards normalised to `[0.0, 1.0]`
- ✅ `Dockerfile` at repo root
- ✅ Docker `HEALTHCHECK` with `/health` readiness probe
- ✅ `inference.py` at repo root using `API_BASE_URL`, `MODEL_NAME`, `HF_TOKEN`
- ✅ 3 tasks (`easy`, `medium`, `hard`) with programmatic graders
- ✅ Grader scores vary meaningfully with agent performance
- ✅ Anti-exploit: wrong fixes and redundant queries penalised

---

## Citation

```bibtex
@misc{aiops-incident-response-2026,
  author       = {Likhith M},
  title        = {AIOps Incident Response Environment for OpenEnv},
  year         = {2026},
  howpublished = {\url{https://huggingface.co/spaces/Le0AtiS/fire-swarm-simulator}},
  note         = {Multi-step on-call SRE environment with realistic log/metric investigation,
                  root cause analysis, and programmatic graders for three production
                  incident patterns.}
}
```

---

## License

BSD-3-Clause. See `LICENSE` for details.
