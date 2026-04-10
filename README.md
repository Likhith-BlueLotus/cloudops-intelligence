---
title: CloudOps Intelligence Environment
emoji: ☁️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
license: bsd-3-clause
short_description: FinOps + Security + DDoS cloud ops for LLM agents
tags:
  - reinforcement-learning
  - openenv
  - aiops
  - finops
  - cloud-security
  - sre
  - devops
  - incident-response
  - terraform
  - aws
---

# CloudOps Intelligence Environment

> **Multi-domain cloud operations environment for LLM agents** — combining
> FinOps cost optimisation, cloud security remediation, and live incident
> response into three progressively harder real-world scenarios.

[![OpenEnv Spec Compliant](https://img.shields.io/badge/OpenEnv-≥0.2.2-blue)](https://github.com/openenv/openenv)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-green.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-103%20passing-brightgreen)](#testing)

---

## Why This Environment?

Every Cloud/SRE team deals with three recurring challenge types **every day**:

| Challenge | Real impact | This environment |
|-----------|-------------|------------------|
| **FinOps waste** | $28B/year in idle cloud resources (Flexera 2024) | Zombie EC2 fleet burning $12k/month |
| **Cloud security** | 82% of breaches involve cloud misconfiguration (IBM X-Force) | S3 public exposure + IAM typo |
| **Live incidents** | Average DDoS costs $50k/hour in mitigation + lost revenue | DDoS + auto-scaling runaway at $51k/hr |

Existing benchmarks (SWE-bench, WebArena, OSWorld) test coding or web navigation.
**No existing benchmark tests a cloud operations agent** that must reason across
billing data, IAM policies, VPC flow logs, and Terraform simultaneously.

---

## Tasks

### Easy — FinOps: Zombie EC2 Cost Anomaly

**Scenario**: Monthly AWS bill spiked 340% ($12,400 vs $2,800 baseline).
Three `m5.2xlarge` instances from a cancelled project ("ProjectPhoenix") have
been running with 0% CPU for 32 days, burning $885/month.

**Investigation path**:
```
view_billing(ec2, month)           → See $9,600 EC2 spike
list_resources(ec2) / run_cli(     → Find 3 zombie instances
  aws ec2 describe-instances)         tagged Project=ProjectPhoenix, Status=cancelled
apply_fix(ec2_fleet, terminate,    → Terminate all three
  config_key=zombie)
verify(ec2_fleet)                  → Confirm fleet healthy
```

**Root cause**: `zombie_ec2_cost_overrun` | **Services**: 2 | **Budget**: 15 steps

---

### Medium — Security + SRE: S3 Exposure + IAM Typo

**Scenario**: A bad deployment (v4.2.0) triggered two simultaneous issues:
1. S3 bucket `prod-customer-data` ACL set to `public-read-write` — customer PII
   exposed to the public internet; GDPR breach window open 3 hours.
2. Payment service IAM role policy has a typo (`s3:GetObejct` instead of
   `s3:GetObject`) — AWS silently ignores the invalid action, causing all
   payment cert loads to fail with 403; **89% checkout error rate**.

**Investigation path**:
```
view_logs(payment_service)         → See S3 403 errors
run_cli(aws s3api get-bucket-acl   → Find public-read-write ACL
  --bucket prod-customer-data)
run_cli(aws iam get-role-policy    → Find typo: s3:GetObejct
  --role-name payment-service-role)
apply_fix(s3, block_public_access) → Block all public access
apply_fix(iam_role, update_policy, → Fix typo to s3:GetObject
  config_key=s3:GetObject)
verify(payment_service)            → Confirm checkout restored
```

**Root causes**: `s3_public_access_enabled`, `iam_role_typo` | **Services**: 5 | **Budget**: 25 steps

---

### Hard — DDoS + FinOps + SRE: Live Attack + Runaway Cost + Cascade

**Scenario**: A coordinated volumetric DDoS from three CIDR ranges floods
the API gateway at 840,000 req/min (700× baseline). Auto-scaling responds by
launching 200 extra EC2 instances — current cost **$51,200/hr** with
`max_capacity=500` (no ceiling). The attack cascades: `order_service` crashes
and `inventory_service` degrades.

**Three root causes**:
1. **No WAF Web ACL** — must write and deploy Terraform:
   ```hcl
   resource "aws_wafv2_ip_set" "block_ips" {
     ip_address_version = "IPV4"
     addresses = ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"]
   }
   resource "aws_wafv2_web_acl" "main" {
     rule { action { block {} } }
   }
   ```
2. **Auto-scaling `max_capacity=500`** with no DDoS protection — must cap and scale in.
3. **No API Gateway rate limiting** — must enable throttling.

**Investigation path**:
```
view_logs(api_gateway)             → See 840k req/min flood
run_cli(aws vpc get-flow-logs)     → Find attack CIDRs:
                                       203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24
run_cli(aws wafv2 list-web-acls)   → Confirm no WAF exists
view_billing(ec2, realtime)        → See $51,200/hr from auto-scaling
write_terraform(aws_wafv2_web_acl, → Deploy WAF blocking rule
  config=<ip block for 3 CIDRs>)
apply_fix(auto_scaling,            → Cap max_capacity + terminate excess
  adjust_config, max_capacity=20)
apply_fix(api_gateway,             → Enable rate limiting
  enable_rate_limiting, throttle)
verify(api_gateway)                → Confirm attack mitigated
```

**Root causes**: `waf_not_configured`, `autoscaling_unbounded`, `api_gateway_no_rate_limit`
**Services**: 6 | **Budget**: 40 steps

---

## Action Space

All actions are text-based JSON objects — no spatial grids, no physics.

| Action | Description | Example |
|--------|-------------|---------|
| `view_logs` | Service log output | `{"action_type": "view_logs", "target": "payment_service"}` |
| `view_metrics` | Time-series data | `{"action_type": "view_metrics", "target": "api_gateway", "parameters": {"metric": "request_rate"}}` |
| `list_resources` | AWS resource inventory | `{"action_type": "list_resources", "parameters": {"type": "ec2"}}` |
| `run_cli` | AWS CLI simulation | `{"action_type": "run_cli", "parameters": {"command": "aws s3api get-bucket-acl --bucket prod-customer-data"}}` |
| `view_billing` | Cost and usage reports | `{"action_type": "view_billing", "target": "ec2", "parameters": {"period": "month"}}` |
| `apply_fix` | Apply remediation | `{"action_type": "apply_fix", "target": "auto_scaling", "parameters": {"fix_type": "adjust_config", "config_key": "max_capacity", "config_value": "20"}}` |
| `write_terraform` | Generate + validate Terraform | `{"action_type": "write_terraform", "parameters": {"resource_type": "aws_wafv2_web_acl", "config": "..."}}` |
| `verify` | Health / security check | `{"action_type": "verify", "target": "api_gateway"}` |
| `escalate` | Hand off (partial credit) | `{"action_type": "escalate"}` |

---

## Observation Space

```python
class IncidentObservation(Observation):
    situation_report: str        # Current step/task status summary
    services: List[ServiceHealth]# Per-service health snapshot
    action_output: str           # Result of the last action (logs, CLI output, etc.)
    available_actions: List[str] # Valid action types
    services_healthy: int        # Count of healthy services
    services_total: int          # Total services in episode
    root_causes_found: int       # Root causes identified so far
    root_causes_total: int       # Total root causes in scenario
    reward: float                # Step reward ∈ [0.0, 1.0]
    done: bool                   # Episode complete flag
```

---

## Reward Function

```
R_step = +0.30  for each new root cause identified
       + 0.30  for each correct fix applied
       + 0.10  for each service verified healthy
       + 0.20  episode completion bonus (all resolved)
       - 0.05  wrong-target fix penalty
       - 0.02  redundant repeated query penalty

All step rewards are clipped to [0.0, 1.0] in the observation.
Penalties accumulate in cumulative_reward only (for grading).
```

**Grading formula** (consistent across all tasks):
```
score = 0.35 × (root_causes_found / total_root_causes)
      + 0.25 × (services_healthy / total_services)
      + 0.20 × normalised_cumulative_reward
      + 0.20 × completion_bonus
```

---

## Baseline Scores (gpt-4o-mini)

| Task | Domain | Root causes | Avg score | Completion rate |
|------|--------|------------|-----------|----------------|
| easy | FinOps | 1 | 0.78 | 85% |
| medium | Security+SRE | 2 | 0.61 | 52% |
| hard | DDoS+FinOps+SRE | 3 | 0.38 | 18% |

The hard task's Terraform WAF deployment remains challenging — even `gpt-4o-mini`
only completes it 18% of the time, leaving significant headroom for improved agents.

---

## Quick Start

### Local (Python)

```bash
git clone https://github.com/le0atis/aiops-incident-response
cd aiops-incident-response
pip install -r requirements.txt

# Start the environment server
uvicorn server.app:app --host 0.0.0.0 --port 7860

# In another terminal, run the baseline LLM agent
export OPENAI_API_KEY=sk-...
python inference.py --task easy    # FinOps task
python inference.py --task medium  # Security+SRE task
python inference.py --task hard    # DDoS+FinOps+SRE task
```

### Docker

```bash
docker build -t cloudops-env .
docker run -p 7860:7860 \
  -e OPENAI_API_KEY=sk-... \
  cloudops-env
```

### HF Spaces (live)

```
https://le0atis-aiops-incident-response.hf.space
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Environment health + uptime |
| `/metadata` | GET | Environment metadata |
| `/schema` | GET | Action/observation JSON schemas |
| `/tasks` | GET | All task definitions |
| `/reset/{task}` | POST | Start new episode |
| `/step` | POST | Take an action |
| `/state` | GET | Current episode state |
| `/grade/{task}` | POST | Programmatic grader |

---

## Project Structure

```
aiops_incident_env/
├── models.py                  # Pydantic types (Action, Observation, State)
├── client.py                  # Async HTTP client wrapper
├── inference.py               # GPT-4o-mini baseline agent
├── openenv.yaml               # OpenEnv manifest
├── requirements.txt
├── Dockerfile
├── server/
│   ├── app.py                 # FastAPI routes + grader
│   └── environment.py         # Scenario engine + action handlers
└── tests/
    ├── conftest.py
    ├── test_models.py          # Pydantic model tests
    ├── test_environment.py     # Environment logic tests (77 tests)
    ├── test_api.py             # FastAPI endpoint tests
    └── test_client.py          # Client smoke tests
```

---

## OpenEnv Compliance Checklist

- [x] `models.py`: `Action`, `Observation`, `State` inherit from OpenEnv base classes
- [x] `client.py`: `reset()`, `step()`, `state` async interface
- [x] `server/environment.py`: `reset()`, `step()`, `state` property
- [x] `openenv.yaml`: spec_version, name, version, description, tasks
- [x] Rewards normalised to `[0.0, 1.0]` in observations
- [x] Programmatic grader at `/grade/{task}`
- [x] `≥ 3 tasks` with easy → medium → hard progression
- [x] Docker + HF Spaces deployment
- [x] 103 automated tests

---

## Citation

```bibtex
@misc{cloudops-intelligence-2026,
  title        = {CloudOps Intelligence: A Multi-Domain Cloud Operations
                  Environment for LLM Agents},
  author       = {le0atis},
  year         = {2026},
  howpublished = {Hugging Face Spaces},
  url          = {https://huggingface.co/spaces/le0atis/aiops-incident-response},
  note         = {OpenEnv-compatible. Combines FinOps, Security, and SRE
                  incident response in a single text-based environment.}
}
```
