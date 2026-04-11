---
title: CloudOps Intelligence Environment
emoji: ☁️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
license: bsd-3-clause
short_description: CloudOps + SOC Analyst env for LLM agents
tags:
  - reinforcement-learning
  - openenv
  - cloudops
  - finops
  - cloud-security
  - sre
  - devops
  - secops
  - soc-analyst
  - incident-response
  - terraform
  - threat-intel
  - aws
---

# CloudOps Intelligence Environment

> **Dual-track cloud operations environment for LLM agents** — CloudOps track:
> FinOps cost optimisation, cloud security remediation, and live DDoS response.
> SOC Analyst track: alert triage, malware containment, and APT multi-stage response.
> Six tasks, real threat intelligence (Feodo Tracker, Spamhaus DROP, MITRE ATT&CK).

[![OpenEnv Spec Compliant](https://img.shields.io/badge/OpenEnv-≥0.2.2-blue)](https://github.com/openenv/openenv)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-green.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-40%20passing-brightgreen)](#testing)

---

## Why This Environment?

Real-world cloud operations teams deal with two distinct problem classes **every day**:

| Domain | Challenge | Real impact | This environment |
|--------|-----------|-------------|------------------|
| **CloudOps / FinOps** | Idle cloud resources | $28B/year waste (Flexera 2024) | Zombie EC2 fleet burning $12k/month |
| **CloudOps / Security** | Cloud misconfiguration | 82% of breaches (IBM X-Force) | S3 public exposure + IAM typo |
| **CloudOps / DDoS** | Live attack + runaway cost | $50k/hr average DDoS impact | DDoS + auto-scaling at $51k/hr |
| **SOC / Alert triage** | Account compromise | 80% of attacks use stolen credentials | Brute-force SSH → active session |
| **SOC / Malware** | C2 beacon + credential dump | QakBot pre-cursor to ransomware | Feodo C2 + LSASS dump (8 accounts) |
| **SOC / APT** | Multi-stage threat | Avg. 207 days to detect (IBM) | C2 + lateral movement + 2.3 GB exfil |

Existing benchmarks (SWE-bench, WebArena, OSWorld) test coding or web navigation.
**No existing benchmark tests a cloud operations + SOC agent** that must reason across
billing data, IAM policies, VPC flow logs, SIEM alerts, and threat intelligence simultaneously.

---

## Tasks

### CloudOps Track

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

### SOC Analyst Track

### SOC Easy — Brute-Force SSH → Account Compromise

**Scenario**: SIEM alert SOC-2847 — 247 failed SSH logins from Tor exit node
`185.220.101.45` (Spamhaus DROP listed), 1 **successful** login as `svc_deploy`.
The attacker is running `sudo` commands and attempting to download an implant.

**Investigation path**:
```
lookup_threat_intel(185.220.101.45)   → Confirm: Tor exit node, abuse score 97/100
view_logs(bastion_host)               → Find active session + attacker commands
apply_fix(bastion_host,               → Revoke attacker session immediately
  revoke_session, session_token)
verify(bastion_host)                  → Confirm clean
```

**Root cause**: `compromised_bastion_access` | **Services**: 2 | **Budget**: 15 steps

---

### SOC Medium — QakBot C2 + LSASS Credential Dump

**Scenario**: SIEM alert SOC-3991 — three correlated rules:
1. QakBot C2 beacon from `ENG-WORKSTATION-47` to `162.243.103.246:8080` (Feodo Tracker, ONLINE)
2. LSASS memory access — 8 account NTLM hashes dumped (MITRE T1003.001)
3. SMB lateral movement probe across `10.0.2.0/24`

**Investigation path**:
```
lookup_threat_intel(162.243.103.246)  → Confirm: QakBot C2, Feodo Tracker
view_logs(endpoint_security)          → Find infected host + C2 connection
apply_fix(endpoint_security,          → Isolate ENG-WORKSTATION-47
  isolate_host, ENG-WORKSTATION-47)
apply_fix(auth_service,               → Rotate all 8 compromised credentials
  revoke_credentials, compromised_accounts)
verify(endpoint_security)             → Confirm C2 severed
```

**Root causes**: `malware_c2_beacon`, `credential_dump` | **Services**: 4 | **Budget**: 25 steps

---

### SOC Hard — APT: C2 + Lateral Movement + S3 Data Exfiltration

**Scenario**: SIEM alert SOC-4128 — five correlated GuardDuty/IDS findings:
1. Active QakBot C2 from `PROD-SRV-12` → `50.16.16.211:443` (ONLINE, Feodo Tracker, 6h+ beacon)
2. WMI/SMB lateral movement from `PROD-SRV-12` → `PROD-SRV-07`, `PROD-SRV-09`, `DB-PRIMARY` (MITRE T1021)
3. `DataScienceRole` credential theft + 1,847 S3 GetObject calls = 2.3 GB exfiltrated (MITRE T1530)
4. API calls originating from C2 IP (MITRE T1078 — Valid Accounts)
5. GuardDuty finding: `UnauthorizedAccess:IAMUser/TorIPCaller`

**Investigation path**:
```
view_logs(endpoint_security)          → EDR: PROD-SRV-12 → 50.16.16.211:443 beacon,
                                        WMI lateral movement to PROD-SRV-07/09/DB-PRIMARY
apply_fix(endpoint_security,          → Isolate PROD-SRV-12 (primary C2 host)
  isolate_host, PROD-SRV-12)
write_terraform(aws_network_acl,      → Block C2 IP 50.16.16.211 at network ACL
  cidr=50.16.16.211/32, rule=DENY)
view_logs(auth_service)               → DataScienceRole session from C2 IP
apply_fix(s3_data_lake,               → Revoke stolen DataScienceRole IAM session
  revoke_session, DataScienceRole)
verify(s3_data_lake)                  → Confirm C2 severed + exfiltration stopped
```

**Root causes**: `active_c2_beacon`, `lateral_movement`, `s3_data_exfiltration`
**Services**: 5 | **Budget**: 40 steps

---

## Action Space

All actions are text-based JSON objects — no spatial grids, no physics.

| Action | Description | Example |
|--------|-------------|---------|
| `view_logs` | Service log output | `{"action_type": "view_logs", "target": "bastion_host"}` |
| `view_metrics` | Time-series data | `{"action_type": "view_metrics", "target": "api_gateway", "parameters": {"metric": "request_rate"}}` |
| `list_resources` | AWS resource inventory | `{"action_type": "list_resources", "parameters": {"type": "ec2"}}` |
| `run_cli` | AWS CLI / system command | `{"action_type": "run_cli", "parameters": {"command": "aws guardduty list-findings"}}` |
| `view_billing` | Cost and usage reports | `{"action_type": "view_billing", "target": "ec2", "parameters": {"period": "month"}}` |
| `lookup_threat_intel` | Query Feodo/Spamhaus/AbuseIPDB feeds | `{"action_type": "lookup_threat_intel", "parameters": {"ioc": "50.16.16.211", "ioc_type": "ip"}}` |
| `apply_fix` | Apply remediation | `{"action_type": "apply_fix", "target": "endpoint_security", "parameters": {"fix_type": "isolate_host", "config_key": "ENG-WORKSTATION-47"}}` |
| `write_terraform` | Generate + validate Terraform | `{"action_type": "write_terraform", "parameters": {"resource_type": "aws_network_acl", "config": "cidr=50.16.16.211/32 rule=DENY"}}` |
| `verify` | Health / security check | `{"action_type": "verify", "target": "network_ids"}` |
| `escalate` | Hand off (partial credit) | `{"action_type": "escalate"}` |

**CloudOps `fix_type` options**: `terminate`, `block_public_access`, `fix_iam`, `adjust_config`, `enable_rate_limiting`

**SOC `fix_type` options**: `revoke_session`, `block_ip`, `isolate_host`, `quarantine`, `revoke_credentials`, `revoke_access`

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
R_step = +0.08  investigation discovery (view_logs / run_cli / view_billing / lookup_threat_intel
                that reveals a new root cause clue for the first time)
       + 0.30  for each new root cause correctly identified via apply_fix / write_terraform
       + 0.30  for each correct fix applied
       + 0.10  for each service verified healthy after fix
       + 0.20  episode completion bonus (all root causes resolved + all services healthy)
       - 0.05  wrong-target fix penalty
       - 0.02  redundant repeated query penalty

All step rewards are clipped to [0.0, 1.0] in the observation.
Penalties accumulate in cumulative_reward only (for grading).
```

**Investigation-first design**: Root cause evidence only appears in the observation
*after* the agent investigates the relevant service. The `+0.08` clue-discovery reward
incentivises proper diagnostic investigation before applying fixes.

**Grading formula** (consistent across all tasks):
```
score = 0.35 × (root_causes_found / total_root_causes)
      + 0.25 × (services_healthy / total_services)
      + 0.20 × normalised_cumulative_reward
      + 0.20 × completion_bonus
```

---

## Baseline Scores (gpt-4o-mini)

| Task | Domain | Root causes | Score | Steps used | Step budget | Success |
|------|--------|------------|-------|-----------|-------------|---------|
| easy | FinOps | 1 | **0.8293** | 6 | 15 | ✅ |
| medium | Security+SRE | 2 | **0.8740** | 4 | 25 | ✅ |
| hard | DDoS+FinOps+SRE | 3 | **0.8462** | 10 | 40 | ✅ |
| soc_easy | SecOps (brute-force) | 1 | **0.8587** | 3 | 15 | ✅ |
| soc_medium | SecOps (C2+cred dump) | 2 | **0.8423** | 7 | 25 | ✅ |
| soc_hard | SecOps (APT) | 3 | **0.8693** | 6 | 40 | ✅ |

**Primary mean (easy/medium/hard): 0.8498** | **Overall mean (all 6 tasks): 0.8533**
*(gpt-4o-mini, single episode per task, investigation-first flow)*

**All 6 tasks complete successfully** — scores are meaningfully differentiated by task difficulty,
step efficiency, and the number of root causes an agent must discover and remediate.

**Investigation-first design**: Root cause evidence only appears in the observation *after* the agent
has investigated the relevant service. The `+0.08` clue-discovery reward incentivises genuine
diagnostic reasoning — an agent that skips investigation and blindly applies fixes will fail to
identify root causes and score near 0.

The scoring formula creates real headroom for stronger agents (GPT-4o, Claude 3.5, Llama-3-70B):
a model that minimises wasted investigation steps can approach 0.95+ on easy/medium tasks.

---

## Quick Start

### Local (Python)

```bash
git clone https://github.com/Likhith-BlueLotus/cloudops-intelligence
cd cloudops-intelligence
pip install -r requirements.txt

# (Optional) Pre-fetch real-world datasets into data/
python data_fetcher.py

# Start the environment server
uvicorn server.app:app --host 0.0.0.0 --port 7860

# In another terminal, set credentials and run the baseline agent
# (runs all 3 tasks — easy, medium, hard — sequentially)
export HF_TOKEN=sk-...            # your OpenAI API key (or HF token)
export API_BASE_URL=https://api.openai.com/v1
export MODEL_NAME=gpt-4o-mini
python inference.py
```

### Docker

```bash
docker build -t cloudops-env .
docker run -p 7860:7860 \
  -e API_BASE_URL=https://api.openai.com/v1 \
  -e MODEL_NAME=gpt-4o-mini \
  -e HF_TOKEN=sk-... \
  cloudops-env
```

### HF Spaces (live)

```
https://le0atis-cloudops-intelligence.hf.space
```

---

## API Reference

### Session lifecycle

The environment is **stateful and session-based**. Each episode has a `session_id`
UUID that must be threaded through `/step` and `/state` calls.

```
POST /reset  {"task": "easy|medium|hard", "seed": 42}
             → {"session_id": "<uuid>", "observation": {...}}

POST /step   {"action": {...}, "session_id": "<uuid>"}
             → {"observation": {...}}

GET  /state?session_id=<uuid>
             → current IncidentState JSON
```

Sessions expire after **5 minutes of inactivity**. Call `/reset` to start a new one.

### Endpoint summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Environment health + uptime |
| `/metadata` | GET | Environment metadata (name, version, tasks) |
| `/schema` | GET | Action/observation JSON schemas |
| `/tasks` | GET | All task definitions with metadata |
| `/reset` | POST | Start new episode → returns `session_id` |
| `/step` | POST | Take an action (requires `session_id`) |
| `/state` | GET | Current episode state (requires `?session_id=`) |
| `/grade/{task}` | POST | Programmatic grader (episode stats → score) |

---

## Project Structure

```
cloudops-intelligence/
├── models.py                  # Pydantic types (Action, Observation, State)
├── client.py                  # Async HTTP client wrapper
├── inference.py               # GPT-4o-mini baseline agent (runs all 3 tasks)
├── data_fetcher.py            # Downloads real-world datasets into data/
├── openenv.yaml               # OpenEnv manifest
├── requirements.txt
├── Dockerfile                 # Fetches real data at build time
├── .env.example               # Safe credential template
├── data/                      # Auto-generated: Spamhaus, CIC-IDS2018, etc.
├── server/
│   ├── app.py                 # FastAPI routes + grader
│   └── environment.py         # Scenario engine + action handlers
└── tests/
    ├── conftest.py
    ├── test_models.py          # Pydantic model tests
    ├── test_environment.py     # Environment logic tests
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
  url          = {https://huggingface.co/spaces/Le0AtiS/cloudops-intelligence},
  note         = {OpenEnv-compatible. Combines FinOps, Security, and SRE
                  incident response in a single text-based environment.}
}
```
