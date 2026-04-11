"""
CloudOps Intelligence Environment — Inference Script
=======================================================

Runs one full episode per task (easy / medium / hard / soc_easy / soc_medium / soc_hard) against a live
CloudOps Intelligence server and reports per-task programmatic scores.

Required environment variables (hackathon spec):
  API_BASE_URL   OpenAI-compatible LLM endpoint (default: https://api.openai.com/v1)
  MODEL_NAME     Model identifier string        (default: gpt-4o-mini)
  HF_TOKEN       Bearer token / API key         (mandatory — no default)

Optional:
  OPENENV_ENDPOINT  Server base URL (default: http://localhost:7860)

Usage:
  python inference.py

Stdout format (strictly follows the hackathon-required [START]/[STEP]/[END] spec):
  [START] task=<name> env=cloudops-intelligence model=<model>
  [STEP]  step=<n> action=<json> reward=<float> done=<true|false> error=<msg|null>
  [END]   success=<true|false> steps=<n> score=<float> rewards=<r1,r2,...>

JSON_SCORES emitted at the end:
  JSON_SCORES: {"easy": <float>, "medium": <float>, "hard": <float>,
               "soc_easy": <float>, "soc_medium": <float>, "soc_hard": <float>}
"""

import json
import logging
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from openai import OpenAI

# ---------------------------------------------------------------------------
# Credentials — reads from environment variables per hackathon spec
# ---------------------------------------------------------------------------
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
API_KEY      = os.getenv("HF_TOKEN") or os.getenv("OPENAI_API_KEY") or os.getenv("API_KEY")
MODEL_NAME   = os.getenv("MODEL_NAME", "gpt-4o-mini")
OPENENV_URL  = os.getenv("OPENENV_ENDPOINT", "http://localhost:7860")

# ---------------------------------------------------------------------------
# Logging — INFO to stderr so [START]/[STEP]/[END] on stdout remain clean
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM client — uses OpenAI client as required by the hackathon spec
# ---------------------------------------------------------------------------
_CLIENT: Optional[OpenAI] = None

def _get_client() -> OpenAI:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = OpenAI(
            api_key=API_KEY or "dummy",
            base_url=API_BASE_URL,
        )
    return _CLIENT

# ---------------------------------------------------------------------------
# Task configuration
# ---------------------------------------------------------------------------
MAX_STEPS_PER_TASK = {
    "easy":       15,
    "medium":     25,
    "hard":       40,
    "soc_easy":   15,
    "soc_medium": 25,
    "soc_hard":   40,
}
TEMPERATURE        = 0.1  # low temperature for deterministic investigation

# ---------------------------------------------------------------------------
# System prompt — defines the agent's role and output format
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a senior Cloud Operations Engineer and SOC Analyst at a large technology company.
You respond to cloud operations incidents (FinOps, SRE, DDoS) and security operations alerts
(brute-force, malware C2, credential theft, data exfiltration).

CRITICAL WORKFLOW — you MUST follow this investigation-first approach:
1. INVESTIGATE FIRST: Use view_logs, view_billing, run_cli, or lookup_threat_intel to gather evidence.
   Root causes will only appear in the status report AFTER you have investigated relevant services.
2. IDENTIFY ROOT CAUSES: Evidence of root causes appears in "EVIDENCE FOUND" section after investigation.
   Read the evidence carefully to understand what went wrong and what fix is appropriate.
3. APPLY FIXES: Based on the evidence, apply the correct remediation using apply_fix or write_terraform.
4. VERIFY: Confirm services are healthy with verify().

Available action types:
- view_logs: Read logs for a service — reveals root cause evidence
  {"action_type": "view_logs", "target": "<service_name>"}

- view_metrics: Read a specific metric time-series
  {"action_type": "view_metrics", "target": "<service_name>", "parameters": {"metric": "<metric_name>"}}

- list_resources: List cloud resources of a given type
  {"action_type": "list_resources", "parameters": {"type": "ec2|s3|iam|waf"}}

- run_cli: Execute an AWS CLI command (simulated) — reveals root cause evidence
  {"action_type": "run_cli", "parameters": {"command": "aws ec2 describe-instances ..."}}

- view_billing: View cost and usage reports — reveals cost anomaly evidence
  {"action_type": "view_billing", "target": "ec2|overall", "parameters": {"period": "month|realtime"}}

- lookup_threat_intel: Query threat intelligence feeds for an IOC — reveals threat evidence
  {"action_type": "lookup_threat_intel", "parameters": {"ioc": "<ip_address>", "ioc_type": "ip"}}
  Use this when you see a suspicious IP in a SOC alert.

- apply_fix: Apply a targeted remediation based on evidence you have gathered
  {"action_type": "apply_fix", "target": "<resource_name>", "parameters": {"fix_type": "<type>", "config_key": "<key>", "config_value": "<value>"}}
  CloudOps fix_types: terminate, block_public_access, fix_iam, adjust_config, enable_rate_limiting
  SOC fix_types: revoke_session, block_ip, isolate_host, quarantine, revoke_credentials, revoke_access

- write_terraform: Write and deploy Terraform configuration (WAF rules, network ACLs)
  {"action_type": "write_terraform", "parameters": {"resource_type": "aws_wafv2_web_acl|aws_network_acl", "config": "<config>"}}

- verify: Confirm a service/resource is healthy or secured after a fix
  {"action_type": "verify", "target": "<service_name>"}

- escalate: Escalate to senior engineer (use only if truly stuck)
  {"action_type": "escalate"}

Investigation strategy by domain:
FINOPS:   view_billing(billing_dashboard) → see evidence → apply_fix(terminate zombie instances) → verify
SECURITY: view_logs(payment_service) + run_cli(aws s3api get-bucket-acl) → see evidence → apply_fix → verify
SRE:      view_logs(service) → view_metrics → apply_fix → verify
DDOS:     view_logs(api_gateway) + run_cli(aws vpc get-flow-logs) → see evidence → write_terraform(wafv2) → apply_fix → verify
SOC:      view_logs(siem/endpoint) + lookup_threat_intel(suspicious_ip) → see evidence → apply_fix(isolate/revoke) → verify

IMPORTANT: The status report shows "EVIDENCE FOUND" ONLY after you investigate relevant services.
Start by investigating the degraded/down services listed in the status report.

JSON FORMAT RULES — strictly enforce these to avoid validation errors:
- ALL parameter values MUST be strings (never integers, booleans, or nested objects).
  CORRECT: {"parameters": {"port": "22", "abuse_score": "97"}}
  WRONG:   {"parameters": {"port": 22, "abuse_score": 97}}
- Use only the action_types listed above — never invent custom action names.
- Respond with ONLY a single valid JSON object. No prose, no explanation."""

# ---------------------------------------------------------------------------
# HTTP helpers (direct HTTP to avoid asyncio complexity)
# ---------------------------------------------------------------------------

def _ping_health(max_retries: int = 5, delay: float = 3.0) -> bool:
    """Ping /health until the server responds or retries exhausted."""
    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(
                f"{OPENENV_URL}/health",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode())
                if body.get("status") == "healthy":
                    log.info("Server health: healthy (attempt %d)", attempt)
                    return True
        except Exception as exc:
            log.warning("Health check attempt %d failed: %s", attempt, exc)
        if attempt < max_retries:
            time.sleep(delay)
    return False


def _post_json(path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{OPENENV_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def _get_json(path: str) -> dict:
    req = urllib.request.Request(
        f"{OPENENV_URL}{path}",
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# Environment interaction
# ---------------------------------------------------------------------------

def _reset_episode(task: str) -> dict:
    return _post_json("/reset", {"task": task, "seed": 42})


def _step(session_id: str, action: dict) -> dict:
    return _post_json("/step", {"action": action, "session_id": session_id})


def _get_state(session_id: str) -> dict:
    try:
        return _get_json(f"/state?session_id={session_id}")
    except Exception:
        return {}


def _grade(task: str, **kwargs) -> dict:
    return _post_json(f"/grade/{task}", kwargs)


# ---------------------------------------------------------------------------
# LLM action decision
# ---------------------------------------------------------------------------

def _build_user_message(obs: dict) -> str:
    """Format the observation into a clear text prompt for the LLM."""
    situation  = obs.get("situation_report", "")
    action_out = obs.get("action_output", "")
    services   = obs.get("services", [])
    rc_found   = obs.get("root_causes_found", 0)
    rc_total   = obs.get("root_causes_total", 0)

    # Build service health table
    svc_lines = []
    for svc in services:
        name     = svc.get("name", "?")
        status   = svc.get("status", "unknown").upper()
        err_rate = svc.get("error_rate_pct", 0.0)
        rt       = svc.get("response_time_ms", 0.0)
        svc_lines.append(
            f"  {name:30s} | {status:10s} | error={err_rate:.1f}% | latency={rt:.0f}ms"
        )
    svc_table = "\n".join(svc_lines) if svc_lines else "  (none)"

    parts = [situation]
    if svc_lines:
        parts.append("SERVICE HEALTH TABLE:\n" + svc_table)
    if action_out:
        parts.append("LAST ACTION OUTPUT:\n" + action_out)
    parts.append(
        f"\nProgress: {rc_found}/{rc_total} root causes identified and fixed."
    )
    parts.append(
        "Decide your next investigation or remediation action. "
        "Respond with ONLY a JSON action object."
    )

    return "\n\n".join(parts)


def _call_llm(messages: List[dict]) -> Optional[str]:
    """Call the LLM and return the raw text content."""
    try:
        resp = _get_client().chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            temperature=TEMPERATURE,
            max_tokens=256,
        )
        return resp.choices[0].message.content
    except Exception as exc:
        log.error("LLM call failed: %s", exc)
        return None


_VALID_ACTION_TYPES = {
    "view_logs", "view_metrics", "list_resources", "run_cli",
    "view_billing", "lookup_threat_intel", "apply_fix",
    "write_terraform", "verify", "escalate",
}

# LLMs frequently emit a fix_type directly as the action_type, e.g.
# {"action_type": "revoke_session", "target": "bastion_host"}
# instead of the correct:
# {"action_type": "apply_fix", "target": "bastion_host",
#  "parameters": {"fix_type": "revoke_session"}}
# Translating these avoids a wasted no-op step.
_FIX_TYPE_AS_ACTION: set = {
    # SOC fix types
    "revoke_session", "revoke_credentials", "revoke_access",
    "isolate_host", "quarantine", "block_ip",
    # CloudOps fix types
    "terminate", "block_public_access", "fix_iam",
    "adjust_config", "enable_rate_limiting", "update_policy",
}


def _sanitize_action(action: dict) -> dict:
    """Ensure action has a valid action_type and all parameter values are strings.

    LLMs sometimes:
    - Use a fix_type directly as action_type — translated to apply_fix so the
      step still executes rather than wasting a turn on a no-op view_logs.
    - Use an invalid action_type variant — falls back to view_logs.
    - Include integer/boolean values in parameters (port numbers, abuse scores)
      which would cause a Pydantic 422 on Dict[str, str] validation.
    """
    action_type = action.get("action_type", "")

    # Translate fix_type-as-action_type → apply_fix
    if action_type in _FIX_TYPE_AS_ACTION:
        log.warning(
            "fix_type %r used as action_type — translating to apply_fix",
            action_type,
        )
        params = action.get("parameters") or {}
        if isinstance(params, dict):
            params = {str(k): str(v) for k, v in params.items()}
        else:
            params = {}
        params.setdefault("fix_type", action_type)
        return {
            "action_type": "apply_fix",
            "target": action.get("target", ""),
            "parameters": params,
        }

    if action_type not in _VALID_ACTION_TYPES:
        log.warning(
            "Invalid action_type %r — falling back to view_logs",
            action_type,
        )
        return {"action_type": "view_logs", "target": action.get("target", "")}

    # Coerce all parameter values to strings to prevent 422 errors
    params = action.get("parameters")
    if isinstance(params, dict):
        action["parameters"] = {str(k): str(v) for k, v in params.items()}
    elif params is not None:
        action["parameters"] = {}

    return action


def _parse_action(raw: Optional[str]) -> dict:
    """Parse LLM output into a valid, sanitized action dict. Falls back to view_logs."""
    if not raw:
        return {"action_type": "view_logs", "target": ""}
    raw = raw.strip()
    # Strip markdown code fences if present
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw
    try:
        action = json.loads(raw)
        if "action_type" in action:
            return _sanitize_action(action)
    except json.JSONDecodeError:
        pass
    # Try to extract JSON from embedded text
    start = raw.find("{")
    end   = raw.rfind("}")
    if start != -1 and end != -1:
        try:
            action = json.loads(raw[start:end + 1])
            if "action_type" in action:
                return _sanitize_action(action)
        except json.JSONDecodeError:
            pass
    return {"action_type": "view_logs", "target": ""}


# ---------------------------------------------------------------------------
# Score computation (local — mirrors server grader for validation)
# ---------------------------------------------------------------------------

def _local_score(
    task: str,
    cumulative_reward: float,
    steps_taken: int,
    rc_found: int,
    rc_total: int,
    svc_healthy: int,
    svc_total: int,
    episode_done: bool,
    escalated: bool,
) -> float:
    rc_ratio   = rc_found / max(1, rc_total)
    svc_ratio  = svc_healthy / max(1, svc_total)
    reward_norm = cumulative_reward / max(1, steps_taken) if steps_taken > 0 else 0.0

    if episode_done and rc_found >= rc_total and svc_healthy >= svc_total:
        completion_bonus = 1.0
    elif rc_ratio > 0.5 or svc_ratio > 0.5:
        completion_bonus = 0.5
    else:
        completion_bonus = 0.0

    if escalated and completion_bonus < 0.5:
        completion_bonus = max(completion_bonus, rc_ratio * 0.5)

    score = (
        0.35 * rc_ratio
        + 0.25 * svc_ratio
        + 0.20 * min(1.0, max(0.0, reward_norm))
        + 0.20 * completion_bonus
    )
    return round(min(1.0, max(0.0, score)), 4)


# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------

def run_episode(task: str) -> dict:
    """
    Run one full episode for the given task.
    Returns a dict with score, steps, and per-step rewards.
    """
    t_task_start = time.time()
    max_steps = MAX_STEPS_PER_TASK[task]
    messages: List[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    rewards: List[float] = []
    cumulative_reward: float = 0.0
    done: bool = False
    steps: int = 0
    error_msg: Optional[str] = None

    print(f"[START] task={task} env=cloudops-intelligence model={MODEL_NAME}", flush=True)
    log.info("=" * 60)
    log.info("TASK: %s  (max_steps=%d)", task.upper(), max_steps)
    log.info("=" * 60)

    # ── Reset ────────────────────────────────────────────────────────────
    try:
        reset_resp = _reset_episode(task)
    except Exception as exc:
        log.error("Reset failed: %s", exc)
        print(f"[END] success=false steps=0 score=0.0 rewards=none", flush=True)
        return {"task": task, "score": 0.0, "steps": 0, "success": False}

    session_id = reset_resp.get("session_id", "")
    obs        = reset_resp.get("observation", reset_resp)

    log.info(
        "Reset OK — task=%s root_causes=%d services=%d",
        task,
        obs.get("root_causes_total", 0),
        obs.get("services_total", 0),
    )

    # Add initial observation to conversation
    messages.append({
        "role": "user",
        "content": _build_user_message(obs),
    })

    # ── Main loop ────────────────────────────────────────────────────────
    _consecutive_errors = 0
    while not done and steps < max_steps:
        # LLM decision
        raw_action = _call_llm(messages)
        action     = _parse_action(raw_action)

        # Step the environment — handle HTTP 422 (invalid action) gracefully
        # by retrying with a safe investigation action rather than aborting.
        try:
            step_resp = _step(session_id, action)
            _consecutive_errors = 0
            error_msg = None
        except Exception as exc:
            error_str = str(exc)
            # 422 = Pydantic validation error on the server — the LLM produced
            # a structurally invalid action (e.g. integer parameter values).
            # Retry once with a sanitized view_logs fallback rather than killing
            # the whole episode.
            if "422" in error_str or "Unprocessable" in error_str:
                log.warning(
                    "Step %d: 422 Unprocessable Entity — retrying with safe fallback action",
                    steps + 1,
                )
                fallback = {"action_type": "view_logs", "target": ""}
                try:
                    step_resp = _step(session_id, fallback)
                    action = fallback
                    error_msg = f"422_recovered:{error_str[:80]}"
                    _consecutive_errors = 0
                except Exception as exc2:
                    error_msg = str(exc2)
                    log.error("Step %d fallback also failed: %s", steps + 1, exc2)
                    _consecutive_errors += 1
                    if _consecutive_errors >= 3:
                        log.error("3 consecutive errors — aborting episode")
                        break
                    continue
            else:
                error_msg = error_str
                log.error("Step %d failed: %s", steps + 1, exc)
                _consecutive_errors += 1
                if _consecutive_errors >= 3:
                    log.error("3 consecutive errors — aborting episode")
                    break
                continue

        obs    = step_resp.get("observation", step_resp)
        reward = float(obs.get("reward", 0.0))
        done   = bool(obs.get("done", False))
        steps += 1
        rewards.append(reward)
        cumulative_reward += reward

        # Structured stdout log (hackathon spec)
        print(
            f"[STEP] step={steps} "
            f"action={json.dumps(action)} "
            f"reward={reward:.2f} "
            f"done={str(done).lower()} "
            f"error={json.dumps(error_msg)}",
            flush=True,
        )

        rc_found  = obs.get("root_causes_found", 0)
        rc_total  = obs.get("root_causes_total", 0)
        svc_hlthy = obs.get("services_healthy", 0)
        svc_total = obs.get("services_total", 0)

        log.info(
            "Step %3d | rc=%d/%d | svc_healthy=%d/%d | reward=%.4f | done=%s",
            steps, rc_found, rc_total, svc_hlthy, svc_total, reward, done,
        )

        # Add result to conversation history
        messages.append({
            "role": "assistant",
            "content": json.dumps(action),
        })
        messages.append({
            "role": "user",
            "content": _build_user_message(obs),
        })

    # ── Episode end ──────────────────────────────────────────────────────
    state = _get_state(session_id)

    rc_found_final  = obs.get("root_causes_found", 0)
    rc_total_final  = obs.get("root_causes_total", 0)
    svc_hlthy_final = obs.get("services_healthy", 0)
    svc_total_final = obs.get("services_total", 0)
    escalated       = state.get("escalated", False)

    success = bool(
        rc_found_final >= rc_total_final
        and svc_hlthy_final >= svc_total_final
    )

    # Compute score via server grader (ground truth)
    try:
        grade_resp = _grade(
            task,
            seed=42,
            cumulative_reward=cumulative_reward,
            steps_taken=steps,
            episode_done=done,
            root_causes_found=rc_found_final,
            services_healthy=svc_hlthy_final,
            services_total=svc_total_final,
            escalated=escalated,
        )
        score = float(grade_resp.get("score", 0.0))
    except Exception as exc:
        log.warning("Server grader failed (%s) — using local scorer", exc)
        score = _local_score(
            task, cumulative_reward, steps,
            rc_found_final, rc_total_final,
            svc_hlthy_final, svc_total_final,
            done, escalated,
        )

    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"score={score:.4f} rewards={rewards_str}",
        flush=True,
    )
    log.info(
        "TASK %s COMPLETE — steps=%d  score=%.4f  "
        "(rc=%d/%d  svc=%d/%d  done=%s)  elapsed=%.1fs",
        task.upper(), steps, score,
        rc_found_final, rc_total_final,
        svc_hlthy_final, svc_total_final,
        done,
        time.time() - t_task_start,
    )

    return {
        "task":    task,
        "score":   score,
        "steps":   steps,
        "success": success,
        "rewards": rewards,
    }


# ---------------------------------------------------------------------------
# Main — validate env, run all 6 tasks, emit JSON_SCORES
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("Model : %s", MODEL_NAME)
    log.info("Server: %s", OPENENV_URL)
    log.info("Budget: 20 min max")

    # Validate credentials
    if not API_KEY:
        raise SystemExit(
            "HF_TOKEN (or OPENAI_API_KEY) environment variable is not set.\n"
            "Export it before running:\n"
            "  export HF_TOKEN=<your-api-key>\n"
            "  export API_BASE_URL=https://api.openai.com/v1   # or HF router\n"
            "  export MODEL_NAME=gpt-4o-mini"
        )

    # Wait for server to be ready
    if not _ping_health():
        raise SystemExit(f"Server at {OPENENV_URL} is not reachable. Start it first.")

    scores: Dict[str, float] = {}
    t_start = time.time()

    # Primary tasks (required minimum: easy → medium → hard)
    primary_tasks = ("easy", "medium", "hard")
    # Bonus tasks (SOC Analyst track — additional difficulty levels)
    bonus_tasks   = ("soc_easy", "soc_medium", "soc_hard")

    for task in primary_tasks:
        log.info("=" * 60)
        result = run_episode(task)
        scores[task] = result["score"]

    for task in bonus_tasks:
        elapsed_so_far = time.time() - t_start
        if elapsed_so_far > 17 * 60:
            log.warning("Approaching 20-min budget — skipping bonus tasks")
            break
        log.info("=" * 60)
        result = run_episode(task)
        scores[task] = result["score"]

    elapsed = time.time() - t_start

    log.info("=" * 60)
    log.info("FINAL SCORES")
    log.info("=" * 60)
    primary_scores = [scores[t] for t in primary_tasks if t in scores]
    for task in primary_tasks:
        if task in scores:
            log.info("  %s [PRIMARY]  score=%.4f", task.ljust(12), scores[task])
    for task in bonus_tasks:
        if task in scores:
            log.info("  %s [BONUS]    score=%.4f", task.ljust(12), scores[task])
    if primary_scores:
        primary_mean = sum(primary_scores) / len(primary_scores)
        log.info("  PRIMARY MEAN (easy/medium/hard): %.4f", primary_mean)
    overall = sum(scores.values()) / max(1, len(scores))
    log.info("  OVERALL MEAN (all tasks)       : %.4f", overall)
    log.info("  Total elapsed                  : %.1fs", elapsed)
    log.info("=" * 60)
    print(f'JSON_SCORES: {json.dumps(scores)}', flush=True)


if __name__ == "__main__":
    main()
