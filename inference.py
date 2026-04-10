"""
AIOps Incident Response Environment — Inference Script
=======================================================

Runs one full episode per task (easy / medium / hard) against a live
AIOps Incident Response server and reports per-task programmatic scores.

Required environment variables (hackathon spec):
  API_BASE_URL   OpenAI-compatible LLM endpoint (default: https://api.openai.com/v1)
  MODEL_NAME     Model identifier string        (default: gpt-4o-mini)
  HF_TOKEN       Bearer token / API key         (mandatory — no default)

Optional:
  OPENENV_ENDPOINT  Server base URL (default: http://localhost:7860)

Usage:
  python inference.py

Stdout format (strictly follows the hackathon-required [START]/[STEP]/[END] spec):
  [START] task=<name> env=aiops-incident-response model=<model>
  [STEP]  step=<n> action=<json> reward=<float> done=<true|false> error=<msg|null>
  [END]   success=<true|false> steps=<n> score=<float> rewards=<r1,r2,...>

JSON_SCORES emitted at the end:
  JSON_SCORES: {"easy": <float>, "medium": <float>, "hard": <float>}
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
API_KEY      = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
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
MAX_STEPS_PER_TASK = {"easy": 15, "medium": 25, "hard": 40}
TEMPERATURE        = 0.1  # low temperature for deterministic investigation

# ---------------------------------------------------------------------------
# System prompt — defines the agent's role and output format
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a senior Cloud Operations Engineer (CloudOps / SRE) at a large technology company.
You are responding to cloud operations incidents that may involve cost anomalies (FinOps),
security vulnerabilities, or live service outages. Your job is to:
1. Investigate the incident using logs, metrics, billing data, and cloud CLI output
2. Identify the root cause(s) — may be a cost issue, security misconfiguration, or service failure
3. Apply targeted fixes (or write Terraform for infrastructure changes like WAF rules)
4. Verify that all services/resources return to healthy status

You must respond with a single JSON action object. Do not output any other text.

Available action types:
- view_logs: Read recent log entries for a service or resource
  {"action_type": "view_logs", "target": "<service_name>"}

- view_metrics: Read a specific metric time-series
  {"action_type": "view_metrics", "target": "<service_name>", "parameters": {"metric": "<metric_name>"}}

- list_resources: List cloud resources of a given type
  {"action_type": "list_resources", "parameters": {"type": "ec2|s3|iam|waf"}}

- run_cli: Execute an AWS CLI command (simulated)
  {"action_type": "run_cli", "parameters": {"command": "aws ec2 describe-instances ..."}}

- view_billing: View cost and usage reports
  {"action_type": "view_billing", "target": "ec2|overall", "parameters": {"period": "month|realtime"}}

- apply_fix: Apply a targeted remediation
  {"action_type": "apply_fix", "target": "<resource_name>", "parameters": {"fix_type": "<type>", "config_key": "<key>", "config_value": "<value>"}}
  fix_type options: terminate, update_policy, block_public_access, fix_iam, adjust_config, enable_rate_limiting, rollback

- write_terraform: Write and deploy Terraform configuration (for WAF, firewall rules, etc.)
  {"action_type": "write_terraform", "parameters": {"resource_type": "aws_wafv2_web_acl", "config": "<terraform_config_describing_what_to_create>"}}

- verify: Confirm a service/resource is healthy or secure after a fix
  {"action_type": "verify", "target": "<service_name>"}

- escalate: Escalate to senior engineer (use as last resort)
  {"action_type": "escalate"}

Investigation strategy by domain:
FINOPS: Check view_billing first → then list_resources to find idle/zombie resources → terminate waste
SECURITY: Check run_cli for bucket ACL / IAM policies → apply policy fix → verify
SRE/SERVICE: view_logs for errors → view_metrics for saturation → apply_fix → verify
DDOS: view_logs(api_gateway) → run_cli(vpc get-flow-logs) → write_terraform(WAF) → verify

Respond with ONLY a valid JSON object like: {"action_type": "view_billing", "target": "ec2", "parameters": {"period": "month"}}"""

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


def _parse_action(raw: Optional[str]) -> dict:
    """Parse LLM output into a valid action dict. Falls back to view_logs."""
    if not raw:
        return {"action_type": "view_logs", "target": "payment_service"}
    raw = raw.strip()
    # Strip markdown code fences if present
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw
    try:
        action = json.loads(raw)
        if "action_type" in action:
            return action
    except json.JSONDecodeError:
        pass
    # Try to extract JSON from embedded text
    start = raw.find("{")
    end   = raw.rfind("}")
    if start != -1 and end != -1:
        try:
            return json.loads(raw[start:end + 1])
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
    return round(min(0.999, max(0.001, score)), 4)


# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------

def run_episode(task: str) -> dict:
    """
    Run one full episode for the given task.
    Returns a dict with score, steps, and per-step rewards.
    """
    max_steps = MAX_STEPS_PER_TASK[task]
    messages: List[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    rewards: List[float] = []
    cumulative_reward: float = 0.0
    done: bool = False
    steps: int = 0
    error_msg: Optional[str] = None

    print(f"[START] task={task} env=aiops-incident-response model={MODEL_NAME}", flush=True)
    log.info("=" * 60)
    log.info("TASK: %s  (max_steps=%d)", task.upper(), max_steps)
    log.info("=" * 60)

    # ── Reset ────────────────────────────────────────────────────────────
    try:
        reset_resp = _reset_episode(task)
    except Exception as exc:
        log.error("Reset failed: %s", exc)
        print(f"[END] success=false steps=0 score=0.0 rewards=", flush=True)
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
    while not done and steps < max_steps:
        # LLM decision
        raw_action = _call_llm(messages)
        action     = _parse_action(raw_action)

        # Step the environment
        try:
            step_resp = _step(session_id, action)
        except Exception as exc:
            error_msg = str(exc)
            log.error("Step %d failed: %s", steps + 1, exc)
            break

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
        f"score={score} rewards={rewards_str}",
        flush=True,
    )
    log.info(
        "TASK %s COMPLETE — steps=%d  score=%.4f  "
        "(rc=%d/%d  svc=%d/%d  done=%s)  elapsed=%.1fs",
        task.upper(), steps, score,
        rc_found_final, rc_total_final,
        svc_hlthy_final, svc_total_final,
        done,
        sum(rewards),  # proxy elapsed
    )

    return {
        "task":    task,
        "score":   score,
        "steps":   steps,
        "success": success,
        "rewards": rewards,
    }


# ---------------------------------------------------------------------------
# Main — validate env, run all 3 tasks, emit JSON_SCORES
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("Model : %s", MODEL_NAME)
    log.info("Server: %s", OPENENV_URL)
    log.info("Budget: 20 min")

    # Validate credentials
    if not API_KEY:
        raise SystemExit(
            "HF_TOKEN (or API_KEY) environment variable is not set.\n"
            "Export it before running:\n"
            "  export HF_TOKEN=<your-api-key>\n"
            "  export API_BASE_URL=https://api.openai.com/v1   # or HF router\n"
            "  export MODEL_NAME=gpt-4o-mini"
        )

    # Wait for server
    if not _ping_health():
        raise SystemExit(f"Server at {OPENENV_URL} is not reachable. Start it first.")

    scores: Dict[str, float] = {}
    t_start = time.time()

    for task in ("easy", "medium", "hard"):
        log.info("=" * 60)
        result = run_episode(task)
        scores[task] = result["score"]
        log.info(
            "TASK %s COMPLETE — steps=%d  score=%.4f",
            task.upper(), result["steps"], result["score"],
        )

    elapsed = time.time() - t_start

    print("\n" + "=" * 60, flush=True)
    print("FINAL SCORES", flush=True)
    print("=" * 60, flush=True)
    for task, score in scores.items():
        print(f"  {task:<10} score={score:.4f}", flush=True)
    overall = sum(scores.values()) / len(scores)
    print(f"\n  OVERALL (mean): {overall:.4f}", flush=True)
    print(f"  Total elapsed : {elapsed:.1f}s", flush=True)
    print("=" * 60, flush=True)
    print(f'\nJSON_SCORES: {json.dumps(scores)}', flush=True)


if __name__ == "__main__":
    main()
