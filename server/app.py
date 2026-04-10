"""
AIOps Incident Response Environment — FastAPI server.

Exposes the OpenEnv-standard HTTP + WebSocket surface:
  POST /reset         start a new episode
  POST /step          advance one step
  GET  /state         read current IncidentState (for graders and loggers)
  GET  /health        rich readiness probe
  GET  /tasks         enumerate all graded tasks
  POST /grade/{task}  run headless programmatic grader
  WS   /ws            real-time WebSocket for low-latency agents
  GET  /metadata      environment metadata
  GET  /schema        action / observation / state JSON schemas
  GET  /docs          Swagger UI
"""

import os
import time
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from openenv.core.env_server import ConcurrencyConfig, create_fastapi_app

from .environment import IncidentResponseEnvironment, SCENARIOS

try:
    from ..models import IncidentAction, IncidentObservation, IncidentState
except ImportError:
    from models import IncidentAction, IncidentObservation, IncidentState  # type: ignore[no-redef]

_SERVER_START_TIME: float = 0.0

_concurrency = ConcurrencyConfig(
    max_concurrent_envs=4,
    session_timeout=300.0,
)

app: FastAPI = create_fastapi_app(
    env=IncidentResponseEnvironment,
    action_cls=IncidentAction,
    observation_cls=IncidentObservation,
    concurrency_config=_concurrency,
)

app.title       = "CloudOps Intelligence Environment"
app.version     = "0.2.0"
app.description = (
    "Multi-step cloud operations environment combining AIOps, FinOps, and Security. "
    "Easy: FinOps cost anomaly (zombie EC2 fleet, $12k billing spike). "
    "Medium: Security + SRE (S3 public exposure + IAM typo causing payment failures). "
    "Hard: DDoS + FinOps + SRE (live attack, WAF Terraform deployment, runaway "
    "auto-scaling at $51k/hr, cascading service failures). "
    "Compatible with OpenEnv ≥ 0.2.2."
)


@asynccontextmanager
async def _lifespan(application: FastAPI):
    global _SERVER_START_TIME
    _SERVER_START_TIME = time.time()
    print("=" * 60)
    print("AIOps Incident Response Environment — server ready")
    print(f"  Endpoints: /reset /step /state /ws /health /tasks /grade")
    print(f"  Max concurrent sessions: {_concurrency.max_concurrent_envs}")
    print(f"  Session timeout: {_concurrency.session_timeout}s")
    print(f"  PID: {os.getpid()}")
    print("=" * 60)
    yield
    print(f"Server shutting down (uptime {time.time() - _SERVER_START_TIME:.1f}s)")


app.router.lifespan_context = _lifespan

# Remove framework stubs so our richer implementations take precedence
app.routes[:] = [
    r for r in app.routes
    if getattr(r, "path", None) not in ("/health", "/metadata", "/schema")
]


@app.get("/health", summary="Readiness probe", tags=["Operations"])
async def health() -> JSONResponse:
    """Returns HTTP 200 with structured readiness detail."""
    return JSONResponse(content={
        "status":         "healthy",
        "uptime_seconds": round(time.time() - _SERVER_START_TIME, 2),
        "environment": {
            "name":                    "aiops-incident-response",
            "version":                 app.version,
            "tasks":                   ["easy", "medium", "hard"],
            "max_concurrent_sessions": _concurrency.max_concurrent_envs,
        },
        "websocket_endpoint": "/ws",
        "pid":                os.getpid(),
    }, status_code=200)


@app.get("/metadata", summary="Environment metadata", tags=["Operations"])
async def get_metadata() -> JSONResponse:
    return JSONResponse(content={
        "name": "AIOps Incident Response Environment",
        "description": (
            "A multi-step on-call engineering environment where an AI agent acts as a "
            "senior on-call engineer responding to production incidents. The agent reads "
            "service logs and metrics, identifies root causes, applies targeted fixes, "
            "and verifies recovery — exactly the workflow performed by SRE and DevOps "
            "teams at every technology company. Three difficulty tiers model real incident "
            "classes: connection pool exhaustion (easy), cache stampede + missing DB index "
            "(medium), and a multi-service cascade with memory leak, message queue disk "
            "saturation, and database deadlock (hard)."
        ),
        "version":           app.version,
        "tasks":             ["easy", "medium", "hard"],
        "reward_range":      [0.0, 1.0],
        "tags":              ["aiops", "incident-response", "sre", "devops", "openenv"],
    }, status_code=200)


@app.get("/schema", summary="Action / observation / state schemas", tags=["Operations"])
async def get_schema() -> JSONResponse:
    try:
        from models import IncidentAction, IncidentObservation, IncidentState
    except ImportError:
        pass
    return JSONResponse(content={
        "action":      IncidentAction.model_json_schema(),
        "observation": IncidentObservation.model_json_schema(),
        "state":       IncidentState.model_json_schema(),
    }, status_code=200)


# ---------------------------------------------------------------------------
# Task metadata
# ---------------------------------------------------------------------------
_TASK_METADATA: Dict[str, dict] = {
    "easy": {
        "id":          "easy",
        "title":       SCENARIOS["easy"]["title"],
        "domain":      SCENARIOS["easy"]["domain"],
        "description": (
            "FinOps: Monthly AWS billing spiked 340% ($12,400 vs $2,800 baseline). "
            "Three EC2 m5.2xlarge instances from a cancelled project have been running "
            "with 0% CPU for 32 days, burning $885/month. "
            "The agent must query billing reports, list idle EC2 instances, "
            "identify the zombie fleet, and terminate all three instances. "
            "2 services (billing_dashboard, ec2_fleet), 1 root cause, 15 step budget."
        ),
        "difficulty":  "easy",
        "max_steps":   15,
        "root_causes": 1,
        "services":    2,
        "score_range": [0.0, 1.0],
        "grader":      "programmatic",
    },
    "medium": {
        "id":          "medium",
        "title":       SCENARIOS["medium"]["title"],
        "domain":      SCENARIOS["medium"]["domain"],
        "description": (
            "Security + SRE: A bad deployment triggered two simultaneous issues. "
            "(1) S3 bucket 'prod-customer-data' has public-read-write ACL — "
            "customer PII exposed for 3 hours (GDPR breach window open). "
            "(2) Payment service IAM role has a typo ('s3:GetObejct') causing "
            "all payment certificate loads to fail with 403 — 89% checkout error rate. "
            "Agent must inspect bucket ACL, audit IAM policy, apply both fixes, "
            "and verify the payment service recovers. "
            "5 services, 2 root causes, 25 step budget."
        ),
        "difficulty":  "medium",
        "max_steps":   25,
        "root_causes": 2,
        "services":    5,
        "score_range": [0.0, 1.0],
        "grader":      "programmatic",
    },
    "hard": {
        "id":          "hard",
        "title":       SCENARIOS["hard"]["title"],
        "domain":      SCENARIOS["hard"]["domain"],
        "description": (
            "DDoS + FinOps + SRE: A coordinated DDoS from three CIDR ranges "
            "(203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) floods the API gateway "
            "at 840k req/min. Auto-scaling responds by launching 200 extra EC2 instances "
            "(cost: $51,200/hr and rising). The attack cascades to order and inventory "
            "services. Three root causes: (1) no WAF Web ACL configured — agent must "
            "write and deploy Terraform to block malicious CIDRs; "
            "(2) auto-scaling max_capacity=500 with no DDoS protection — agent must "
            "cap it and terminate excess instances; "
            "(3) no API Gateway rate limiting configured. "
            "6 services, 3 root causes, 40 step budget."
        ),
        "difficulty":  "hard",
        "max_steps":   40,
        "root_causes": 3,
        "services":    6,
        "score_range": [0.0, 1.0],
        "grader":      "programmatic",
    },
}


@app.get("/tasks", summary="List all graded tasks", tags=["Tasks"])
async def list_tasks() -> JSONResponse:
    return JSONResponse(content={"tasks": list(_TASK_METADATA.values())}, status_code=200)


# ---------------------------------------------------------------------------
# Programmatic grader
# ---------------------------------------------------------------------------
class GradeRequest(BaseModel):
    seed:              int   = 42
    cumulative_reward: float = 0.0
    steps_taken:       int   = 0
    episode_done:      bool  = False
    root_causes_found: int   = -1  # -1 → conservative fallback
    services_healthy:  int   = -1  # -1 → conservative fallback
    services_total:    int   = -1
    escalated:         bool  = False


@app.post(
    "/grade/{task}",
    summary="Run programmatic grader for a task",
    tags=["Tasks"],
)
async def grade_task(task: str, body: GradeRequest = GradeRequest()) -> JSONResponse:
    """
    Scores a completed agent episode.

    Scoring formula:
      score = 0.35 × root_cause_ratio     (root causes found / total)
            + 0.25 × service_health_ratio  (services healthy / total)
            + 0.20 × normalised_reward     (cumulative_reward / steps_taken)
            + 0.20 × completion_bonus      (1.0 if all fixed, 0.5 if partial, 0 otherwise)
    """
    if task not in _TASK_METADATA:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown task {task!r}. Valid: {list(_TASK_METADATA)}",
        )

    cfg          = _TASK_METADATA[task]
    rc_total     = cfg["root_causes"]
    svc_total    = cfg["services"]
    max_steps    = cfg["max_steps"]

    # ── Retrieve episode stats ───────────────────────────────────────────
    rc_found  = body.root_causes_found  if body.root_causes_found  >= 0 else 0
    svc_hlthy = body.services_healthy   if body.services_healthy   >= 0 else 0
    svc_tot   = body.services_total     if body.services_total     >= 0 else svc_total

    # ── Score components ─────────────────────────────────────────────────
    rc_ratio   = float(min(1.0, rc_found / max(1, rc_total)))
    svc_ratio  = float(min(1.0, svc_hlthy / max(1, svc_tot)))
    reward_norm = float(min(1.0, max(0.0,
        body.cumulative_reward / max(1, body.steps_taken)
    ))) if body.steps_taken > 0 else 0.0

    if body.episode_done and rc_found >= rc_total and svc_hlthy >= svc_tot:
        completion_bonus = 1.0
    elif rc_ratio > 0.5 or svc_ratio > 0.5:
        completion_bonus = 0.5
    else:
        completion_bonus = 0.0

    if body.escalated and completion_bonus < 0.5:
        completion_bonus = max(completion_bonus, rc_ratio * 0.5)

    score = float(min(0.999, max(0.001,
        0.35 * rc_ratio
        + 0.25 * svc_ratio
        + 0.20 * reward_norm
        + 0.20 * completion_bonus
    )))

    return JSONResponse(content={
        "task":              task,
        "seed":              body.seed,
        "steps_taken":       body.steps_taken,
        "root_causes_found": rc_found,
        "root_causes_total": rc_total,
        "services_healthy":  svc_hlthy,
        "services_total":    svc_tot,
        "rc_ratio":          round(rc_ratio, 4),
        "svc_ratio":         round(svc_ratio, 4),
        "reward_norm":       round(reward_norm, 4),
        "completion_bonus":  round(completion_bonus, 4),
        "score":             round(score, 4),
        "score_range":       [0.0, 1.0],
        "grader":            "programmatic",
        "deterministic":     True,
    }, status_code=200)


def main() -> None:
    import uvicorn
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "7860")),
        workers=int(os.environ.get("WORKERS", "1")),
        log_level="info",
    )


if __name__ == "__main__":
    main()
