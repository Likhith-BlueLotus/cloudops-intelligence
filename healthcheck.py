#!/usr/bin/env python3
"""
Docker HEALTHCHECK probe for the AIOps Incident Response Environment.

Performs two sequential checks:
  1. GET /health  — verifies the FastAPI process is alive and reports status=healthy.
  2. POST /reset  — verifies the environment initialises without error,
                    confirming models, session pool, and scenario library are ready.

Exit codes:
  0 — healthy (both checks passed)
  1 — unhealthy (at least one check failed; error written to stderr)
"""
import json
import sys
import urllib.request

BASE = "http://localhost:7860"

try:
    with urllib.request.urlopen(BASE + "/health", timeout=5) as resp:
        data = json.load(resp)
    assert data.get("status") == "healthy", f"/health returned unexpected payload: {data}"

    req = urllib.request.Request(
        BASE + "/reset",
        data=json.dumps({"task": "easy"}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        obs_env = json.load(resp)

    # Accept both flat observation and {observation: {...}} envelope
    obs = obs_env.get("observation", obs_env)
    assert "situation_report" in obs or "observation" in obs_env, (
        f"/reset returned unexpected payload shape: {list(obs_env.keys())}"
    )

    sys.exit(0)

except Exception as exc:
    print(f"HEALTHCHECK FAILED: {exc}", file=sys.stderr)
    sys.exit(1)
