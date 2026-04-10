"""
AIOps Incident Response — async OpenEnv client.

Wraps the HTTP / WebSocket surface so external code does not need to
construct raw requests.  Mirrors the openenv-core AsyncEnvClient interface.

Usage:
    async with IncidentResponseEnv(base_url="http://localhost:7860") as env:
        obs = await env.reset(task="easy")
        while not obs.done:
            obs = await env.step(action)
        state = await env.get_state()
"""

import asyncio
import json
from typing import Any, Dict, Optional

try:
    import httpx
except ImportError:  # pragma: no cover
    raise ImportError("pip install httpx to use IncidentResponseEnv client")

from models import IncidentAction, IncidentObservation, IncidentState


class IncidentResponseEnv:
    """
    Async HTTP client for the AIOps Incident Response server.

    All public methods are coroutines and must be awaited.

    Parameters
    ----------
    base_url : str
        Base URL of the running server (default ``http://localhost:7860``).
    timeout : float
        Per-request timeout in seconds (default 60).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:7860",
        timeout: float = 60.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._session_id: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def __aenter__(self) -> "IncidentResponseEnv":
        self._client = httpx.AsyncClient(
            base_url=self._base,
            timeout=self._timeout,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()
        self._client = None

    # ── Core API ──────────────────────────────────────────────────────────

    async def reset(
        self,
        task: str = "easy",
        seed: int = 42,
    ) -> IncidentObservation:
        """Start a new episode. Returns the initial observation."""
        client = self._require_client()
        resp = await client.post(
            "/reset",
            json={"task": task, "seed": seed},
        )
        resp.raise_for_status()
        data = resp.json()
        self._session_id = data.get("session_id")
        obs_data = data.get("observation", data)
        return IncidentObservation.model_validate(obs_data)

    async def step(self, action: IncidentAction) -> IncidentObservation:
        """Advance the environment by one step."""
        client = self._require_client()
        payload: Dict[str, Any] = {
            "action": action.model_dump(exclude_none=True),
        }
        if self._session_id:
            payload["session_id"] = self._session_id
        resp = await client.post("/step", json=payload)
        resp.raise_for_status()
        data = resp.json()
        obs_data = data.get("observation", data)
        return IncidentObservation.model_validate(obs_data)

    async def get_state(self) -> IncidentState:
        """Return the current server-side state (for graders / loggers)."""
        client = self._require_client()
        params: Dict[str, str] = {}
        if self._session_id:
            params["session_id"] = self._session_id
        resp = await client.get("/state", params=params)
        resp.raise_for_status()
        return IncidentState.model_validate(resp.json())

    async def health(self) -> Dict[str, Any]:
        """Ping the readiness probe."""
        client = self._require_client()
        resp = await client.get("/health")
        resp.raise_for_status()
        return resp.json()

    async def grade(self, task: str, **kwargs: Any) -> Dict[str, Any]:
        """Call the programmatic grader for a completed episode."""
        client = self._require_client()
        resp = await client.post(f"/grade/{task}", json=kwargs)
        resp.raise_for_status()
        return resp.json()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError(
                "IncidentResponseEnv must be used as an async context manager: "
                "async with IncidentResponseEnv() as env: ..."
            )
        return self._client


# ---------------------------------------------------------------------------
# Convenience synchronous wrapper for notebooks and scripts
# ---------------------------------------------------------------------------

def run_episode_sync(
    task: str = "easy",
    base_url: str = "http://localhost:7860",
    max_steps: int = 40,
) -> Dict[str, Any]:
    """
    Run a single episode synchronously (blocks until done or step limit).
    Returns summary dict: {"task", "steps", "score", "obs"}.

    Useful in Jupyter notebooks and quick tests.
    """

    async def _run() -> Dict[str, Any]:
        async with IncidentResponseEnv(base_url=base_url) as env:
            obs = await env.reset(task=task)
            steps = 0
            while not obs.done and steps < max_steps:
                # Dummy action for testing only — not a real agent
                action = IncidentAction(
                    action_type="view_logs",
                    target=(obs.services[0].name if obs.services else ""),
                )
                obs = await env.step(action)
                steps += 1
            state = await env.get_state()
            grade = await env.grade(
                task,
                cumulative_reward=state.cumulative_reward,
                steps_taken=state.step_count,
                episode_done=obs.done,
                root_causes_found=obs.root_causes_found,
                services_healthy=obs.services_healthy,
                services_total=obs.services_total,
            )
            return {"task": task, "steps": steps, "score": grade.get("score"), "obs": obs}

    return asyncio.run(_run())
