"""
Pydantic data contracts for the AIOps Incident Response Environment.

Three top-level schemas implement the OpenEnv typed interface:
  IncidentAction      — action taken by the on-call engineer agent
  IncidentObservation — current incident state observed by the agent
  IncidentState       — server-side ground truth for graders and loggers
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field
from openenv.core.env_server import Action, Observation, State


class IncidentAction(Action):
    """
    Action submitted by the on-call engineer agent each step.

    The agent investigates the incident by querying logs and metrics,
    then applies targeted fixes and verifies resolution.

    action_type choices:
      view_logs     — retrieve recent log output for a service
      view_metrics  — retrieve a specific metric time-series for a service
      apply_fix     — apply a remediation action to a service or component
      verify        — run a health check against a service to confirm recovery
      escalate      — escalate to senior on-call (terminates episode with partial score)
    """

    action_type: str = Field(
        ...,
        description=(
            "Action to take: 'view_logs' | 'view_metrics' | 'apply_fix' | 'verify' | 'escalate'"
        ),
    )
    target: Optional[str] = Field(
        None,
        description=(
            "Target service or component name (e.g. 'payment_service', 'user_db', 'redis_cache'). "
            "Required for view_logs, view_metrics, and apply_fix."
        ),
    )
    parameters: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        description=(
            "Additional parameters depending on action_type:\n"
            "  view_metrics: {'metric': 'connections|cpu|memory|error_rate', 'window': '5m|1h'}\n"
            "  apply_fix:    {'fix_type': 'restart|adjust_config|clear_cache|increase_capacity|rollback',\n"
            "                  'config_key': 'max_connections|heap_size|...', 'config_value': '200|2g|...'}"
        ),
    )


class ServiceHealth(BaseModel):
    """Health snapshot for a single service."""

    name: str = Field(..., description="Service identifier.")
    status: str = Field(
        ..., description="Current status: 'healthy' | 'degraded' | 'down'."
    )
    error_rate_pct: float = Field(
        ..., ge=0.0, le=100.0, description="Error rate as percentage (0–100)."
    )
    response_time_ms: float = Field(..., description="P95 response latency in ms.")
    uptime_pct: float = Field(
        ..., ge=0.0, le=100.0, description="Rolling 1-hour uptime percentage."
    )


class IncidentObservation(Observation):
    """
    Observation returned to the agent after each action.

    The agent sees the plain-text situation report, per-service health,
    and the output of the last action (log lines, metric table, fix result).
    reward is the normalised step reward in [0, 1].
    """

    situation_report: str = Field(
        ...,
        description=(
            "Plain-text summary of the current incident state, "
            "including affected services, user impact, and elapsed time."
        ),
    )
    services: List[ServiceHealth] = Field(
        default_factory=list,
        description="Live health snapshot for every service in this incident.",
    )
    action_output: str = Field(
        default="",
        description=(
            "Output from the most recent action: log lines, metric table, "
            "fix confirmation, or verification result."
        ),
    )
    available_actions: List[str] = Field(
        default_factory=list,
        description=(
            "Reminder of legal action_type values for this step: "
            "['view_logs', 'view_metrics', 'apply_fix', 'verify', 'escalate']."
        ),
    )
    services_healthy: int = Field(
        default=0, description="Count of services currently in 'healthy' status."
    )
    services_total: int = Field(
        default=0, description="Total number of services in this incident scope."
    )
    root_causes_found: int = Field(
        default=0,
        description="Number of root causes the agent has correctly identified so far.",
    )
    root_causes_total: int = Field(
        default=0, description="Total number of root causes in this incident."
    )
    reward: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Step reward normalised to [0.0, 1.0].",
    )
    done: bool = Field(
        default=False, description="True when the episode is complete (all services healthy or step limit reached)."
    )


class IncidentState(State):
    """
    Ground-truth server-side state used by graders and loggers.
    Not revealed to the agent during rollout.
    """

    task: str = Field(default="easy", description="Task difficulty: 'easy' | 'medium' | 'hard'.")
    incident_title: str = Field(default="", description="Short title of the active incident.")
    step_count: int = Field(default=0, ge=0, description="Steps taken so far in this episode.")
    actions_log: List[str] = Field(
        default_factory=list,
        description="Chronological record of all actions taken, for replay and audit.",
    )
    root_causes_identified: List[str] = Field(
        default_factory=list,
        description="Root cause IDs the agent has correctly diagnosed.",
    )
    fixes_applied: List[str] = Field(
        default_factory=list, description="Fix IDs that have been successfully applied."
    )
    services_status: Dict[str, str] = Field(
        default_factory=dict,
        description="Current status string per service_id.",
    )
    resolved: bool = Field(
        default=False,
        description="True when all services are healthy and all root causes fixed.",
    )
    escalated: bool = Field(
        default=False,
        description="True if the agent chose to escalate before resolving.",
    )
    cumulative_reward: float = Field(
        default=0.0, description="Sum of per-step rewards accumulated in this episode."
    )
