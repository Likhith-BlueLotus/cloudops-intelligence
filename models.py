"""
Pydantic data contracts for the CloudOps Intelligence Environment.

Three top-level schemas implement the OpenEnv typed interface:
  IncidentAction      — action taken by the on-call/SOC engineer agent
  IncidentObservation — current incident state observed by the agent
  IncidentState       — server-side ground truth for graders and loggers
"""

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field
from openenv.core.env_server import Action, Observation, State

# All legal action types across both CloudOps and SOC Analyst tracks.
ActionType = Literal[
    "view_logs",           # Retrieve recent log output for a service / component
    "view_metrics",        # Retrieve a metric time-series (cpu, error_rate, …)
    "list_resources",      # List AWS resources of a given type (ec2, s3, iam, …)
    "run_cli",             # Run a mock AWS CLI command and get its output
    "view_billing",        # View billing / cost data for a service or time period
    "lookup_threat_intel", # Query the threat-intel feed for an IOC (IP / hash)
    "apply_fix",           # Apply a targeted remediation to a service / component
    "write_terraform",     # Write and apply a Terraform HCL resource (WAF, NACL, …)
    "verify",              # Health-check a service to confirm successful recovery
    "escalate",            # Escalate to senior on-call (ends episode, partial score)
]


class IncidentAction(Action):
    """
    Action submitted by the on-call / SOC engineer agent each step.

    CloudOps investigation flow:
      1. view_billing / list_resources / run_cli — identify cost anomaly or misconfiguration
      2. view_logs / view_metrics              — gather evidence
      3. apply_fix / write_terraform           — remediate root causes
      4. verify                                — confirm health restored

    SOC Analyst investigation flow:
      1. lookup_threat_intel                   — confirm IOC classification
      2. view_logs / run_cli                   — query SIEM / endpoint telemetry
      3. apply_fix (revoke_session / isolate_host / revoke_credentials / revoke_access)
      4. verify                                — confirm containment
    """

    action_type: ActionType = Field(
        ...,
        description=(
            "Action to perform. CloudOps: 'view_logs' | 'view_metrics' | 'list_resources' | "
            "'run_cli' | 'view_billing' | 'apply_fix' | 'write_terraform' | 'verify' | 'escalate'. "
            "SOC track adds: 'lookup_threat_intel'."
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
            "  view_logs:           {'lines': '50'}\n"
            "  view_metrics:        {'metric': 'cpu|error_rate|latency', 'window': '5m|1h'}\n"
            "  list_resources:      {'type': 'ec2|s3|iam|lambda'}\n"
            "  run_cli:             {'command': 'aws ec2 describe-instances ...'}\n"
            "  view_billing:        {'period': 'day|week|month', 'service': 'ec2|s3|...'}\n"
            "  lookup_threat_intel: {'ioc': '1.2.3.4', 'ioc_type': 'ip|domain|hash'}\n"
            "  apply_fix:           {'fix_type': 'terminate|block_public_access|fix_iam|\n"
            "                         enable_rate_limiting|adjust_config|update_policy|\n"
            "                         revoke_session|block_ip|isolate_host|quarantine|\n"
            "                         revoke_credentials|revoke_access',\n"
            "                        'config_key': '<resource-id|setting>', 'config_value': '<value>'}\n"
            "  write_terraform:     {'resource_type': 'aws_wafv2_web_acl|aws_network_acl', 'config': '<hcl>'}"
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
            "['view_logs', 'view_metrics', 'list_resources', 'run_cli', 'view_billing', "
            "'lookup_threat_intel', 'apply_fix', 'write_terraform', 'verify', 'escalate']."
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

    task: str = Field(
        default="easy",
        description=(
            "Active task ID: 'easy' | 'medium' | 'hard' (CloudOps track) | "
            "'soc_easy' | 'soc_medium' | 'soc_hard' (SOC Analyst track)."
        ),
    )
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
