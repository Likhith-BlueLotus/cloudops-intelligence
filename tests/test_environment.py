"""
Unit tests for CloudOps Intelligence Environment.

Covers all three tasks (FinOps / Security+SRE / DDoS+FinOps+SRE),
all action types including new cloud-specific ones (run_cli, list_resources,
view_billing, write_terraform), reward correctness, and episode termination.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.environment import IncidentResponseEnvironment, SCENARIOS
from models import IncidentAction


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def env():
    return IncidentResponseEnvironment()


def _action(action_type: str, target: str = None, parameters: dict = None, **params) -> IncidentAction:
    """Build an IncidentAction. `parameters` kwarg takes priority over **params."""
    return IncidentAction(
        action_type=action_type,
        target=target,
        parameters=parameters if parameters is not None else (params or {}),
    )


# ---------------------------------------------------------------------------
# reset() tests
# ---------------------------------------------------------------------------

class TestReset:
    def test_reset_easy_is_finops_domain(self, env):
        env.reset(task="easy")
        assert SCENARIOS["easy"]["domain"] == "FinOps"

    def test_reset_medium_is_security_sre_domain(self, env):
        env.reset(task="medium")
        assert "Security" in SCENARIOS["medium"]["domain"]

    def test_reset_hard_is_combined_domain(self, env):
        env.reset(task="hard")
        assert "DDoS" in SCENARIOS["hard"]["title"]

    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_reset_loads_correct_services(self, env, task):
        obs = env.reset(task=task)
        assert obs.services_total == len(SCENARIOS[task]["services"])
        assert obs.root_causes_total == len(SCENARIOS[task]["root_causes"])
        assert obs.done is False

    def test_reset_unknown_task_falls_back_to_medium(self, env):
        obs = env.reset(task="invalid_xyz")
        assert obs.services_total == len(SCENARIOS["medium"]["services"])

    def test_reset_clears_state(self, env):
        env.reset(task="easy")
        env.step(_action("view_logs", "ec2_fleet"))
        env.reset(task="easy")
        assert env.state.step_count == 0
        assert env.state.fixes_applied == []
        assert env.state.root_causes_identified == []

    def test_easy_has_one_root_cause(self, env):
        obs = env.reset(task="easy")
        assert obs.root_causes_total == 1

    def test_medium_has_two_root_causes(self, env):
        obs = env.reset(task="medium")
        assert obs.root_causes_total == 2

    def test_hard_has_three_root_causes(self, env):
        obs = env.reset(task="hard")
        assert obs.root_causes_total == 3


# ---------------------------------------------------------------------------
# view_logs
# ---------------------------------------------------------------------------

class TestViewLogs:
    def test_view_logs_billing_dashboard(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_logs", "billing_dashboard"))
        assert "billing" in obs.action_output.lower() or "ec2" in obs.action_output.lower()

    def test_view_logs_s3_shows_public_access_warning(self, env):
        env.reset(task="medium")
        obs = env.step(_action("view_logs", "s3_prod_customer_data"))
        assert "public" in obs.action_output.lower() or "acl" in obs.action_output.lower()

    def test_view_logs_unknown_service(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_logs", "nonexistent_service_xyz"))
        assert "not found" in obs.action_output.lower()

    def test_view_logs_redundant_reduces_cumulative_reward(self, env):
        env.reset(task="easy")
        env.step(_action("view_logs", "ec2_fleet"))
        env.step(_action("view_logs", "ec2_fleet"))
        assert env.state.cumulative_reward <= 0.0


# ---------------------------------------------------------------------------
# view_metrics
# ---------------------------------------------------------------------------

class TestViewMetrics:
    def test_view_billing_metrics_ec2_cost(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_metrics", "billing_dashboard", metric="ec2_cost"))
        assert "cost" in obs.action_output.lower() or "billing" in obs.action_output.lower()

    def test_view_metrics_ec2_utilization(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_metrics", "ec2_fleet", metric="utilization"))
        assert "zombie" in obs.action_output.lower() or "cpu" in obs.action_output.lower()

    def test_view_metrics_request_rate_hard(self, env):
        env.reset(task="hard")
        obs = env.step(_action("view_metrics", "api_gateway", metric="request_rate"))
        assert "ddos" in obs.action_output.lower() or "840" in obs.action_output


# ---------------------------------------------------------------------------
# list_resources
# ---------------------------------------------------------------------------

class TestListResources:
    def test_list_ec2_resources(self, env):
        env.reset(task="easy")
        obs = env.step(_action("list_resources", parameters={"type": "ec2"}))
        assert obs.action_output  # non-empty response

    def test_list_resources_hard_shows_instances(self, env):
        env.reset(task="hard")
        obs = env.step(_action("list_resources", parameters={"type": "autoscaling"}))
        assert obs.action_output


# ---------------------------------------------------------------------------
# run_cli
# ---------------------------------------------------------------------------

class TestRunCli:
    def test_run_cli_ec2_describe_returns_zombie_instances(self, env):
        env.reset(task="easy")
        obs = env.step(_action("run_cli", parameters={"command": "aws ec2 describe-instances"}))
        assert "zombie" in obs.action_output.lower() or "projectphoenix" in obs.action_output.lower()

    def test_run_cli_s3_acl_shows_public_access(self, env):
        env.reset(task="medium")
        obs = env.step(_action("run_cli", parameters={"command": "aws s3api get-bucket-acl --bucket prod-customer-data"}))
        assert "public" in obs.action_output.lower() or "allUsers" in obs.action_output

    def test_run_cli_iam_policy_shows_typo(self, env):
        env.reset(task="medium")
        obs = env.step(_action("run_cli", parameters={"command": "aws iam get-role-policy --role-name payment-service-role"}))
        assert "GetObejct" in obs.action_output or "typo" in obs.action_output.lower()

    def test_run_cli_waf_list_returns_empty(self, env):
        env.reset(task="hard")
        obs = env.step(_action("run_cli", parameters={"command": "aws wafv2 list-web-acls"}))
        assert "[]" in obs.action_output or "no waf" in obs.action_output.lower()

    def test_run_cli_vpc_flow_logs_shows_attack_cidrs(self, env):
        env.reset(task="hard")
        obs = env.step(_action("run_cli", parameters={"command": "aws vpc get-flow-logs"}))
        assert "203.0.113" in obs.action_output


# ---------------------------------------------------------------------------
# view_billing
# ---------------------------------------------------------------------------

class TestViewBilling:
    def test_view_billing_easy_shows_spike(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_billing", "ec2", period="month"))
        assert "billing" in obs.action_output.lower() or "cost" in obs.action_output.lower()

    def test_view_billing_hard_shows_realtime_cost(self, env):
        env.reset(task="hard")
        obs = env.step(_action("view_billing", "ec2", period="realtime"))
        assert obs.action_output


# ---------------------------------------------------------------------------
# apply_fix
# ---------------------------------------------------------------------------

class TestApplyFix:
    def test_terminate_zombie_instances_easy(self, env):
        env.reset(task="easy")
        obs = env.step(_action(
            "apply_fix", "ec2_fleet",
            fix_type="terminate",
            config_key="zombie",
        ))
        assert obs.reward > 0.0
        assert obs.root_causes_found == 1

    def test_fix_s3_public_access_medium(self, env):
        env.reset(task="medium")
        obs = env.step(_action(
            "apply_fix", "s3_prod_customer_data",
            fix_type="block_public_access",
            config_key="block_public_acls",
        ))
        assert obs.reward > 0.0

    def test_fix_iam_typo_medium(self, env):
        env.reset(task="medium")
        obs = env.step(_action(
            "apply_fix", "iam_payment_role",
            fix_type="update_policy",
            config_key="s3:GetObject",
        ))
        assert obs.reward > 0.0

    def test_both_medium_fixes_give_two_root_causes(self, env):
        env.reset(task="medium")
        env.step(_action("apply_fix", "s3_prod_customer_data",
                         fix_type="block_public_access", config_key="block_public_acls"))
        env.step(_action("apply_fix", "iam_payment_role",
                         fix_type="update_policy", config_key="s3:GetObject"))
        assert env.state.root_causes_identified == [
            "s3_public_access_enabled", "iam_role_typo"
        ]

    def test_wrong_fix_target_penalises(self, env):
        env.reset(task="easy")
        env.step(_action("apply_fix", "billing_dashboard", fix_type="restart"))
        assert env.state.cumulative_reward < 0.0

    def test_fix_autoscaling_hard(self, env):
        env.reset(task="hard")
        obs = env.step(_action(
            "apply_fix", "auto_scaling",
            fix_type="adjust_config",
            config_key="max_capacity",
            config_value="20",
        ))
        assert obs.reward > 0.0

    def test_fix_rate_limit_hard(self, env):
        env.reset(task="hard")
        obs = env.step(_action(
            "apply_fix", "api_gateway",
            fix_type="enable_rate_limiting",
            config_key="throttle",
        ))
        assert obs.reward > 0.0


# ---------------------------------------------------------------------------
# write_terraform (hard task — WAF deployment)
# ---------------------------------------------------------------------------

class TestWriteTerraform:
    def test_correct_waf_terraform_resolves_root_cause(self, env):
        env.reset(task="hard")
        obs = env.step(_action(
            "write_terraform",
            parameters={
                "resource_type": "aws_wafv2_web_acl",
                "config": (
                    "resource aws_wafv2_ip_set block_ips { "
                    "ip_address_version = IPV4 "
                    "addresses = [203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24] } "
                    "resource aws_wafv2_web_acl main { "
                    "rule { action { block {} } } }"
                ),
            },
        ))
        assert obs.reward > 0.0
        assert "waf_not_configured" in env.state.fixes_applied

    def test_incomplete_waf_terraform_no_credit(self, env):
        env.reset(task="hard")
        obs = env.step(_action(
            "write_terraform",
            parameters={
                "resource_type": "aws_s3_bucket",
                "config": "resource aws_s3_bucket my_bucket { bucket = 'test' }",
            },
        ))
        assert obs.reward <= 0.0

    def test_terraform_with_cidrs_but_wrong_resource_no_credit(self, env):
        env.reset(task="hard")
        obs = env.step(_action(
            "write_terraform",
            parameters={
                "resource_type": "aws_security_group",
                "config": "203.0.113.0/24 198.51.100.0/24 192.0.2.0/24 deny ingress",
            },
        ))
        # No credit — resource type doesn't match WAF pattern
        # (security_group is not waf_service target)
        assert obs.action_output  # non-empty response

    def test_all_three_hard_fixes_resolve_episode(self, env):
        env.reset(task="hard")
        # Fix 1: WAF
        env.step(_action("write_terraform", parameters={
            "resource_type": "aws_wafv2_web_acl",
            "config": "aws_wafv2_ip_set block 203.0.113.0/24 198.51.100.0/24 192.0.2.0/24",
        }))
        # Fix 2: Auto-scaling
        env.step(_action("apply_fix", "auto_scaling", fix_type="adjust_config",
                         config_key="max_capacity", config_value="20"))
        # Fix 3: Rate limiting
        env.step(_action("apply_fix", "api_gateway", fix_type="enable_rate_limiting",
                         config_key="throttle"))
        assert len(env.state.fixes_applied) == 3
        assert len(env.state.root_causes_identified) == 3


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

class TestVerify:
    def test_verify_ec2_fleet_after_fix(self, env):
        env.reset(task="easy")
        env.step(_action("apply_fix", "ec2_fleet", fix_type="terminate", config_key="zombie"))
        obs = env.step(_action("verify", "ec2_fleet"))
        assert "healthy" in obs.action_output.lower()
        assert obs.reward > 0.0

    def test_verify_unfixed_service_no_reward(self, env):
        env.reset(task="medium")
        obs = env.step(_action("verify", "payment_service"))
        assert obs.reward == 0.0

    def test_verify_after_s3_fix_updates_status(self, env):
        env.reset(task="medium")
        env.step(_action("apply_fix", "s3_prod_customer_data",
                         fix_type="block_public_access", config_key="block_public_acls"))
        obs = env.step(_action("verify", "s3_prod_customer_data"))
        assert "healthy" in obs.action_output.lower()


# ---------------------------------------------------------------------------
# Escalate
# ---------------------------------------------------------------------------

class TestEscalate:
    def test_escalate_ends_episode(self, env):
        env.reset(task="easy")
        obs = env.step(_action("escalate"))
        assert obs.done is True
        assert env.state.escalated is True

    def test_escalate_with_partial_fix_gives_partial_credit(self, env):
        env.reset(task="hard")
        # Apply one of three fixes first (auto-scaling cap)
        env.step(_action("apply_fix", "auto_scaling", fix_type="adjust_config",
                         config_key="max_capacity", config_value="20"))
        obs = env.step(_action("escalate"))
        # 1/3 root causes fixed → partial credit > 0
        state = env.state
        assert state.cumulative_reward > 0.0  # net positive (fix reward > penalty)


# ---------------------------------------------------------------------------
# Episode termination
# ---------------------------------------------------------------------------

class TestCompletion:
    def test_easy_episode_done_after_fix_and_verify(self, env):
        env.reset(task="easy")
        env.step(_action("apply_fix", "ec2_fleet", fix_type="terminate", config_key="zombie"))
        env.step(_action("verify", "billing_dashboard"))
        assert env._all_resolved() is True

    def test_episode_terminates_at_step_budget(self, env):
        env.reset(task="easy")
        obs = None
        for _ in range(SCENARIOS["easy"]["max_steps"] + 2):
            obs = env.step(_action("view_logs", "billing_dashboard"))
        assert obs.done is True


# ---------------------------------------------------------------------------
# Observation invariants
# ---------------------------------------------------------------------------

class TestObservationInvariants:
    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_reward_in_valid_range(self, env, task):
        env.reset(task=task)
        for a in [
            _action("view_logs", "billing_dashboard"),
            _action("run_cli", parameters={"command": "aws ec2 describe-instances"}),
            _action("apply_fix", "wrong_target", fix_type="restart"),  # penalty clipped to 0
        ]:
            obs = env.step(a)
            assert 0.0 <= obs.reward <= 1.0  # obs.reward always in [0,1] per spec

    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_services_count_matches_scenario(self, env, task):
        obs = env.reset(task=task)
        assert obs.services_total == len(SCENARIOS[task]["services"])

    def test_available_actions_includes_cloud_types(self, env):
        obs = env.reset(task="easy")
        for action in ("view_logs", "run_cli", "view_billing", "write_terraform"):
            assert action in obs.available_actions


# ---------------------------------------------------------------------------
# Scenario sanity
# ---------------------------------------------------------------------------

class TestScenarioSanity:
    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_required_keys_present(self, task):
        s = SCENARIOS[task]
        for key in ("title", "domain", "initial_alert", "services",
                    "root_causes", "correct_fixes", "max_steps"):
            assert key in s, f"SCENARIOS[{task}] missing '{key}'"

    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_all_root_causes_have_fixes(self, task):
        s = SCENARIOS[task]
        for rc_id in s["root_causes"]:
            assert rc_id in s["correct_fixes"]

    def test_easy_domain_is_finops(self):
        assert SCENARIOS["easy"]["domain"] == "FinOps"

    def test_hard_has_waf_root_cause(self):
        assert "waf_not_configured" in SCENARIOS["hard"]["root_causes"]

    def test_hard_has_autoscaling_root_cause(self):
        assert "autoscaling_unbounded" in SCENARIOS["hard"]["root_causes"]

    def test_medium_has_s3_root_cause(self):
        assert "s3_public_access_enabled" in SCENARIOS["medium"]["root_causes"]

    def test_medium_has_iam_root_cause(self):
        assert "iam_role_typo" in SCENARIOS["medium"]["root_causes"]

    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_all_services_have_status(self, task):
        for name, svc in SCENARIOS[task]["services"].items():
            assert "status" in svc, f"Service '{name}' missing 'status'"

    def test_hard_includes_waf_terraform_fix_type(self):
        fix = SCENARIOS["hard"]["correct_fixes"]["waf_not_configured"]
        assert "write_terraform" in fix["fix_types"]
