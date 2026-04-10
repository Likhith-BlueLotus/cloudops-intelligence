"""
Unit tests for IncidentResponseEnvironment.

Covers:
- reset() initialises correct scenario
- step() handles all action types
- root cause identification and fixing
- reward function correctness
- completion detection
- grading formula
- edge cases (unknown service, redundant queries, wrong fix)
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


def _action(action_type: str, target: str = None, **params) -> IncidentAction:
    return IncidentAction(
        action_type=action_type,
        target=target,
        parameters=params or {},
    )


# ---------------------------------------------------------------------------
# reset() tests
# ---------------------------------------------------------------------------

class TestReset:
    def test_reset_easy_loads_scenario(self, env):
        obs = env.reset(task="easy")
        assert obs.services_total == len(SCENARIOS["easy"]["services"])
        assert obs.root_causes_total == len(SCENARIOS["easy"]["root_causes"])
        assert obs.done is False
        assert obs.reward == 0.0

    def test_reset_medium_loads_scenario(self, env):
        obs = env.reset(task="medium")
        assert obs.services_total == len(SCENARIOS["medium"]["services"])
        assert obs.root_causes_total == len(SCENARIOS["medium"]["root_causes"])

    def test_reset_hard_loads_scenario(self, env):
        obs = env.reset(task="hard")
        assert obs.services_total == len(SCENARIOS["hard"]["services"])
        assert obs.root_causes_total == len(SCENARIOS["hard"]["root_causes"])

    def test_reset_unknown_task_falls_back_to_medium(self, env):
        obs = env.reset(task="unknown_task_xyz")
        assert obs.services_total == len(SCENARIOS["medium"]["services"])

    def test_reset_produces_clean_state(self, env):
        env.reset(task="easy")
        env.step(_action("view_logs", "payment_service"))
        # Second reset should clear all state
        obs = env.reset(task="easy")
        assert env.state.step_count == 0
        assert env.state.root_causes_identified == []
        assert env.state.fixes_applied == []

    def test_reset_easy_has_three_services(self, env):
        env.reset(task="easy")
        assert len(SCENARIOS["easy"]["services"]) == 3

    def test_reset_medium_has_five_services(self, env):
        env.reset(task="medium")
        assert len(SCENARIOS["medium"]["services"]) == 5

    def test_reset_hard_has_seven_services(self, env):
        env.reset(task="hard")
        assert len(SCENARIOS["hard"]["services"]) == 7


# ---------------------------------------------------------------------------
# view_logs tests
# ---------------------------------------------------------------------------

class TestViewLogs:
    def test_view_logs_returns_log_content(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_logs", "payment_service"))
        assert "payment_service" in obs.action_output.lower()
        assert "connection" in obs.action_output.lower()
        assert obs.reward >= 0.0

    def test_view_logs_unknown_service_returns_error(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_logs", "nonexistent_service_xyz"))
        assert "not found" in obs.action_output.lower()
        assert obs.reward == 0.0

    def test_view_logs_redundant_query_penalised(self, env):
        # Penalty is applied to cumulative_reward but clipped to 0 in obs.reward
        # (OpenEnv reward field must be in [0, 1])
        env.reset(task="easy")
        env.step(_action("view_logs", "payment_service"))
        env.step(_action("view_logs", "payment_service"))
        # cumulative reward should reflect the penalty
        state = env.state
        assert state.cumulative_reward <= 0.0  # net effect: penalty deducted


# ---------------------------------------------------------------------------
# view_metrics tests
# ---------------------------------------------------------------------------

class TestViewMetrics:
    def test_view_metrics_returns_metric_data(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_metrics", "user_db", metric="connections"))
        assert "connections" in obs.action_output.lower()
        assert obs.reward >= 0.0

    def test_view_metrics_unknown_service_returns_error(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_metrics", "no_such_service", metric="cpu"))
        assert "not found" in obs.action_output.lower()

    def test_view_metrics_no_metric_specified(self, env):
        env.reset(task="easy")
        obs = env.step(_action("view_metrics", "user_db"))
        # Should prompt with available metrics
        assert obs.action_output  # not empty

    def test_view_metrics_redundant_penalised(self, env):
        # Redundancy penalty reduces cumulative_reward; obs.reward is clipped to [0,1]
        env.reset(task="easy")
        env.step(_action("view_metrics", "user_db", metric="connections"))
        env.step(_action("view_metrics", "user_db", metric="connections"))
        state = env.state
        assert state.cumulative_reward <= 0.0


# ---------------------------------------------------------------------------
# apply_fix tests
# ---------------------------------------------------------------------------

class TestApplyFix:
    def test_correct_fix_easy_awards_reward(self, env):
        env.reset(task="easy")
        obs = env.step(_action(
            "apply_fix", "user_db",
            fix_type="adjust_config",
            config_key="max_connections",
            config_value="200",
        ))
        assert obs.reward > 0.0
        assert obs.root_causes_found == 1

    def test_correct_fix_updates_service_status(self, env):
        env.reset(task="easy")
        env.step(_action(
            "apply_fix", "user_db",
            fix_type="adjust_config",
            config_key="max_connections",
            config_value="200",
        ))
        state = env.state
        # fixes_applied stores root cause IDs, not service names
        assert "user_db_connection_pool_exhausted" in state.fixes_applied

    def test_wrong_service_fix_penalised(self, env):
        # Wrong-fix penalty reduces cumulative_reward; obs.reward is clipped to [0,1]
        env.reset(task="easy")
        env.step(_action("apply_fix", "redis_cache", fix_type="restart"))
        state = env.state
        assert state.cumulative_reward < 0.0

    def test_fix_type_variants_accepted(self, env):
        """Alternative fix_type strings should still match."""
        env.reset(task="easy")
        obs = env.step(_action(
            "apply_fix", "user_db",
            fix_type="increase_capacity",
        ))
        assert obs.reward > 0.0

    def test_medium_both_fixes_required_for_full_score(self, env):
        env.reset(task="medium")
        env.step(_action(
            "apply_fix", "redis_cache",
            fix_type="adjust_config",
            config_key="cache_ttl",
            config_value="3600",
        ))
        state = env.state
        assert len(state.fixes_applied) == 1
        assert len(state.root_causes_identified) == 1

    def test_hard_all_three_fixes_needed(self, env):
        env.reset(task="hard")
        # Fix 1
        env.step(_action("apply_fix", "message_queue", fix_type="clear_queue"))
        # Fix 2
        env.step(_action("apply_fix", "order_service", fix_type="rollback"))
        # Fix 3
        env.step(_action("apply_fix", "inventory_service", fix_type="kill_query"))
        state = env.state
        assert len(state.fixes_applied) == 3
        assert len(state.root_causes_identified) == 3


# ---------------------------------------------------------------------------
# verify tests
# ---------------------------------------------------------------------------

class TestVerify:
    def test_verify_after_fix_awards_reward(self, env):
        env.reset(task="easy")
        env.step(_action(
            "apply_fix", "user_db",
            fix_type="adjust_config",
            config_key="max_connections",
            config_value="200",
        ))
        obs = env.step(_action("verify", "payment_service"))
        assert obs.reward > 0.0
        assert "healthy" in obs.action_output.lower()

    def test_verify_unfixed_service_zero_reward(self, env):
        env.reset(task="easy")
        obs = env.step(_action("verify", "payment_service"))
        # Service still degraded; should report degraded status
        assert "degraded" in obs.action_output.lower() or obs.reward == 0.0

    def test_verify_unknown_service(self, env):
        env.reset(task="easy")
        obs = env.step(_action("verify", "nonexistent_svc"))
        assert "not found" in obs.action_output.lower()


# ---------------------------------------------------------------------------
# Escalate tests
# ---------------------------------------------------------------------------

class TestEscalate:
    def test_escalate_ends_episode(self, env):
        env.reset(task="easy")
        obs = env.step(_action("escalate"))
        assert obs.done is True
        assert env.state.escalated is True

    def test_escalate_with_partial_fixes_gives_partial_credit(self, env):
        env.reset(task="hard")
        # Fix one of three
        env.step(_action("apply_fix", "message_queue", fix_type="clear_queue"))
        obs = env.step(_action("escalate"))
        assert obs.reward > 0.0  # partial credit

    def test_post_escalate_step_returns_done_message(self, env):
        env.reset(task="easy")
        env.step(_action("escalate"))
        obs = env.step(_action("view_logs", "payment_service"))
        # Subsequent steps after episode ends should say so
        assert obs.done is True


# ---------------------------------------------------------------------------
# Episode completion tests
# ---------------------------------------------------------------------------

class TestCompletion:
    def test_episode_done_when_all_fixed_easy(self, env):
        env.reset(task="easy")
        env.step(_action(
            "apply_fix", "user_db",
            fix_type="adjust_config",
            config_key="max_connections",
            config_value="100",
        ))
        obs = env.step(_action("verify", "payment_service"))
        # After all root causes fixed, done should be True
        assert env._all_resolved() is True
        assert obs.done is True

    def test_episode_terminates_at_step_budget(self, env):
        env.reset(task="easy")
        max_steps = SCENARIOS["easy"]["max_steps"]
        obs = None
        for _ in range(max_steps + 2):
            obs = env.step(_action("view_logs", "payment_service"))
        assert obs.done is True


# ---------------------------------------------------------------------------
# State tests
# ---------------------------------------------------------------------------

class TestState:
    def test_state_step_count_increments(self, env):
        env.reset(task="easy")
        for i in range(1, 4):
            env.step(_action("view_logs", "payment_service"))
            assert env.state.step_count == i

    def test_state_task_reflects_reset_task(self, env):
        env.reset(task="hard")
        assert env.state.task == "hard"

    def test_state_actions_log_populated(self, env):
        env.reset(task="easy")
        env.step(_action("view_logs", "payment_service"))
        assert len(env.state.actions_log) == 1


# ---------------------------------------------------------------------------
# Observation invariants
# ---------------------------------------------------------------------------

class TestObservationInvariants:
    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_reward_always_in_range(self, env, task):
        env.reset(task=task)
        for action in [
            _action("view_logs", "payment_service"),
            _action("view_metrics", "user_db", metric="connections"),
            _action("apply_fix", "redis_cache", fix_type="restart"),
        ]:
            obs = env.step(action)
            assert -1.0 <= obs.reward <= 1.0

    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_services_count_matches_scenario(self, env, task):
        obs = env.reset(task=task)
        assert obs.services_total == len(SCENARIOS[task]["services"])

    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_root_causes_count_matches_scenario(self, env, task):
        obs = env.reset(task=task)
        assert obs.root_causes_total == len(SCENARIOS[task]["root_causes"])

    def test_available_actions_always_present(self, env):
        obs = env.reset(task="easy")
        assert "view_logs" in obs.available_actions
        assert "apply_fix" in obs.available_actions
        assert "verify" in obs.available_actions


# ---------------------------------------------------------------------------
# Scenario library sanity
# ---------------------------------------------------------------------------

class TestScenarioSanity:
    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_scenario_has_required_keys(self, task):
        s = SCENARIOS[task]
        for key in ("title", "initial_alert", "services", "root_causes",
                    "correct_fixes", "max_steps", "difficulty"):
            assert key in s, f"SCENARIOS[{task}] missing key '{key}'"

    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_root_causes_have_correct_fixes(self, task):
        s = SCENARIOS[task]
        for rc_id in s["root_causes"]:
            assert rc_id in s["correct_fixes"], (
                f"Root cause '{rc_id}' has no entry in correct_fixes for task '{task}'"
            )

    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
    def test_all_services_have_status_field(self, task):
        for name, svc in SCENARIOS[task]["services"].items():
            assert "status" in svc, f"Service '{name}' in task '{task}' missing 'status'"

    def test_easy_has_one_root_cause(self):
        assert len(SCENARIOS["easy"]["root_causes"]) == 1

    def test_medium_has_two_root_causes(self):
        assert len(SCENARIOS["medium"]["root_causes"]) == 2

    def test_hard_has_three_root_causes(self):
        assert len(SCENARIOS["hard"]["root_causes"]) == 3
