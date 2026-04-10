"""Tests for Pydantic model validation."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import IncidentAction, IncidentObservation, IncidentState, ServiceHealth


class TestIncidentAction:
    def test_view_logs_action_valid(self):
        a = IncidentAction(action_type="view_logs", target="payment_service")
        assert a.action_type == "view_logs"
        assert a.target == "payment_service"

    def test_apply_fix_with_parameters(self):
        a = IncidentAction(
            action_type="apply_fix",
            target="user_db",
            parameters={"fix_type": "adjust_config", "config_key": "max_connections"},
        )
        assert a.parameters["fix_type"] == "adjust_config"

    def test_escalate_no_target_required(self):
        a = IncidentAction(action_type="escalate")
        assert a.action_type == "escalate"
        assert a.target is None

    def test_missing_action_type_raises(self):
        with pytest.raises(Exception):
            IncidentAction()


class TestServiceHealth:
    def test_valid_service(self):
        s = ServiceHealth(
            name="payment_service",
            status="degraded",
            error_rate_pct=45.0,
            response_time_ms=8400.0,
            uptime_pct=61.0,
        )
        assert s.error_rate_pct == 45.0

    def test_error_rate_bounds(self):
        with pytest.raises(Exception):
            ServiceHealth(
                name="svc",
                status="healthy",
                error_rate_pct=110.0,  # > 100 — invalid
                response_time_ms=10.0,
                uptime_pct=99.9,
            )


class TestIncidentObservation:
    def test_reward_must_be_in_range(self):
        with pytest.raises(Exception):
            IncidentObservation(
                situation_report="Test",
                reward=1.5,  # > 1.0 — invalid
                done=False,
            )

    def test_valid_observation(self):
        obs = IncidentObservation(
            situation_report="Incident active",
            services=[],
            action_output="Logs retrieved",
            reward=0.5,
            done=False,
        )
        assert obs.reward == 0.5
        assert obs.done is False


class TestIncidentState:
    def test_default_state(self):
        s = IncidentState()
        assert s.task == "easy"
        assert s.step_count == 0
        assert s.resolved is False
        assert s.escalated is False

    def test_state_with_values(self):
        s = IncidentState(
            task="hard",
            step_count=10,
            root_causes_identified=["message_queue_disk_full"],
            fixes_applied=["message_queue_disk_full"],
            services_status={"order_service": "down"},
            resolved=False,
        )
        assert len(s.fixes_applied) == 1
        assert s.task == "hard"
