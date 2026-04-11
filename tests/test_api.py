"""
Integration tests for FastAPI endpoints.
Uses TestClient (synchronous WSGI) to exercise all routes.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastapi.testclient import TestClient
    from server.app import app

    client = TestClient(app, raise_server_exceptions=False)
    FASTAPI_AVAILABLE = True
except Exception:
    FASTAPI_AVAILABLE = False


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI / server not available")
class TestHealthEndpoint:
    def test_health_returns_200(self):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_healthy_status(self):
        resp = client.get("/health")
        assert resp.json().get("status") == "healthy"

    def test_health_includes_environment_info(self):
        data = client.get("/health").json()
        assert "environment" in data
        env_info = data["environment"]
        assert "tasks" in env_info
        expected = {"easy", "medium", "hard", "soc_easy", "soc_medium", "soc_hard"}
        assert expected.issubset(set(env_info["tasks"]))


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI / server not available")
class TestTasksEndpoint:
    def test_tasks_returns_six_tasks(self):
        data = client.get("/tasks").json()
        assert len(data["tasks"]) == 6

    def test_tasks_have_correct_difficulty_labels(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["easy"]["difficulty"] == "easy"
        assert tasks["medium"]["difficulty"] == "medium"
        assert tasks["hard"]["difficulty"] == "hard"
        assert tasks["soc_easy"]["difficulty"] == "soc_easy"
        assert tasks["soc_medium"]["difficulty"] == "soc_medium"
        assert tasks["soc_hard"]["difficulty"] == "soc_hard"

    def test_task_max_steps_easy_is_15(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["easy"]["max_steps"] == 15

    def test_task_max_steps_medium_is_25(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["medium"]["max_steps"] == 25

    def test_task_max_steps_hard_is_40(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["hard"]["max_steps"] == 40

    def test_soc_task_max_steps_correct(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["soc_easy"]["max_steps"] == 15
        assert tasks["soc_medium"]["max_steps"] == 25
        assert tasks["soc_hard"]["max_steps"] == 40

    def test_task_root_causes_easy_is_1(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["easy"]["root_causes"] == 1

    def test_task_root_causes_medium_is_2(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["medium"]["root_causes"] == 2

    def test_task_root_causes_hard_is_3(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["hard"]["root_causes"] == 3

    def test_soc_task_root_causes_correct(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["soc_easy"]["root_causes"] == 1
        assert tasks["soc_medium"]["root_causes"] == 2
        assert tasks["soc_hard"]["root_causes"] == 3

    def test_task_services_easy_is_2(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["easy"]["services"] == 2

    def test_soc_task_services_correct(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["soc_easy"]["services"] == 2
        assert tasks["soc_medium"]["services"] == 4
        assert tasks["soc_hard"]["services"] == 5


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI / server not available")
class TestSchemaEndpoint:
    def test_schema_returns_action_observation_state(self):
        data = client.get("/schema").json()
        assert "action" in data
        assert "observation" in data
        assert "state" in data


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI / server not available")
class TestGraderEndpoint:
    @pytest.mark.parametrize("task", ["easy", "medium", "hard", "soc_easy", "soc_medium", "soc_hard"])
    def test_grade_returns_score_in_range(self, task):
        resp = client.post(f"/grade/{task}", json={
            "seed": 42,
            "cumulative_reward": 0.6,
            "steps_taken": 10,
            "episode_done": False,
            "root_causes_found": 0,
            "services_healthy": 0,
            "services_total": 3,
        })
        assert resp.status_code == 200
        score = resp.json()["score"]
        assert 0.0 <= score <= 1.0

    def test_grade_unknown_task_returns_404(self):
        resp = client.post("/grade/impossible_task", json={})
        assert resp.status_code == 404

    def test_grade_full_resolution_easy_scores_high(self):
        resp = client.post("/grade/easy", json={
            "seed": 42,
            "cumulative_reward": 0.8,
            "steps_taken": 6,
            "episode_done": True,
            "root_causes_found": 1,
            "services_healthy": 3,
            "services_total": 3,
            "escalated": False,
        })
        assert resp.status_code == 200
        score = resp.json()["score"]
        assert score >= 0.7

    def test_grade_nop_agent_scores_low(self):
        resp = client.post("/grade/hard", json={
            "seed": 42,
            "cumulative_reward": 0.0,
            "steps_taken": 40,
            "episode_done": True,
            "root_causes_found": 0,
            "services_healthy": 0,
            "services_total": 7,
            "escalated": False,
        })
        assert resp.status_code == 200
        score = resp.json()["score"]
        assert score < 0.3

    def test_grade_partial_fix_medium_intermediate_score(self):
        # Fixed 1 of 2 root causes
        resp = client.post("/grade/medium", json={
            "seed": 42,
            "cumulative_reward": 0.3,
            "steps_taken": 12,
            "episode_done": False,
            "root_causes_found": 1,
            "services_healthy": 3,
            "services_total": 5,
        })
        score = resp.json()["score"]
        assert 0.3 <= score <= 0.75

    def test_grade_is_deterministic(self):
        payload = {
            "seed": 42,
            "cumulative_reward": 0.6,
            "steps_taken": 8,
            "episode_done": True,
            "root_causes_found": 1,
            "services_healthy": 3,
            "services_total": 3,
        }
        s1 = client.post("/grade/easy", json=payload).json()["score"]
        s2 = client.post("/grade/easy", json=payload).json()["score"]
        assert s1 == s2

    def test_grade_response_has_expected_fields(self):
        resp = client.post("/grade/easy", json={"seed": 42}).json()
        for field in ("task", "score", "root_causes_found", "services_healthy",
                      "grader", "deterministic"):
            assert field in resp


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI / server not available")
class TestMetadataEndpoint:
    def test_metadata_returns_name(self):
        data = client.get("/metadata").json()
        assert "cloudops" in data["name"].lower() or "cloud" in data["name"].lower()

    def test_metadata_includes_tasks(self):
        data = client.get("/metadata").json()
        expected = {"easy", "medium", "hard", "soc_easy", "soc_medium", "soc_hard"}
        assert expected.issubset(set(data["tasks"]))

    def test_metadata_includes_secops_tags(self):
        data = client.get("/metadata").json()
        tags = data.get("tags", [])
        assert "secops" in tags or "soc" in tags


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI / server not available")
class TestSOCScenarios:
    """End-to-end episode tests for the three SOC Analyst tasks."""

    def _reset(self, task: str) -> tuple:
        resp = client.post("/reset", json={"task": task, "seed": 42})
        assert resp.status_code == 200
        data = resp.json()
        return data["session_id"], data["observation"]

    def _step(self, session_id: str, action: dict) -> dict:
        resp = client.post("/step", json={"action": action, "session_id": session_id})
        assert resp.status_code == 200
        return resp.json()["observation"]

    def test_soc_easy_reset_contains_alert(self):
        _sid, obs = self._reset("soc_easy")
        assert "185.220.101.45" in obs["situation_report"] or "SOC-2847" in obs["situation_report"]

    def test_soc_easy_lookup_threat_intel(self):
        sid, _obs = self._reset("soc_easy")
        obs = self._step(sid, {
            "action_type": "lookup_threat_intel",
            "parameters": {"ioc": "185.220.101.45", "ioc_type": "ip"},
        })
        assert "185.220.101.45" in obs["action_output"]
        assert "THREAT INTEL" in obs["action_output"].upper() or "Tor" in obs["action_output"]

    def test_soc_easy_full_resolution(self):
        sid, _obs = self._reset("soc_easy")
        # Investigate
        self._step(sid, {"action_type": "view_logs", "target": "bastion_host"})
        # Apply fix
        obs = self._step(sid, {
            "action_type": "apply_fix",
            "target": "bastion_host",
            "parameters": {"fix_type": "revoke_session", "config_key": "session_token"},
        })
        assert obs["reward"] > 0.0

    def test_soc_medium_reset_contains_c2_ip(self):
        _sid, obs = self._reset("soc_medium")
        report = obs["situation_report"]
        assert "162.243.103.246" in report or "SOC-3991" in report or "QakBot" in report

    def test_soc_medium_isolate_host_fix(self):
        sid, _obs = self._reset("soc_medium")
        self._step(sid, {"action_type": "view_logs", "target": "endpoint_security"})
        obs = self._step(sid, {
            "action_type": "apply_fix",
            "target": "endpoint_security",
            "parameters": {"fix_type": "isolate_host", "config_key": "ENG-WORKSTATION-47"},
        })
        assert obs["reward"] > 0.0

    def test_soc_hard_reset_contains_c2_ip(self):
        _sid, obs = self._reset("soc_hard")
        report = obs["situation_report"]
        assert "50.16.16.211" in report or "SOC-4128" in report or "APT" in report

    def test_soc_hard_terraform_blocks_c2(self):
        sid, _obs = self._reset("soc_hard")
        obs = self._step(sid, {
            "action_type": "write_terraform",
            "parameters": {
                "resource_type": "aws_network_acl",
                "config": "cidr=50.16.16.211/32 rule=DENY port=all action=block c2_ip=50.16.16.211",
            },
        })
        assert obs["reward"] > 0.0, f"Expected reward > 0, got {obs['reward']}: {obs['action_output']}"

    def test_lookup_clean_ip_returns_clean_verdict(self):
        sid, _obs = self._reset("soc_easy")
        obs = self._step(sid, {
            "action_type": "lookup_threat_intel",
            "parameters": {"ioc": "8.8.8.8", "ioc_type": "ip"},
        })
        assert "CLEAN" in obs["action_output"] or "not in" in obs["action_output"].lower()

    def test_lookup_empty_ioc_returns_error(self):
        sid, _obs = self._reset("soc_easy")
        obs = self._step(sid, {
            "action_type": "lookup_threat_intel",
            "parameters": {"ioc": "", "ioc_type": "ip"},
        })
        assert obs["reward"] == 0.0

    # ── Regression tests for critical bugs fixed in audit ─────────────────

    def test_soc_scenarios_have_root_causes_in_observation(self):
        """Regression: SOC scenarios were missing root_causes → rc_total was 0."""
        for task, expected_rc_total in [("soc_easy", 1), ("soc_medium", 2), ("soc_hard", 3)]:
            _sid, obs = self._reset(task)
            assert obs["root_causes_total"] == expected_rc_total, (
                f"{task}: expected root_causes_total={expected_rc_total}, "
                f"got {obs['root_causes_total']}"
            )

    def test_soc_easy_full_episode_resolves(self):
        """Regression: _all_resolved() always returned False for SOC tasks."""
        sid, _obs = self._reset("soc_easy")
        self._step(sid, {"action_type": "lookup_threat_intel",
                         "parameters": {"ioc": "185.220.101.45", "ioc_type": "ip"}})
        self._step(sid, {"action_type": "apply_fix", "target": "bastion_host",
                         "parameters": {"fix_type": "revoke_session", "config_key": "session_token"}})
        obs = self._step(sid, {"action_type": "verify", "target": "bastion_host"})
        assert obs["done"] is True, f"Episode should be done after all fixes: done={obs['done']}"
        assert obs["root_causes_found"] == 1

    def test_soc_apply_fix_uses_success_message(self):
        """Regression: _handle_apply_fix ignored success_message → generic output."""
        sid, _obs = self._reset("soc_easy")
        obs = self._step(sid, {
            "action_type": "apply_fix",
            "target": "bastion_host",
            "parameters": {"fix_type": "revoke_session", "config_key": "session_token"},
        })
        # SOC-2847 success_message should appear in the output
        assert "SOC-2847" in obs["action_output"] or "REMEDIATED" in obs["action_output"]

    def test_soc_hard_terraform_success_message(self):
        """Regression: write_terraform used hardcoded WAF message for all scenarios."""
        sid, _obs = self._reset("soc_hard")
        obs = self._step(sid, {
            "action_type": "write_terraform",
            "parameters": {
                "resource_type": "aws_network_acl",
                "config": "cidr=50.16.16.211/32 rule=DENY port=all 50.16.16.211",
            },
        })
        assert obs["reward"] > 0.0
        # Should NOT say "api_gateway" (that is the WAF/DDoS context, not SOC)
        assert "api_gateway" not in obs["action_output"].lower() or "C2" in obs["action_output"]

    def test_partial_fix_does_not_complete_episode(self):
        """Regression: episode must stay open when only 1/3 RCs are fixed."""
        sid, _obs = self._reset("soc_hard")
        # Fix only the first RC (active_c2_beacon → network_ids)
        self._step(sid, {
            "action_type": "write_terraform",
            "parameters": {
                "resource_type": "aws_network_acl",
                "config": "cidr=50.16.16.211/32 rule=DENY 50.16.16.211 block",
            },
        })
        obs = self._step(sid, {"action_type": "verify", "target": "network_ids"})
        # Episode must NOT be done — 2 root causes still open
        assert obs["done"] is False, "Episode must not be done with only 1/3 RCs fixed"
        assert obs["root_causes_found"] == 1
        assert obs["root_causes_total"] == 3

    def test_all_services_heal_when_all_rcs_fixed(self):
        """Regression: verifying after ALL RCs fixed must make all services healthy."""
        sid, _obs = self._reset("soc_easy")
        self._step(sid, {
            "action_type": "apply_fix",
            "target": "bastion_host",
            "parameters": {"fix_type": "revoke_session", "config_key": "session_token"},
        })
        obs = self._step(sid, {"action_type": "verify", "target": "bastion_host"})
        # All 2 services must be healthy — auth_service heals via full-recovery cascade
        assert obs["services_healthy"] == obs["services_total"], (
            f"Expected all services healthy, got {obs['services_healthy']}/{obs['services_total']}"
        )
        assert obs["done"] is True

    def test_hard_task_all_services_heal_on_final_verify(self):
        """Regression: hard task — all 6 services must heal when all 3 RCs fixed."""
        sid, _obs = self._reset("hard")
        self._step(sid, {"action_type": "write_terraform", "parameters": {
            "resource_type": "aws_wafv2_web_acl",
            "config": "ip_set_cidrs 203.0.113.0/24 198.51.100.0/24 192.0.2.0/24 block",
        }})
        self._step(sid, {"action_type": "apply_fix", "target": "auto_scaling",
                         "parameters": {"fix_type": "adjust_config", "config_key": "max_capacity", "config_value": "20"}})
        self._step(sid, {"action_type": "apply_fix", "target": "api_gateway",
                         "parameters": {"fix_type": "enable_rate_limiting", "config_key": "throttle", "config_value": "1000"}})
        obs = self._step(sid, {"action_type": "verify", "target": "api_gateway"})
        assert obs["services_healthy"] == obs["services_total"], (
            f"hard: expected 6/6 services healthy, got {obs['services_healthy']}/{obs['services_total']}"
        )
        assert obs["done"] is True
