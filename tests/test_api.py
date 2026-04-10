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
        assert set(env_info["tasks"]) == {"easy", "medium", "hard"}


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI / server not available")
class TestTasksEndpoint:
    def test_tasks_returns_three_tasks(self):
        data = client.get("/tasks").json()
        assert len(data["tasks"]) == 3

    def test_tasks_have_correct_difficulty_labels(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["easy"]["difficulty"] == "easy"
        assert tasks["medium"]["difficulty"] == "medium"
        assert tasks["hard"]["difficulty"] == "hard"

    def test_task_max_steps_easy_is_15(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["easy"]["max_steps"] == 15

    def test_task_max_steps_medium_is_25(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["medium"]["max_steps"] == 25

    def test_task_max_steps_hard_is_40(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["hard"]["max_steps"] == 40

    def test_task_root_causes_easy_is_1(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["easy"]["root_causes"] == 1

    def test_task_root_causes_medium_is_2(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["medium"]["root_causes"] == 2

    def test_task_root_causes_hard_is_3(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["hard"]["root_causes"] == 3

    def test_task_services_easy_is_2(self):
        tasks = {t["id"]: t for t in client.get("/tasks").json()["tasks"]}
        assert tasks["easy"]["services"] == 2


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI / server not available")
class TestSchemaEndpoint:
    def test_schema_returns_action_observation_state(self):
        data = client.get("/schema").json()
        assert "action" in data
        assert "observation" in data
        assert "state" in data


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI / server not available")
class TestGraderEndpoint:
    @pytest.mark.parametrize("task", ["easy", "medium", "hard"])
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
        assert "aiops" in data["name"].lower() or "incident" in data["name"].lower()

    def test_metadata_includes_tasks(self):
        data = client.get("/metadata").json()
        assert set(data["tasks"]) == {"easy", "medium", "hard"}
