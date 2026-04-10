"""Lightweight smoke test for the IncidentResponseEnv sync client wrapper."""
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_client_import():
    """Client module must import without error."""
    from client import IncidentResponseEnv  # noqa: F401


def test_client_context_manager_requires_await():
    """Calling _require_client outside async context raises RuntimeError."""
    from client import IncidentResponseEnv
    env = IncidentResponseEnv()
    with pytest.raises(RuntimeError, match="async context manager"):
        env._require_client()
