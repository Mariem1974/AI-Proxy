"""
Shared pytest configuration for AI-Proxy E2E tests.
Verifies the backend is reachable before any test runs.
"""

import pytest
import requests


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: marks tests as slow (skipped with -m 'not slow')")


def pytest_sessionstart(session):
    try:
        r = requests.get("http://localhost:5000/api/features", timeout=5)
        r.raise_for_status()
    except Exception as e:
        pytest.exit(
            f"\n\n❌ Backend not reachable at http://localhost:5000 — start it first.\n{e}\n",
            returncode=1,
        )
