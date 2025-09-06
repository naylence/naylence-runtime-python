"""
Configuration and fixtures for Fame fabric integration tests.
"""

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def integration_test_dir():
    """Return the integration test directory path."""
    return Path(__file__).parent
