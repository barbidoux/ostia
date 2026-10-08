"""The isolated gate pytest runs with no ini file: register the markers the P1 tests use."""

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "req(*ids): requirement ids proven by the test")
    config.addinivalue_line("markers", "bench: needs real hardware on the Debian bench")
