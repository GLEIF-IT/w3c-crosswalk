"""Shared pytest options for explicit live W3C headless acceptance tests."""

from __future__ import annotations


def pytest_addoption(parser):
    """Register live-stack options without affecting ordinary unit tests."""
    parser.addoption("--w3c-stack", choices=("attach", "process", "docker"), default=None)
    parser.addoption("--manifest", default=None)
    parser.addoption("--manifest-out", default=None)
    parser.addoption("--keria-admin-url", default=None)
    parser.addoption("--keria-boot-url", default=None)
    parser.addoption("--qvi-alias", default=None)
    parser.addoption("--qvi-passcode", default=None)
    parser.addoption("--holder-alias", default=None)
    parser.addoption("--holder-passcode", default=None)
    parser.addoption("--source-credential-said", default=None)
    parser.addoption("--python-verifier-url", default=None)
    parser.addoption("--node-verifier-url", default=None)
    parser.addoption("--go-verifier-url", default=None)
    parser.addoption("--python-verifier-submission-url", default=None)
    parser.addoption("--node-verifier-submission-url", default=None)
    parser.addoption("--go-verifier-submission-url", default=None)
    parser.addoption("--dashboard-url", default=None)
    parser.addoption("--boot-if-needed", action="store_true", default=False)
    parser.addoption("--unsafe-raw-tokens", action="store_true", default=False)
    parser.addoption("--keep-stack", action="store_true", default=False)
    parser.addoption("--process-root", default=None)
    parser.addoption("--keria-bin", default=None)
    parser.addoption("--docker-project", default="w3c-crosswalk")
    parser.addoption("--env-file", default=None)
