"""CLI contract tests for the nested crosswalk command tree."""

from __future__ import annotations

import json
from pathlib import Path

from hio.base import doing

from w3c_crosswalk.cli import main


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class _CompletedVerifyDoer(doing.Doer):
    """Tiny fake verifier doer for CLI tests."""

    def __init__(self):
        self.ran = False
        super().__init__()

    def recur(self, tyme):
        self.ran = True
        return True


def test_cli_status_project_uses_nested_command_tree(tmp_path, capsys):
    """Project status through `crosswalk status project` and emit the new route shape."""
    fixture = FIXTURES / "vrd-acdc.json"
    store = tmp_path / "status-store.json"

    exit_code = main(
        [
            "status",
            "project",
            "--acdc",
            str(fixture),
            "--issuer-did",
            "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001",
            "--store",
            str(store),
            "--base-url",
            "http://status.example",
        ]
    )

    captured = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert captured["id"].startswith("http://status.example/status/")


def test_cli_verify_vc_runs_operation_without_emitting_terminal_json(monkeypatch, capsys):
    """Run one verifier doer without adding a separate completion reporter."""
    seen = {}
    fake_doer = _CompletedVerifyDoer()

    def fake_verify_vc_doer(*, base_url, token, timeout, poll_interval, clienter=None, tock=0.03125):
        seen["server"] = base_url
        seen["token"] = token
        seen["wait"] = {"timeout": timeout, "poll": poll_interval}
        return fake_doer

    monkeypatch.setattr("w3c_crosswalk.cli.verify.vc.verify_vc_doer", fake_verify_vc_doer)

    exit_code = main(
        [
            "verify",
            "vc",
            "--token",
            "inline-token",
            "--server",
            "http://verifier.example",
        ]
    )

    assert exit_code == 0
    assert fake_doer.ran is True
    assert seen["server"] == "http://verifier.example"
    assert seen["token"] == "inline-token"
    assert capsys.readouterr().out == ""


def test_cli_serve_status_returns_service_doers(monkeypatch):
    """Dispatch the nested serve status command into the doer-assembly path."""
    seen = {}

    def fake_setup_status_doers(config):
        seen["config"] = config
        return object(), []

    monkeypatch.setattr("w3c_crosswalk.cli.serve.status.setup_status_doers", fake_setup_status_doers)

    exit_code = main(
        [
            "serve",
            "status",
            "--host",
            "127.0.0.1",
            "--port",
            "8899",
            "--store",
            "/tmp/status-store.json",
            "--base-url",
            "http://status.example",
        ]
    )

    assert exit_code == 0
    assert seen["config"].port == 8899
    assert seen["config"].store_path == "/tmp/status-store.json"


def test_cli_serve_verifier_returns_service_doers(monkeypatch):
    """Dispatch the nested serve verifier command into the doer-assembly path."""
    seen = {}

    def fake_setup_verifier_doers(config):
        seen["config"] = config
        return object(), []

    monkeypatch.setattr("w3c_crosswalk.cli.serve.verifier.setup_verifier_doers", fake_setup_verifier_doers)

    exit_code = main(
        [
            "serve",
            "verifier",
            "--host",
            "127.0.0.1",
            "--port",
            "8898",
            "--resolver",
            "http://resolver.example/1.0/identifiers",
            "--operation-root",
            "/tmp/crosswalk-opr",
        ]
    )

    assert exit_code == 0
    assert seen["config"].port == 8898
    assert seen["config"].resolver_url == "http://resolver.example/1.0/identifiers"


def test_cli_serve_verifier_worker_returns_worker_doers(monkeypatch):
    """Dispatch the nested serve verifier-worker command into worker doer assembly."""
    seen = {}

    def fake_setup_verifier_worker_doers(config):
        seen["config"] = config
        return []

    monkeypatch.setattr("w3c_crosswalk.cli.serve.verifier_worker.setup_verifier_worker_doers", fake_setup_verifier_worker_doers)

    exit_code = main(
        [
            "serve",
            "verifier-worker",
            "--host",
            "127.0.0.1",
            "--port",
            "8898",
            "--resolver",
            "http://resolver.example/1.0/identifiers",
            "--operation-root",
            "/tmp/crosswalk-opr",
        ]
    )

    assert exit_code == 0
    assert seen["config"].port == 8898
    assert seen["config"].resolver_url == "http://resolver.example/1.0/identifiers"
