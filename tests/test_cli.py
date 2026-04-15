"""CLI contract tests for the nested crosswalk command tree."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from hio.base import doing

from w3c_crosswalk.cli import main


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class _CompletedVerifyDoer(doing.Doer):
    """Tiny fake verifier doer for CLI tests."""

    def __init__(self, *, error=None, operation=None):
        self.ran = False
        self.error = error
        self.operation = operation
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


def test_cli_issue_vc_can_write_raw_token_file(monkeypatch, tmp_path, capsys):
    """Allow `issue vc` to emit both the JSON artifact and raw token file."""
    fixture = tmp_path / "source-acdc.json"
    output = tmp_path / "vc.json"
    token_output = tmp_path / "vc.token"
    fixture.write_text(json.dumps({"d": "Efake"}), encoding="utf-8")

    class FakeSigner:
        kid = "fake#key"
        public_jwk = {"kty": "OKP"}

        def close(self):
            pass

    fake_artifact = SimpleNamespace(
        token="header.payload.signature",
        to_dict=lambda: {"ok": True, "kind": "vc+jwt", "token": "header.payload.signature"},
    )

    monkeypatch.setattr("w3c_crosswalk.cli.issue.vc.KeriHabSigner.open", lambda **_: FakeSigner())
    monkeypatch.setattr("w3c_crosswalk.cli.issue.vc.issue_vc_artifact", lambda **_: fake_artifact)

    exit_code = main(
        [
            "issue",
            "vc",
            "--acdc",
            str(fixture),
            "--issuer-did",
            "did:webs:example.com:dws:Efake",
            "--status-base-url",
            "http://status.example",
            "--name",
            "qvi",
            "--alias",
            "qvi",
            "--passcode",
            "0123456789abcdefghijk",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["kind"] == "vc+jwt"
    assert token_output.read_text(encoding="utf-8") == "header.payload.signature"
    assert captured.out.splitlines() == [f"vc: {output}", f"jwt: {token_output}"]


def test_cli_verify_vc_runs_operation_without_emitting_terminal_json(monkeypatch, capsys):
    """Run one verifier doer and print a compact success message."""
    seen = {}
    fake_doer = _CompletedVerifyDoer(
        operation={
            "done": True,
            "response": {
                "ok": True,
                "payload": {
                    "type": ["VerifiableCredential", "VRDCredential"],
                    "id": "urn:said:Ecredential",
                    "issuer": "did:webs:issuer",
                },
            },
        }
    )

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
    assert capsys.readouterr().out.strip() == (
        "verified vc+jwt: \n"
        "type=VRDCredential \n"
        "id=urn:said:Ecredential \n"
        "issuer=did:webs:issuer"
    )


def test_cli_verify_vp_reports_success_summary(monkeypatch, capsys):
    """Print holder and embedded credential count after successful VP verification."""
    fake_doer = _CompletedVerifyDoer(
        operation={
            "done": True,
            "response": {
                "ok": True,
                "payload": {"holder": "did:webs:holder"},
                "checks": {"embeddedCredentialCount": 1},
            },
        }
    )
    monkeypatch.setattr("w3c_crosswalk.cli.verify.vp.verify_vp_doer", lambda **_: fake_doer)

    exit_code = main(["verify", "vp", "--token", "inline-token", "--server", "http://verifier.example"])

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == (
        "verified vp+jwt: \n"
        "holder=did:webs:holder \n"
        "embeddedCredentials=1"
    )


def test_cli_verify_pair_reports_success_summary(monkeypatch, tmp_path, capsys):
    """Print credential type and source/VC identifiers after successful pair verification."""
    acdc = tmp_path / "acdc.json"
    acdc.write_text(json.dumps({"d": "Ecredential"}), encoding="utf-8")
    fake_doer = _CompletedVerifyDoer(
        operation={
            "done": True,
            "response": {
                "ok": True,
                "payload": {
                    "type": ["VerifiableCredential", "VRDCredential"],
                    "id": "urn:said:Ecredential",
                    "crosswalk": {"sourceCredentialSaid": "Ecredential"},
                },
            },
        }
    )
    monkeypatch.setattr("w3c_crosswalk.cli.verify.pair.verify_pair_doer", lambda **_: fake_doer)

    exit_code = main(
        [
            "verify",
            "pair",
            "--acdc",
            str(acdc),
            "--token",
            "inline-token",
            "--server",
            "http://verifier.example",
        ]
    )

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == (
        "verified crosswalk pair: \n"
        "type=VRDCredential \n"
        "source=Ecredential \n"
        "vc=urn:said:Ecredential"
    )


def test_cli_verify_reports_doer_error(monkeypatch, capsys):
    """Print a compact verifier API error instead of dumping operation JSON."""
    monkeypatch.setattr(
        "w3c_crosswalk.cli.verify.vc.verify_vc_doer",
        lambda **_: _CompletedVerifyDoer(error=RuntimeError("verification request failed: could not connect")),
    )

    exit_code = main(["verify", "vc", "--token", "inline-token", "--server", "http://verifier.example"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() == "verification request failed: could not connect"


def test_cli_verify_reports_timeout(monkeypatch, capsys):
    """Print verifier timeout errors without exposing full operation resources."""
    monkeypatch.setattr(
        "w3c_crosswalk.cli.verify.vc.verify_vc_doer",
        lambda **_: _CompletedVerifyDoer(error=TimeoutError("timed out waiting for operation verify-vc.1")),
    )

    exit_code = main(["verify", "vc", "--token", "inline-token", "--server", "http://verifier.example"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() == "timed out waiting for operation verify-vc.1"


def test_cli_verify_reports_terminal_operation_error(monkeypatch, capsys):
    """Print terminal operation error messages in a short human form."""
    monkeypatch.setattr(
        "w3c_crosswalk.cli.verify.vc.verify_vc_doer",
        lambda **_: _CompletedVerifyDoer(error=RuntimeError("verification failed: invalid token")),
    )

    exit_code = main(["verify", "vc", "--token", "inline-token", "--server", "http://verifier.example"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() == "verification failed: invalid token"


def test_cli_verify_reports_not_ok_response(monkeypatch, capsys):
    """Print the first verifier response error for ok=false results."""
    monkeypatch.setattr(
        "w3c_crosswalk.cli.verify.vc.verify_vc_doer",
        lambda **_: _CompletedVerifyDoer(error=RuntimeError("verification failed: credential is revoked")),
    )

    exit_code = main(["verify", "vc", "--token", "inline-token", "--server", "http://verifier.example"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() == "verification failed: credential is revoked"


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
