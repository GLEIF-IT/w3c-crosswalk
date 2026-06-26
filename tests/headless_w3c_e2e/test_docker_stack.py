"""Docker-stack orchestration tests for live headless W3C E2E."""

from __future__ import annotations

import subprocess

import pytest

from headless_w3c_e2e import docker_stack
from headless_w3c_e2e.docker_stack import ManagedDockerStack


def test_docker_stack_config_overrides_use_host_and_container_urls(tmp_path):
    """Docker mode should poll host ports and submit from KERIA to service DNS."""
    stack = ManagedDockerStack(repo_root=tmp_path, env_file=tmp_path / ".env")

    overrides = stack.config_overrides()

    assert overrides["admin_url"] == "http://127.0.0.1:3901"
    assert overrides["boot_url"] == "http://127.0.0.1:3903"
    assert overrides["verifierUrls"] == {
        "python": "http://127.0.0.1:8788",
        "node": "http://127.0.0.1:8789",
        "go": "http://127.0.0.1:8790",
    }
    assert overrides["verifierSubmissionUrls"] == {
        "python": "http://isomer-python:8788",
        "node": "http://isomer-node:8788",
        "go": "http://isomer-go:8788",
    }
    assert overrides["dashboardUrl"] == "http://127.0.0.1:8791"


def test_docker_stack_start_uses_compose_and_real_seed_service(monkeypatch, tmp_path):
    """The supervisor should launch compose services and the seeder container."""
    (tmp_path / ".env").write_text("KERIA_IMAGE=test\n", encoding="utf-8")
    stack = ManagedDockerStack(repo_root=tmp_path, env_file=tmp_path / ".env", keep_stack=True)
    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        if command[-3:] == ["run", "--rm", "signifypy-seed"]:
            stack.manifest_path.parent.mkdir(parents=True, exist_ok=True)
            stack.manifest_path.write_text("{}", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(stack, "_wait_for_stack_health", lambda: None)

    stack.start()

    assert any(command[-3:] == ["--profile", "seed", "config"] for command in commands)
    assert any(command[-2:] == ["up", "-d"] for command in commands)
    assert any(command[-3:] == ["run", "--rm", "signifypy-seed"] for command in commands)
    assert all("compose" in command for command in commands)


def test_witness_oobi_health_requires_endpoint_replies(monkeypatch):
    """Witness readiness requires curls-derived end-role and loc-scheme replies."""
    payload = b'{"v":"KERI10JSON0000fd_","t":"icp"}'

    monkeypatch.setattr(docker_stack, "urlopen", lambda *_args, **_kwargs: FakeResponse(payload))

    with pytest.raises(ValueError, match="end role reply, loc scheme reply, Docker witness curl"):
        docker_stack._check_witness_oobi(
            "wan",
            "http://127.0.0.1:5642/oobi/test",
            "http://witness-demo:5642/",
        )


def test_witness_oobi_health_accepts_curls_backed_introduction(monkeypatch):
    """A usable witness OOBI includes KEL, end-role, loc-scheme, and witness URL."""
    payload = (
        b'{"v":"KERI10JSON0000fd_","t":"icp"}'
        b'{"v":"KERI10JSON00011c_","t":"rpy","r":"/loc/scheme","a":{"url":"http://witness-demo:5642/"}}'
        b'{"v":"KERI10JSON00011c_","t":"rpy","r":"/end/role/add","a":{"role":"controller"}}'
    )

    monkeypatch.setattr(docker_stack, "urlopen", lambda *_args, **_kwargs: FakeResponse(payload))

    docker_stack._check_witness_oobi(
        "wan",
        "http://127.0.0.1:5642/oobi/test",
        "http://witness-demo:5642/",
    )


class FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json+cesr"}

    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_exc_info):
        return False

    def read(self) -> bytes:
        return self.body
