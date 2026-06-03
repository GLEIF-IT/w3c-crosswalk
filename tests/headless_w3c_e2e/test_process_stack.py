"""Process-stack orchestration tests for live headless W3C E2E."""

from __future__ import annotations

from urllib.parse import quote

from headless_w3c_e2e.did_webs_resolver_service import did_webs_artifact_url, normalize_document
from headless_w3c_e2e.process_stack import ManagedProcessStack, ProcessStackPorts


def test_process_stack_reserves_distinct_ports():
    """Process mode should reserve a complete unique port set."""
    ports = ProcessStackPorts.reserve()
    values = [
        ports.keria_admin,
        ports.keria_http,
        ports.keria_boot,
        ports.vlei,
        ports.did_webs_resolver,
        ports.python_verifier,
        ports.node_verifier,
        ports.go_verifier,
        ports.dashboard,
    ]

    assert len(values) == len(set(values))


def test_process_stack_config_overrides_use_host_reachable_submission_urls(tmp_path):
    """KERIA and evidence polling both use localhost URLs in process mode."""
    ports = ProcessStackPorts(
        keria_admin=4101,
        keria_http=4102,
        keria_boot=4103,
        vlei=4723,
        did_webs_resolver=4678,
        python_verifier=4788,
        node_verifier=4789,
        go_verifier=4790,
        dashboard=4791,
    )
    stack = ManagedProcessStack(runtime_root=tmp_path, ports=ports)

    overrides = stack.config_overrides()

    assert overrides["admin_url"] == "http://127.0.0.1:4101"
    assert overrides["boot_url"] == "http://127.0.0.1:4103"
    assert overrides["verifierUrls"] == {
        "python": "http://127.0.0.1:4788",
        "node": "http://127.0.0.1:4789",
        "go": "http://127.0.0.1:4790",
    }
    assert overrides["verifierSubmissionUrls"] == overrides["verifierUrls"]


def test_process_stack_start_uses_real_service_commands(monkeypatch, tmp_path):
    """The supervisor should launch services, not verifier callables."""
    ports = ProcessStackPorts(
        keria_admin=4101,
        keria_http=4102,
        keria_boot=4103,
        vlei=4723,
        did_webs_resolver=4678,
        python_verifier=4788,
        node_verifier=4789,
        go_verifier=4790,
        dashboard=4791,
    )
    started: list[tuple[str, list[str]]] = []
    stack = ManagedProcessStack(runtime_root=tmp_path, ports=ports, keria_bin="/bin/keria")

    def fake_spawn(name, argv, **_kwargs):
        started.append((name, argv))

    monkeypatch.setattr(stack, "_spawn", fake_spawn)
    monkeypatch.setattr(stack, "_seed_wallets", lambda: None)
    monkeypatch.setattr("headless_w3c_e2e.process_stack._required_binary", lambda name: f"/bin/{name}")

    stack.start()

    names = [name for name, _argv in started]
    assert names == [
        "vlei",
        "keria",
        "did-webs-resolver",
        "isomer-dashboard",
        "isomer-python",
        "isomer-node",
        "isomer-go",
    ]
    assert any(argv[0].endswith("isomer") and argv[1:3] == ["verifier", "serve"] for _name, argv in started)
    assert any(argv[:3] == ["npm", "run", "serve"] for _name, argv in started)
    assert any(argv[:3] == ["go", "run", "./cmd/isomer-go"] for _name, argv in started)
    keria_argv = next(argv for name, argv in started if name == "keria")
    assert "--config-dir" in keria_argv
    assert "--config-file" in keria_argv
    assert any(
        argv[:3] == [stack.python_bin, "-m", "headless_w3c_e2e.did_webs_resolver_service"]
        for _name, argv in started
    )


def test_process_resolver_preserves_encoded_host_port_separator():
    """Raw resolver path DID values should map to the KERIA did:web artifact."""
    did = "did:webs:127.0.0.1%3A49965:dws:EGGM-R1"

    canonical, url = did_webs_artifact_url(did)

    assert canonical == did
    assert url == "http://127.0.0.1:49965/dws/EGGM-R1/did.json"


def test_process_resolver_decodes_hio_quoted_did_once():
    """HIO path quoting encodes the host port separator twice at transport."""
    did = "did:webs:127.0.0.1%3A49965:dws:EGGM-R1"
    path_did = quote(did)

    canonical, url = did_webs_artifact_url(path_did)

    assert canonical == did
    assert url == "http://127.0.0.1:49965/dws/EGGM-R1/did.json"


def test_process_resolver_tolerates_malformed_local_port_separator():
    """Local process mode should recover raw localhost port separators."""
    did = "did:webs:127.0.0.1:49965:dws:EGGM-R1"

    canonical, url = did_webs_artifact_url(did)

    assert canonical == did
    assert url == "http://127.0.0.1:49965/dws/EGGM-R1/did.json"


def test_process_resolver_dedupes_normalized_also_known_as():
    """Go rejects DID Documents with duplicate alsoKnownAs array entries."""
    source = "did:web:127.0.0.1%3A49965:dws:EGGM-R1"
    target = "did:webs:127.0.0.1%3A49965:dws:EGGM-R1"

    document = normalize_document(
        {
            "id": source,
            "alsoKnownAs": [source, target],
            "verificationMethod": [{"id": f"{source}#key-1", "controller": source}],
        },
        target,
    )

    assert document["alsoKnownAs"] == [target]
    assert document["verificationMethod"][0]["id"] == f"{target}#key-1"
    assert document["verificationMethod"][0]["controller"] == target
