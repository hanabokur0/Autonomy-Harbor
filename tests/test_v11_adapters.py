from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from personal_agent_runtime.adapters import (
    AdapterBinding,
    AdapterConflict,
    AdapterError,
    AdapterNotFound,
    AdapterRegistry,
    SandboxAdapter,
    build_adapter_registry,
)
from personal_agent_runtime.appliance import (
    issue_execution_permit,
    registry_dict,
    save_signer,
    trusted_signer_dict,
)
from personal_agent_runtime.appliance_services import executor_handler
from personal_agent_runtime.github_adapter import GitHubAdapter
from personal_agent_runtime.models import ActionRequest, CapabilityGrant, CapabilityRegistry, GateDecision
from personal_agent_runtime.verifiable import Ed25519Signer


class FakeTransport:
    def __init__(self, response: Mapping[str, Any] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response = dict(response or {})

    def request(self, *, method: str, url: str, headers: Mapping[str, str], json_body=None):
        self.calls.append({
            "method": method,
            "url": url,
            "headers": dict(headers),
            "json_body": None if json_body is None else dict(json_body),
        })
        return dict(self.response)


def _issue_request() -> ActionRequest:
    return ActionRequest(
        request_id="adapter-issue-001",
        capability="github.issue.create",
        action="create_issue",
        resource="hanabokur0/Autonomy-Harbor",
        payload={"title": "Adapter layer test", "body": "Created through a scoped adapter."},
        actor="repo-maintainer-agent",
    )


def test_adapter_registry_is_deterministic_and_authority_free(tmp_path: Path):
    registry = AdapterRegistry()
    registry.register(SandboxAdapter(tmp_path / "sandbox"))
    manifest = registry.manifest()
    assert manifest[0]["adapter_id"] == "sandbox"
    assert manifest[0]["authority_effect"] == "NONE"
    assert all("effect" not in binding for binding in manifest[0]["bindings"])


def test_duplicate_adapter_binding_is_rejected(tmp_path: Path):
    registry = AdapterRegistry()
    registry.register(SandboxAdapter(tmp_path / "one"))

    class ConflictingAdapter:
        adapter_id = "conflict"
        bindings = (AdapterBinding("filesystem.write", "write_text"),)
        def execute(self, request):
            return {}

    with pytest.raises(AdapterConflict, match="duplicate_adapter_binding"):
        registry.register(ConflictingAdapter())


def test_unknown_capability_has_no_fallback_adapter(tmp_path: Path):
    registry = build_adapter_registry(sandbox_root=tmp_path / "sandbox")
    request = ActionRequest(
        request_id="unknown-1",
        capability="bank.transfer",
        action="send",
        resource="account/1",
    )
    with pytest.raises(AdapterNotFound, match="adapter_not_found"):
        registry.execute(request)


def test_github_read_adapter_normalizes_response_without_token():
    transport = FakeTransport({
        "full_name": "hanabokur0/Autonomy-Harbor",
        "private": False,
        "default_branch": "main",
        "html_url": "https://github.com/hanabokur0/Autonomy-Harbor",
    })
    adapter = GitHubAdapter(transport=transport)
    request = ActionRequest(
        request_id="repo-read-1",
        capability="github.repo.read",
        action="get_repo",
        resource="hanabokur0/Autonomy-Harbor",
    )
    result = adapter.execute(request)
    assert result["repository_full_name"] == "hanabokur0/Autonomy-Harbor"
    assert transport.calls[0]["method"] == "GET"
    assert "Authorization" not in transport.calls[0]["headers"]


def test_github_write_requires_token_before_transport_call():
    transport = FakeTransport()
    adapter = GitHubAdapter(transport=transport)
    with pytest.raises(AdapterError, match="github_token_required"):
        adapter.execute(_issue_request())
    assert transport.calls == []


def test_github_issue_create_uses_token_but_never_returns_it():
    transport = FakeTransport({
        "number": 42,
        "state": "open",
        "title": "Adapter layer test",
        "html_url": "https://github.com/hanabokur0/Autonomy-Harbor/issues/42",
    })
    adapter = GitHubAdapter(token="secret-token", transport=transport)
    result = adapter.execute(_issue_request())
    assert result["issue_number"] == 42
    assert transport.calls[0]["method"] == "POST"
    assert transport.calls[0]["headers"]["Authorization"] == "Bearer secret-token"
    assert "secret-token" not in json.dumps(result)


def test_executor_refuses_adapter_before_permit_verification(tmp_path: Path, monkeypatch):
    gate = Ed25519Signer.generate(subject="runtime-gate")
    executor = save_signer(tmp_path / "executor.key", subject="runtime-executor")
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps([
        trusted_signer_dict(gate.trusted_record("execution_permit_issuer"))
    ]), encoding="utf-8")
    monkeypatch.setenv("AUTONOMY_HARBOR_GITHUB_TOKEN", "secret-token")
    config = {
        "trust_store": str(trust_path),
        "private_key": str(tmp_path / "executor.key"),
        "subject": "runtime-executor",
        "permit_replay_db": str(tmp_path / "permit.sqlite3"),
        "sandbox_root": str(tmp_path / "sandbox"),
        "adapters": [{"type": "github", "token_env": "AUTONOMY_HARBOR_GITHUB_TOKEN"}],
    }
    handle = executor_handler({}, config)
    response = None
    with pytest.raises(PermissionError, match="signed_execution_permit_required"):
        handle({"op": "execute", "request": {
            "request_id": _issue_request().request_id,
            "capability": _issue_request().capability,
            "action": _issue_request().action,
            "resource": _issue_request().resource,
            "payload": dict(_issue_request().payload),
            "actor": _issue_request().actor,
        }})
    assert response is None


def test_adapter_schema_declares_no_authority():
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas" / "adapter_manifest.schema.json").read_text(encoding="utf-8"))
    assert schema["properties"]["authority_effect"]["const"] == "NONE"
    docs = (root / "docs" / "ADAPTERS.md").read_text(encoding="utf-8")
    assert "Adapter != Authority" in docs
    assert "signed ExecutionPermit" in docs
