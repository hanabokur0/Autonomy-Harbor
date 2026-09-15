"""MCP inbound adapter for Autonomy Harbor.

MCP is an ingress surface, not an authority source. Tool calls are converted
into ActionRequests and sent through the existing Appliance path:

    MCP -> Planner -> Gate -> ExecutionPermit -> Executor -> Adapter -> Verifier

The MCP process never issues review leases and never mutates the capability
registry. A pre-existing *signed* review lease may be presented as data for a
REVIEW request; the Gate independently verifies and consumes it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Mapping

from .appliance import UnixJsonClient, registry_from_dict
from .appliance_services import load_profile
from .gate import CapabilityGate
from .models import ActionRequest, CapabilityRegistry

DEFAULT_APPLIANCE_PROFILE = ".par-appliance/config/appliance_profile.json"
DEFAULT_RECEIPTS_LOG = ".par-appliance/state/mcp/finalized_receipts.jsonl"
DEFAULT_ACTOR = "mcp-agent"


class FinalizedReceiptLog:
    """Local mirror of independently verified final receipts only.

    REVIEW and DENY requests are intentionally not represented as final action
    receipts here because no Executor/Verifier execution path occurred.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def append(self, receipt: Mapping[str, Any]) -> None:
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(dict(receipt), ensure_ascii=False, sort_keys=True) + "\n")

    def tail(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self._path.is_file():
            return []
        with self._lock:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        values = [json.loads(line) for line in lines if line.strip()]
        return values[-max(1, min(int(limit), 200)):]

    def find(self, request_id: str) -> dict[str, Any] | None:
        if not self._path.is_file():
            return None
        with self._lock:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            if not line.strip():
                continue
            value = json.loads(line)
            if value.get("request_id") == request_id:
                return value
        return None


class HarborMCPBridge:
    """Inbound MCP bridge to an already-running Autonomy Harbor appliance."""

    def __init__(
        self,
        *,
        profile_path: str | Path,
        actor: str = DEFAULT_ACTOR,
        receipt_log: FinalizedReceiptLog | None = None,
        client_factory: Callable[..., Any] = UnixJsonClient,
    ) -> None:
        if not actor.strip():
            raise ValueError("mcp_actor_required")
        self._actor = actor.strip()
        self._profile_path = Path(profile_path)
        self._profile = load_profile(self._profile_path)
        self._receipt_log = receipt_log
        self._client_factory = client_factory
        self._registry = self._load_registry()
        self._gate = CapabilityGate()

        services = self._profile.get("services", {})
        required = ("planner", "gate", "executor", "verifier")
        missing = [role for role in required if role not in services or not services[role].get("socket")]
        if missing:
            raise ValueError(f"mcp_profile_missing_services:{','.join(missing)}")

    @property
    def actor(self) -> str:
        return self._actor

    @property
    def registry(self) -> CapabilityRegistry:
        return self._registry

    def _load_registry(self) -> CapabilityRegistry:
        gate = dict(self._profile.get("services", {}).get("gate", {}))
        registry_path = gate.get("registry")
        if not registry_path:
            raise ValueError("mcp_profile_gate_registry_missing")
        raw = json.loads(Path(registry_path).read_text(encoding="utf-8"))
        return registry_from_dict(raw)

    def _client(self, role: str):
        socket_path = self._profile["services"][role]["socket"]
        return self._client_factory(socket_path)

    def list_capability_grants(self) -> list[dict[str, Any]]:
        return [
            {
                "grant_id": grant.grant_id,
                "capability": grant.capability,
                "effect": grant.effect,
                "actions": list(grant.actions),
                "resources": list(grant.resources),
                "issued_by": grant.issued_by,
                "note": grant.note,
            }
            for grant in self._registry.grants
        ]

    def check_capability(self, capability: str, action: str, resource: str) -> dict[str, Any]:
        request = ActionRequest(
            request_id="__mcp_dry_run__",
            capability=capability,
            action=action,
            resource=resource,
            actor=self._actor,
        )
        decision = self._gate.evaluate(request, self._registry)
        return {
            "verdict": decision.verdict,
            "reason": decision.reason,
            "matched_grant_ids": list(decision.matched_grant_ids),
        }

    def submit_action_request(
        self,
        *,
        request_id: str,
        capability: str,
        action: str,
        resource: str,
        payload: Mapping[str, Any] | None = None,
        signed_review_lease: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submit via Planner -> Gate -> Permit -> Executor -> Verifier.

        The actor is operator-configured on the bridge and is deliberately not
        accepted as a model/tool argument.
        """
        intent = {
            "request_id": request_id,
            "capability": capability,
            "action": action,
            "resource": resource,
            "payload": dict(payload or {}),
            "actor": self._actor,
        }
        planned = self._client("planner").call({"op": "propose", "intent": intent})
        request = planned["request"]

        gate_message: dict[str, Any] = {"op": "authorize", "request": request}
        if signed_review_lease is not None:
            gate_message["signed_review_lease"] = dict(signed_review_lease)
        gated = self._client("gate").call(gate_message)
        decision = dict(gated["decision"])

        if decision.get("verdict") != "ALLOW":
            return {
                "status": "NOT_EXECUTED",
                "gate": decision,
                "base_decision": gated.get("base_decision"),
                "receipt": None,
                "note": "REVIEW/DENY remains inside the Harbor; MCP cannot issue approval.",
            }

        permit = gated.get("execution_permit")
        if not permit:
            raise RuntimeError("gate_allowed_without_execution_permit")

        executed = self._client("executor").call(
            {"op": "execute", "request": request, "execution_permit": permit}
        )
        if executed.get("executed") is not True:
            return {
                "status": "EXECUTION_REJECTED",
                "gate": decision,
                "reason": executed.get("reason"),
                "receipt": None,
            }

        signed_result = executed.get("signed_execution_result")
        if not signed_result:
            raise RuntimeError("executor_missing_signed_result")

        finalized = self._client("verifier").call(
            {
                "op": "finalize",
                "request": request,
                "execution_permit": permit,
                "signed_execution_result": signed_result,
            }
        )
        if finalized.get("verified") is not True:
            raise RuntimeError("verifier_failed_to_finalize")

        receipt = dict(finalized["receipt"])
        if self._receipt_log is not None:
            self._receipt_log.append(receipt)
        return {
            "status": "VERIFIED",
            "gate": decision,
            "outcome": receipt.get("outcome"),
            "result": receipt.get("result", {}),
            "receipt": receipt,
            "signed_receipt": finalized.get("signed_receipt"),
        }

    def list_receipts(self, limit: int = 20) -> list[dict[str, Any]]:
        if self._receipt_log is None:
            return []
        return self._receipt_log.tail(limit)

    def get_receipt(self, request_id: str) -> dict[str, Any] | None:
        if self._receipt_log is None:
            return None
        return self._receipt_log.find(request_id)


def build_server():
    """Build an MCP v2 server lazily so core installs do not require MCP."""
    try:
        from mcp.server import MCPServer
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError('MCP support is optional; install with: pip install -e ".[mcp]"') from exc

    profile_path = Path(os.environ.get("PAR_MCP_APPLIANCE_PROFILE", DEFAULT_APPLIANCE_PROFILE))
    actor = os.environ.get("PAR_MCP_ACTOR", DEFAULT_ACTOR)
    receipt_path = Path(os.environ.get("PAR_MCP_RECEIPTS_LOG", DEFAULT_RECEIPTS_LOG))
    bridge = HarborMCPBridge(
        profile_path=profile_path,
        actor=actor,
        receipt_log=FinalizedReceiptLog(receipt_path),
    )

    mcp = MCPServer(
        "autonomy-harbor",
        instructions=(
            "This is an inbound adapter to Autonomy Harbor. MCP tool calls can propose "
            "actions, but cannot grant authority, issue review leases, mutate the registry, "
            "or bypass the signed ExecutionPermit path."
        ),
    )

    @mcp.tool()
    def list_capability_grants() -> list[dict[str, Any]]:
        """Read the active Capability Registry. This grants no authority."""
        return bridge.list_capability_grants()

    @mcp.tool()
    def check_capability(capability: str, action: str, resource: str) -> dict[str, Any]:
        """Dry-run the deterministic Gate locally. No permit is issued and nothing executes."""
        return bridge.check_capability(capability, action, resource)

    @mcp.tool()
    def submit_action_request(
        request_id: str,
        capability: str,
        action: str,
        resource: str,
        payload: dict[str, Any] | None = None,
        signed_review_lease: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submit an action proposal through the Harbor appliance.

        REVIEW does not execute. A signed review lease may be supplied only if
        it was issued by the separate human authority surface; this server has
        no lease-issuance capability.
        """
        return bridge.submit_action_request(
            request_id=request_id,
            capability=capability,
            action=action,
            resource=resource,
            payload=payload,
            signed_review_lease=signed_review_lease,
        )

    @mcp.tool()
    def list_receipts(limit: int = 20) -> list[dict[str, Any]]:
        """List finalized, independently verified action receipts mirrored by this MCP ingress."""
        return bridge.list_receipts(limit)

    @mcp.tool()
    def get_receipt(request_id: str) -> dict[str, Any] | None:
        """Get the latest finalized verified receipt for a request ID."""
        return bridge.get_receipt(request_id)

    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
