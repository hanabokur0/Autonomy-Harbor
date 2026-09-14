from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

VALID_EFFECTS = frozenset({"ALLOW", "REVIEW", "DENY"})


def _freeze_mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return MappingProxyType(dict(value or {}))


@dataclass(frozen=True, slots=True)
class ActionRequest:
    request_id: str
    capability: str
    action: str
    resource: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    actor: str = "agent"

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id is required")
        if not self.capability.strip():
            raise ValueError("capability is required")
        if not self.action.strip():
            raise ValueError("action is required")
        if not self.resource.strip():
            raise ValueError("resource is required")
        object.__setattr__(self, "payload", _freeze_mapping(self.payload))


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    grant_id: str
    capability: str
    effect: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    issued_by: str = "human"
    note: str = ""

    def __post_init__(self) -> None:
        effect = self.effect.upper()
        if effect not in VALID_EFFECTS:
            raise ValueError(f"invalid effect: {self.effect}")
        if not self.grant_id.strip():
            raise ValueError("grant_id is required")
        if not self.capability.strip():
            raise ValueError("capability is required")
        if not self.actions:
            raise ValueError("at least one action is required")
        if not self.resources:
            raise ValueError("at least one resource is required")
        object.__setattr__(self, "effect", effect)
        object.__setattr__(self, "actions", tuple(self.actions))
        object.__setattr__(self, "resources", tuple(self.resources))


@dataclass(frozen=True, slots=True)
class CapabilityRegistry:
    registry_id: str
    version: str
    grants: tuple[CapabilityGrant, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "grants", tuple(self.grants))


@dataclass(frozen=True, slots=True)
class GateDecision:
    verdict: str
    reason: str
    matched_grant_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ActionReceipt:
    receipt_version: str
    request_id: str
    capability: str
    action: str
    resource: str
    gate: str
    gate_reason: str
    matched_grant_ids: tuple[str, ...]
    outcome: str
    result: Mapping[str, Any]
    registry_id: str
    registry_version: str
    created_at: str
    previous_receipt_hash: str | None
    receipt_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "matched_grant_ids", tuple(self.matched_grant_ids))
        object.__setattr__(self, "result", _freeze_mapping(self.result))
