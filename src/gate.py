from __future__ import annotations

from fnmatch import fnmatchcase

from .models import ActionRequest, CapabilityGrant, CapabilityRegistry, GateDecision

PROTECTED_CAPABILITY_PREFIXES = (
    "runtime.permission.",
    "runtime.registry.",
    "runtime.gate.",
    "runtime.policy.",
)


class CapabilityGate:
    """Deterministic gate. It never infers authority from model output."""

    def evaluate(self, request: ActionRequest, registry: CapabilityRegistry) -> GateDecision:
        if request.capability.startswith(PROTECTED_CAPABILITY_PREFIXES):
            return GateDecision(
                verdict="DENY",
                reason="control_plane_capability_is_not_agent_addressable",
            )

        matches = tuple(
            grant
            for grant in registry.grants
            if self._matches(grant, request)
        )

        if not matches:
            return GateDecision(
                verdict="DENY",
                reason="no_matching_capability_grant",
            )

        denies = tuple(g.grant_id for g in matches if g.effect == "DENY")
        if denies:
            return GateDecision(
                verdict="DENY",
                reason="explicit_deny_precedence",
                matched_grant_ids=denies,
            )

        reviews = tuple(g.grant_id for g in matches if g.effect == "REVIEW")
        if reviews:
            return GateDecision(
                verdict="REVIEW",
                reason="human_review_required",
                matched_grant_ids=reviews,
            )

        allows = tuple(g.grant_id for g in matches if g.effect == "ALLOW")
        if allows:
            return GateDecision(
                verdict="ALLOW",
                reason="explicit_capability_grant",
                matched_grant_ids=allows,
            )

        return GateDecision(verdict="DENY", reason="no_effective_grant")

    @staticmethod
    def _matches(grant: CapabilityGrant, request: ActionRequest) -> bool:
        if not fnmatchcase(request.capability, grant.capability):
            return False
        if not any(fnmatchcase(request.action, pattern) for pattern in grant.actions):
            return False
        if not any(fnmatchcase(request.resource, pattern) for pattern in grant.resources):
            return False
        return True
