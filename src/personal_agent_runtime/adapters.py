from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Mapping, Protocol

from .executor import SandboxedExecutor
from .models import ActionRequest


class AdapterError(RuntimeError):
    pass


class AdapterNotFound(AdapterError):
    pass


class AdapterConflict(AdapterError):
    pass


@dataclass(frozen=True, slots=True)
class AdapterBinding:
    capability: str
    action: str

    def __post_init__(self) -> None:
        if not self.capability.strip() or not self.action.strip():
            raise ValueError("adapter_binding_requires_capability_and_action")


@dataclass(frozen=True, slots=True)
class AdapterDispatchResult:
    adapter_id: str
    output: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"adapter_id": self.adapter_id, "output": dict(self.output)}


class ExecutionAdapter(Protocol):
    adapter_id: str
    bindings: tuple[AdapterBinding, ...]

    def execute(self, request: ActionRequest) -> Mapping[str, Any]: ...


class AdapterRegistry:
    """Deterministic adapter dispatch only. This registry grants no authority."""

    def __init__(self) -> None:
        self._by_binding: dict[tuple[str, str], ExecutionAdapter] = {}
        self._ids: set[str] = set()

    def register(self, adapter: ExecutionAdapter) -> None:
        adapter_id = str(adapter.adapter_id).strip()
        if not adapter_id:
            raise ValueError("adapter_id_required")
        if adapter_id in self._ids:
            raise AdapterConflict(f"duplicate_adapter_id:{adapter_id}")
        if not adapter.bindings:
            raise ValueError("adapter_requires_at_least_one_binding")
        pending: list[tuple[str, str]] = []
        for binding in adapter.bindings:
            key = (binding.capability, binding.action)
            if key in self._by_binding or key in pending:
                raise AdapterConflict(f"duplicate_adapter_binding:{binding.capability}:{binding.action}")
            pending.append(key)
        self._ids.add(adapter_id)
        for key in pending:
            self._by_binding[key] = adapter

    def resolve(self, request: ActionRequest) -> ExecutionAdapter:
        adapter = self._by_binding.get((request.capability, request.action))
        if adapter is None:
            raise AdapterNotFound(
                f"adapter_not_found:{request.capability}:{request.action}"
            )
        return adapter

    def execute(self, request: ActionRequest) -> AdapterDispatchResult:
        adapter = self.resolve(request)
        output = adapter.execute(request)
        return AdapterDispatchResult(adapter_id=adapter.adapter_id, output=dict(output))

    def manifest(self) -> list[dict[str, Any]]:
        result: dict[str, list[dict[str, str]]] = {}
        for (capability, action), adapter in sorted(self._by_binding.items()):
            result.setdefault(adapter.adapter_id, []).append(
                {"capability": capability, "action": action}
            )
        return [
            {
                "adapter_id": adapter_id,
                "bindings": bindings,
                "authority_effect": "NONE",
            }
            for adapter_id, bindings in sorted(result.items())
        ]


class SandboxAdapter:
    adapter_id = "sandbox"
    bindings = (
        AdapterBinding("tool.echo", "echo"),
        AdapterBinding("filesystem.read", "read_text"),
        AdapterBinding("filesystem.write", "write_text"),
    )

    def __init__(self, root: Path) -> None:
        self._executor = SandboxedExecutor(root)

    def execute(self, request: ActionRequest) -> Mapping[str, Any]:
        return self._executor.execute(request)


def build_adapter_registry(
    *,
    sandbox_root: str | Path,
    config: Mapping[str, Any] | None = None,
) -> AdapterRegistry:
    """Build executor-side adapters from non-secret config.

    Secret values are resolved from environment variables inside the executor process.
    Adapter configuration does not alter Harbor capability policy.
    """
    registry = AdapterRegistry()
    registry.register(SandboxAdapter(Path(sandbox_root)))

    for item in list((config or {}).get("adapters", [])):
        if not isinstance(item, Mapping):
            raise ValueError("adapter_config_item_must_be_object")
        if item.get("enabled", True) is not True:
            continue
        adapter_type = str(item.get("type", "")).strip().lower()
        if adapter_type == "github":
            from .github_adapter import GitHubAdapter

            token_env = str(item.get("token_env", "AUTONOMY_HARBOR_GITHUB_TOKEN"))
            token = os.environ.get(token_env)
            registry.register(
                GitHubAdapter(
                    token=token,
                    api_base=str(item.get("api_base", "https://api.github.com")),
                )
            )
        else:
            raise ValueError(f"unknown_adapter_type:{adapter_type}")
    return registry
