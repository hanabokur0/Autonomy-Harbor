from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .models import ActionRequest


class ExecutionError(RuntimeError):
    pass


class SandboxedExecutor:
    """Small reference executor. Real adapters should remain separate processes/modules."""

    def __init__(self, sandbox_root: Path):
        self._root = sandbox_root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def execute(self, request: ActionRequest) -> Mapping[str, Any]:
        handlers = {
            "echo": self._echo,
            "read_text": self._read_text,
            "write_text": self._write_text,
        }
        handler = handlers.get(request.action)
        if handler is None:
            raise ExecutionError(f"unsupported_action:{request.action}")
        return handler(request)

    def _echo(self, request: ActionRequest) -> Mapping[str, Any]:
        return {"text": str(request.payload.get("text", ""))}

    def _read_text(self, request: ActionRequest) -> Mapping[str, Any]:
        path = self._safe_path(request.resource)
        if not path.is_file():
            raise ExecutionError("resource_not_found")
        return {"text": path.read_text(encoding="utf-8")}

    def _write_text(self, request: ActionRequest) -> Mapping[str, Any]:
        path = self._safe_path(request.resource)
        text = request.payload.get("text")
        if not isinstance(text, str):
            raise ExecutionError("text_payload_required")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return {"bytes_written": len(text.encode("utf-8"))}

    def _safe_path(self, resource: str) -> Path:
        candidate = (self._root / resource).resolve()
        try:
            candidate.relative_to(self._root)
        except ValueError as exc:
            raise ExecutionError("sandbox_escape_denied") from exc
        return candidate
