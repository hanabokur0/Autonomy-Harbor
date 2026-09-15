from __future__ import annotations

import json
from typing import Any, Mapping, Protocol
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from .adapters import AdapterBinding, AdapterError
from .models import ActionRequest


class GitHubTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]: ...


class UrllibGitHubTransport:
    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        data = None
        if json_body is not None:
            data = json.dumps(dict(json_body), ensure_ascii=False).encode("utf-8")
        req = urllib_request.Request(
            url,
            method=method,
            data=data,
            headers=dict(headers),
        )
        try:
            with urllib_request.urlopen(req, timeout=15) as response:
                raw = response.read()
        except urllib_error.HTTPError as exc:
            raise AdapterError(f"github_http_error:{exc.code}") from exc
        except urllib_error.URLError as exc:
            raise AdapterError("github_transport_error") from exc
        if not raw:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, Mapping):
            raise AdapterError("github_response_not_object")
        return dict(value)


class GitHubAdapter:
    """Executor-side GitHub adapter. It knows API mechanics, never policy."""

    adapter_id = "github"
    bindings = (
        AdapterBinding("github.repo.read", "get_repo"),
        AdapterBinding("github.issue.create", "create_issue"),
    )

    def __init__(
        self,
        *,
        token: str | None = None,
        api_base: str = "https://api.github.com",
        transport: GitHubTransport | None = None,
    ) -> None:
        self._token = token.strip() if isinstance(token, str) and token.strip() else None
        self._api_base = api_base.rstrip("/")
        self._transport = transport or UrllibGitHubTransport()

    def execute(self, request: ActionRequest) -> Mapping[str, Any]:
        if request.capability == "github.repo.read" and request.action == "get_repo":
            return self._get_repo(request)
        if request.capability == "github.issue.create" and request.action == "create_issue":
            return self._create_issue(request)
        raise AdapterError(
            f"github_binding_not_supported:{request.capability}:{request.action}"
        )

    def _headers(self, *, require_auth: bool) -> dict[str, str]:
        if require_auth and self._token is None:
            raise AdapterError("github_token_required")
        headers = {
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Autonomy-Harbor-GitHub-Adapter/1.1",
        }
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    @staticmethod
    def _repo_resource(resource: str) -> tuple[str, str]:
        parts = resource.strip("/").split("/")
        if len(parts) != 2 or not all(parts):
            raise AdapterError("github_resource_must_be_owner_repo")
        return parts[0], parts[1]

    @staticmethod
    def _repo_path(owner: str, repo: str) -> str:
        return "/repos/{}/{}".format(
            urllib_parse.quote(owner, safe=""),
            urllib_parse.quote(repo, safe=""),
        )

    def _get_repo(self, request: ActionRequest) -> Mapping[str, Any]:
        owner, repo = self._repo_resource(request.resource)
        value = self._transport.request(
            method="GET",
            url=f"{self._api_base}{self._repo_path(owner, repo)}",
            headers=self._headers(require_auth=False),
        )
        return {
            "repository_full_name": value.get("full_name", request.resource),
            "private": bool(value.get("private", False)),
            "default_branch": value.get("default_branch"),
            "html_url": value.get("html_url"),
        }

    def _create_issue(self, request: ActionRequest) -> Mapping[str, Any]:
        owner, repo = self._repo_resource(request.resource)
        title = request.payload.get("title")
        if not isinstance(title, str) or not title.strip():
            raise AdapterError("github_issue_title_required")
        body = request.payload.get("body")
        if body is not None and not isinstance(body, str):
            raise AdapterError("github_issue_body_must_be_string")
        payload: dict[str, Any] = {"title": title.strip()}
        if body is not None:
            payload["body"] = body
        for field in ("labels", "assignees"):
            value = request.payload.get(field)
            if value is not None:
                if not isinstance(value, (list, tuple)) or not all(isinstance(x, str) for x in value):
                    raise AdapterError(f"github_issue_{field}_must_be_string_array")
                payload[field] = list(value)

        value = self._transport.request(
            method="POST",
            url=f"{self._api_base}{self._repo_path(owner, repo)}/issues",
            headers=self._headers(require_auth=True),
            json_body=payload,
        )
        return {
            "repository_full_name": request.resource,
            "issue_number": value.get("number"),
            "state": value.get("state"),
            "title": value.get("title", title.strip()),
            "html_url": value.get("html_url"),
        }
