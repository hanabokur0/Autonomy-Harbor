from __future__ import annotations

import json
import multiprocessing as mp
from pathlib import Path
import time
from typing import Any

from .appliance import UnixJsonClient, initialize_appliance
from .appliance_services import load_profile, run_service

ROLES = ("planner", "review_signer", "gate", "executor", "verifier")


def _wait(path: str, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if Path(path).exists():
            try:
                response = UnixJsonClient(path, timeout=0.25).call({"op": "health"})
                if response.get("ok"):
                    return
            except Exception:
                pass
        time.sleep(0.05)
    raise TimeoutError(f"service_socket_not_ready:{path}")


def run_appliance_demo(root: str | Path) -> dict[str, Any]:
    profile_path = initialize_appliance(root)
    profile = load_profile(profile_path)
    processes: dict[str, mp.Process] = {}
    try:
        ctx = mp.get_context("spawn")
        for role in ROLES:
            process = ctx.Process(target=run_service, kwargs={"role": role, "profile_path": profile_path})
            process.start()
            processes[role] = process
        for role in ROLES:
            _wait(profile["services"][role]["socket"])

        clients = {
            role: UnixJsonClient(profile["services"][role]["socket"])
            for role in ROLES
        }
        health = {role: clients[role].call({"op": "health"}) for role in ROLES}
        intent = {
            "request_id": "appliance-demo-001",
            "capability": "filesystem.write",
            "action": "write_text",
            "resource": "approved/appliance.txt",
            "payload": {"text": "Personal Agent Runtime v0.9 appliance boundary works."},
            "actor": "repo-maintainer-agent",
        }
        planned = clients["planner"].call({"op": "propose", "intent": intent})
        request = planned["request"]

        first_gate = clients["gate"].call({"op": "authorize", "request": request})
        if first_gate["decision"]["verdict"] != "REVIEW":
            raise RuntimeError("demo_expected_review")

        approval = clients["review_signer"].call({
            "op": "approve_review",
            "request": request,
            "base_decision": first_gate["base_decision"],
            "approval": {"approved": True, "approved_by": "human:appliance-demo"},
            "ttl_seconds": 300,
        })
        signed_lease = approval["signed_review_lease"]

        second_gate = clients["gate"].call({
            "op": "authorize",
            "request": request,
            "signed_review_lease": signed_lease,
        })
        permit = second_gate.get("execution_permit")
        if second_gate["decision"]["verdict"] != "ALLOW" or permit is None:
            raise RuntimeError("demo_permit_not_issued")

        raw_without_permit = clients["executor"].call({"op": "execute", "request": request})
        executed = clients["executor"].call({
            "op": "execute", "request": request, "execution_permit": permit
        })
        replay = clients["executor"].call({
            "op": "execute", "request": request, "execution_permit": permit
        })
        finalized = clients["verifier"].call({
            "op": "finalize",
            "request": request,
            "execution_permit": permit,
            "signed_execution_result": executed["signed_execution_result"],
        })

        pids = {role: health[role]["service_pid"] for role in ROLES}
        return {
            "appliance_version": "0.9",
            "profile": str(profile_path),
            "service_pids": pids,
            "process_isolation_confirmed": len(set(pids.values())) == len(ROLES),
            "first_gate": first_gate["decision"],
            "review_lease_signer": signed_lease["signer_id"],
            "second_gate": second_gate["decision"],
            "execution_permit_signer": permit["signer_id"],
            "raw_executor_call": {
                "ok": raw_without_permit.get("ok"),
                "reason": raw_without_permit.get("reason"),
            },
            "execution": {
                "executed": executed.get("executed"),
                "outcome": executed.get("outcome"),
                "result_signer": executed.get("signed_execution_result", {}).get("signer_id"),
            },
            "permit_replay": {
                "executed": replay.get("executed"),
                "reason": replay.get("reason"),
            },
            "verification": {
                "verified": finalized.get("verified"),
                "outcome": finalized.get("receipt", {}).get("outcome"),
                "receipt_signer": finalized.get("signed_receipt", {}).get("signer_id"),
            },
            "written_file": str(Path(root).resolve() / "sandbox" / "approved" / "appliance.txt"),
        }
    finally:
        for role in ROLES:
            service = profile.get("services", {}).get(role, {}) if 'profile' in locals() else {}
            socket_path = service.get("socket")
            if socket_path and Path(socket_path).exists():
                try:
                    UnixJsonClient(socket_path, timeout=0.25).call({"op": "shutdown"})
                except Exception:
                    pass
        for process in processes.values():
            process.join(timeout=1.0)
            if process.is_alive():
                process.terminate()
                process.join(timeout=1.0)
