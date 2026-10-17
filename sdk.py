"""Minimal Python client for routing agent actions through TrustMesh."""
from __future__ import annotations
import urllib.error, urllib.request, json

class TrustMeshClient:
    def __init__(self, base_url: str, token: str, timeout: float = 5.0):
        self.base_url, self.token, self.timeout = base_url.rstrip("/"), token, timeout

    def execute_tool(self, tool_name: str, arguments: dict, idempotency_key: str | None = None) -> dict:
        """Call a fixed server-side sandbox tool; policy and execution stay at gateway."""
        import uuid
        data = json.dumps({"arguments": arguments, "idempotency_key": idempotency_key or uuid.uuid4().hex}).encode()
        req = urllib.request.Request(self.base_url + "/v1/tools/" + tool_name + "/execute", data=data, method="POST",
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response: return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            try: detail = json.loads(exc.read())
            except Exception: detail = {"detail": "Gateway request failed"}
            return {"decision": "BLOCK", "executed": False, "http_status": exc.code, **detail}
        except (urllib.error.URLError, TimeoutError) as exc:
            return {"decision": "BLOCK", "executed": False, "reasons": ["Gateway unavailable; no local tool executed: " + str(exc)]}

    def evaluate(self, action: str, resource: str = "", payload: str = "", context: dict | None = None) -> dict:
        data = json.dumps({"action": action, "resource": resource, "payload": payload, "context": context or {}}).encode()
        req = urllib.request.Request(self.base_url + "/v1/actions/evaluate", data=data, method="POST",
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response: return json.loads(response.read())
        except (urllib.error.URLError, TimeoutError) as exc:
            # Fail closed: callers must not execute the action without a policy response.
            return {"decision": "BLOCK", "risk": 100, "reasons": ["TrustMesh unreachable; fail-closed client: " + str(exc)]}

    def resume_tool(self, event_id: int) -> dict:
        """Resume the exact server-stored sandbox request after human approval."""
        req = urllib.request.Request(self.base_url + f"/v1/actions/{event_id}/resume", data=b"{}", method="POST",
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            try: detail = json.loads(exc.read())
            except Exception: detail = {"detail": "Gateway resume failed"}
            return {"decision": "BLOCK", "executed": False, "http_status": exc.code, **detail}
        except (urllib.error.URLError, TimeoutError) as exc:
            return {"decision": "BLOCK", "executed": False, "reasons": ["Gateway unavailable; server did not execute the request: " + str(exc)]}

