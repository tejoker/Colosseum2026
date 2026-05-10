"""HTTP client for the SauronID core."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional

import requests


class SauronIDError(RuntimeError):
    """Raised when the SauronID core rejects a request."""

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"SauronID HTTP {status}: {body}")


@dataclass
class SauronIDClient:
    """Thin HTTP client. Holds base URL and optional admin key.

    The admin key is required for `/admin/...` routes only. Per-call signing
    is handled by `SignedAgent` (see `agent.py`); this client deliberately
    does NOT cache agent secrets.
    """

    base_url: str
    admin_key: Optional[str] = None
    timeout: float = 10.0

    def __post_init__(self):
        self.base_url = self.base_url.rstrip("/")

    # ── low-level HTTP ────────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        h = dict(headers or {})
        if json_body is not None and "content-type" not in {k.lower() for k in h}:
            h["content-type"] = "application/json"
        body = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else None
        return requests.request(method, url, headers=h, data=body, timeout=self.timeout)

    def get_json(
        self, path: str, *, headers: Optional[Mapping[str, str]] = None
    ) -> Any:
        r = self._request("GET", path, headers=headers)
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)
        return r.json()

    def post_json(
        self,
        path: str,
        body: Mapping[str, Any],
        *,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        r = self._request("POST", path, json_body=body, headers=headers)
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)
        return r.json()

    def delete(
        self, path: str, *, headers: Optional[Mapping[str, str]] = None
    ) -> Any:
        r = self._request("DELETE", path, headers=headers)
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)
        return r.json() if r.text else {}

    # ── high-level helpers ────────────────────────────────────────────────

    def admin_headers(self) -> dict:
        if not self.admin_key:
            raise RuntimeError("admin_key not set on SauronIDClient")
        return {"x-admin-key": self.admin_key}

    def admin_stats(self) -> Any:
        return self.get_json("/admin/stats", headers=self.admin_headers())

    def health(self) -> bool:
        try:
            return self.get_json("/admin/stats", headers=self.admin_headers()) is not None
        except SauronIDError:
            return False

    def user_auth(self, email: str, password: str) -> dict:
        """Returns {session, key_image} for the human session token."""
        return self.post_json(
            "/user/auth", {"email": email, "password": password}
        )

    # ── server time helper ───────────────────────────────────────────────

    @staticmethod
    def now_ms() -> int:
        return int(time.time() * 1000)
