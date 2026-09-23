"""
Low-level HTTP client for the NetBox REST API.

Auth uses ``Authorization: Token <api_token>`` against ``/api/...``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

from ...core.errors import IntegrationError
from ...core.logging import get_logger

logger = get_logger("sami.integrations.netbox.http")


class NetBoxHttpClient:
    """Thin wrapper around NetBox's JSON REST API."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        timeout_seconds: int = 30,
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token.strip()
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl
        # Accept either http://host:port or http://host:port/api
        if self.base_url.lower().endswith("/api"):
            self.api_root = self.base_url + "/"
        else:
            self.api_root = self.base_url + "/api/"

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Token {self.api_token}",
        }

    def _url(self, path: str) -> str:
        return urljoin(self.api_root, path.lstrip("/"))

    def get(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = self._url(path)
        try:
            logger.debug("NetBox GET %s params=%s", url, params)
            response = requests.get(
                url,
                headers=self._headers(),
                params=params or {},
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
            if response.status_code in {401, 403}:
                raise IntegrationError(
                    f"NetBox authentication failed (HTTP {response.status_code})"
                )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise IntegrationError("NetBox returned a non-object JSON payload")
            return payload
        except IntegrationError:
            raise
        except requests.exceptions.Timeout as e:
            raise IntegrationError(f"NetBox request timed out: {e}") from e
        except requests.exceptions.RequestException as e:
            detail = ""
            if getattr(e, "response", None) is not None and e.response is not None:
                try:
                    body = e.response.json()
                    detail = f" - {body}"
                except Exception:
                    text = (e.response.text or "")[:200]
                    if text:
                        detail = f" - {text}"
            raise IntegrationError(f"NetBox API request failed: {e}{detail}") from e

    def list_results(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        query = dict(params or {})
        query["limit"] = max(1, min(int(limit), 100))
        payload = self.get(path, params=query)
        results = payload.get("results")
        if isinstance(results, list):
            return [item for item in results if isinstance(item, dict)]
        return []

    def status(self) -> Dict[str, Any]:
        return self.get("status/")
