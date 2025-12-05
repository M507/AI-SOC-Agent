"""
Low-level HTTP client for TheHive.

This module is responsible for:
- authentication (API key header)
- building URLs
- making HTTP requests
- basic error handling
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from ....core.errors import IntegrationError
from ....core.logging import get_logger


logger = get_logger("sami.integrations.thehive.http")


@dataclass
class TheHiveHttpClient:
    """
    Simple HTTP client for TheHive's REST API.
    """

    base_url: str
    api_key: str
    timeout_seconds: int = 30

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def authenticate(self) -> None:
        """
        Placeholder for any explicit authentication logic.

        TheHive typically uses API keys in headers, so there may be no
        separate login step. This method exists to match the design doc
        and as a hook for future changes.
        """

        logger.debug("TheHiveHttpClient.authenticate called (no-op for API key)")

    def request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to TheHive and return the parsed JSON body.
        """

        url = build_url(self.base_url, path)
        logger.debug(
            "TheHive HTTP request",
            extra={"method": method, "url": url, "params": params},
        )

        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=self._headers(),
                json=json,
                params=params,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise IntegrationError(f"TheHive request failed: {exc}") from exc

        handle_thehive_error(response)

        try:
            return response.json()
        except ValueError as exc:
            raise IntegrationError(
                f"TheHive response did not contain valid JSON (status={response.status_code})"
            ) from exc

    def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.request("GET", path, params=params)

    def post(
        self,
        path: str,
        json: Dict[str, Any],
    ) -> Dict[str, Any]:
        return self.request("POST", path, json=json)

    def patch(
        self,
        path: str,
        json: Dict[str, Any],
    ) -> Dict[str, Any]:
        return self.request("PATCH", path, json=json)

    def delete(self, path: str) -> None:
        self.request("DELETE", path)


def build_url(base_url: str, path: str) -> str:
    """
    Join base URL and path safely.
    """

    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def handle_thehive_error(response: requests.Response) -> None:
    """
    Raise an IntegrationError for non-success responses from TheHive.
    """

    if 200 <= response.status_code < 300:
        return

    try:
        payload = response.json()
    except ValueError:
        payload = {"raw": response.text}

    logger.error(
        "TheHive HTTP error",
        extra={
            "status_code": response.status_code,
            "payload": payload,
        },
    )
    raise IntegrationError(
        f"TheHive error {response.status_code}: {payload}"
    )


