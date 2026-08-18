"""JSON-file store for approval requests. Same layout as sessions/autoruns."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from ...core.logging import get_logger
from .models import ApprovalRequest, RequestStatus

logger = get_logger("sami.approval_queue.store")


class RequestStore:
    """Load and persist ApprovalRequest objects under storage_dir/requests/."""

    def __init__(self, storage_dir: str = "data/ai_controller") -> None:
        self.storage_dir = Path(storage_dir)
        self.requests_dir = self.storage_dir / "requests"
        self.requests_dir.mkdir(parents=True, exist_ok=True)
        self._items: Dict[str, ApprovalRequest] = {}
        self._load_all()

    def _load_all(self) -> None:
        for path in self.requests_dir.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                request = ApprovalRequest.from_dict(data)
                self._items[request.id] = request
            except Exception as exc:
                logger.error("Failed to load request from %s: %s", path, exc)

    def _path(self, request_id: str) -> Path:
        return self.requests_dir / f"{request_id}.json"

    def _save(self, request: ApprovalRequest) -> None:
        path = self._path(request.id)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(request.to_dict(), handle, indent=2)

    def put(self, request: ApprovalRequest) -> ApprovalRequest:
        self._items[request.id] = request
        self._save(request)
        return request

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        return self._items.get(request_id)

    def list(
        self,
        status: Optional[RequestStatus] = None,
        cluster_id: Optional[str] = None,
    ) -> List[ApprovalRequest]:
        items = list(self._items.values())
        if status is not None:
            items = [item for item in items if item.status == status]
        if cluster_id:
            items = [item for item in items if item.cluster_id == cluster_id]
        return sorted(items, key=lambda item: item.created_at, reverse=True)

    def count(self, status: Optional[RequestStatus] = None) -> int:
        if status is None:
            return len(self._items)
        return sum(1 for item in self._items.values() if item.status == status)
