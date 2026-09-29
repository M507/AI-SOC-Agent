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
        self._mtimes: Dict[str, float] = {}
        self._generation = 0
        self._reads = 0
        self.refresh()

    @property
    def generation(self) -> int:
        return self._generation

    def _load_file(self, path: Path) -> Optional[ApprovalRequest]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            self._reads += 1
            return ApprovalRequest.from_dict(data)
        except Exception as exc:
            logger.error("Failed to load request from %s: %s", path, exc)
            return None

    def refresh(self) -> bool:
        """Reload files whose mtime changed. Returns True when the snapshot changed."""
        changed = False
        on_disk: Dict[str, Path] = {}
        for path in self.requests_dir.glob("*.json"):
            on_disk[path.stem] = path

        for request_id in list(self._items.keys()):
            if request_id not in on_disk:
                del self._items[request_id]
                self._mtimes.pop(request_id, None)
                changed = True

        for request_id, path in on_disk.items():
            try:
                mtime = path.stat().st_mtime
            except OSError as exc:
                logger.error("Failed to stat request %s: %s", path, exc)
                continue
            if request_id in self._mtimes and self._mtimes[request_id] == mtime and request_id in self._items:
                continue
            request = self._load_file(path)
            if request is None:
                continue
            self._items[request.id] = request
            self._mtimes[request.id] = mtime
            changed = True

        if changed:
            self._generation += 1
        return changed

    def _path(self, request_id: str) -> Path:
        return self.requests_dir / f"{request_id}.json"

    def _save(self, request: ApprovalRequest) -> None:
        path = self._path(request.id)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(request.to_dict(), handle, indent=2)
        self._mtimes[request.id] = path.stat().st_mtime
        self._generation += 1

    def put(self, request: ApprovalRequest) -> ApprovalRequest:
        self._items[request.id] = request
        self._save(request)
        return request

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        self.refresh()
        return self._items.get(request_id)

    def snapshot(self) -> List[ApprovalRequest]:
        """Current tickets after picking up disk changes. One directory scan."""
        self.refresh()
        return list(self._items.values())

    def list(
        self,
        status: Optional[RequestStatus] = None,
        cluster_id: Optional[str] = None,
    ) -> List[ApprovalRequest]:
        items = self.snapshot()
        if status is not None:
            items = [item for item in items if item.status == status]
        if cluster_id:
            items = [item for item in items if item.cluster_id == cluster_id]
        return sorted(items, key=lambda item: item.created_at, reverse=True)

    def count(self, status: Optional[RequestStatus] = None) -> int:
        items = self.snapshot()
        if status is None:
            return len(items)
        return sum(1 for item in items if item.status == status)
