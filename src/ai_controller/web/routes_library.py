"""Read-only markdown from the runbook, standards, and documentation trees."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException

_REPO = Path(__file__).resolve().parents[3]
_ROOTS = {
    "runbooks": _REPO / "run_books",
    "standards": _REPO / "standards",
    "documentation": _REPO / "documentation",
}
_ROLE_LABELS = {
    "soc1": "SOC1",
    "soc2": "SOC2",
    "soc3": "SOC3",
}

router = APIRouter(prefix="/api/library", tags=["library"])


def _root(collection: str) -> Path:
    root = _ROOTS.get(collection)
    if root is None or not root.is_dir():
        raise HTTPException(status_code=404, detail="Unknown library")
    return root.resolve()


def _title(path: Path) -> str:
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("# "):
                return line[2:].strip() or path.stem
    except OSError:
        pass
    return path.stem.replace("_", " ")


def _safe_file(root: Path, relative: str) -> Path:
    text = (relative or "").strip().replace("\\", "/")
    if not text or text.startswith("/") or ".." in Path(text).parts:
        raise HTTPException(status_code=400, detail="Path is outside this library")
    candidate = (root / text).resolve()
    if not candidate.is_relative_to(root) or candidate.suffix.lower() != ".md" or not candidate.is_file():
        raise HTTPException(status_code=400, detail="Path is outside this library")
    return candidate


def _files(root: Path) -> list[dict]:
    found = []
    for path in sorted(root.rglob("*.md")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        found.append({"path": relative, "title": _title(path)})
    return found


@router.get("/{collection}")
async def list_library(collection: str):
    root = _root(collection)
    files = _files(root)
    if collection != "runbooks":
        label = "Documentation" if collection == "documentation" else "Standards"
        return {"success": True, "groups": [{"id": collection, "label": label, "files": files}]}
    groups = []
    shared = [item for item in files if "/" not in item["path"]]
    if shared:
        groups.append({"id": "shared", "label": "Shared", "files": shared})
    for role, label in _ROLE_LABELS.items():
        role_files = [item for item in files if item["path"].startswith(f"{role}/")]
        if role_files:
            groups.append({"id": role, "label": label, "files": role_files})
    return {"success": True, "groups": groups}


@router.get("/{collection}/file")
async def read_library_file(collection: str, path: str):
    root = _root(collection)
    target = _safe_file(root, path)
    relative = target.relative_to(root).as_posix()
    return {
        "success": True,
        "path": relative,
        "title": _title(target),
        "markdown": target.read_text(encoding="utf-8", errors="replace"),
    }
