"""안전 삭제: 영구 삭제 대신 격리함으로 옮기고, 원래 위치를 기록해 두어 복원할 수 있다."""
from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from pathlib import Path

from .core import dir_size, human, is_protected


def base_dir() -> Path:
    p = Path(os.environ.get("CLEANUP_HOME", Path.home() / ".cleanup_app")) / "quarantine"
    p.mkdir(parents=True, exist_ok=True)
    return p


def move_to_quarantine(paths: list[str]) -> dict:
    batch = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    bdir = base_dir() / batch
    bdir.mkdir()
    entries, errors = [], []
    for i, src in enumerate(paths):
        try:
            if is_protected(src):
                raise PermissionError("보호된 경로")
            if not os.path.lexists(src):
                raise FileNotFoundError("이미 없음")
            size = dir_size(src)[0] if os.path.isdir(src) and not os.path.islink(src) else os.lstat(src).st_size
            dest = bdir / f"{i:04d}_{os.path.basename(src)}"
            shutil.move(src, dest)
            entries.append({"orig": src, "stored": str(dest), "size": size})
        except Exception as e:  # noqa: BLE001
            errors.append({"path": src, "error": str(e)})
    if entries:
        (bdir / "manifest.json").write_text(json.dumps({"created": time.time(), "entries": entries},
                                                      ensure_ascii=False, indent=1), encoding="utf-8")
    else:
        shutil.rmtree(bdir, ignore_errors=True)
        batch = ""
    return {"batch": batch, "moved": len(entries), "bytes": sum(e["size"] for e in entries), "errors": errors}


def list_batches() -> list[dict]:
    out = []
    for d in sorted(base_dir().iterdir(), reverse=True):
        m = d / "manifest.json"
        if not m.is_file():
            continue
        data = json.loads(m.read_text(encoding="utf-8"))
        total = sum(e["size"] for e in data["entries"])
        out.append({"batch": d.name, "created": data["created"], "count": len(data["entries"]),
                    "size": total, "size_h": human(total), "sample": [e["orig"] for e in data["entries"][:3]]})
    return out


def _batch_dir(batch: str) -> Path:
    if not batch or "/" in batch or "\\" in batch or ".." in batch:
        raise ValueError("잘못된 배치 이름")
    d = base_dir() / batch
    if not d.is_dir():
        raise FileNotFoundError(batch)
    return d


def restore(batch: str) -> dict:
    d = _batch_dir(batch)
    data = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    restored, errors = 0, []
    for e in data["entries"]:
        try:
            if os.path.lexists(e["orig"]):
                raise FileExistsError("원래 위치에 같은 이름이 이미 있음")
            os.makedirs(os.path.dirname(e["orig"]), exist_ok=True)
            shutil.move(e["stored"], e["orig"])
            restored += 1
        except Exception as ex:  # noqa: BLE001
            errors.append({"path": e["orig"], "error": str(ex)})
    if not errors:
        shutil.rmtree(d, ignore_errors=True)
    return {"restored": restored, "errors": errors}


def purge(batch: str) -> dict:
    d = _batch_dir(batch)
    shutil.rmtree(d)
    return {"purged": batch}
