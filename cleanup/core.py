"""공통 유틸: 파일 순회, 크기 계산, 보호 경로 판단."""
from __future__ import annotations

import os
import time
from pathlib import Path

NOW = time.time

# 정리 대상이 될 수 없는 macOS 시스템 경로 (홈 폴더 밖)
_SYSTEM = ("/bin", "/sbin", "/usr", "/etc", "/System", "/Library", "/Applications", "/private",
           "/var", "/opt", "/cores", "/dev", "/Volumes/Macintosh HD")


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def home() -> Path:
    return Path.home()


def is_protected(path: str | os.PathLike) -> bool:
    """홈 폴더 자체·홈의 상위·루트·macOS 시스템 폴더·홈 바로 아래 핵심 폴더는 정리 대상이 될 수 없다."""
    p = Path(os.path.abspath(path))
    h = Path(os.path.abspath(home()))
    if p == h or p in h.parents or p.parent == p:
        return True
    if h in p.parents:
        # ~/Library, ~/Documents 같은 최상위 폴더 자체는 통째로 못 옮기게 막는다 (하위 항목만 허용)
        return p.parent == h and p.name in {"Library", "Documents", "Desktop", "Downloads", "Pictures",
                                            "Movies", "Music", "Public", "Applications"}
    s = str(p)
    return any(s == x or s.startswith(x + "/") for x in _SYSTEM)


def safe_stat(path: str | os.PathLike):
    try:
        return os.lstat(path)
    except OSError:
        return None


def dir_size(path: str, cap_files: int = 200_000) -> tuple[int, float]:
    """폴더 전체 크기와 가장 최근 수정시각. 심볼릭 링크는 따라가지 않는다."""
    total, newest, seen = 0, 0.0, 0
    stack = [path]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            st = e.stat(follow_symlinks=False)
                            total += st.st_size
                            newest = max(newest, st.st_mtime)
                            seen += 1
                            if seen >= cap_files:
                                return total, newest
                    except OSError:
                        continue
        except OSError:
            continue
    return total, newest


def walk(root: str, prune=None, progress: dict | None = None):
    """('dir', path) 는 prune(name, path) 가 참일 때만 방출하고 내부로 들어가지 않는다.
    ('file', path, stat) 는 일반 파일. 심볼릭 링크는 따라가지 않는다."""
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                continue
            if prune and prune(d, full):
                yield ("dir", full)
            else:
                keep.append(d)
        dirnames[:] = keep
        if progress is not None:
            progress["dir"] = dirpath
        for f in filenames:
            full = os.path.join(dirpath, f)
            st = safe_stat(full)
            if st is None or not os.path.isfile(full) or os.path.islink(full):
                continue
            if progress is not None:
                progress["files"] = progress.get("files", 0) + 1
            yield ("file", full, st)


def default_roots() -> list[str]:
    h = home()
    names = ["Downloads", "Desktop", "Documents", "Pictures", "Movies", "Music", "Projects", "dev",
             "Developer", "Code", "repos", "workspace"]
    out = [str(h / n) for n in names if (h / n).is_dir()]
    return out or [str(h)]


def age_days(ts: float) -> int:
    return int((NOW() - ts) / 86400) if ts else 0


def finding(fid: int, path: str, size: int, kind: str, reason: str, confidence: str = "review",
            mtime: float = 0.0, is_dir: bool | None = None, extra: dict | None = None) -> dict:
    d = {"id": fid, "path": path, "size": size, "size_h": human(size), "kind": kind,
         "reason": reason, "confidence": confidence,  # safe | review | info
         "mtime": mtime, "age_days": age_days(mtime),
         "is_dir": os.path.isdir(path) if is_dir is None else is_dir}
    if extra:
        d.update(extra)
    return d
