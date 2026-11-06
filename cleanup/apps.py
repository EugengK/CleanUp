"""macOS 설치 앱 목록과 '마지막 사용' 시점.

Spotlight 의 마지막 실행일(kMDItemLastUsedDate)을 mdls 로 읽습니다. 값이 없으면 앱 폴더 수정일로 대체하고
그 사실을 화면에 표시합니다. 앱 제거는 이 프로그램이 하지 않습니다 (Finder/Launchpad 에서 직접).
주의: 이 코드는 맥이 아닌 환경에서 개발되어, 실제 맥에서의 동작은 사용자 확인이 필요합니다.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone

from .core import age_days, dir_size, finding


def _mac():
    out = []
    for base in ("/Applications", os.path.expanduser("~/Applications")):
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if not name.endswith(".app"):
                continue
            p = os.path.join(base, name)
            ts, how = 0.0, "마지막 실행(Spotlight)"
            try:
                r = subprocess.run(["mdls", "-name", "kMDItemLastUsedDate", "-raw", p],
                                   capture_output=True, text=True, timeout=10)
                v = r.stdout.strip()
                if v and v != "(null)":
                    ts = datetime.strptime(v[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
            except Exception:
                pass
            if not ts:
                ts, how = os.stat(p).st_mtime, "설치/수정일(사용기록 없음)"
            size, _ = dir_size(p)
            out.append((name[:-4], p, size, ts, how, ""))
    return out


def scan_apps(unused_days=180, progress=None):
    if sys.platform != "darwin":
        return {"items": [], "notes": ["이 탭은 macOS에서만 동작합니다 (현재 OS에서는 건너뜀)."]}
    items = []
    for i, (name, path, size, ts, how, _) in enumerate(sorted(_mac(), key=lambda r: r[3]), 1):
        days = age_days(ts) if ts else None
        unused = days is None or days >= unused_days
        reason = (f"{days}일 동안 사용 흔적 없음" if days is not None else "사용 기록을 알 수 없음") + f" · 근거: {how}"
        f = finding(i, path, size, "app", reason, "review" if unused else "info", ts, True,
                    {"name": name, "removable": False})
        f["label"] = name
        items.append(f)
    return {"items": items, "notes": ["목록과 추정만 제공합니다. 제거는 Finder에서 앱을 휴지통으로 옮기거나 Launchpad에서 길게 눌러 삭제하세요.",
                                      "앱을 지워도 ~/Library 에 설정·캐시가 남을 수 있습니다 ('AI 흔적' 탭의 Library 항목 참고)."]}
