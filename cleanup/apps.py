"""설치된 앱 목록과 '마지막 사용' 추정.

정직한 한계:
- macOS: Spotlight 의 마지막 실행일(kMDItemLastUsedDate)을 읽으므로 비교적 정확합니다.
- Windows: OS가 앱별 마지막 실행일을 따로 기록하지 않습니다. 설치 폴더 안 파일의 최근 접근/수정 시각으로
  '추정'하며, 정확하지 않을 수 있습니다. (Windows 코드는 개발 환경에서 직접 실행해 보지 못했습니다.)
- Linux: .desktop 항목의 실행 파일 접근 시각으로 추정합니다.
앱 제거는 이 프로그램이 하지 않습니다 (관리자 권한/제거 프로그램이 필요하므로). OS의 제거 화면 안내만 제공합니다.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime

from .core import age_days, dir_size, finding, human


def _newest_in(path: str, limit=3000) -> float:
    newest, n = 0.0, 0
    for dp, _, files in os.walk(path):
        for f in files:
            try:
                st = os.stat(os.path.join(dp, f))
            except OSError:
                continue
            newest = max(newest, st.st_atime, st.st_mtime)
            n += 1
            if n >= limit:
                return newest
    return newest


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
                    ts = datetime.strptime(v[:19], "%Y-%m-%d %H:%M:%S").timestamp()
            except Exception:
                pass
            if not ts:
                ts, how = os.stat(p).st_mtime, "설치/수정일(사용기록 없음)"
            size, _ = dir_size(p)
            out.append((name[:-4], p, size, ts, how, ""))
    return out


def _windows():
    import winreg  # type: ignore
    out, seen = [], set()
    keys = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")]
    for hive, sub in keys:
        try:
            k = winreg.OpenKey(hive, sub)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(k)[0]):
            try:
                sk = winreg.OpenKey(k, winreg.EnumKey(k, i))

                def val(n):
                    try:
                        return winreg.QueryValueEx(sk, n)[0]
                    except OSError:
                        return None
                name, loc = val("DisplayName"), val("InstallLocation")
                if not name or name in seen or val("SystemComponent") == 1 or val("ParentKeyName"):
                    continue
                seen.add(name)
                size = (val("EstimatedSize") or 0) * 1024
                ts, how = 0.0, "설치 폴더 파일의 최근 접근/수정(추정)"
                if loc and os.path.isdir(loc):
                    ts = _newest_in(loc)
                if not ts:
                    d = val("InstallDate")
                    try:
                        ts, how = datetime.strptime(str(d), "%Y%m%d").timestamp(), "설치일(사용기록 없음)"
                    except Exception:
                        how = "기록 없음"
                out.append((name, loc or "", size, ts, how, val("Publisher") or ""))
            except OSError:
                continue
    return out


def _linux():
    out, seen = [], set()
    for base in ("/usr/share/applications", os.path.expanduser("~/.local/share/applications")):
        if not os.path.isdir(base):
            continue
        for fn in os.listdir(base):
            if not fn.endswith(".desktop"):
                continue
            name = exe = ""
            try:
                for line in open(os.path.join(base, fn), encoding="utf-8", errors="ignore"):
                    if line.startswith("Name=") and not name:
                        name = line[5:].strip()
                    elif line.startswith("Exec=") and not exe:
                        exe = line[5:].split()[0]
            except OSError:
                continue
            if not name or name in seen:
                continue
            seen.add(name)
            path = exe if os.path.isabs(exe) else (next((os.path.join(d, exe) for d in os.environ.get("PATH", "").split(":")
                                                       if os.path.exists(os.path.join(d, exe))), ""))
            ts, how = 0.0, "실행 파일 접근시각(추정)"
            size = 0
            if path and os.path.exists(path):
                st = os.stat(path)
                ts, size = max(st.st_atime, st.st_mtime), st.st_size
            out.append((name, path, size, ts, how, ""))
    return out


def scan_apps(unused_days=180, progress=None):
    if sys.platform == "darwin":
        rows, hint = _mac(), "Finder에서 앱을 휴지통으로 옮기거나 Launchpad에서 길게 눌러 삭제하세요."
    elif sys.platform == "win32":
        rows, hint = _windows(), "설정 > 앱 > 설치된 앱 에서 제거하세요."
    else:
        rows, hint = _linux(), "패키지 관리자(apt/snap 등)로 제거하세요."
    items = []
    for i, (name, path, size, ts, how, pub) in enumerate(sorted(rows, key=lambda r: r[3]), 1):
        days = age_days(ts) if ts else None
        unused = days is None or days >= unused_days
        reason = (f"{days}일 동안 사용 흔적 없음" if days is not None else "사용 기록을 알 수 없음") + f" · 근거: {how}"
        if pub:
            reason += f" · {pub}"
        f = finding(i, path or name, size, "app", reason, "review" if unused else "info", ts, True,
                    {"name": name, "removable": False})
        f["label"] = name
        items.append(f)
    return {"items": items, "notes": [hint, "이 탭은 목록과 추정만 제공합니다. 앱 제거는 직접 해주세요."]}
