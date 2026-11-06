"""보안상 점검할 만한 파일 찾기. 백신이 아닙니다 — 단순 규칙(휴리스틱) 기반 '의심 후보'만 알려줍니다."""
from __future__ import annotations

import os
import plistlib
import re
import stat
import sys

from .core import finding, walk

SKIP = {".git", "node_modules", "site-packages", "__pycache__", ".venv", "venv", "Library", ".Trash"}
SECRET_PATTERNS = [
    ("AWS 액세스 키", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Anthropic API 키", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API 키", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("GitHub 토큰", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack 토큰", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Google API 키", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("개인 키(PEM)", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]
TEXT_EXT = {".env", ".json", ".txt", ".md", ".py", ".js", ".ts", ".yml", ".yaml", ".toml", ".cfg", ".ini",
            ".sh", ".conf", ".properties", ".bat", ""}
RISKY_NAMES = {".env", "id_rsa", "id_ed25519", "id_ecdsa", "credentials", "credentials.json", ".npmrc",
               ".pypirc", ".netrc", "secrets.json", "service-account.json"}
RISKY_EXT = {".pem", ".key", ".p12", ".pfx", ".ppk"}
EXEC_EXT = {".dmg", ".pkg", ".command", ".sh", ".app", ".jar", ".scpt", ".workflow", ".exe", ".msi", ".bat"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp3", ".mp4", ".zip"}
EXPOSED_DIRS = ("downloads", "desktop", "documents")


def _mask(s: str) -> str:
    return s[:4] + "…" + s[-2:] if len(s) > 8 else "…"


def _launch_agents(start_id):
    """~/Library/LaunchAgents: 로그인 때 자동 실행되도록 등록된 항목. 실행 파일이 없거나 임시/다운로드 폴더에 있으면 의심."""
    out, fid = [], start_id
    d = os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents")
    if not os.path.isdir(d):
        return out
    for fn in sorted(os.listdir(d)):
        p = os.path.join(d, fn)
        if not fn.endswith(".plist") or not os.path.isfile(p):
            continue
        try:
            with open(p, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            continue
        prog = pl.get("Program") or (pl.get("ProgramArguments") or [""])[0]
        why = None
        if prog and not os.path.exists(prog):
            why = f"자동 실행 등록은 남아 있는데 실행 파일이 없음 ({prog}) — 지운 앱의 잔재일 가능성"
        elif prog and any(x in prog for x in ("/tmp/", "/Downloads/", "/private/var/")):
            why = f"임시/다운로드 폴더의 프로그램을 자동 실행하도록 등록됨 ({prog}) — 출처 확인 필요"
        if why:
            st = os.lstat(p)
            fid += 1
            out.append(finding(fid, p, st.st_size, "launch_agent", why, "review", st.st_mtime, False))
    return out


def scan_security(roots, installer_days=30, progress=None):
    items, fid = [], 0

    def add(path, st, kind, reason, conf="review", extra=None):
        nonlocal fid
        fid += 1
        items.append(finding(fid, path, st.st_size, kind, reason, conf, st.st_mtime, False, extra))

    for root in roots:
        if not os.path.isdir(root):
            continue
        for item in walk(root, prune=lambda n, p: n in SKIP, progress=progress):
            if item[0] != "file":
                continue
            _, path, st = item
            name = os.path.basename(path)
            low, ext = name.lower(), os.path.splitext(name)[1].lower()
            exposed = any(seg in path.lower().split(os.sep) for seg in EXPOSED_DIRS)
            flagged = False
            # 1) 이중 확장자 위장 (invoice.pdf.exe)
            stem_ext = os.path.splitext(os.path.splitext(name)[0])[1].lower()
            if ext in EXEC_EXT and stem_ext in DOC_EXT:
                add(path, st, "disguised", f"문서처럼 보이는 실행 파일 (이중 확장자 {stem_ext}{ext}) — 열지 말고 확인하세요", "review")
                continue
            # 2) 비밀 파일 이름
            if low in RISKY_NAMES or low.startswith(".env.") or ext in RISKY_EXT:
                reason = "비밀번호/키가 들어 있을 수 있는 파일"
                if exposed:
                    reason += " — 다운로드/바탕화면/문서 폴더에 노출되어 있음"
                if os.name == "posix" and (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)) and low.startswith("id_"):
                    reason += " · SSH 개인키가 다른 사용자도 읽을 수 있는 권한 (chmod 600 필요)"
                add(path, st, "secret_file", reason + ". 지워도 이미 유출됐다면 키 재발급이 먼저입니다.")
                flagged = True
            # 3) 내용 속 키 패턴 (작은 텍스트 파일만)
            if not flagged and ext in TEXT_EXT and 0 < st.st_size <= 256 * 1024:
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                except OSError:
                    text = ""
                for label, rx in SECRET_PATTERNS:
                    m = rx.search(text)
                    if m:
                        add(path, st, "leaked_key", f"{label}처럼 보이는 문자열 발견 ({_mask(m.group(0))}). "
                            "AI 대화/코드에 붙여넣은 키일 수 있음 — 해당 서비스에서 키를 폐기·재발급하세요.")
                        break
            # 4) 다운로드에 방치된 설치 파일
            if ext in EXEC_EXT and exposed:
                from .core import age_days
                if age_days(st.st_mtime) >= installer_days:
                    add(path, st, "installer", f"{age_days(st.st_mtime)}일 전에 받은 설치/실행 파일이 남아 있음 (이미 설치했다면 삭제해도 됨)")
    items.extend(_launch_agents(fid))
    items.sort(key=lambda r: ({"disguised": 0, "leaked_key": 1, "launch_agent": 2, "secret_file": 3}.get(r["kind"], 3), -r["size"]))
    return {"items": items, "notes": ["이 탭은 안티바이러스가 아닙니다. 규칙에 걸린 '후보'만 보여주며 오탐이 있을 수 있습니다.",
                                      "키 문자열은 일부만 가려서 표시하며 어디에도 전송·저장하지 않습니다."]}
