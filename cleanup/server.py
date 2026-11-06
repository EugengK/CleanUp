"""로컬 웹 서버 (127.0.0.1 전용). 스캔은 백그라운드 작업으로 돌리고, 삭제는 '직전 스캔 결과에 있는 경로'만 허용한다."""
from __future__ import annotations

import json
import secrets
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import apps, dupes, footprints, junk, quarantine, security
from .core import default_roots, home, human, is_protected

STATIC = Path(__file__).parent / "static"
SCANNERS = {
    "junk": lambda roots, p, prog: junk.scan_junk(roots, stale_days=p.get("stale_days", 180),
                                                 min_stale_mb=p.get("min_stale_mb", 5), progress=prog),
    "dupes": lambda roots, p, prog: dupes.scan_dupes(roots, min_kb=p.get("min_kb", 10), progress=prog),
    "footprints": lambda roots, p, prog: footprints.scan_footprints(roots, stale_days=p.get("stale_days", 180), progress=prog),
    "apps": lambda roots, p, prog: apps.scan_apps(unused_days=p.get("unused_days", 180), progress=prog),
    "security": lambda roots, p, prog: security.scan_security(roots, progress=prog),
}


class State:
    def __init__(self):
        self.token = secrets.token_urlsafe(24)
        self.jobs: dict[str, dict] = {}
        self.lock = threading.Lock()


def make_handler(state: State, port_getter):
    class H(BaseHTTPRequestHandler):
        server_version = "CleanUp"

        def log_message(self, *a):  # 조용히
            pass

        # ---- 보안: Host 검사(DNS rebinding 방어) + 토큰(CSRF 방어)
        def _host_ok(self):
            return self.headers.get("Host", "") in (f"127.0.0.1:{port_getter()}", f"localhost:{port_getter()}")

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _auth(self):
            return self._host_ok() and secrets.compare_digest(self.headers.get("X-Token", ""), state.token)

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "forbidden"})
            u = urlparse(self.path)
            if u.path == "/":
                html = (STATIC / "index.html").read_text(encoding="utf-8").replace("__TOKEN__", state.token)
                return self._send(200, html.encode(), "text/html; charset=utf-8")
            if not self._auth():
                return self._send(403, {"error": "forbidden"})
            if u.path == "/api/defaults":
                return self._send(200, {"home": str(home()), "roots": default_roots()})
            if u.path == "/api/job":
                job = state.jobs.get(parse_qs(u.query).get("id", [""])[0])
                if not job:
                    return self._send(404, {"error": "no such job"})
                out = {k: job[k] for k in ("state", "progress", "error")}
                if job["state"] == "done":
                    out["result"] = job["result"]
                return self._send(200, out)
            if u.path == "/api/quarantine":
                return self._send(200, {"batches": quarantine.list_batches()})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._auth():
                return self._send(403, {"error": "forbidden"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self._send(400, {"error": "bad json"})
            path = urlparse(self.path).path
            try:
                if path == "/api/scan":
                    return self._send(200, {"job": self._start_scan(body)})
                if path == "/api/trash":
                    return self._send(200, self._trash(body))
                if path == "/api/restore":
                    return self._send(200, quarantine.restore(str(body.get("batch", ""))))
                if path == "/api/purge":
                    return self._send(200, quarantine.purge(str(body.get("batch", ""))))
            except (ValueError, FileNotFoundError) as e:
                return self._send(400, {"error": str(e)})
            self._send(404, {"error": "not found"})

        def _start_scan(self, body):
            kind = body.get("kind")
            if kind not in SCANNERS:
                raise ValueError("알 수 없는 스캔 종류")
            roots = [r for r in body.get("roots", []) if isinstance(r, str)] or default_roots()
            params = body.get("params", {}) if isinstance(body.get("params"), dict) else {}
            jid = uuid.uuid4().hex[:10]
            job = {"state": "running", "progress": {"files": 0, "dir": ""}, "result": None, "error": None,
                   "paths": {}, "kind": kind}
            state.jobs[jid] = job

            def run():
                try:
                    res = SCANNERS[kind](roots, params, job["progress"])
                    for it in res["items"]:
                        job["paths"][it["id"]] = it["path"]
                    res["total_size"] = sum(i["size"] for i in res["items"] if i["confidence"] != "info")
                    res["total_h"] = human(res["total_size"])
                    if "wasted_total" in res:
                        res["wasted_h"] = human(res["wasted_total"])
                    job["result"], job["state"] = res, "done"
                except Exception as e:  # noqa: BLE001
                    job["error"], job["state"] = f"{type(e).__name__}: {e}", "error"

            threading.Thread(target=run, daemon=True).start()
            return jid

        def _trash(self, body):
            job = state.jobs.get(body.get("job", ""))
            if not job or job["state"] != "done":
                raise ValueError("스캔 결과가 없습니다. 다시 스캔하세요.")
            if job["kind"] == "apps":
                raise ValueError("앱은 이 프로그램에서 삭제하지 않습니다.")
            paths, skipped = [], []
            for i in body.get("ids", []):
                p = job["paths"].get(i)
                if p is None:
                    continue
                (skipped if is_protected(p) else paths).append(p)
            res = quarantine.move_to_quarantine(paths)
            res["errors"] += [{"path": p, "error": "보호된 경로"} for p in skipped]
            return res

    return H


def serve(port=8765, open_browser=True):
    state = State()
    httpd = None
    for p in range(port, port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), make_handler(state, lambda: httpd.server_address[1]))
            break
        except OSError:
            continue
    if httpd is None:
        raise SystemExit("사용 가능한 포트를 찾지 못했습니다.")
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"CleanUp 실행 중: {url}  (종료: Ctrl+C)")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
    return httpd
