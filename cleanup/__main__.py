import argparse

from .server import serve

ap = argparse.ArgumentParser(prog="cleanup", description="AI 부산물·중복 파일·오래된 앱 정리 도우미")
ap.add_argument("--port", type=int, default=8765)
ap.add_argument("--no-browser", action="store_true")
a = ap.parse_args()
serve(a.port, not a.no_browser)
