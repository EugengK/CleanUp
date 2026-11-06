import os, time
from pathlib import Path
import pytest
from cleanup import dupes, junk, quarantine, security, footprints
from cleanup.core import is_protected


def touch(p: Path, text="x", age_days=0):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    if age_days:
        t = time.time() - age_days * 86400
        os.utime(p, (t, t))
    return p


def test_dupes_finds_exact_copies_only(tmp_path):
    a = touch(tmp_path / "a" / "photo.jpg", "A" * 20000)
    b = touch(tmp_path / "b" / "photo (1).jpg", "A" * 20000)
    c = touch(tmp_path / "c" / "other.jpg", "A" * 19999 + "B")   # 크기 같고 내용 다름
    r = dupes.scan_dupes([str(tmp_path)], min_kb=1)
    assert len(r["groups"]) == 1
    paths = [i["path"] for i in r["items"]]
    assert str(c) not in paths
    keep = [i for i in r["items"] if i["keep"]][0]
    assert keep["path"] == str(a)               # "(1)" 복사본이 아닌 쪽을 보관 추천


def test_hardlink_not_duplicate(tmp_path):
    a = touch(tmp_path / "a.bin", "Z" * 20000)
    os.link(a, tmp_path / "b.bin")
    assert dupes.scan_dupes([str(tmp_path)], min_kb=1)["groups"] == []


def test_junk_categories(tmp_path):
    touch(tmp_path / "p" / "__pycache__" / "m.pyc")
    touch(tmp_path / "p" / "IMPLEMENTATION_SUMMARY.md", age_days=30)
    touch(tmp_path / "p" / "README.md", age_days=300)
    touch(tmp_path / "p" / "CLAUDE.md", age_days=300)
    touch(tmp_path / "p" / "new_PLAN.md", age_days=1)          # 너무 최근 → 제외
    touch(tmp_path / "p" / "old.log", age_days=90)
    r = junk.scan_junk([str(tmp_path)], include_stale=False)
    got = {(os.path.basename(i["path"]), i["kind"]) for i in r["items"]}
    assert ("__pycache__", "cache") in got
    assert ("IMPLEMENTATION_SUMMARY.md", "ai_doc") in got
    assert ("old.log", "log") in got
    names = {n for n, _ in got}
    assert not names & {"README.md", "CLAUDE.md", "new_PLAN.md"}


def test_stale_large_file(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"0" * 2_000_000)
    t = time.time() - 400 * 86400
    os.utime(f, (t, t))
    r = junk.scan_junk([str(tmp_path)], stale_days=180, min_stale_mb=1)
    assert any(i["kind"] == "stale" for i in r["items"])


def test_security_masks_secret_and_detects_disguise(tmp_path):
    key = "sk-ant-" + "a1B2c3D4" * 4
    touch(tmp_path / "notes.txt", f"my key {key}")
    touch(tmp_path / "invoice.pdf.exe", "MZ")
    touch(tmp_path / ".env", "A=1")
    r = security.scan_security([str(tmp_path)])
    kinds = {i["kind"] for i in r["items"]}
    assert {"leaked_key", "disguised", "secret_file"} <= kinds
    assert all(key not in i["reason"] for i in r["items"])      # 전체 키는 절대 노출 안 됨


def test_footprints_project(tmp_path):
    touch(tmp_path / "proj" / "package.json", "{}")
    touch(tmp_path / "proj" / "CLAUDE.md", "hi")
    r = footprints.scan_footprints([str(tmp_path)])
    kinds = {i["kind"] for i in r["items"]}
    assert "marker" in kinds and "project" in kinds


def test_quarantine_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEANUP_HOME", str(tmp_path / "app"))
    monkeypatch.setenv("HOME", str(tmp_path))
    f = touch(tmp_path / "data" / "x.txt", "hello")
    d = tmp_path / "data" / "dir"; touch(d / "y.txt", "yy")
    res = quarantine.move_to_quarantine([str(f), str(d)])
    assert res["moved"] == 2 and not f.exists() and not d.exists()
    b = res["batch"]
    assert quarantine.list_batches()[0]["count"] == 2
    assert quarantine.restore(b)["restored"] == 2
    assert f.read_text() == "hello" and (d / "y.txt").exists()


def test_quarantine_refuses_protected_and_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("CLEANUP_HOME", str(tmp_path / "app"))
    monkeypatch.setenv("HOME", str(tmp_path))
    r = quarantine.move_to_quarantine([str(tmp_path), "/", "/usr"])
    assert r["moved"] == 0 and len(r["errors"]) == 3
    with pytest.raises(ValueError):
        quarantine.restore("../etc")


def test_is_protected(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert is_protected(tmp_path) and is_protected("/") and is_protected("/usr/lib")
    assert not is_protected(tmp_path / "Downloads" / "a.txt")


def test_launch_agent_orphan(tmp_path, monkeypatch):
    import plistlib
    monkeypatch.setenv("HOME", str(tmp_path))
    d = tmp_path / "Library" / "LaunchAgents"; d.mkdir(parents=True)
    (d / "com.gone.app.plist").write_bytes(plistlib.dumps({"Label": "x", "ProgramArguments": ["/Applications/Gone.app/run"]}))
    r = security.scan_security([str(tmp_path / "Downloads")])
    assert [i["kind"] for i in r["items"]] == ["launch_agent"]


def test_mac_top_level_dirs_protected(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert is_protected(tmp_path / "Library") and is_protected(tmp_path / "Documents")
    assert not is_protected(tmp_path / "Library" / "Caches" / "pip")
    assert is_protected("/Applications/Safari.app") and is_protected("/System/Library")
