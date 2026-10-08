"""Self-contained tests for modules 1-2 (stdlib only; run: python tests/test_ccreg.py)."""
import hashlib, json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ccreg_scan import hash_pattern_score, scan_python
from ccreg_receipts import scan, canonical_digest

def make_release(d: Path, files: dict, with_root=True):
    entries = []
    for p, c in files.items():
        (d / p).parent.mkdir(parents=True, exist_ok=True); (d / p).write_text(c)
        entries.append({"path": p, "size": len(c), "sha256": hashlib.sha256(c.encode()).hexdigest()})
    body = {"version": "1", "files": entries}
    m = {**body, "manifest_root": canonical_digest(body)} if with_root else body
    (d / "RELEASE_MANIFEST.json").write_text(json.dumps(m))

def test_fake_receipts_flagged():
    for h in ("3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e",
              "7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b",
              "0123456789abcdef" * 4):
        assert hash_pattern_score(h)["suspicious"], h

def test_real_digests_not_flagged():
    assert not any(hash_pattern_score(hashlib.sha256(str(i).encode()).hexdigest())["suspicious"] for i in range(20000))

def test_hardcoded_status_flagged():
    assert scan_python('def f():\n    return {"status": "VERIFIED"}\n', "x")

def test_command_name_pass_flagged():
    assert scan_python("s = 'PASS' if args.command == 'verify' else 'X'\n", "x")

def test_computed_status_clean():
    assert not scan_python("s = 'PASS' if all(results) else 'FAIL'\nd = {'status': s}\n", "x")

def test_receipts_intact():
    with tempfile.TemporaryDirectory() as t:
        make_release(Path(t), {"a.py": "x=1", "b/c.txt": "hi"})
        r = scan(Path(t)); assert r and r[0]["verdict"] == "RECEIPTS_VERIFIED"

def test_receipts_tampered_file():
    with tempfile.TemporaryDirectory() as t:
        make_release(Path(t), {"a.py": "x=1"}); (Path(t) / "a.py").write_text("x=2")
        r = scan(Path(t))[0]; assert r["verdict"] == "RECEIPTS_BROKEN" and r["MISMATCH"] == 1

def test_receipts_missing_file():
    with tempfile.TemporaryDirectory() as t:
        make_release(Path(t), {"a.py": "x=1"}); (Path(t) / "a.py").unlink()
        assert scan(Path(t))[0]["MISSING"] == 1

def test_manifest_root_forged():
    with tempfile.TemporaryDirectory() as t:
        make_release(Path(t), {"a.py": "x=1"})
        m = json.loads((Path(t) / "RELEASE_MANIFEST.json").read_text()); m["version"] = "999"
        (Path(t) / "RELEASE_MANIFEST.json").write_text(json.dumps(m))
        assert scan(Path(t))[0]["manifest_root"] == "MISMATCH"

def test_path_escape():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t) / "pkg"; root.mkdir(); (Path(t) / "secret").write_text("s")
        (root / "m.json").write_text(json.dumps({"files": [{"path": "../secret", "sha256": hashlib.sha256(b"s").hexdigest()}]}))
        assert scan(root)[0]["ESCAPES_ROOT"] == 1

if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    bad = 0
    for n, f in tests:
        try: f()
        except Exception as e: bad += 1; print("FAIL", n, type(e).__name__, e)
    print(f"{len(tests) - bad}/{len(tests)} passed"); sys.exit(1 if bad else 0)
