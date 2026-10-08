"""CC-REG-01 module 2: recompute every declared file hash and manifest root.

Finds JSON files that declare file digests in any of the common shapes:
  {"files": [{"path": ..., "sha256": ...}]}      (release manifests)
  {"files": {"path": "sha256"}}                  (SHA256 manifests)
  {"...": {"file.py": "<64 hex>"}}               (evidence blocks)
and a "manifest_root" (SHA-256 of the canonical JSON of the manifest without it).
Each declared digest is recomputed from the bytes on disk. Stdlib only.
"""
import hashlib, json, sys
from pathlib import Path

HEX = set("0123456789abcdef")
is_hex64 = lambda s: isinstance(s, str) and len(s) == 64 and set(s) <= HEX

def canonical_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()

def declared_files(node, out=None):
    """Collect (path, sha256) pairs from any nesting of the supported shapes."""
    out = [] if out is None else out
    if isinstance(node, dict):
        if isinstance(node.get("path"), str) and is_hex64(node.get("sha256")):
            out.append((node["path"], node["sha256"]))
        for k, v in node.items():
            if isinstance(v, str) and is_hex64(v) and ("." in k or "/" in k):
                out.append((k, v))
            else:
                declared_files(v, out)
    elif isinstance(node, list):
        for v in node: declared_files(v, out)
    return out

def check_manifest(mpath: Path):
    try: data = json.loads(mpath.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError): return None
    pairs = declared_files(data)
    has_root = isinstance(data, dict) and "manifest_root" in data
    if not pairs and not has_root: return None
    base = mpath.parent; rows = []
    for rel, want in pairs:
        p = (base / rel)
        if not p.resolve().is_relative_to(base.resolve()):
            rows.append({"path": rel, "result": "ESCAPES_ROOT"}); continue
        if not p.is_file():
            rows.append({"path": rel, "result": "MISSING"}); continue
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        rows.append({"path": rel, "result": "MATCH" if got == want else "MISMATCH"})
    root = None
    if has_root:
        body = {k: v for k, v in data.items() if k != "manifest_root"}
        root = "MATCH" if canonical_digest(body) == data["manifest_root"] else "MISMATCH"
    counts = {r: sum(x["result"] == r for x in rows) for r in ("MATCH", "MISMATCH", "MISSING", "ESCAPES_ROOT")}
    ok = counts["MATCH"] == len(rows) and root in (None, "MATCH")
    return {"manifest": str(mpath), "declared": len(rows), **counts, "manifest_root": root,
            "verdict": "RECEIPTS_VERIFIED" if ok else "RECEIPTS_BROKEN",
            "problems": [x for x in rows if x["result"] != "MATCH"][:20]}

def scan(root: Path):
    return [r for f in sorted(Path(root).rglob("*.json")) if "__pycache__" not in f.parts
            for r in [check_manifest(f)] if r]

if __name__ == "__main__":
    res = [r for a in sys.argv[1:] for r in scan(Path(a))]
    print(json.dumps({"manifests": res, "broken": sum(r["verdict"] != "RECEIPTS_VERIFIED" for r in res)}, indent=2))
    sys.exit(1 if any(r["verdict"] != "RECEIPTS_VERIFIED" for r in res) else 0)
