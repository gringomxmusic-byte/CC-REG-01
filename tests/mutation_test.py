import shutil, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
M = {
 'pattern threshold too loose':   ('ccreg_scan.py', '"suspicious": longest >= 8}', '"suspicious": longest >= 3}'),
 'interleaved strides removed':   ('ccreg_scan.py', 'for stride in (1, 2, 3, 4):', 'for stride in (1,):'),
 'status dict check removed':     ('ccreg_scan.py', 'and "status" in k.value.lower()', 'and False'),
 'command-name check removed':    ('ccreg_scan.py', 'if names <= {"args", "command", "cmd"} and consts:', 'if False:'),
 'file bytes not compared':       ('ccreg_receipts.py', '"MATCH" if got == want else "MISMATCH"', '"MATCH"'),
 'missing files ignored':         ('ccreg_receipts.py', 'rows.append({"path": rel, "result": "MISSING"}); continue', 'continue'),
 'root not recomputed':           ('ccreg_receipts.py', 'root = "MATCH" if canonical_digest(body) == data["manifest_root"] else "MISMATCH"', 'root = "MATCH"'),
 'path escape allowed':           ('ccreg_receipts.py', 'if not p.resolve().is_relative_to(base.resolve()):', 'if False:'),
}
caught = {}
for name, (f, old, new) in M.items():
    with tempfile.TemporaryDirectory() as td:
        dst = Path(td) / 'p'; shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns('__pycache__', '*.zip'))
        s = (dst / f).read_text(); assert s.count(old) == 1, name; (dst / f).write_text(s.replace(old, new))
        caught[name] = subprocess.run([sys.executable, '-B', 'tests/test_ccreg.py'], cwd=dst, capture_output=True).returncode != 0
for k, v in caught.items(): print(('CAUGHT  ' if v else 'MISSED  ') + k)
print(f'{sum(caught.values())}/{len(caught)} mutants caught'); sys.exit(0 if all(caught.values()) else 1)
