"""CC-REG-01 module 1: static scanner for two failure patterns found in real audits.

  1. PATTERNED_HASH  - a "sha256" that is a hand-typed sequence, not a digest
                       (e.g. 3f2e1d0c9b8a7f6e..., 7c8b9a0f1e2d3c4b...).
  2. HARDCODED_PASS  - a status literal ("PASS", "VERIFIED", ...) returned or
                       assigned without depending on any computed condition.
A finding is evidence for review, not a verdict. Stdlib only.
"""
import ast, json, re, sys
from pathlib import Path

HEX64 = re.compile(r'\b[0-9a-f]{64}\b')
STATUS = re.compile(r'^(PASS|PASSED|VERIFIED|SUCCESS|CERTIFIED|[A-Z_]*_VERIFIED|[A-Z_]*_PASS)$')

def hash_pattern_score(h: str) -> dict:
    """Real SHA-256 output looks random. Hand-typed strings contain arithmetic runs,
    either adjacent (0123...) or interleaved (3f2e1d0c... = 3,2,1,0 woven with f,e,d,c).
    For each stride 1-4 and offset, find the longest run of equal steps (mod 16)."""
    d = [int(c, 16) for c in h]
    longest, where = 1, None
    for stride in (1, 2, 3, 4):
        for off in range(stride):
            seq = d[off::stride]
            steps = [(seq[i+1] - seq[i]) % 16 for i in range(len(seq) - 1)]
            run = 1
            for i in range(1, len(steps)):
                run = run + 1 if steps[i] == steps[i-1] else 1
                if run > longest: longest, where = run, (stride, off, steps[i])
    return {"longest_equal_step_run": longest, "pattern": where, "suspicious": longest >= 8}

def scan_hashes(text: str, where: str):
    out = []
    for h in set(HEX64.findall(text.lower())):
        s = hash_pattern_score(h)
        if s["suspicious"]:
            out.append({"type": "PATTERNED_HASH", "where": where, "value": h, **s})
    return out

def _depends_on_computation(node) -> bool:
    return any(isinstance(n, (ast.Compare, ast.BoolOp, ast.Call, ast.Name)) and not
               (isinstance(n, ast.Name) and n.id in ("True", "False")) for n in ast.walk(node))

def scan_python(src: str, where: str):
    out = []
    try: tree = ast.parse(src)
    except SyntaxError as e: return [{"type": "PARSE_ERROR", "where": where, "detail": str(e)}]
    for node in ast.walk(tree):
        # dict entries like "status": "VERIFIED"
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and isinstance(k.value, str) and "status" in k.value.lower()
                        and isinstance(v, ast.Constant) and isinstance(v.value, str) and STATUS.match(v.value)):
                    out.append({"type": "HARDCODED_PASS", "where": f"{where}:{v.lineno}",
                                "detail": f"{k.value!r}: {v.value!r} is a literal, not computed"})
        # 'PASS' if <cond> else ...  where <cond> only compares the command name
        if isinstance(node, ast.IfExp) and isinstance(node.body, ast.Constant) and \
                isinstance(node.body.value, str) and STATUS.match(node.body.value):
            names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
            consts = [n.value for n in ast.walk(node.test) if isinstance(n, ast.Constant)]
            if names <= {"args", "command", "cmd"} and consts:
                out.append({"type": "HARDCODED_PASS", "where": f"{where}:{node.lineno}",
                            "detail": f"{node.body.value!r} chosen by command name only {consts}, not by results"})
    return out

def scan_path(p: Path):
    findings = []
    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file() and f.suffix in (".py", ".json", ".md", ".txt")]
    for f in files:
        text = f.read_text(errors="ignore")
        findings += scan_hashes(text, str(f))
        if f.suffix == ".py": findings += scan_python(text, str(f))
    return findings

if __name__ == "__main__":
    res = [x for a in sys.argv[1:] for x in scan_path(Path(a))]
    print(json.dumps({"findings": res, "count": len(res)}, indent=2))
    sys.exit(1 if res else 0)
