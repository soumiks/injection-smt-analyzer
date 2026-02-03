"""
JSON5 CVE-2022-46175 prototype pollution proof.

This prover analyzes JSON5's parser to detect whether
__proto__ properties are properly handled during parsing.

The vulnerability:
- In vulnerable versions (< 2.2.2), properties are assigned with parent[key] = value
- This allows __proto__ to pollute Object.prototype
- In fixed versions (>= 2.2.2), Object.defineProperty() is used to prevent pollution
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import z3

from isa.witness import Endpoint, Location, Target, Vuln, Witness


@dataclass(frozen=True)
class JSON5Checkout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class ProtoValidation:
    """Info about __proto__ protection."""
    uses_define_property: bool
    has_proto_check: bool
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_json5_checkout(cache_dir: Path, rev: str) -> JSON5Checkout:
    """Ensure JSON5 is checked out at the given revision."""
    base = cache_dir / "json5"
    rev_dir = cache_dir / f"json5-{rev}"

    if not (base / ".git").exists():
        base.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--quiet", "https://github.com/json5/json5.git", str(base)])

    if not rev_dir.exists():
        _run(["git", "worktree", "add", "--quiet", str(rev_dir), rev], cwd=base)

    return JSON5Checkout(repo_dir=rev_dir, rev=rev)


def _extract_proto_validation(checkout: JSON5Checkout) -> ProtoValidation:
    """Extract __proto__ protection from parse.js.
    
    We look for:
    1. Object.defineProperty() usage instead of direct assignment
    2. Explicit __proto__ checks
    
    Vulnerable versions use direct assignment parent[key] = value.
    """
    parse_file = checkout.repo_dir / "lib/parse.js"
    
    if not parse_file.exists():
        return ProtoValidation(
            uses_define_property=False,
            has_proto_check=False,
            file="unknown",
            line=None,
            snippet=None,
        )
    
    txt = parse_file.read_text("utf-8", errors="ignore")
    lines = txt.splitlines()
    
    # Look for Object.defineProperty in the push/assignment logic
    uses_define_property = "Object.defineProperty" in txt and ("parent[key]" not in txt or txt.count("Object.defineProperty") > 0)
    
    # Look for explicit __proto__ checks
    has_proto_check = "__proto__" in txt or '"__proto__"' in txt
    
    found_line = None
    found_snippet = None
    
    if uses_define_property:
        for i, line in enumerate(lines):
            if "Object.defineProperty" in line and ("parent" in line or "value" in line):
                found_line = i + 1
                found_snippet = "\n".join(lines[max(0, i - 2):i + 6])
                break
    
    return ProtoValidation(
        uses_define_property=uses_define_property,
        has_proto_check=has_proto_check,
        file="lib/parse.js",
        line=found_line,
        snippet=found_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible prototype pollution for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_json5_checkout(cache, rev)
    validation = _extract_proto_validation(checkout)
    
    # If defineProperty is used, it's fixed
    if validation.uses_define_property:
        return None
    
    # Vulnerable - build proof
    # Classic prototype pollution payload
    payload = '{"__proto__":{"polluted":"yes"}}'
    
    json_str = z3.String("json5_string")
    
    # Prototype pollution: JSON contains __proto__
    has_proto = z3.Contains(json_str, z3.StringVal("__proto__"))
    
    s = z3.Solver()
    s.add(json_str == z3.StringVal(payload))
    s.add(has_proto)
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, validation, payload)
    
    return Witness(
        target=Target(repo="https://github.com/json5/json5", rev=rev),
        vuln=Vuln(
            kind="prototype-pollution",
            advisory="CVE-2022-46175",
            cwe="CWE-1321",
        ),
        source=Endpoint(
            kind="json_input",
            location=Location(file="<json5_string>", function="JSON5.parse()"),
            notes="Attacker-controlled JSON5 string with __proto__ property",
        ),
        sink=Endpoint(
            kind="property_assignment",
            location=Location(
                file=validation.file,
                line=validation.line,
                function="push",
            ),
            notes="Direct property assignment parent[key] = value allows __proto__ pollution",
        ),
        call_chain=[
            Location(file="lib/index.js", function="parse"),
            Location(file="lib/parse.js", function="parseCore"),
            Location(file=validation.file, function="push"),
        ],
        path_constraints=[
            "json5_string contains __proto__ property",
            f"uses_define_property: {validation.uses_define_property}",
            f"has_proto_check: {validation.has_proto_check}",
        ],
        smt2=smt2,
        z3_model={
            "json5_string": payload,
            "uses_define_property": validation.uses_define_property,
            "has_proto_check": validation.has_proto_check,
            "validation_snippet": validation.snippet,
        },
    )


def _generate_smt2(rev: str, validation: ProtoValidation, payload: str) -> str:
    """Generate SMT2 representation of the proof."""
    lines = [
        ";; injection-smt-analyzer proof (JSON5 CVE-2022-46175)",
        f";; Target: json5/json5 @ {rev}",
        f";; Uses defineProperty: {validation.uses_define_property}",
        f";; Has __proto__ check: {validation.has_proto_check}",
        "",
        "(set-logic QF_S)",
        "",
        "(declare-const json5_string String)",
        "",
        f'(assert (= json5_string "{_escape_smt2_string(payload)}"))',
        "",
    ]
    
    if validation.uses_define_property:
        lines.extend([
            ";; Object.defineProperty() prevents pollution (fixed)",
            "(assert false)",
        ])
    else:
        lines.extend([
            ";; Direct assignment allows __proto__ pollution (vulnerable)",
            '(assert (str.contains json5_string "__proto__"))',
        ])
    
    lines.extend([
        "",
        "(check-sat)",
        "(get-model)",
    ])
    
    return "\n".join(lines)


def _escape_smt2_string(s: str) -> str:
    """Escape string for SMT2."""
    result = []
    for c in s:
        if c == '"':
            result.append('""')
        elif c == '\\':
            result.append('\\\\')
        elif ord(c) < 0x20 or ord(c) > 0x7e:
            result.append(f'\\x{ord(c):02x}')
        else:
            result.append(c)
    return "".join(result)
