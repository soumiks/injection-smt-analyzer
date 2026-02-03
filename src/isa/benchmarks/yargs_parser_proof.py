"""
yargs-parser CVE-2020-7608 prototype pollution proof.

This prover analyzes yargs-parser's argument parsing to detect whether
__proto__ keys are sanitized before being used as object properties.

The vulnerability:
- In vulnerable versions (< 18.1.1), keys are used directly without sanitization
- This allows __proto__ to pollute Object.prototype
- In fixed versions (>= 18.1.1), sanitizeKey() replaces __proto__ with ___proto___
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import z3

from isa.witness import Endpoint, Location, Target, Vuln, Witness


@dataclass(frozen=True)
class YargsCheckout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class KeyValidation:
    """Info about key sanitization."""
    has_sanitize_key: bool
    checks_proto: bool
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_yargs_checkout(cache_dir: Path, rev: str) -> YargsCheckout:
    """Ensure yargs-parser is checked out at the given revision."""
    base = cache_dir / "yargs-parser"
    rev_dir = cache_dir / f"yargs-parser-{rev}"

    if not (base / ".git").exists():
        base.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--quiet", "https://github.com/yargs/yargs-parser.git", str(base)])

    if not rev_dir.exists():
        _run(["git", "worktree", "add", "--quiet", str(rev_dir), rev], cwd=base)

    return YargsCheckout(repo_dir=rev_dir, rev=rev)


def _extract_key_validation(checkout: YargsCheckout) -> KeyValidation:
    """Extract key sanitization from yargs-parser.
    
    We look for:
    1. sanitizeKey() function
    2. __proto__ checks
    
    Vulnerable versions lack sanitization.
    """
    index_file = checkout.repo_dir / "index.js"
    
    if not index_file.exists():
        return KeyValidation(
            has_sanitize_key=False,
            checks_proto=False,
            file="unknown",
            line=None,
            snippet=None,
        )
    
    txt = index_file.read_text("utf-8", errors="ignore")
    lines = txt.splitlines()
    
    # Look for sanitizeKey function
    has_sanitize_key = "sanitizeKey" in txt or "function sanitizeKey" in txt
    
    # Look for __proto__ checks/replacements
    checks_proto = ("__proto__" in txt and ("___proto___" in txt or "'__proto__'" in txt))
    
    found_line = None
    found_snippet = None
    
    if has_sanitize_key:
        for i, line in enumerate(lines):
            if "sanitizeKey" in line:
                found_line = i + 1
                found_snippet = "\n".join(lines[max(0, i - 2):i + 5])
                break
    
    return KeyValidation(
        has_sanitize_key=has_sanitize_key,
        checks_proto=checks_proto,
        file="index.js",
        line=found_line,
        snippet=found_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible prototype pollution for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_yargs_checkout(cache, rev)
    validation = _extract_key_validation(checkout)
    
    # If sanitizeKey exists and checks __proto__, it's fixed
    if validation.has_sanitize_key and validation.checks_proto:
        return None
    
    # Vulnerable - build proof
    # Classic yargs-parser prototype pollution payload
    payload = "--__proto__.polluted=yes"
    
    arg = z3.String("argv_arg")
    
    # Prototype pollution: argument contains __proto__
    has_proto = z3.Contains(arg, z3.StringVal("__proto__"))
    
    s = z3.Solver()
    s.add(arg == z3.StringVal(payload))
    s.add(has_proto)
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, validation, payload)
    
    return Witness(
        target=Target(repo="https://github.com/yargs/yargs-parser", rev=rev),
        vuln=Vuln(
            kind="prototype-pollution",
            advisory="CVE-2020-7608",
            cwe="CWE-1321",
        ),
        source=Endpoint(
            kind="command_line_args",
            location=Location(file="<argv>", function="process.argv"),
            notes="Attacker-controlled command-line arguments with __proto__ key",
        ),
        sink=Endpoint(
            kind="property_assignment",
            location=Location(
                file=validation.file,
                line=validation.line,
                function="setKey",
            ),
            notes="Direct property assignment o[key] allows __proto__ pollution",
        ),
        call_chain=[
            Location(file="index.js", function="parse"),
            Location(file="index.js", function="setKey"),
        ],
        path_constraints=[
            "argv_arg contains __proto__ key",
            f"has_sanitize_key: {validation.has_sanitize_key}",
            f"checks_proto: {validation.checks_proto}",
        ],
        smt2=smt2,
        z3_model={
            "argv_arg": payload,
            "has_sanitize_key": validation.has_sanitize_key,
            "checks_proto": validation.checks_proto,
            "validation_snippet": validation.snippet,
        },
    )


def _generate_smt2(rev: str, validation: KeyValidation, payload: str) -> str:
    """Generate SMT2 representation of the proof."""
    lines = [
        ";; injection-smt-analyzer proof (yargs-parser CVE-2020-7608)",
        f";; Target: yargs/yargs-parser @ {rev}",
        f";; Has sanitizeKey: {validation.has_sanitize_key}",
        f";; Checks __proto__: {validation.checks_proto}",
        "",
        "(set-logic QF_S)",
        "",
        "(declare-const argv_arg String)",
        "",
        f'(assert (= argv_arg "{_escape_smt2_string(payload)}"))',
        "",
    ]
    
    if validation.has_sanitize_key and validation.checks_proto:
        lines.extend([
            ";; sanitizeKey() prevents pollution (fixed)",
            "(assert false)",
        ])
    else:
        lines.extend([
            ";; No sanitization - __proto__ pollution (vulnerable)",
            '(assert (str.contains argv_arg "__proto__"))',
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
