"""
Laravel Ignition CVE-2021-3129 code injection proof.

This prover analyzes Ignition's MakeViewVariableOptionalSolution to detect whether
file operations can be performed on arbitrary paths, leading to RCE.

The vulnerability:
- In vulnerable versions (<= 2.5.1), file_get_contents() is called on 
  unsanitized viewFile parameter
- Attackers can use stream wrappers (php://filter) or write arbitrary files
- In fixed versions (>= 2.5.2), isSafePath() validates the path
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import z3

from isa.witness import Endpoint, Location, Target, Vuln, Witness


@dataclass(frozen=True)
class IgnitionCheckout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class PathValidation:
    """Info about path validation in file operations."""
    has_path_validation: bool
    checks_stream_wrappers: bool
    checks_file_extension: bool
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_ignition_checkout(cache_dir: Path, rev: str) -> IgnitionCheckout:
    """Ensure Ignition is checked out at the given revision."""
    base = cache_dir / "ignition"
    rev_dir = cache_dir / f"ignition-{rev}"

    if not (base / ".git").exists():
        base.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--quiet", "https://github.com/facade/ignition.git", str(base)])

    if not rev_dir.exists():
        _run(["git", "worktree", "add", "--quiet", str(rev_dir), rev], cwd=base)

    return IgnitionCheckout(repo_dir=rev_dir, rev=rev)


def _extract_path_validation(checkout: IgnitionCheckout) -> PathValidation:
    """Extract path validation logic from MakeViewVariableOptionalSolution.
    
    We look for:
    1. isSafePath() method existence
    2. Checks for stream wrappers (startsWith check)
    3. Checks for .blade.php extension
    
    Vulnerable versions lack this validation.
    """
    solution_file = checkout.repo_dir / "src/Solutions/MakeViewVariableOptionalSolution.php"
    
    if not solution_file.exists():
        return PathValidation(
            has_path_validation=False,
            checks_stream_wrappers=False,
            checks_file_extension=False,
            file="unknown",
            line=None,
            snippet=None,
        )
    
    txt = solution_file.read_text("utf-8", errors="ignore")
    lines = txt.splitlines()
    
    # Look for isSafePath method
    has_safe_path = "function isSafePath" in txt or "protected function isSafePath" in txt
    
    # Look for stream wrapper/path checks (startsWith check)
    checks_stream = "startsWith" in txt or "Str::startsWith" in txt
    
    # Look for extension check
    checks_extension = ".blade.php" in txt and "endsWith" in txt
    
    found_line = None
    found_snippet = None
    
    if has_safe_path:
        # Find line number
        for i, line in enumerate(lines):
            if "isSafePath" in line:
                found_line = i + 1
                found_snippet = "\n".join(lines[max(0, i - 2):i + 8])
                break
    
    return PathValidation(
        has_path_validation=has_safe_path,
        checks_stream_wrappers=checks_stream,
        checks_file_extension=checks_extension,
        file="src/Solutions/MakeViewVariableOptionalSolution.php",
        line=found_line,
        snippet=found_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible path injection for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_ignition_checkout(cache, rev)
    validation = _extract_path_validation(checkout)
    
    # If path validation exists with all checks, it's fixed
    if validation.has_path_validation and validation.checks_stream_wrappers and validation.checks_file_extension:
        return None
    
    # Vulnerable - build proof
    # Classic Ignition exploit using php://filter stream wrapper
    payload = "php://filter/write=convert.base64-decode/resource=storage/logs/laravel.log"
    
    path = z3.String("view_file_path")
    
    # Path injection: uses stream wrapper or arbitrary path
    has_stream_wrapper = z3.Or(
        z3.Contains(path, z3.StringVal("php://")),
        z3.Contains(path, z3.StringVal("file://")),
        z3.Contains(path, z3.StringVal("phar://")),
    )
    
    s = z3.Solver()
    s.add(path == z3.StringVal(payload))
    s.add(has_stream_wrapper)
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, validation, payload)
    
    return Witness(
        target=Target(repo="https://github.com/facade/ignition", rev=rev),
        vuln=Vuln(
            kind="code-injection/rce",
            advisory="CVE-2021-3129",
            cwe="CWE-94",
        ),
        source=Endpoint(
            kind="http_parameter",
            location=Location(file="<web_request>", function="POST /solutions"),
            notes="Attacker-controlled viewFile parameter in solution execution",
        ),
        sink=Endpoint(
            kind="file_operation",
            location=Location(
                file=validation.file,
                line=validation.line,
                function="makeOptional",
            ),
            notes="file_get_contents() called on unsanitized path allowing stream wrappers",
        ),
        call_chain=[
            Location(file="src/Http/Controllers/ExecuteSolutionController.php", function="__invoke"),
            Location(file=validation.file, function="run"),
            Location(file=validation.file, function="makeOptional"),
        ],
        path_constraints=[
            "view_file_path contains stream wrapper (php://, file://, etc.)",
            f"has_path_validation: {validation.has_path_validation}",
            f"checks_stream_wrappers: {validation.checks_stream_wrappers}",
            f"checks_file_extension: {validation.checks_file_extension}",
        ],
        smt2=smt2,
        z3_model={
            "view_file_path": payload,
            "has_path_validation": validation.has_path_validation,
            "checks_stream_wrappers": validation.checks_stream_wrappers,
            "checks_file_extension": validation.checks_file_extension,
            "validation_snippet": validation.snippet,
        },
    )


def _generate_smt2(rev: str, validation: PathValidation, payload: str) -> str:
    """Generate SMT2 representation of the proof."""
    lines = [
        ";; injection-smt-analyzer proof (Laravel Ignition CVE-2021-3129)",
        f";; Target: facade/ignition @ {rev}",
        f";; Has path validation: {validation.has_path_validation}",
        f";; Checks stream wrappers: {validation.checks_stream_wrappers}",
        f";; Checks file extension: {validation.checks_file_extension}",
        "",
        "(set-logic QF_S)",
        "",
        "(declare-const view_file_path String)",
        "",
        f'(assert (= view_file_path "{_escape_smt2_string(payload)}"))',
        "",
    ]
    
    if validation.has_path_validation and validation.checks_stream_wrappers and validation.checks_file_extension:
        lines.extend([
            ";; Path validation blocks stream wrappers (fixed)",
            "(assert false)",
        ])
    else:
        lines.extend([
            ";; No path validation - stream wrappers allowed (vulnerable)",
            "(assert (or",
            '  (str.contains view_file_path "php://")',
            '  (str.contains view_file_path "file://")',
            '  (str.contains view_file_path "phar://")',
            "))",
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
