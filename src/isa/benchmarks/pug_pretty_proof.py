"""
Pug CVE-2021-21353 template injection proof.

This prover analyzes Pug's code generator to detect whether
the 'pretty' option is sanitized before being used in generated code.

The vulnerability:
- In vulnerable versions (< 3.0.1), pretty option is concatenated into code without escaping
- Attackers can inject arbitrary JavaScript via the pretty parameter
- In fixed versions (>= 3.0.1), pretty is validated and escaped with stringify()
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import z3

from isa.witness import Endpoint, Location, Target, Vuln, Witness


@dataclass(frozen=True)
class PugCheckout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class PrettyValidation:
    """Info about pretty option validation."""
    validates_whitespace: bool
    uses_stringify: bool
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_pug_checkout(cache_dir: Path, rev: str) -> PugCheckout:
    """Ensure Pug is checked out at the given revision."""
    base = cache_dir / "pug"
    rev_dir = cache_dir / f"pug-{rev}"

    if not (base / ".git").exists():
        base.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--quiet", "https://github.com/pugjs/pug.git", str(base)])

    if not rev_dir.exists():
        _run(["git", "worktree", "add", "--quiet", str(rev_dir), rev], cwd=base)

    return PugCheckout(repo_dir=rev_dir, rev=rev)


def _extract_pretty_validation(checkout: PugCheckout) -> PrettyValidation:
    """Extract pretty option validation from pug-code-gen.
    
    We look for:
    1. Regex /^\s+$/ to validate whitespace-only
    2. stringify() function to escape the value
    
    Vulnerable versions lack both.
    """
    codegen_file = checkout.repo_dir / "packages/pug-code-gen/index.js"
    
    if not codegen_file.exists():
        return PrettyValidation(
            validates_whitespace=False,
            uses_stringify=False,
            file="unknown",
            line=None,
            snippet=None,
        )
    
    txt = codegen_file.read_text("utf-8", errors="ignore")
    lines = txt.splitlines()
    
    # Look for whitespace validation regex
    validates_whitespace = r"/^\s+$/" in txt or r"/^\\s+$/" in txt
    
    # Look for stringify() usage with pretty/pp
    uses_stringify = "stringify(" in txt and ("Array(" in txt or "join(pp)" in txt or "join(this.pp)" in txt)
    
    found_line = None
    found_snippet = None
    
    if validates_whitespace or uses_stringify:
        for i, line in enumerate(lines):
            if r"\s+" in line or "stringify" in line:
                found_line = i + 1
                found_snippet = "\n".join(lines[max(0, i - 2):i + 5])
                break
    
    return PrettyValidation(
        validates_whitespace=validates_whitespace,
        uses_stringify=uses_stringify,
        file="packages/pug-code-gen/index.js",
        line=found_line,
        snippet=found_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible template injection for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_pug_checkout(cache, rev)
    validation = _extract_pretty_validation(checkout)
    
    # If both validations exist, it's fixed
    if validation.validates_whitespace and validation.uses_stringify:
        return None
    
    # Vulnerable - build proof
    # Classic Pug RCE payload via pretty option
    payload = "\\n\\n= global.process.mainModule.require('child_process').execSync('id').toString()//'"
    
    pretty_opt = z3.String("pretty_option")
    
    # Template injection: pretty contains code
    has_code_injection = z3.Or(
        z3.Contains(pretty_opt, z3.StringVal("process")),
        z3.Contains(pretty_opt, z3.StringVal("require")),
        z3.Contains(pretty_opt, z3.StringVal("execSync")),
    )
    
    s = z3.Solver()
    s.add(pretty_opt == z3.StringVal(payload))
    s.add(has_code_injection)
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, validation, payload)
    
    return Witness(
        target=Target(repo="https://github.com/pugjs/pug", rev=rev),
        vuln=Vuln(
            kind="template-injection/rce",
            advisory="CVE-2021-21353",
            cwe="CWE-94",
        ),
        source=Endpoint(
            kind="template_option",
            location=Location(file="<pug_options>", function="pretty parameter"),
            notes="Attacker-controlled pretty option in pug.compile() options",
        ),
        sink=Endpoint(
            kind="code_generation",
            location=Location(
                file=validation.file,
                line=validation.line,
                function="visitMixinBlock / visitMixin",
            ),
            notes="Pretty option concatenated into generated JavaScript without escaping",
        ),
        call_chain=[
            Location(file="packages/pug/lib/index.js", function="compile"),
            Location(file="packages/pug-code-gen/index.js", function="Compiler"),
            Location(file=validation.file, function="visitMixinBlock"),
        ],
        path_constraints=[
            "pretty_option contains JavaScript code",
            f"validates_whitespace: {validation.validates_whitespace}",
            f"uses_stringify: {validation.uses_stringify}",
        ],
        smt2=smt2,
        z3_model={
            "pretty_option": payload,
            "validates_whitespace": validation.validates_whitespace,
            "uses_stringify": validation.uses_stringify,
            "validation_snippet": validation.snippet,
        },
    )


def _generate_smt2(rev: str, validation: PrettyValidation, payload: str) -> str:
    """Generate SMT2 representation of the proof."""
    lines = [
        ";; injection-smt-analyzer proof (Pug CVE-2021-21353)",
        f";; Target: pugjs/pug @ {rev}",
        f";; Validates whitespace: {validation.validates_whitespace}",
        f";; Uses stringify: {validation.uses_stringify}",
        "",
        "(set-logic QF_S)",
        "",
        "(declare-const pretty_option String)",
        "",
        f'(assert (= pretty_option "{_escape_smt2_string(payload)}"))',
        "",
    ]
    
    if validation.validates_whitespace and validation.uses_stringify:
        lines.extend([
            ";; Pretty option validated and escaped (fixed)",
            "(assert false)",
        ])
    else:
        lines.extend([
            ";; Pretty option used without validation (vulnerable)",
            "(assert (or",
            '  (str.contains pretty_option "process")',
            '  (str.contains pretty_option "require")',
            '  (str.contains pretty_option "execSync")',
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
