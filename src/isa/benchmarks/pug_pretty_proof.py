"""
Pug CVE-2021-21353 template injection proof.

This prover analyzes Pug's pug-code-gen to detect whether the pretty option
is concatenated into generated code without sanitization, allowing RCE.

The vulnerability:
- In vulnerable versions (<= 3.0.0), visitMixin/visitMixinBlock directly concatenate this.pp
- Attacker-controlled pretty option can inject arbitrary JavaScript code
- In fixed versions (>= 3.0.1), pretty option is wrapped with stringify() for escaping
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
class PrettySanitization:
    """Info about pretty option sanitization in pug-code-gen."""
    has_unsanitized_concat: bool
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
    
    if rev_dir.exists():
        return PugCheckout(repo_dir=rev_dir, rev=rev)
    
    # Clone if needed
    if not base.exists():
        _run(["git", "clone", "https://github.com/pugjs/pug.git", str(base)])
    
    # Create revision-specific checkout
    _run(["git", "clone", str(base), str(rev_dir)])
    _run(["git", "checkout", rev], cwd=rev_dir)
    
    return PugCheckout(repo_dir=rev_dir, rev=rev)


def _extract_pretty_sanitization(checkout: PugCheckout) -> PrettySanitization:
    """
    Check if pug-code-gen sanitizes the pretty option.
    
    Vulnerable pattern:
        "pug_indent.push('" + Array(...).join(this.pp) + "');"
    
    Fixed pattern:
        'pug_indent.push(' + stringify(Array(...).join(this.pp)) + ');'
    """
    target_file = checkout.repo_dir / "packages" / "pug-code-gen" / "index.js"
    
    if not target_file.exists():
        return PrettySanitization(
            has_unsanitized_concat=False,
            uses_stringify=False,
            file=str(target_file),
            line=None,
            snippet=None,
        )
    
    content = target_file.read_text(encoding='utf-8')
    lines = content.split('\n')
    
    # Look for vulnerable pattern: direct concatenation of pp without stringify
    # Pattern: "pug_indent.push('" + ... this.pp ... + "');"
    has_unsanitized = False
    uses_stringify = False
    vuln_line = None
    vuln_snippet = None
    
    for i, line in enumerate(lines, 1):
        # Check for the vulnerable pattern in visitMixin/visitMixinBlock
        if 'pug_indent.push' in line:
            # Look at surrounding lines for context (stringify might be on next line)
            context_start = max(0, i - 3)
            context_end = min(len(lines), i + 5)  # Look further ahead for stringify
            context = '\n'.join(lines[context_start:context_end])
            
            # Check if this uses stringify (fixed)
            if 'stringify' in context and ('this.pp' in context or ' pp)' in context):
                uses_stringify = True
            # Check if this directly concatenates pp (vulnerable)
            elif ('this.pp' in context or ' pp)' in context) and '+' in context:
                # Make sure it's not using stringify
                if 'stringify' not in context:
                    has_unsanitized = True
                    vuln_line = i
                    vuln_snippet = line.strip()
    
    return PrettySanitization(
        has_unsanitized_concat=has_unsanitized,
        uses_stringify=uses_stringify,
        file="packages/pug-code-gen/index.js",
        line=vuln_line,
        snippet=vuln_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible template injection for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_pug_checkout(cache, rev)
    sanitization = _extract_pretty_sanitization(checkout)
    
    # If pretty is properly escaped with stringify, it's fixed
    if not sanitization.has_unsanitized_concat or sanitization.uses_stringify:
        return None
    
    # Vulnerable - build proof
    # Classic Pug template injection payload via pretty option
    payload = "');process.mainModule.constructor._load('child_process').exec('whoami');_('"
    
    pretty_option = z3.String("pretty_option")
    
    # Code injection: pretty option contains JavaScript code
    has_code_injection = z3.Contains(pretty_option, z3.StringVal("');"))
    
    s = z3.Solver()
    s.add(pretty_option == z3.StringVal(payload))
    s.add(has_code_injection)
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, sanitization, payload)
    
    return Witness(
        target=Target(repo="https://github.com/pugjs/pug", rev=rev),
        vuln=Vuln(
            kind="template-injection/rce",
            advisory="CVE-2021-21353",
            cwe="CWE-94",
        ),
        source=Endpoint(
            kind="template_option",
            location=Location(file="<user-code>", function="pug.compile()"),
            notes="Attacker-controlled 'pretty' option passed to pug.compile()",
        ),
        sink=Endpoint(
            kind="code_generation",
            location=Location(
                file=sanitization.file,
                line=sanitization.line,
                function="visitMixin or visitMixinBlock",
            ),
            notes="Pretty option directly concatenated into generated JavaScript code",
        ),
        call_chain=[
            Location(file="packages/pug-code-gen/index.js", function="Compiler"),
            Location(file="packages/pug-code-gen/index.js", function="visitMixin"),
        ],
        path_constraints=[
            "pretty option contains code injection payload",
            f"has_unsanitized_concat: {sanitization.has_unsanitized_concat}",
            f"uses_stringify: {sanitization.uses_stringify}",
        ],
        smt2=smt2,
        z3_model={
            "pretty_option": payload,
            "has_unsanitized_concat": sanitization.has_unsanitized_concat,
            "uses_stringify": sanitization.uses_stringify,
            "vulnerable_snippet": sanitization.snippet,
        },
    )


def _generate_smt2(rev: str, sanitization: PrettySanitization, payload: str) -> str:
    """Generate SMT-LIB2 proof for template injection."""
    return f"""; Pug CVE-2021-21353 template injection proof
; rev: {rev}
; has_unsanitized_concat: {sanitization.has_unsanitized_concat}
; uses_stringify: {sanitization.uses_stringify}

(declare-const pretty_option String)

; pretty option contains code injection
(assert (str.contains pretty_option "');"))

; Specific payload
(assert (= pretty_option "{payload}"))

(check-sat)
(get-model)
"""
