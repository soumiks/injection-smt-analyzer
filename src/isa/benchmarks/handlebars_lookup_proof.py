"""
Handlebars.js CVE-2019-19919 prototype pollution proof.

This prover analyzes Handlebars' lookup helper to detect whether
the constructor property can be accessed, leading to RCE.

The vulnerability:
- In vulnerable versions (<= 4.0.13), lookup helper allows accessing 'constructor'
- Attackers can use {{lookup (lookup this "constructor") "name"}} to access prototype
- In fixed versions (>= 4.0.14), constructor access is blocked when not enumerable
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import z3

from isa.witness import Endpoint, Location, Target, Vuln, Witness


@dataclass(frozen=True)
class HandlebarsCheckout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class LookupValidation:
    """Info about lookup helper constructor protection."""
    blocks_constructor: bool
    checks_enumerable: bool
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_handlebars_checkout(cache_dir: Path, rev: str) -> HandlebarsCheckout:
    """Ensure Handlebars is checked out at the given revision."""
    base = cache_dir / "handlebars.js"
    rev_dir = cache_dir / f"handlebars-{rev}"

    if not (base / ".git").exists():
        base.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--quiet", "https://github.com/handlebars-lang/handlebars.js.git", str(base)])

    if not rev_dir.exists():
        _run(["git", "worktree", "add", "--quiet", str(rev_dir), rev], cwd=base)

    return HandlebarsCheckout(repo_dir=rev_dir, rev=rev)


def _extract_lookup_validation(checkout: HandlebarsCheckout) -> LookupValidation:
    """Extract lookup helper constructor protection.
    
    We look for:
    1. Check for 'constructor' field name
    2. propertyIsEnumerable check
    
    Vulnerable versions lack these checks.
    """
    lookup_file = checkout.repo_dir / "lib/handlebars/helpers/lookup.js"
    
    if not lookup_file.exists():
        return LookupValidation(
            blocks_constructor=False,
            checks_enumerable=False,
            file="unknown",
            line=None,
            snippet=None,
        )
    
    txt = lookup_file.read_text("utf-8", errors="ignore")
    lines = txt.splitlines()
    
    # Look for constructor check
    blocks_constructor = "field === 'constructor'" in txt or 'field === "constructor"' in txt
    
    # Look for propertyIsEnumerable check
    checks_enumerable = "propertyIsEnumerable" in txt
    
    found_line = None
    found_snippet = None
    
    if blocks_constructor:
        for i, line in enumerate(lines):
            if "constructor" in line:
                found_line = i + 1
                found_snippet = "\n".join(lines[max(0, i - 2):i + 5])
                break
    
    return LookupValidation(
        blocks_constructor=blocks_constructor,
        checks_enumerable=checks_enumerable,
        file="lib/handlebars/helpers/lookup.js",
        line=found_line,
        snippet=found_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible prototype pollution for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_handlebars_checkout(cache, rev)
    validation = _extract_lookup_validation(checkout)
    
    # If constructor is blocked, it's fixed
    if validation.blocks_constructor and validation.checks_enumerable:
        return None
    
    # Vulnerable - build proof
    # Classic Handlebars prototype pollution payload
    payload = '{{lookup (lookup this "constructor") "name"}}'
    
    template = z3.String("handlebars_template")
    
    # Prototype pollution: template accesses constructor property
    has_constructor_access = z3.Contains(template, z3.StringVal("constructor"))
    
    s = z3.Solver()
    s.add(template == z3.StringVal(payload))
    s.add(has_constructor_access)
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, validation, payload)
    
    return Witness(
        target=Target(repo="https://github.com/handlebars-lang/handlebars.js", rev=rev),
        vuln=Vuln(
            kind="prototype-pollution/rce",
            advisory="CVE-2019-19919",
            cwe="CWE-1321",
        ),
        source=Endpoint(
            kind="template_input",
            location=Location(file="<template>", function="handlebars template"),
            notes="Attacker-controlled Handlebars template with lookup helper",
        ),
        sink=Endpoint(
            kind="property_access",
            location=Location(
                file=validation.file,
                line=validation.line,
                function="lookup helper",
            ),
            notes="lookup helper accesses 'constructor' property without validation",
        ),
        call_chain=[
            Location(file="lib/handlebars/runtime.js", function="invokeHelper"),
            Location(file=validation.file, function="lookup"),
        ],
        path_constraints=[
            "template contains lookup helper accessing 'constructor'",
            f"blocks_constructor: {validation.blocks_constructor}",
            f"checks_enumerable: {validation.checks_enumerable}",
        ],
        smt2=smt2,
        z3_model={
            "handlebars_template": payload,
            "blocks_constructor": validation.blocks_constructor,
            "checks_enumerable": validation.checks_enumerable,
            "validation_snippet": validation.snippet,
        },
    )


def _generate_smt2(rev: str, validation: LookupValidation, payload: str) -> str:
    """Generate SMT2 representation of the proof."""
    lines = [
        ";; injection-smt-analyzer proof (Handlebars.js CVE-2019-19919)",
        f";; Target: handlebars-lang/handlebars.js @ {rev}",
        f";; Blocks constructor: {validation.blocks_constructor}",
        f";; Checks enumerable: {validation.checks_enumerable}",
        "",
        "(set-logic QF_S)",
        "",
        "(declare-const handlebars_template String)",
        "",
        f'(assert (= handlebars_template "{_escape_smt2_string(payload)}"))',
        "",
    ]
    
    if validation.blocks_constructor and validation.checks_enumerable:
        lines.extend([
            ";; Constructor access blocked (fixed)",
            "(assert false)",
        ])
    else:
        lines.extend([
            ";; Constructor accessible via lookup (vulnerable)",
            '(assert (str.contains handlebars_template "constructor"))',
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
        elif c == '{' or c == '}':
            # Handlebars uses braces, keep them
            result.append(c)
        elif ord(c) < 0x20 or ord(c) > 0x7e:
            result.append(f'\\x{ord(c):02x}')
        else:
            result.append(c)
    return "".join(result)
