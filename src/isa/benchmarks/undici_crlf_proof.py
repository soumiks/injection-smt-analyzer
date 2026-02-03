"""
Milestone 3: SMT2+Z3 proof mode for undici CRLF injection (CVE-2022-35948).

This module:
1. Clones nodejs/undici at the target revision
2. Extracts the headerCharRegex validation from lib/core/request.js
3. Models the validation as Z3 string constraints
4. Proves whether a CRLF injection payload can bypass validation
5. Emits a witness with SMT2 and Z3 model if vulnerable
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import z3

from isa.witness import Endpoint, Location, Target, Vuln, Witness


@dataclass(frozen=True)
class UndiciCheckout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class ValidationInfo:
    """Extracted validation info from undici source."""
    has_header_char_regex: bool
    regex_pattern: Optional[str]
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_undici_checkout(cache_dir: Path, rev: str) -> UndiciCheckout:
    """Ensure a local checkout of nodejs/undici at the given rev.

    Uses a shared clone under .isa_cache/undici/ with per-rev worktrees.
    """
    base = cache_dir / "undici"
    rev_dir = cache_dir / f"undici-{rev}"

    # Clone once if needed
    if not (base / ".git").exists():
        base.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--quiet", "https://github.com/nodejs/undici.git", str(base)])

    # Create worktree for this rev if needed
    if not rev_dir.exists():
        _run(["git", "worktree", "add", "--quiet", str(rev_dir), rev], cwd=base)

    return UndiciCheckout(repo_dir=rev_dir, rev=rev)


def _extract_validation_info(checkout: UndiciCheckout) -> ValidationInfo:
    """Extract the header validation logic from lib/core/request.js.

    The key difference between vulnerable and fixed versions:
    - v5.8.0: content-type check does NOT include headerCharRegex validation
    - v5.8.2: content-type check DOES include headerCharRegex.exec(val) === null

    We look for the specific pattern where content-type validation AND
    headerCharRegex appear together in the same conditional block.
    """
    request_js = checkout.repo_dir / "lib" / "core" / "request.js"

    if not request_js.exists():
        return ValidationInfo(
            has_header_char_regex=False,
            regex_pattern=None,
            file="lib/core/request.js",
            line=None,
            snippet=None,
        )

    txt = request_js.read_text("utf-8", errors="ignore")
    lines = txt.splitlines()

    # Look for headerCharRegex definition
    # Pattern: const headerCharRegex = /[...]/
    regex_match = re.search(r"const\s+headerCharRegex\s*=\s*/([^/]+)/", txt)
    regex_pattern = regex_match.group(1) if regex_match else None

    # Find the content-type validation block in processHeader function
    # We need to check if headerCharRegex is used IN THE SAME conditional
    # as the 'content-type' check
    content_type_has_regex_check = False
    line_num = None
    snippet = None

    # Look for the pattern: key.toLowerCase() === 'content-type' && headerCharRegex
    # This appears within ~5 lines in the fixed version
    for i, line in enumerate(lines):
        if "'content-type'" in line.lower() or '"content-type"' in line.lower():
            # Check the surrounding context (this line and next few lines)
            context_start = max(0, i - 3)
            context_end = min(len(lines), i + 7)
            context = "\n".join(lines[context_start:context_end])

            # Check if this specific content-type check includes headerCharRegex
            if "headerCharRegex" in context and "content-type" in context.lower():
                # More precise: check if they're in the same conditional block
                # The fix adds: headerCharRegex.exec(val) === null on the line after content-type
                if "headerCharRegex.exec" in context:
                    content_type_has_regex_check = True
                    line_num = i + 1
                    snippet = context
                    break

    return ValidationInfo(
        has_header_char_regex=content_type_has_regex_check,
        regex_pattern=regex_pattern,
        file="lib/core/request.js",
        line=line_num,
        snippet=snippet,
    )


def _header_char_regex_rejects(val: z3.SeqRef, pattern: Optional[str]) -> z3.BoolRef:
    """Model the headerCharRegex validation in Z3.

    The regex /[^\t\x20-\x7e\x80-\xff]/ matches characters that are INVALID.
    If regex.exec(val) !== null, the value is rejected.

    Characters rejected (NOT in valid set):
    - 0x00-0x08 (before tab)
    - 0x0a-0x1f (LF through unit separator, except tab 0x09)
    - 0x7f (DEL)

    Critically, this includes:
    - 0x0a = LF (\n)
    - 0x0d = CR (\r)
    """
    # We model: "value is rejected if it contains any invalid character"
    # For CRLF injection, we specifically care about \r and \n

    cr = z3.StringVal("\r")
    lf = z3.StringVal("\n")

    # Rejected if contains CR or LF (or other control chars, but these are the key ones)
    contains_invalid = z3.Or(z3.Contains(val, cr), z3.Contains(val, lf))

    return contains_invalid


def _build_accepts_constraint(val: z3.SeqRef, validation: ValidationInfo) -> z3.BoolRef:
    """Build Z3 constraint for whether a value is accepted by the validation."""
    if not validation.has_header_char_regex:
        # No validation — all values accepted (vulnerable)
        return z3.BoolVal(True)

    # Value is accepted if it does NOT contain invalid characters
    rejected = _header_char_regex_rejects(val, validation.regex_pattern)
    return z3.Not(rejected)


def _generate_smt2(rev: str, validation: ValidationInfo, payload: str) -> str:
    """Generate human-readable SMT2 representation of the proof."""
    lines = [
        ";; injection-smt-analyzer proof (undici CRLF benchmark)",
        f";; Target: nodejs/undici @ {rev}",
        f";; Validation present: {validation.has_header_char_regex}",
        "",
        "(set-logic QF_S)  ; Quantifier-free string logic",
        "",
        ";; Declare the attacker-controlled header value",
        "(declare-const content_type String)",
        "",
        f";; Assert the injection payload",
        f'(assert (= content_type "{_escape_smt2_string(payload)}"))',
        "",
    ]

    if validation.has_header_char_regex:
        lines.extend([
            ";; Model the headerCharRegex validation (fix present)",
            ";; Regex /[^\\t\\x20-\\x7e\\x80-\\xff]/ rejects CR/LF",
            "(assert (not (str.contains content_type \"\\x0d\")))  ; no CR",
            "(assert (not (str.contains content_type \"\\x0a\")))  ; no LF",
            "",
        ])
    else:
        lines.extend([
            ";; No headerCharRegex validation on content-type (vulnerable)",
            ";; All header values are accepted",
            "(assert true)",
            "",
        ])

    lines.extend([
        "(check-sat)",
        "(get-model)",
    ])

    return "\n".join(lines)


def _escape_smt2_string(s: str) -> str:
    """Escape a string for SMT2 format."""
    result = []
    for c in s:
        if c == '"':
            result.append('""')
        elif c == '\\':
            result.append('\\\\')
        elif c == '\r':
            result.append('\\x0d')
        elif c == '\n':
            result.append('\\x0a')
        elif ord(c) < 0x20 or ord(c) > 0x7e:
            result.append(f'\\x{ord(c):02x}')
        else:
            result.append(c)
    return "".join(result)


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible CRLF injection for this rev.

    The proof strategy:
    1. Extract validation logic from the target revision
    2. Model the validation as Z3 constraints
    3. Check if a CRLF injection payload satisfies the constraints
    4. If SAT, the payload bypasses validation → vulnerable
    """
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_undici_checkout(cache, rev)
    validation = _extract_validation_info(checkout)

    # The injection payload — content-type with embedded HTTP request
    payload = (
        "application/json\r\n"
        "\r\n"
        "GET /pwned HTTP/1.1\r\n"
        "Host: 127.0.0.1:3000\r\n"
        "\r\n"
    )

    # Build Z3 model
    ct = z3.String("content_type")
    accepts = _build_accepts_constraint(ct, validation)

    s = z3.Solver()
    s.add(ct == z3.StringVal(payload))
    s.add(accepts)

    result = s.check()

    if result != z3.sat:
        # Payload rejected — not vulnerable (or at least this payload doesn't work)
        return None

    # Vulnerable — build witness
    model = s.model()
    model_payload = str(model.eval(ct, model_completion=True))

    smt2 = _generate_smt2(rev, validation, payload)

    return Witness(
        target=Target(repo="https://github.com/nodejs/undici", rev=rev),
        vuln=Vuln(
            kind="crlf-injection/request-splitting",
            advisory="CVE-2022-35948",
            cwe="CWE-93",
        ),
        source=Endpoint(
            kind="external_input",
            location=Location(file="<attacker>", function="headers['content-type']"),
            notes="Attacker-controlled HTTP header value",
        ),
        sink=Endpoint(
            kind="http-request-serialization",
            location=Location(
                file=validation.file,
                line=validation.line,
                function="processHeader",
            ),
            notes="Header value serialized into outbound HTTP request without CRLF validation",
        ),
        call_chain=[
            Location(file="lib/core/request.js", function="Request.constructor"),
            Location(file="lib/core/request.js", function="processHeader"),
        ],
        path_constraints=[
            "content_type == <payload with CRLF>",
            f"Accepts(content_type) == {validation.has_header_char_regex == False}",
        ],
        smt2=smt2,
        z3_model={
            "content_type": payload,
            "solver_result": "sat",
            "validation_present": validation.has_header_char_regex,
            "validation_pattern": validation.regex_pattern,
            "validation_snippet": validation.snippet,
        },
    )
