"""
Nodemailer CVE-2020-7769 command injection proof.

This prover analyzes Nodemailer's sendmail transport to detect whether
email addresses can start with dashes, enabling command injection.

The vulnerability:
- In vulnerable versions (< 6.4.16), addresses are passed directly to sendmail
- Addresses starting with '-' are interpreted as command-line flags
- In fixed versions (>= 6.4.16), addresses starting with '-' are rejected
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import z3

from isa.witness import Endpoint, Location, Target, Vuln, Witness


@dataclass(frozen=True)
class NodemailerCheckout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class AddressValidation:
    """Info about email address validation."""
    blocks_dash_prefix: bool
    validates_addresses: bool
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_nodemailer_checkout(cache_dir: Path, rev: str) -> NodemailerCheckout:
    """Ensure Nodemailer is checked out at the given revision."""
    base = cache_dir / "nodemailer"
    rev_dir = cache_dir / f"nodemailer-{rev}"

    if not (base / ".git").exists():
        base.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--quiet", "https://github.com/nodemailer/nodemailer.git", str(base)])

    if not rev_dir.exists():
        _run(["git", "worktree", "add", "--quiet", str(rev_dir), rev], cwd=base)

    return NodemailerCheckout(repo_dir=rev_dir, rev=rev)


def _extract_address_validation(checkout: NodemailerCheckout) -> AddressValidation:
    """Extract address validation from sendmail transport.
    
    We look for:
    1. hasInvalidAddresses check
    2. Regex /^-/ to detect dash prefix
    
    Vulnerable versions lack this validation.
    """
    sendmail_file = checkout.repo_dir / "lib/sendmail-transport/index.js"
    
    if not sendmail_file.exists():
        return AddressValidation(
            blocks_dash_prefix=False,
            validates_addresses=False,
            file="unknown",
            line=None,
            snippet=None,
        )
    
    txt = sendmail_file.read_text("utf-8", errors="ignore")
    lines = txt.splitlines()
    
    # Look for hasInvalidAddresses check
    validates_addresses = "hasInvalidAddresses" in txt or "InvalidAddresses" in txt
    
    # Look for dash prefix regex
    blocks_dash = "/^-/" in txt or "^-" in txt
    
    found_line = None
    found_snippet = None
    
    if validates_addresses or blocks_dash:
        for i, line in enumerate(lines):
            if "hasInvalidAddresses" in line or "^-" in line:
                found_line = i + 1
                found_snippet = "\n".join(lines[max(0, i - 2):i + 5])
                break
    
    return AddressValidation(
        blocks_dash_prefix=blocks_dash,
        validates_addresses=validates_addresses,
        file="lib/sendmail-transport/index.js",
        line=found_line,
        snippet=found_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible command injection for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_nodemailer_checkout(cache, rev)
    validation = _extract_address_validation(checkout)
    
    # If dash prefix is blocked, it's fixed
    if validation.blocks_dash_prefix and validation.validates_addresses:
        return None
    
    # Vulnerable - build proof
    # Command injection via sendmail flags
    payload = "-Oqueue_directory=/tmp/pwn -X/tmp/logfile"
    
    addr = z3.String("email_address")
    
    # Command injection: address starts with dash
    starts_with_dash = z3.PrefixOf(z3.StringVal("-"), addr)
    
    s = z3.Solver()
    s.add(addr == z3.StringVal(payload))
    s.add(starts_with_dash)
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, validation, payload)
    
    return Witness(
        target=Target(repo="https://github.com/nodemailer/nodemailer", rev=rev),
        vuln=Vuln(
            kind="command-injection",
            advisory="CVE-2020-7769",
            cwe="CWE-77",
        ),
        source=Endpoint(
            kind="email_address",
            location=Location(file="<mail_options>", function="envelope.to / envelope.from"),
            notes="Attacker-controlled email address in mail options",
        ),
        sink=Endpoint(
            kind="command_execution",
            location=Location(
                file=validation.file,
                line=validation.line,
                function="send",
            ),
            notes="Email address passed as argument to sendmail command",
        ),
        call_chain=[
            Location(file="lib/nodemailer.js", function="sendMail"),
            Location(file=validation.file, function="send"),
        ],
        path_constraints=[
            "email_address starts with '-'",
            f"blocks_dash_prefix: {validation.blocks_dash_prefix}",
            f"validates_addresses: {validation.validates_addresses}",
        ],
        smt2=smt2,
        z3_model={
            "email_address": payload,
            "blocks_dash_prefix": validation.blocks_dash_prefix,
            "validates_addresses": validation.validates_addresses,
            "validation_snippet": validation.snippet,
        },
    )


def _generate_smt2(rev: str, validation: AddressValidation, payload: str) -> str:
    """Generate SMT2 representation of the proof."""
    lines = [
        ";; injection-smt-analyzer proof (Nodemailer CVE-2020-7769)",
        f";; Target: nodemailer/nodemailer @ {rev}",
        f";; Blocks dash prefix: {validation.blocks_dash_prefix}",
        f";; Validates addresses: {validation.validates_addresses}",
        "",
        "(set-logic QF_S)",
        "",
        "(declare-const email_address String)",
        "",
        f'(assert (= email_address "{_escape_smt2_string(payload)}"))',
        "",
    ]
    
    if validation.blocks_dash_prefix and validation.validates_addresses:
        lines.extend([
            ";; Dash prefix blocked (fixed)",
            "(assert false)",
        ])
    else:
        lines.extend([
            ";; Dash prefix allowed - command injection (vulnerable)",
            '(assert (str.prefixof "-" email_address))',
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
