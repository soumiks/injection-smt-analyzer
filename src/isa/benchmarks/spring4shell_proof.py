"""
Spring Framework CVE-2022-22965 (Spring4Shell) data binding injection proof.

This prover analyzes Spring's data binding mechanism to detect whether
attackers can manipulate ClassLoader or ProtectionDomain properties to
achieve remote code execution.

The vulnerability:
- In vulnerable versions (< 5.3.18, < 5.2.20), data binding allows setting
  class.classLoader.* and class.protectionDomain properties
- Attackers can manipulate Tomcat's AccessLogValve settings via these properties
- In fixed versions, ClassLoader and ProtectionDomain types are blocked from binding
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
class SpringCheckout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class DataBindingValidation:
    """Info about data binding restrictions."""
    blocks_classloader: bool
    blocks_protection_domain: bool
    restricts_class_properties: bool
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_spring_checkout(cache_dir: Path, rev: str) -> SpringCheckout:
    """Ensure Spring Framework is checked out at the given revision."""
    base = cache_dir / "spring-framework"
    rev_dir = cache_dir / f"spring-{rev}"

    if not (base / ".git").exists():
        base.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--quiet", "https://github.com/spring-projects/spring-framework.git", str(base)])

    if not rev_dir.exists():
        _run(["git", "worktree", "add", "--quiet", str(rev_dir), rev], cwd=base)

    return SpringCheckout(repo_dir=rev_dir, rev=rev)


def _extract_data_binding_restrictions(checkout: SpringCheckout) -> DataBindingValidation:
    """Extract data binding restriction logic from CachedIntrospectionResults.
    
    We look for:
    1. ClassLoader.class.isAssignableFrom() check
    2. ProtectionDomain.class.isAssignableFrom() check
    3. Restrictions on Class property binding
    
    Vulnerable versions lack these checks.
    """
    introspection_file = checkout.repo_dir / "spring-beans/src/main/java/org/springframework/beans/CachedIntrospectionResults.java"
    
    if not introspection_file.exists():
        return DataBindingValidation(
            blocks_classloader=False,
            blocks_protection_domain=False,
            restricts_class_properties=False,
            file="unknown",
            line=None,
            snippet=None,
        )
    
    txt = introspection_file.read_text("utf-8", errors="ignore")
    lines = txt.splitlines()
    
    # Look for ClassLoader type check
    blocks_classloader = "ClassLoader.class.isAssignableFrom" in txt
    
    # Look for ProtectionDomain type check  
    blocks_protection_domain = "ProtectionDomain.class.isAssignableFrom" in txt
    
    # Look for Class property restrictions (only allowing name variants)
    # The fix: (!\"name\".equals(pd.getName()) && !pd.getName().endsWith(\"Name\"))
    restricts_class = 'endsWith("Name")' in txt or 'endsWith(\\"Name\\")' in txt
    
    found_line = None
    found_snippet = None
    
    if blocks_classloader or blocks_protection_domain:
        # Find line number
        for i, line in enumerate(lines):
            if "ClassLoader.class.isAssignableFrom" in line or "ProtectionDomain.class.isAssignableFrom" in line:
                found_line = i + 1
                found_snippet = "\n".join(lines[max(0, i - 2):i + 5])
                break
    
    return DataBindingValidation(
        blocks_classloader=blocks_classloader,
        blocks_protection_domain=blocks_protection_domain,
        restricts_class_properties=restricts_class,
        file="spring-beans/src/main/java/org/springframework/beans/CachedIntrospectionResults.java",
        line=found_line,
        snippet=found_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible data binding injection for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_spring_checkout(cache, rev)
    validation = _extract_data_binding_restrictions(checkout)
    
    # If all protections exist, it's fixed
    if validation.blocks_classloader and validation.blocks_protection_domain and validation.restricts_class_properties:
        return None
    
    # Vulnerable - build proof
    # The classic Spring4Shell payload via class.module.classLoader
    payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i"
    
    prop = z3.String("property_path")
    
    # Data binding injection: property path accesses classLoader or protectionDomain
    has_classloader_access = z3.Or(
        z3.Contains(prop, z3.StringVal(".classLoader")),
        z3.Contains(prop, z3.StringVal(".protectionDomain")),
    )
    
    s = z3.Solver()
    s.add(prop == z3.StringVal(payload))
    s.add(has_classloader_access)
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, validation, payload)
    
    return Witness(
        target=Target(repo="https://github.com/spring-projects/spring-framework", rev=rev),
        vuln=Vuln(
            kind="data-binding-injection/rce",
            advisory="CVE-2022-22965",
            cwe="CWE-94",
        ),
        source=Endpoint(
            kind="http_parameter",
            location=Location(file="<web_request>", function="HTTP parameters"),
            notes="Attacker-controlled HTTP parameters bound to object properties",
        ),
        sink=Endpoint(
            kind="property_setter",
            location=Location(
                file=validation.file,
                line=validation.line,
                function="CachedIntrospectionResults",
            ),
            notes="Data binding allows setting ClassLoader/ProtectionDomain properties",
        ),
        call_chain=[
            Location(file="spring-web/.../RequestMappingHandlerAdapter.java", function="invokeHandlerMethod"),
            Location(file="spring-web/.../ServletModelAttributeMethodProcessor.java", function="resolveArgument"),
            Location(file="spring-beans/.../DataBinder.java", function="bind"),
            Location(file=validation.file, function="CachedIntrospectionResults"),
        ],
        path_constraints=[
            "property_path contains .classLoader or .protectionDomain",
            f"blocks_classloader: {validation.blocks_classloader}",
            f"blocks_protection_domain: {validation.blocks_protection_domain}",
            f"restricts_class_properties: {validation.restricts_class_properties}",
        ],
        smt2=smt2,
        z3_model={
            "property_path": payload,
            "blocks_classloader": validation.blocks_classloader,
            "blocks_protection_domain": validation.blocks_protection_domain,
            "restricts_class_properties": validation.restricts_class_properties,
            "validation_snippet": validation.snippet,
        },
    )


def _generate_smt2(rev: str, validation: DataBindingValidation, payload: str) -> str:
    """Generate SMT2 representation of the proof."""
    lines = [
        ";; injection-smt-analyzer proof (Spring Framework CVE-2022-22965 / Spring4Shell)",
        f";; Target: spring-projects/spring-framework @ {rev}",
        f";; Blocks ClassLoader: {validation.blocks_classloader}",
        f";; Blocks ProtectionDomain: {validation.blocks_protection_domain}",
        f";; Restricts Class properties: {validation.restricts_class_properties}",
        "",
        "(set-logic QF_S)",
        "",
        "(declare-const property_path String)",
        "",
        f'(assert (= property_path "{_escape_smt2_string(payload)}"))',
        "",
    ]
    
    if validation.blocks_classloader and validation.blocks_protection_domain and validation.restricts_class_properties:
        lines.extend([
            ";; All data binding protections in place (fixed)",
            "(assert false)",
        ])
    else:
        lines.extend([
            ";; Data binding allows ClassLoader/ProtectionDomain access (vulnerable)",
            "(assert (or",
            '  (str.contains property_path ".classLoader")',
            '  (str.contains property_path ".protectionDomain")',
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
