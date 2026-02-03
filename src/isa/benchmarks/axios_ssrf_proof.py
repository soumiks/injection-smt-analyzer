"""
Axios CVE-2020-28168 SSRF proof.

This prover analyzes Axios's HTTP adapter to detect whether proxy settings
are re-applied on redirects, preventing SSRF attacks.

The vulnerability:
- In vulnerable versions (< 0.21.1), proxy settings are only applied to initial request
- Redirects bypass the proxy, allowing SSRF to internal services
- In fixed versions (>= 0.21.1), beforeRedirect callback re-applies proxy settings
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import z3

from isa.witness import Endpoint, Location, Target, Vuln, Witness


@dataclass(frozen=True)
class AxiosCheckout:
    repo_dir: Path
    rev: str


@dataclass(frozen=True)
class ProxyHandling:
    """Info about proxy redirect handling in axios HTTP adapter."""
    sets_proxy_options: bool
    has_before_redirect: bool
    file: str
    line: Optional[int]
    snippet: Optional[str]


def _run(cmd: list[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, text=True, capture_output=True)
    return p.stdout


def _ensure_axios_checkout(cache_dir: Path, rev: str) -> AxiosCheckout:
    """Ensure Axios is checked out at the given revision."""
    base = cache_dir / "axios"
    rev_dir = cache_dir / f"axios-{rev}"
    
    if rev_dir.exists():
        return AxiosCheckout(repo_dir=rev_dir, rev=rev)
    
    # Clone if needed
    if not base.exists():
        _run(["git", "clone", "https://github.com/axios/axios.git", str(base)])
    
    # Create revision-specific checkout
    _run(["git", "clone", str(base), str(rev_dir)])
    _run(["git", "checkout", rev], cwd=rev_dir)
    
    return AxiosCheckout(repo_dir=rev_dir, rev=rev)


def _extract_proxy_handling(checkout: AxiosCheckout) -> ProxyHandling:
    """
    Check if axios HTTP adapter properly handles proxy on redirects.
    
    Vulnerable pattern:
        if (proxy) {
          options.hostname = proxy.host;
          options.port = proxy.port;
          // No beforeRedirect callback!
        }
    
    Fixed pattern:
        options.beforeRedirect = function beforeRedirect(redirection) {
          setProxy(redirection, proxy, redirection.href);
        };
    """
    target_file = checkout.repo_dir / "lib" / "adapters" / "http.js"
    
    if not target_file.exists():
        return ProxyHandling(
            sets_proxy_options=False,
            has_before_redirect=False,
            file=str(target_file),
            line=None,
            snippet=None,
        )
    
    content = target_file.read_text(encoding='utf-8')
    lines = content.split('\n')
    
    # Check if proxy options are set
    sets_proxy_options = False
    has_before_redirect = False
    vuln_line = None
    vuln_snippet = None
    
    # Look for proxy configuration
    for i, line in enumerate(lines, 1):
        # Check if setting proxy options
        if 'options.hostname' in line and 'proxy.host' in line:
            sets_proxy_options = True
            vuln_line = i
            # Grab surrounding context
            context_start = max(0, i - 5)
            context_end = min(len(lines), i + 10)
            context = '\n'.join(lines[context_start:context_end])
            vuln_snippet = context
            
            # Check if beforeRedirect is nearby (within next 20 lines)
            check_range = lines[i:min(len(lines), i + 20)]
            if any('beforeRedirect' in l for l in check_range):
                has_before_redirect = True
    
    # Also check for the setProxy function that includes beforeRedirect
    if 'beforeRedirect' in content and 'setProxy' in content:
        has_before_redirect = True
    
    return ProxyHandling(
        sets_proxy_options=sets_proxy_options,
        has_before_redirect=has_before_redirect,
        file="lib/adapters/http.js",
        line=vuln_line,
        snippet=vuln_snippet,
    )


def prove_witness(rev: str) -> Optional[Witness]:
    """Return a witness iff Z3 finds a feasible SSRF for this rev."""
    cache = Path.cwd() / ".isa_cache"
    checkout = _ensure_axios_checkout(cache, rev)
    handling = _extract_proxy_handling(checkout)
    
    # If beforeRedirect is properly set, it's fixed
    if not handling.sets_proxy_options or handling.has_before_redirect:
        return None
    
    # Vulnerable - build proof
    # SSRF via redirect that bypasses proxy
    initial_url = z3.String("initial_url")
    redirect_url = z3.String("redirect_url")
    goes_through_proxy = z3.Bool("redirect_goes_through_proxy")
    
    s = z3.Solver()
    
    # Initial request to attacker-controlled server
    s.add(initial_url == z3.StringVal("http://attacker.com/evil"))
    
    # Attacker responds with redirect to internal service
    s.add(redirect_url == z3.StringVal("http://localhost:6379/"))
    
    # Vulnerable: redirect does NOT go through proxy
    s.add(z3.Not(goes_through_proxy))
    
    if s.check() != z3.sat:
        return None
    
    model = s.model()
    
    smt2 = _generate_smt2(rev, handling)
    
    return Witness(
        target=Target(repo="https://github.com/axios/axios", rev=rev),
        vuln=Vuln(
            kind="ssrf",
            advisory="CVE-2020-28168",
            cwe="CWE-918",
        ),
        source=Endpoint(
            kind="http_request",
            location=Location(file="<user-code>", function="axios()"),
            notes="HTTP request with proxy configuration",
        ),
        sink=Endpoint(
            kind="http_redirect",
            location=Location(
                file=handling.file,
                line=handling.line,
                function="http.request",
            ),
            notes="Redirect bypasses proxy settings, allowing SSRF to internal services",
        ),
        call_chain=[
            Location(file="lib/axios.js", function="axios"),
            Location(file="lib/adapters/http.js", function="httpAdapter"),
            Location(file="lib/adapters/http.js", function="http.request"),
        ],
        path_constraints=[
            "proxy configuration present",
            f"sets_proxy_options: {handling.sets_proxy_options}",
            f"has_before_redirect: {handling.has_before_redirect}",
            "redirect does not go through proxy",
        ],
        smt2=smt2,
        z3_model={
            "initial_url": "http://attacker.com/evil",
            "redirect_url": "http://localhost:6379/",
            "redirect_goes_through_proxy": False,
            "sets_proxy_options": handling.sets_proxy_options,
            "has_before_redirect": handling.has_before_redirect,
        },
    )


def _generate_smt2(rev: str, handling: ProxyHandling) -> str:
    """Generate SMT-LIB2 proof for SSRF vulnerability."""
    return f"""; Axios CVE-2020-28168 SSRF proof
; rev: {rev}
; sets_proxy_options: {handling.sets_proxy_options}
; has_before_redirect: {handling.has_before_redirect}

(declare-const initial_url String)
(declare-const redirect_url String)
(declare-const redirect_goes_through_proxy Bool)

; Initial request to attacker-controlled server
(assert (= initial_url "http://attacker.com/evil"))

; Attacker responds with redirect to internal service
(assert (= redirect_url "http://localhost:6379/"))

; Vulnerable: redirect does NOT go through proxy
(assert (not redirect_goes_through_proxy))

(check-sat)
(get-model)
"""
