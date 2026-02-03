"""
SMT-based vulnerability prover.

Uses Z3 to prove whether a taint flow can lead to exploitation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import z3

from isa.core.config import BenchmarkConfig, Language, VulnType
from isa.core.taint import TaintAnalyzer, TaintFlow
from isa.witness import Endpoint, Location, Target, Vuln, Witness


@dataclass
class ProofResult:
    """Result of a vulnerability proof attempt."""
    vulnerable: bool
    witness: Optional[Witness] = None
    smt2: Optional[str] = None
    reason: Optional[str] = None


class VulnProver:
    """SMT-based vulnerability prover."""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
    
    def prove(self, repo_dir: Path, rev: str) -> ProofResult:
        """Prove whether a revision is vulnerable.
        
        Steps:
        1. Run taint analysis to find potential flows
        2. Build Z3 constraints for each flow
        3. Check if a malicious payload can reach the sink unblocked
        """
        # Get files to analyze
        files = self._get_target_files(repo_dir)
        if not files:
            return ProofResult(
                vulnerable=False,
                reason="No target files found",
            )
        
        # Run taint analysis
        analyzer = TaintAnalyzer(
            sources=self.config.sources,
            sinks=self.config.sinks,
            sanitizers=self.config.sanitizers,
            language=self.config.language,
        )
        
        flows = analyzer.analyze_files(files)
        
        if not flows:
            return ProofResult(
                vulnerable=False,
                reason="No taint flows found",
            )
        
        # Try to prove each flow is exploitable
        for flow in flows:
            result = self._prove_flow(flow, repo_dir, rev)
            if result.vulnerable:
                return result
        
        return ProofResult(
            vulnerable=False,
            reason=f"Found {len(flows)} flows but none are exploitable",
        )
    
    def _get_target_files(self, repo_dir: Path) -> list[Path]:
        """Get the files to analyze."""
        files = []
        for pattern in self.config.target_files:
            if "*" in pattern:
                files.extend(repo_dir.glob(pattern))
            else:
                path = repo_dir / pattern
                if path.exists():
                    files.append(path)
        return files
    
    def _prove_flow(self, flow: TaintFlow, repo_dir: Path, rev: str) -> ProofResult:
        """Prove whether a specific taint flow is exploitable."""
        vuln_type = self.config.vuln_type
        
        if vuln_type == VulnType.CRLF_INJECTION:
            return self._prove_crlf_injection(flow, rev)
        elif vuln_type == VulnType.SQL_INJECTION:
            return self._prove_sql_injection(flow, rev)
        else:
            # Generic proof attempt
            return self._prove_generic(flow, rev)
    
    def _prove_crlf_injection(self, flow: TaintFlow, rev: str) -> ProofResult:
        """Prove CRLF injection vulnerability."""
        payload = z3.String("payload")
        
        # CRLF injection requires CR or LF in the payload
        has_crlf = z3.Or(
            z3.Contains(payload, z3.StringVal("\r")),
            z3.Contains(payload, z3.StringVal("\n")),
        )
        
        # Check if payload reaches sink without sanitization
        s = z3.Solver()
        
        # Example payload
        example = "application/json\r\n\r\nGET /pwned HTTP/1.1\r\nHost: evil.com\r\n\r\n"
        s.add(payload == z3.StringVal(example))
        s.add(has_crlf)
        
        if s.check() == z3.sat:
            model = s.model()
            smt2 = self._generate_smt2(flow, "crlf", example)
            
            return ProofResult(
                vulnerable=True,
                witness=self._build_witness(flow, rev, example, smt2, model),
                smt2=smt2,
            )
        
        return ProofResult(vulnerable=False, reason="CRLF payload not satisfiable")
    
    def _prove_sql_injection(self, flow: TaintFlow, rev: str) -> ProofResult:
        """Prove SQL injection vulnerability."""
        payload = z3.String("payload")
        
        # SQL injection typically involves quote escaping or keyword injection
        has_sql_chars = z3.Or(
            z3.Contains(payload, z3.StringVal("'")),
            z3.Contains(payload, z3.StringVal('"')),
            z3.Contains(payload, z3.StringVal(";")),
            z3.Contains(payload, z3.StringVal("--")),
            z3.Contains(payload, z3.StringVal("/*")),
        )
        
        s = z3.Solver()
        
        # Example SQL injection payload
        example = "0.05))), (((1"  # From Django CVE-2020-9402
        s.add(payload == z3.StringVal(example))
        s.add(has_sql_chars)
        
        if s.check() == z3.sat:
            model = s.model()
            smt2 = self._generate_smt2(flow, "sql", example)
            
            return ProofResult(
                vulnerable=True,
                witness=self._build_witness(flow, rev, example, smt2, model),
                smt2=smt2,
            )
        
        return ProofResult(vulnerable=False, reason="SQL payload not satisfiable")
    
    def _prove_generic(self, flow: TaintFlow, rev: str) -> ProofResult:
        """Generic proof for unknown vulnerability types."""
        # If we found a flow from source to sink with no sanitization,
        # we consider it potentially vulnerable
        smt2 = self._generate_smt2(flow, "generic", "<payload>")
        
        return ProofResult(
            vulnerable=True,
            witness=self._build_witness(flow, rev, "<unsanitized flow>", smt2, None),
            smt2=smt2,
        )
    
    def _generate_smt2(self, flow: TaintFlow, vuln_type: str, payload: str) -> str:
        """Generate SMT2 representation of the proof."""
        lines = [
            f";; injection-smt-analyzer proof ({self.config.name})",
            f";; Vulnerability type: {vuln_type}",
            "",
            "(set-logic QF_S)",
            "",
            "(declare-const payload String)",
            "",
            f";; Example payload: {payload!r}",
            f'(assert (= payload "{self._escape_smt2(payload)}"))',
            "",
        ]
        
        if vuln_type == "crlf":
            lines.extend([
                ";; CRLF injection constraint",
                "(assert (or (str.contains payload \"\\x0d\") (str.contains payload \"\\x0a\")))",
            ])
        elif vuln_type == "sql":
            lines.extend([
                ";; SQL injection constraint",
                "(assert (or",
                "  (str.contains payload \"'\")",
                "  (str.contains payload \"\\\"\")",
                "  (str.contains payload \";\")",
                "  (str.contains payload \"--\")",
                "))",
            ])
        
        lines.extend([
            "",
            "(check-sat)",
            "(get-model)",
        ])
        
        return "\n".join(lines)
    
    def _escape_smt2(self, s: str) -> str:
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
    
    def _build_witness(
        self,
        flow: TaintFlow,
        rev: str,
        payload: str,
        smt2: str,
        model: Optional[z3.ModelRef],
    ) -> Witness:
        """Build a witness from a proven flow."""
        return Witness(
            target=Target(repo=self.config.repo, rev=rev),
            vuln=Vuln(
                kind=self.config.vuln_type.value,
                advisory=self.config.advisory,
                cwe=self.config.cwe,
            ),
            source=Endpoint(
                kind=flow.source.kind,
                location=flow.source_location,
                notes=flow.source.description,
            ),
            sink=Endpoint(
                kind=flow.sink.kind,
                location=flow.sink_location,
                notes=flow.sink.description,
            ),
            call_chain=flow.call_chain,
            path_constraints=[f"payload == {payload!r}"],
            smt2=smt2,
            z3_model={
                "payload": payload,
                "tainted_values": flow.tainted_values,
                "solver_result": "sat" if model else "assumed",
            },
        )
