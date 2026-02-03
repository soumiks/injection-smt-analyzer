"""
Unified analyzer that uses the config-driven framework.

This module provides the main entry point for analyzing benchmarks.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Optional

from isa.core.config import BenchmarkConfig, get_benchmark, list_benchmarks
from isa.core.prover import ProofResult, VulnProver
from isa.witness import Witness

# Import to register benchmarks
import isa.benchmarks.definitions  # noqa: F401


class Analyzer:
    """Unified analyzer for all benchmarks."""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path.cwd() / ".isa_cache"
    
    def analyze(
        self,
        benchmark_id: str,
        rev: str,
        mode: str = "prove",
    ) -> dict[str, Any]:
        """Analyze a benchmark at a specific revision.
        
        Args:
            benchmark_id: ID of the benchmark to run
            rev: Git revision to analyze
            mode: Analysis mode ("prove" for full analysis, "demo" for placeholder)
            
        Returns:
            Analysis result as a dictionary
        """
        config = get_benchmark(benchmark_id)
        if config is None:
            return {
                "ok": False,
                "error": f"Unknown benchmark: {benchmark_id}",
                "available": list_benchmarks(),
            }
        
        if mode == "demo":
            return self._demo_mode(config, rev)
        
        return self._prove_mode(config, rev)
    
    def _demo_mode(self, config: BenchmarkConfig, rev: str) -> dict[str, Any]:
        """Run in demo mode with placeholder witness."""
        from isa.witness import Endpoint, Location, Target, Vuln, Witness
        
        witness = Witness(
            target=Target(repo=config.repo, rev=rev),
            vuln=Vuln(kind=config.vuln_type.value, advisory=config.advisory, cwe=config.cwe),
            source=Endpoint(
                kind=config.sources[0].kind if config.sources else "unknown",
                location=Location(file="demo", function="demo"),
                notes="Demo mode - placeholder witness",
            ),
            sink=Endpoint(
                kind=config.sinks[0].kind if config.sinks else "unknown",
                location=Location(file="demo", function="demo"),
                notes="Demo mode - placeholder witness",
            ),
            call_chain=[],
            path_constraints=[],
        )
        
        return {
            "ok": True,
            "mode": "demo",
            "vulnerable": True,
            "witness": witness.to_dict(),
        }
    
    def _prove_mode(self, config: BenchmarkConfig, rev: str) -> dict[str, Any]:
        """Run full proof mode with taint analysis and Z3."""
        # Ensure repo is checked out
        repo_dir = self._ensure_checkout(config, rev)
        if repo_dir is None:
            return {
                "ok": False,
                "error": f"Failed to checkout {config.repo} at {rev}",
            }
        
        # Run the prover
        prover = VulnProver(config)
        result = prover.prove(repo_dir, rev)
        
        if result.vulnerable:
            return {
                "ok": True,
                "vulnerable": True,
                "witness": result.witness.to_dict() if result.witness else None,
            }
        else:
            return {
                "ok": True,
                "vulnerable": False,
                "rev": rev,
                "reason": result.reason,
            }
    
    def _ensure_checkout(self, config: BenchmarkConfig, rev: str) -> Optional[Path]:
        """Ensure the repository is checked out at the specified revision."""
        # Extract repo name from URL
        repo_name = config.repo.rstrip("/").split("/")[-1]
        base_dir = self.cache_dir / repo_name
        rev_dir = self.cache_dir / f"{repo_name}-{rev}"
        
        try:
            # Clone if needed
            if not base_dir.exists():
                base_dir.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["git", "clone", "--quiet", config.repo, str(base_dir)],
                    check=True,
                    capture_output=True,
                )
            
            # Create worktree for this revision
            if not rev_dir.exists():
                subprocess.run(
                    ["git", "worktree", "add", "--quiet", str(rev_dir), rev],
                    cwd=str(base_dir),
                    check=True,
                    capture_output=True,
                )
            
            return rev_dir
        except subprocess.CalledProcessError as e:
            print(f"Git error: {e.stderr.decode() if e.stderr else e}")
            return None


def get_analyzer(cache_dir: Optional[Path] = None) -> Analyzer:
    """Get an analyzer instance."""
    return Analyzer(cache_dir)
