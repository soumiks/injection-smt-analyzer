"""
Command-line interface for injection-smt-analyzer.
"""

import argparse
import json
import sys
from typing import Optional

# Import benchmark definitions to register them
import isa.benchmarks.definitions  # noqa: F401

from isa.core.config import list_benchmarks


VERSION = "0.2.0"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="isa",
        description="injection-smt-analyzer: Static analysis for injection vulnerabilities using SMT/Z3",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Version command
    sub.add_parser("version", help="Print version")

    # List command
    sub.add_parser("list", help="List available benchmarks")

    # Analyze command
    p_analyze = sub.add_parser("analyze", help="Analyze a benchmark")
    p_analyze.add_argument(
        "--benchmark", "-b",
        required=True,
        help="Benchmark ID (use 'isa list' to see available)",
    )
    p_analyze.add_argument(
        "--rev", "-r",
        required=True,
        help="Git revision/tag to analyze",
    )
    p_analyze.add_argument(
        "--mode", "-m",
        default="prove",
        choices=["prove", "demo", "legacy"],
        help="Analysis mode: prove (full), demo (placeholder), legacy (old prover)",
    )
    p_analyze.add_argument(
        "--output", "-o",
        choices=["json", "pretty", "summary"],
        default="pretty",
        help="Output format",
    )

    args = parser.parse_args(argv)

    if args.cmd == "version":
        print(VERSION)
        return 0

    if args.cmd == "list":
        benchmarks = list_benchmarks()
        print("Available benchmarks:")
        for b in benchmarks:
            print(f"  - {b}")
        return 0

    if args.cmd == "analyze":
        return _cmd_analyze(args)

    return 1


def _cmd_analyze(args) -> int:
    """Handle the analyze command."""
    benchmark_id = args.benchmark
    rev = args.rev
    mode = args.mode
    output = args.output

    # Legacy mode: use the old provers for backward compatibility
    if mode == "legacy" or benchmark_id in ("undici_crlf", "django_sql", "log4j_jndi", "spring4shell", "laravel_ignition", "handlebars_lookup", "nodemailer_sendmail", "pug_pretty", "json5_proto", "yargs_parser"):
        return _legacy_analyze(benchmark_id, rev, mode if mode != "legacy" else "prove", output)

    # New framework mode
    from isa.analyzer import get_analyzer
    
    analyzer = get_analyzer()
    result = analyzer.analyze(benchmark_id, rev, mode)
    
    _print_result(result, output)
    return 0 if result.get("ok") else 1


def _legacy_analyze(benchmark_id: str, rev: str, mode: str, output: str) -> int:
    """Use the legacy provers for backward compatibility."""
    if benchmark_id == "undici_crlf":
        from isa.benchmarks.undici_crlf import demo_witness
        from isa.benchmarks.undici_crlf_proof import prove_witness
        
        if mode == "demo":
            w = demo_witness(rev)
            result = {"ok": True, "mode": "demo", "witness": w.to_dict()}
        else:
            w = prove_witness(rev)
            if w is None:
                result = {"ok": True, "vulnerable": False, "rev": rev}
            else:
                result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    if benchmark_id == "django_sql":
        from isa.benchmarks.django_sql_proof import prove_witness
        
        w = prove_witness(rev)
        if w is None:
            result = {"ok": True, "vulnerable": False, "rev": rev}
        else:
            result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    if benchmark_id == "log4j_jndi":
        from isa.benchmarks.log4j_jndi_proof import prove_witness
        
        w = prove_witness(rev)
        if w is None:
            result = {"ok": True, "vulnerable": False, "rev": rev}
        else:
            result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    if benchmark_id == "spring4shell":
        from isa.benchmarks.spring4shell_proof import prove_witness
        
        w = prove_witness(rev)
        if w is None:
            result = {"ok": True, "vulnerable": False, "rev": rev}
        else:
            result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    if benchmark_id == "laravel_ignition":
        from isa.benchmarks.laravel_ignition_proof import prove_witness
        
        w = prove_witness(rev)
        if w is None:
            result = {"ok": True, "vulnerable": False, "rev": rev}
        else:
            result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    if benchmark_id == "handlebars_lookup":
        from isa.benchmarks.handlebars_lookup_proof import prove_witness
        
        w = prove_witness(rev)
        if w is None:
            result = {"ok": True, "vulnerable": False, "rev": rev}
        else:
            result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    if benchmark_id == "nodemailer_sendmail":
        from isa.benchmarks.nodemailer_sendmail_proof import prove_witness
        
        w = prove_witness(rev)
        if w is None:
            result = {"ok": True, "vulnerable": False, "rev": rev}
        else:
            result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    if benchmark_id == "pug_pretty":
        from isa.benchmarks.pug_pretty_proof import prove_witness
        
        w = prove_witness(rev)
        if w is None:
            result = {"ok": True, "vulnerable": False, "rev": rev}
        else:
            result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    if benchmark_id == "json5_proto":
        from isa.benchmarks.json5_proto_proof import prove_witness
        
        w = prove_witness(rev)
        if w is None:
            result = {"ok": True, "vulnerable": False, "rev": rev}
        else:
            result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    if benchmark_id == "yargs_parser":
        from isa.benchmarks.yargs_parser_proof import prove_witness
        
        w = prove_witness(rev)
        if w is None:
            result = {"ok": True, "vulnerable": False, "rev": rev}
        else:
            result = {"ok": True, "vulnerable": True, "witness": w.to_dict()}
        
        _print_result(result, output)
        return 0
    
    print(f"Error: Legacy mode not available for benchmark: {benchmark_id}", file=sys.stderr)
    return 1


def _print_result(result: dict, output: str) -> None:
    """Print analysis result in the specified format."""
    if output == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    elif output == "summary":
        ok = result.get("ok", False)
        vulnerable = result.get("vulnerable", "unknown")
        if ok:
            status = "VULNERABLE" if vulnerable else "NOT VULNERABLE"
            print(f"Result: {status}")
            if "reason" in result:
                print(f"Reason: {result['reason']}")
            if "witness" in result and vulnerable:
                w = result["witness"]
                print(f"Vuln: {w.get('vuln', {}).get('kind', 'unknown')}")
                print(f"Advisory: {w.get('vuln', {}).get('advisory', 'N/A')}")
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")
    else:  # pretty (default)
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
