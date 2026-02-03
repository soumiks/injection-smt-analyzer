# injection-smt-analyzer

Static analysis tool for detecting injection vulnerabilities using SMT (Z3), AST parsing (tree-sitter), and interprocedural taint analysis.

## What it does

Instead of just flagging "this looks vulnerable," the tool:

1. **Parses source code** using tree-sitter (supports JavaScript and Python)
2. **Performs taint analysis** tracking data from sources to sinks
3. **Models validation logic** as Z3 string constraints
4. **Checks satisfiability** of an injection payload
5. **Produces a witness** with:
   - Source → sink dataflow
   - Call chain
   - Path constraints
   - SMT2 formula
   - Z3 model (concrete exploit)

## Status

| Milestone | Description | Status |
|-----------|-------------|--------|
| 0 | Repo skeleton + tooling | ✅ |
| 1 | undici CRLF benchmark harness | ✅ |
| 2 | Witness schema + `isa analyze` stub | ✅ |
| 3 | undici CRLF proof mode (SMT2+Z3) | ✅ |
| 4 | Django SQL injection benchmark | ✅ |
| 5 | tree-sitter AST parsing | ✅ |
| 6 | Interprocedural taint analysis framework | ✅ |
| 7 | Config-driven benchmark system | ✅ |

## Benchmarks

### 1. undici CRLF injection (CVE-2022-35948)

Node.js `undici` HTTP client CRLF injection via `content-type` header.

- **Vulnerable:** `v5.8.0` — no `headerCharRegex` validation
- **Fixed:** `v5.8.2` — added regex check that rejects CR/LF

```bash
isa analyze --benchmark undici_crlf --rev v5.8.0 --output summary
# Result: VULNERABLE

isa analyze --benchmark undici_crlf --rev v5.8.2 --output summary
# Result: NOT VULNERABLE
```

### 2. Django GIS SQL injection (CVE-2020-9402)

Django ORM SQL injection via `tolerance` parameter in GIS functions (Oracle backend).

- **Vulnerable:** `3.0.3` — tolerance directly interpolated into SQL
- **Fixed:** `3.0.4` — tolerance wrapped in `Value()` for proper escaping

```bash
isa analyze --benchmark django_sql --rev 3.0.3 --output summary
# Result: VULNERABLE

isa analyze --benchmark django_sql --rev 3.0.4 --output summary
# Result: NOT VULNERABLE
```

## Quick Start

```bash
# Setup (creates venv, installs deps)
make venv

# List available benchmarks
isa list

# Run proofs
make prove

# Run all tests
make test
```

## Usage

```bash
# Analyze a benchmark
isa analyze --benchmark <id> --rev <revision> [--mode prove|demo] [--output json|pretty|summary]

# List benchmarks
isa list

# Version
isa version
```

## Example Output

```json
{
  "ok": true,
  "vulnerable": true,
  "witness": {
    "target": {
      "repo": "https://github.com/nodejs/undici",
      "rev": "v5.8.0"
    },
    "vuln": {
      "kind": "crlf-injection/request-splitting",
      "advisory": "CVE-2022-35948",
      "cwe": "CWE-93"
    },
    "source": {
      "kind": "external_input",
      "location": {"file": "<attacker>", "function": "headers['content-type']"}
    },
    "sink": {
      "kind": "http-request-serialization",
      "location": {"file": "lib/core/request.js", "function": "processHeader"}
    },
    "smt2": "...",
    "z3_model": {
      "content_type": "application/json\r\n\r\nGET /pwned HTTP/1.1\r\n..."
    }
  }
}
```

## Architecture

```
src/isa/
├── cli.py                    # CLI entry point
├── analyzer.py               # Unified analyzer
├── witness.py                # Witness dataclass schema
├── core/
│   ├── config.py             # Benchmark configuration system
│   ├── parser.py             # tree-sitter AST parsing
│   ├── taint.py              # Interprocedural taint analysis
│   └── prover.py             # SMT-based vulnerability prover
└── benchmarks/
    ├── definitions.py        # Benchmark configurations
    ├── undici_crlf.py        # undici demo witness
    ├── undici_crlf_proof.py  # undici Z3 prover
    └── django_sql_proof.py   # Django Z3 prover

tests/
├── test_undici_crlf.py       # undici benchmark tests
└── test_django_sql.py        # Django benchmark tests
```

## Adding a New Benchmark

1. Define the benchmark in `src/isa/benchmarks/definitions.py`:

```python
MY_BENCHMARK = BenchmarkConfig(
    id="my_benchmark",
    name="My Vulnerability",
    repo="https://github.com/org/repo",
    language=Language.JAVASCRIPT,  # or PYTHON
    vuln_type=VulnType.SQL_INJECTION,
    sources=[SourceSpec(...)],
    sinks=[SinkSpec(...)],
    sanitizers=[SanitizerSpec(...)],
    target_files=["path/to/file.py"],
    revisions=[
        RevisionSpec(tag="v1.0", expected_vulnerable=True),
        RevisionSpec(tag="v1.1", expected_vulnerable=False),
    ],
)
register_benchmark(MY_BENCHMARK)
```

2. Optionally, create a specialized prover in `src/isa/benchmarks/`.

3. Add tests in `tests/`.

## Dev Setup

```bash
# Create venv and install deps
make venv

# Run tests
make test          # Full test suite
make test-fast     # Skip integration tests

# Run proofs for all benchmarks
make prove
```

## License

MIT
