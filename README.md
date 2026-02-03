# injection-smt-analyzer

Static analysis tool for detecting injection vulnerabilities using SMT (SMT2) and Z3.

## What it does

Instead of just flagging "this looks vulnerable," the tool:

1. **Extracts validation logic** from source code
2. **Models the validation** as Z3 string constraints
3. **Checks satisfiability** of an injection payload
4. **Produces a witness** with:
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

## Benchmarks

### undici CRLF injection (CVE-2022-35948)

The first benchmark targets a CRLF injection vulnerability in the Node.js `undici` HTTP client:

- **Vulnerable:** `v5.8.0` — no validation on `content-type` header
- **Fixed:** `v5.8.2` — added `headerCharRegex` check that rejects CR/LF

The prover:
1. Clones undici at the target revision
2. Extracts the `headerCharRegex` validation from `lib/core/request.js`
3. Models the regex as Z3 string constraints
4. Checks if a CRLF injection payload satisfies the constraints
5. If SAT → emits a witness proving the vulnerability

## Quick Start

```bash
# Setup (creates venv, installs deps)
make venv

# Run the prover against vulnerable version
make prove

# Run all tests
make test
```

## Usage

```bash
# Prove vulnerability in v5.8.0
isa analyze --benchmark undici_crlf --rev v5.8.0 --mode prove

# Check if v5.8.2 is vulnerable (should return vulnerable: false)
isa analyze --benchmark undici_crlf --rev v5.8.2 --mode prove

# Demo mode (placeholder witness, no Z3)
isa analyze --benchmark undici_crlf --rev v5.8.0 --mode demo
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
      "content_type": "application/json\r\n\r\nGET /pwned HTTP/1.1\r\n...",
      "validation_present": false
    }
  }
}
```

## Dev Setup

macOS/Homebrew Python uses PEP 668 (externally-managed env). Use a venv:

```bash
make venv
```

Run tests:

```bash
make test          # Full test suite
make test-fast     # Skip integration tests (faster)
```

## Architecture

```
src/isa/
├── cli.py                    # CLI entry point
├── witness.py                # Witness dataclass schema
└── benchmarks/
    ├── undici_crlf.py        # Demo/placeholder witness
    └── undici_crlf_proof.py  # Z3-backed prover (Milestone 3)

tests/
└── test_undici_crlf.py       # Unit + integration tests
```

## License

MIT
