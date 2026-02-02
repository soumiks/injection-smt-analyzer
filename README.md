# injection-smt-analyzer

Static analysis experiments for injection vulnerabilities using SMT (SMT2) and Z3.

## Goals (initial)

- Start with a **repro harness**: known vulnerable vs fixed commits (first target: `nodejs/undici` CRLF injection / request splitting).
- Build an interprocedural analysis that can emit a **witness**:
  - source → sink
  - call chain
  - path constraints
  - Z3 model (when applicable)

This repo will evolve milestone-by-milestone.

## Status

- Milestone 0: repo skeleton + tooling ✅
- Milestone 1: undici CRLF benchmark harness ✅
- Milestone 2: witness schema + `isa analyze` stub ✅
- Milestone 3: undici CRLF proof mode (SMT2+Z3 best-effort) (in progress)

## Dev setup

macOS/Homebrew Python uses PEP 668 (externally-managed env). Use a venv:

```bash
make venv
```

Quick demo (prints a placeholder witness JSON):

```bash
make demo
```

## License

MIT
