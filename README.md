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

Milestone 0: repo skeleton + tooling (in progress).

## License

MIT
