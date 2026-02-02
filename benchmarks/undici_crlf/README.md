# Benchmark: undici CRLF injection (request splitting)

Target: https://github.com/nodejs/undici

This benchmark checks a known CRLF injection / request splitting issue.

- Vulnerable: `v5.8.0`
- Fixed: `v5.8.2`
- Fix commit: https://github.com/nodejs/undici/commit/66165d604fd0aee70a93ed5c44ad4cc2df395f80

## Run

From repo root:

```bash
bash benchmarks/undici_crlf/run_check.sh
```

Expected results:

- `v5.8.0` should produce **2** requests on the local server (`/` and injected `/pwned`).
- `v5.8.2` should reject the header and produce **0** requests.
