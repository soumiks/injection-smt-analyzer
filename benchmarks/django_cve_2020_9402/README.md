# Benchmark: Django CVE-2020-9402 (SQL injection)

Target: https://github.com/django/django

Advisory: CVE-2020-9402 / GHSA-3gh2-xw74-jmcw

Fix commit:
- https://github.com/django/django/commit/6695d29b1c1ce979725816295a26ecc64ae0e927

Notes:
- SQL injection in Oracle GIS handling (tolerance parameter).
- Goal: add a minimal pre-fix vs post-fix regression harness and then an SMT/Z3-backed witness.

## Plan

- Identify a minimal reproducer (likely unit-test-level) that exercises the vulnerable code path.
- Run it on a vulnerable rev (pre-fix) and fixed rev (post-fix) and record expected behavior.
