VENV?=.venv
PY?=$(VENV)/bin/python
ISA?=$(VENV)/bin/isa

.PHONY: venv
venv:
	python3 -m venv $(VENV)
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e ".[dev]"

.PHONY: list
list: venv
	$(ISA) list

.PHONY: demo
# Prints a placeholder witness (schema smoke test)
demo: venv
	$(ISA) analyze --benchmark undici_crlf --rev v5.8.0 --mode demo

.PHONY: prove
# Run the Z3-backed prover against all benchmarks
prove: prove-undici prove-django

.PHONY: prove-undici
prove-undici: venv
	@echo "=== undici CRLF: v5.8.0 (vulnerable) ==="
	$(ISA) analyze --benchmark undici_crlf --rev v5.8.0 --output summary
	@echo ""
	@echo "=== undici CRLF: v5.8.2 (fixed) ==="
	$(ISA) analyze --benchmark undici_crlf --rev v5.8.2 --output summary

.PHONY: prove-django
prove-django: venv
	@echo ""
	@echo "=== Django SQL: 3.0.3 (vulnerable) ==="
	$(ISA) analyze --benchmark django_sql --rev 3.0.3 --output summary
	@echo ""
	@echo "=== Django SQL: 3.0.4 (fixed) ==="
	$(ISA) analyze --benchmark django_sql --rev 3.0.4 --output summary

.PHONY: test
test: venv
	$(VENV)/bin/pytest

.PHONY: test-fast
# Run only unit tests (skip integration tests that clone repos)
test-fast: venv
	$(VENV)/bin/pytest -k "not Prover and not Django" -v

.PHONY: clean
clean:
	rm -rf $(VENV) .isa_cache __pycache__ src/**/__pycache__ .pytest_cache
