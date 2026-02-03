VENV?=.venv
PY?=$(VENV)/bin/python

.PHONY: venv
venv:
	python3 -m venv $(VENV)
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e ".[dev]"

.PHONY: demo
# Prints a placeholder witness (schema smoke test)
demo: venv
	$(VENV)/bin/python -m isa.cli analyze --benchmark undici_crlf --rev v5.8.0 --mode demo

.PHONY: prove
# Run the Z3-backed prover against both vulnerable and fixed versions
prove: venv
	@echo "=== Testing v5.8.0 (vulnerable) ==="
	$(VENV)/bin/python -m isa.cli analyze --benchmark undici_crlf --rev v5.8.0 --mode prove
	@echo ""
	@echo "=== Testing v5.8.2 (fixed) ==="
	$(VENV)/bin/python -m isa.cli analyze --benchmark undici_crlf --rev v5.8.2 --mode prove

.PHONY: test
test: venv
	$(VENV)/bin/pytest

.PHONY: test-fast
# Run only unit tests (skip integration tests that clone repos)
test-fast: venv
	$(VENV)/bin/pytest -k "not Prover" -v

.PHONY: clean
clean:
	rm -rf $(VENV) .isa_cache __pycache__ src/**/__pycache__ .pytest_cache
