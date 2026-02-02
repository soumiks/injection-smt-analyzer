VENV?=.venv
PY?=$(VENV)/bin/python

.PHONY: venv
venv:
	python3 -m venv $(VENV)
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e .

.PHONY: demo
# Prints a placeholder witness (schema smoke test)
demo: venv
	$(VENV)/bin/python -m isa.cli analyze --benchmark undici_crlf --rev v5.8.0
