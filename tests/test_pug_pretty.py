"""Tests for Pug CVE-2021-21353 template injection benchmark."""
import json, pytest
from pathlib import Path
from isa.benchmarks.pug_pretty_proof import prove_witness, _extract_pretty_validation, _ensure_pug_checkout
from isa.witness import Witness

class TestPrettyValidationExtraction:
    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"
    def test_pug_3_0_0_has_no_validation(self, cache_dir):
        checkout = _ensure_pug_checkout(cache_dir, "pug@3.0.0")
        validation = _extract_pretty_validation(checkout)
        assert not (validation.validates_whitespace and validation.uses_stringify)
    def test_pug_3_0_1_has_validation(self, cache_dir):
        checkout = _ensure_pug_checkout(cache_dir, "pug@3.0.1")
        validation = _extract_pretty_validation(checkout)
        assert validation.validates_whitespace and validation.uses_stringify

class TestPugProver:
    def test_pug_3_0_0_is_vulnerable(self):
        witness = prove_witness("pug@3.0.0")
        assert witness is not None and witness.vuln.advisory == "CVE-2021-21353"
    def test_pug_3_0_1_is_not_vulnerable(self):
        assert prove_witness("pug@3.0.1") is None

class TestPugCLI:
    def test_cli_analyze_vulnerable(self):
        from isa.cli import main
        assert main(["analyze", "--benchmark", "pug_pretty", "--rev", "pug@3.0.0"]) == 0
