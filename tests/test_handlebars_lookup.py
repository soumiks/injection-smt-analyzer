"""
Tests for Handlebars.js CVE-2019-19919 prototype pollution benchmark.
"""

import json
import pytest
from pathlib import Path

from isa.benchmarks.handlebars_lookup_proof import (
    prove_witness,
    _extract_lookup_validation,
    _ensure_handlebars_checkout,
)
from isa.witness import Witness


class TestLookupValidationExtraction:
    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"

    def test_v4_0_13_has_no_protection(self, cache_dir):
        checkout = _ensure_handlebars_checkout(cache_dir, "v4.0.13")
        validation = _extract_lookup_validation(checkout)
        assert not (validation.blocks_constructor and validation.checks_enumerable)

    def test_v4_0_14_has_protection(self, cache_dir):
        checkout = _ensure_handlebars_checkout(cache_dir, "v4.0.14")
        validation = _extract_lookup_validation(checkout)
        assert validation.blocks_constructor and validation.checks_enumerable


class TestHandlebarsProver:
    def test_v4_0_13_is_vulnerable(self):
        witness = prove_witness("v4.0.13")
        assert witness is not None
        assert witness.vuln.kind == "prototype-pollution/rce"
        assert witness.vuln.advisory == "CVE-2019-19919"

    def test_v4_0_14_is_not_vulnerable(self):
        witness = prove_witness("v4.0.14")
        assert witness is None

    def test_witness_json_serializable(self):
        witness = prove_witness("v4.0.13")
        assert witness is not None
        json_str = json.dumps(witness.to_dict(), indent=2)
        parsed = json.loads(json_str)
        assert parsed["target"]["rev"] == "v4.0.13"


class TestHandlebarsCLI:
    def test_cli_analyze_vulnerable(self):
        from isa.cli import main
        result = main(["analyze", "--benchmark", "handlebars_lookup", "--rev", "v4.0.13"])
        assert result == 0

    def test_cli_analyze_fixed(self):
        from isa.cli import main
        result = main(["analyze", "--benchmark", "handlebars_lookup", "--rev", "v4.0.14"])
        assert result == 0
