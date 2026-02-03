"""
Tests for the Laravel Ignition CVE-2021-3129 code injection benchmark.
"""

import json
import pytest
from pathlib import Path

from isa.benchmarks.laravel_ignition_proof import (
    prove_witness,
    _extract_path_validation,
    _ensure_ignition_checkout,
)
from isa.witness import Witness


class TestPathValidationExtraction:
    """Test extraction of path validation logic from Ignition source."""

    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"

    def test_2_5_1_has_no_validation(self, cache_dir):
        """2.5.1 should NOT have path validation."""
        checkout = _ensure_ignition_checkout(cache_dir, "2.5.1")
        validation = _extract_path_validation(checkout)

        assert not (validation.has_path_validation and 
                   validation.checks_stream_wrappers and 
                   validation.checks_file_extension)

    def test_2_5_2_has_validation(self, cache_dir):
        """2.5.2 should have path validation."""
        checkout = _ensure_ignition_checkout(cache_dir, "2.5.2")
        validation = _extract_path_validation(checkout)

        assert validation.has_path_validation


class TestLaravelIgnitionProver:
    """Integration tests for the Laravel Ignition prover."""

    def test_2_5_1_is_vulnerable(self):
        """2.5.1 should produce a witness (vulnerable)."""
        witness = prove_witness("2.5.1")

        assert witness is not None
        assert isinstance(witness, Witness)
        assert witness.target.rev == "2.5.1"
        assert witness.vuln.kind == "code-injection/rce"
        assert witness.vuln.advisory == "CVE-2021-3129"

    def test_2_5_2_is_not_vulnerable(self):
        """2.5.2 should NOT produce a witness (fixed)."""
        witness = prove_witness("2.5.2")

        assert witness is None

    def test_witness_json_serializable(self):
        """Witness should be JSON-serializable."""
        witness = prove_witness("2.5.1")
        assert witness is not None

        json_str = json.dumps(witness.to_dict(), indent=2)
        parsed = json.loads(json_str)

        assert parsed["target"]["rev"] == "2.5.1"
        assert parsed["vuln"]["kind"] == "code-injection/rce"


class TestLaravelIgnitionCLI:
    """Test CLI integration for Laravel Ignition benchmark."""

    def test_cli_analyze_vulnerable(self):
        """CLI analyze for vulnerable version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "laravel_ignition", "--rev", "2.5.1"])
        assert result == 0

    def test_cli_analyze_fixed(self):
        """CLI analyze for fixed version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "laravel_ignition", "--rev", "2.5.2"])
        assert result == 0
