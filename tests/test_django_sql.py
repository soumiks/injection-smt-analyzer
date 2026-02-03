"""
Tests for the Django CVE-2020-9402 SQL injection benchmark.

These tests verify:
1. Vulnerable revision (3.0.3) produces a witness
2. Fixed revision (3.0.4) does NOT produce a witness
3. Witness structure is correct
4. SMT2 output is valid
"""

import json
import pytest

from isa.benchmarks.django_sql_proof import (
    prove_witness,
    _extract_tolerance_handling,
    _ensure_django_checkout,
)
from isa.witness import Witness
from pathlib import Path


class TestToleranceHandlingExtraction:
    """Test extraction of tolerance handling from Django source."""

    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"

    def test_3_0_3_has_no_value_wrapper(self, cache_dir):
        """3.0.3 should NOT have Value() wrapper on tolerance."""
        checkout = _ensure_django_checkout(cache_dir, "3.0.3")
        validation = _extract_tolerance_handling(checkout)

        assert not validation.uses_value_wrapper

    def test_3_0_4_has_value_wrapper(self, cache_dir):
        """3.0.4 should have Value() wrapper on tolerance."""
        checkout = _ensure_django_checkout(cache_dir, "3.0.4")
        validation = _extract_tolerance_handling(checkout)

        assert validation.uses_value_wrapper


class TestDjangoProver:
    """Integration tests for the Django SQL injection prover."""

    def test_3_0_3_is_vulnerable(self):
        """3.0.3 should produce a witness (vulnerable)."""
        witness = prove_witness("3.0.3")

        assert witness is not None
        assert isinstance(witness, Witness)
        assert witness.target.rev == "3.0.3"
        assert witness.vuln.kind == "sql-injection"
        assert witness.vuln.advisory == "CVE-2020-9402"
        assert witness.smt2 is not None
        assert witness.z3_model is not None

    def test_3_0_4_is_not_vulnerable(self):
        """3.0.4 should NOT produce a witness (fixed)."""
        witness = prove_witness("3.0.4")

        assert witness is None

    def test_witness_json_serializable(self):
        """Witness should be JSON-serializable."""
        witness = prove_witness("3.0.3")
        assert witness is not None

        json_str = json.dumps(witness.to_dict(), indent=2)
        parsed = json.loads(json_str)

        assert parsed["target"]["rev"] == "3.0.3"
        assert parsed["vuln"]["kind"] == "sql-injection"

    def test_smt2_contains_key_assertions(self):
        """SMT2 output should contain the key proof elements."""
        witness = prove_witness("3.0.3")
        assert witness is not None

        smt2 = witness.smt2
        assert "(set-logic" in smt2
        assert "tolerance" in smt2
        assert "(check-sat)" in smt2


class TestDjangoCLI:
    """Test CLI integration for Django benchmark."""

    def test_cli_analyze_django_vulnerable(self):
        """CLI analyze for vulnerable version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "django_sql", "--rev", "3.0.3"])
        assert result == 0

    def test_cli_analyze_django_fixed(self):
        """CLI analyze for fixed version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "django_sql", "--rev", "3.0.4"])
        assert result == 0
