"""
Tests for the Spring Framework CVE-2022-22965 (Spring4Shell) data binding injection benchmark.

These tests verify:
1. Vulnerable revision (5.3.17) produces a witness
2. Fixed revision (5.3.18) does NOT produce a witness
3. Witness structure is correct
4. SMT2 output is valid
"""

import json
import pytest

from isa.benchmarks.spring4shell_proof import (
    prove_witness,
    _extract_data_binding_restrictions,
    _ensure_spring_checkout,
)
from isa.witness import Witness
from pathlib import Path


class TestDataBindingRestrictionExtraction:
    """Test extraction of data binding restriction logic from Spring source."""

    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"

    def test_5_3_17_has_no_restrictions(self, cache_dir):
        """5.3.17 should NOT have ClassLoader/ProtectionDomain blocking."""
        checkout = _ensure_spring_checkout(cache_dir, "v5.3.17")
        validation = _extract_data_binding_restrictions(checkout)

        # Vulnerable version lacks restrictions
        assert not (validation.blocks_classloader and 
                   validation.blocks_protection_domain and 
                   validation.restricts_class_properties)

    def test_5_3_18_has_restrictions(self, cache_dir):
        """5.3.18 should have ClassLoader/ProtectionDomain blocking."""
        checkout = _ensure_spring_checkout(cache_dir, "v5.3.18")
        validation = _extract_data_binding_restrictions(checkout)

        # Fixed version has all restrictions
        assert validation.blocks_classloader
        assert validation.blocks_protection_domain


class TestSpring4ShellProver:
    """Integration tests for the Spring4Shell prover."""

    def test_5_3_17_is_vulnerable(self):
        """5.3.17 should produce a witness (vulnerable to Spring4Shell)."""
        witness = prove_witness("v5.3.17")

        assert witness is not None
        assert isinstance(witness, Witness)
        assert witness.target.rev == "v5.3.17"
        assert witness.vuln.kind == "data-binding-injection/rce"
        assert witness.vuln.advisory == "CVE-2022-22965"
        assert witness.smt2 is not None
        assert witness.z3_model is not None
        assert "classLoader" in witness.z3_model["property_path"]

    def test_5_3_18_is_not_vulnerable(self):
        """5.3.18 should NOT produce a witness (Spring4Shell fixed)."""
        witness = prove_witness("v5.3.18")

        assert witness is None

    def test_witness_json_serializable(self):
        """Witness should be JSON-serializable."""
        witness = prove_witness("v5.3.17")
        assert witness is not None

        json_str = json.dumps(witness.to_dict(), indent=2)
        parsed = json.loads(json_str)

        assert parsed["target"]["rev"] == "v5.3.17"
        assert parsed["vuln"]["kind"] == "data-binding-injection/rce"

    def test_smt2_contains_key_assertions(self):
        """SMT2 output should contain the key proof elements."""
        witness = prove_witness("v5.3.17")
        assert witness is not None

        smt2 = witness.smt2
        assert "(set-logic" in smt2
        assert "property_path" in smt2
        assert "(check-sat)" in smt2
        assert "classLoader" in smt2


class TestSpring4ShellCLI:
    """Test CLI integration for Spring4Shell benchmark."""

    def test_cli_analyze_spring_vulnerable(self):
        """CLI analyze for vulnerable version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "spring4shell", "--rev", "v5.3.17"])
        assert result == 0

    def test_cli_analyze_spring_fixed(self):
        """CLI analyze for fixed version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "spring4shell", "--rev", "v5.3.18"])
        assert result == 0
