"""
Tests for the Apache Log4j CVE-2021-44228 (Log4Shell) JNDI injection benchmark.

These tests verify:
1. Vulnerable revision (2.14.1) produces a witness
2. Fixed revision (2.15.0) does NOT produce a witness
3. Witness structure is correct
4. SMT2 output is valid
"""

import json
import pytest

from isa.benchmarks.log4j_jndi_proof import (
    prove_witness,
    _extract_jndi_restrictions,
    _ensure_log4j_checkout,
)
from isa.witness import Witness
from pathlib import Path


class TestJndiRestrictionExtraction:
    """Test extraction of JNDI restriction logic from Log4j source."""

    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"

    def test_2_14_1_has_no_restrictions(self, cache_dir):
        """2.14.1 should NOT have JNDI allowlist restrictions."""
        checkout = _ensure_log4j_checkout(cache_dir, "rel/2.14.1")
        validation = _extract_jndi_restrictions(checkout)

        # Vulnerable version lacks all restrictions
        assert not (validation.has_protocol_allowlist and 
                   validation.has_host_allowlist and 
                   validation.has_class_allowlist)

    def test_2_15_0_has_restrictions(self, cache_dir):
        """2.15.0 should have JNDI allowlist restrictions."""
        checkout = _ensure_log4j_checkout(cache_dir, "rel/2.15.0")
        validation = _extract_jndi_restrictions(checkout)

        # Fixed version has all restrictions
        assert validation.has_protocol_allowlist
        assert validation.has_host_allowlist
        assert validation.has_class_allowlist


class TestLog4jProver:
    """Integration tests for the Log4j JNDI injection prover."""

    def test_2_14_1_is_vulnerable(self):
        """2.14.1 should produce a witness (vulnerable to Log4Shell)."""
        witness = prove_witness("rel/2.14.1")

        assert witness is not None
        assert isinstance(witness, Witness)
        assert witness.target.rev == "rel/2.14.1"
        assert witness.vuln.kind == "jndi-injection/rce"
        assert witness.vuln.advisory == "CVE-2021-44228"
        assert witness.smt2 is not None
        assert witness.z3_model is not None
        assert "${jndi:" in witness.z3_model["log_message"]

    def test_2_15_0_is_not_vulnerable(self):
        """2.15.0 should NOT produce a witness (Log4Shell fixed)."""
        witness = prove_witness("rel/2.15.0")

        assert witness is None

    def test_witness_json_serializable(self):
        """Witness should be JSON-serializable."""
        witness = prove_witness("rel/2.14.1")
        assert witness is not None

        json_str = json.dumps(witness.to_dict(), indent=2)
        parsed = json.loads(json_str)

        assert parsed["target"]["rev"] == "rel/2.14.1"
        assert parsed["vuln"]["kind"] == "jndi-injection/rce"

    def test_smt2_contains_key_assertions(self):
        """SMT2 output should contain the key proof elements."""
        witness = prove_witness("rel/2.14.1")
        assert witness is not None

        smt2 = witness.smt2
        assert "(set-logic" in smt2
        assert "log_message" in smt2
        assert "(check-sat)" in smt2
        assert "${jndi:" in smt2


class TestLog4jCLI:
    """Test CLI integration for Log4j benchmark."""

    def test_cli_analyze_log4j_vulnerable(self):
        """CLI analyze for vulnerable version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "log4j_jndi", "--rev", "rel/2.14.1"])
        assert result == 0

    def test_cli_analyze_log4j_fixed(self):
        """CLI analyze for fixed version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "log4j_jndi", "--rev", "rel/2.15.0"])
        assert result == 0
