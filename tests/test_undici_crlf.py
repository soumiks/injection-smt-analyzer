"""
Tests for the undici CRLF injection benchmark (Milestone 3).

These tests verify:
1. Vulnerable revision (v5.8.0) produces a witness
2. Fixed revision (v5.8.2) does NOT produce a witness
3. Witness structure is correct
4. SMT2 output is valid
"""

import json
import pytest

from isa.benchmarks.undici_crlf_proof import (
    prove_witness,
    _extract_validation_info,
    _ensure_undici_checkout,
    _header_char_regex_rejects,
    _build_accepts_constraint,
)
from isa.witness import Witness
from pathlib import Path
import z3


class TestValidationExtraction:
    """Test extraction of validation logic from undici source."""

    @pytest.fixture(scope="class")
    def cache_dir(self, tmp_path_factory):
        return tmp_path_factory.mktemp("isa_cache")

    def test_v5_8_0_has_no_content_type_validation(self, cache_dir):
        """v5.8.0 should NOT have headerCharRegex validation on content-type."""
        checkout = _ensure_undici_checkout(cache_dir, "v5.8.0")
        validation = _extract_validation_info(checkout)

        # The vulnerable version lacks the regex check on content-type
        # Note: the regex exists in the file but is NOT applied to content-type
        assert not validation.has_header_char_regex

    def test_v5_8_2_has_content_type_validation(self, cache_dir):
        """v5.8.2 should have headerCharRegex validation on content-type."""
        checkout = _ensure_undici_checkout(cache_dir, "v5.8.2")
        validation = _extract_validation_info(checkout)

        assert validation.has_header_char_regex
        assert validation.regex_pattern is not None
        # The pattern should reject control characters
        assert "\\t" in validation.regex_pattern or "x20" in validation.regex_pattern


class TestZ3Constraints:
    """Test Z3 constraint modeling."""

    def test_rejects_cr(self):
        """Constraint should identify CR in string."""
        val = z3.String("val")
        rejects = _header_char_regex_rejects(val, None)

        s = z3.Solver()
        s.add(val == z3.StringVal("test\rvalue"))
        s.add(rejects)
        assert s.check() == z3.sat

    def test_rejects_lf(self):
        """Constraint should identify LF in string."""
        val = z3.String("val")
        rejects = _header_char_regex_rejects(val, None)

        s = z3.Solver()
        s.add(val == z3.StringVal("test\nvalue"))
        s.add(rejects)
        assert s.check() == z3.sat

    def test_accepts_clean_value(self):
        """Constraint should NOT reject clean values."""
        val = z3.String("val")
        rejects = _header_char_regex_rejects(val, None)

        s = z3.Solver()
        s.add(val == z3.StringVal("application/json"))
        s.add(rejects)
        assert s.check() == z3.unsat


class TestProver:
    """Integration tests for the full prover."""

    @pytest.fixture(scope="class")
    def cache_dir(self):
        # Use the real cache location for integration tests
        return Path.cwd() / ".isa_cache"

    def test_v5_8_0_is_vulnerable(self):
        """v5.8.0 should produce a witness (vulnerable)."""
        witness = prove_witness("v5.8.0")

        assert witness is not None
        assert isinstance(witness, Witness)
        assert witness.target.rev == "v5.8.0"
        assert witness.vuln.kind == "crlf-injection/request-splitting"
        assert witness.vuln.advisory == "CVE-2022-35948"
        assert witness.smt2 is not None
        assert witness.z3_model is not None
        assert "\r\n" in witness.z3_model["content_type"]

    def test_v5_8_2_is_not_vulnerable(self):
        """v5.8.2 should NOT produce a witness (fixed)."""
        witness = prove_witness("v5.8.2")

        assert witness is None

    def test_witness_json_serializable(self):
        """Witness should be JSON-serializable."""
        witness = prove_witness("v5.8.0")
        assert witness is not None

        json_str = json.dumps(witness.to_dict(), indent=2)
        parsed = json.loads(json_str)

        assert parsed["target"]["rev"] == "v5.8.0"
        assert parsed["vuln"]["kind"] == "crlf-injection/request-splitting"

    def test_smt2_contains_key_assertions(self):
        """SMT2 output should contain the key proof elements."""
        witness = prove_witness("v5.8.0")
        assert witness is not None

        smt2 = witness.smt2
        assert "(set-logic" in smt2
        assert "content_type" in smt2
        assert "(check-sat)" in smt2
        # Vulnerable version should have "assert true" (no validation)
        assert "true" in smt2.lower()


class TestCLI:
    """Test CLI integration."""

    def test_cli_version(self):
        """CLI version command should work."""
        from isa.cli import main

        # Capture via return code
        result = main(["version"])
        assert result == 0

    def test_cli_analyze_demo_mode(self):
        """CLI analyze in demo mode should work."""
        from isa.cli import main
        import io
        import sys

        # This just checks it doesn't crash
        result = main(["analyze", "--benchmark", "undici_crlf", "--mode", "demo"])
        assert result == 0

    def test_cli_analyze_prove_mode_vulnerable(self):
        """CLI analyze in prove mode for vulnerable version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "undici_crlf", "--rev", "v5.8.0", "--mode", "prove"])
        assert result == 0

    def test_cli_analyze_prove_mode_fixed(self):
        """CLI analyze in prove mode for fixed version."""
        from isa.cli import main

        result = main(["analyze", "--benchmark", "undici_crlf", "--rev", "v5.8.2", "--mode", "prove"])
        assert result == 0
