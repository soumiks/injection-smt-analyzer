"""Tests for Pug CVE-2021-21353 template injection benchmark."""
import json
import pytest
from pathlib import Path
from isa.benchmarks.pug_pretty_proof import (
    prove_witness,
    _extract_pretty_sanitization,
    _ensure_pug_checkout,
)
from isa.witness import Witness


class TestPrettySanitizationExtraction:
    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"

    def test_pug_3_0_0_has_no_sanitization(self, cache_dir):
        """pug@3.0.0 should have unsanitized concatenation."""
        checkout = _ensure_pug_checkout(cache_dir, "pug@3.0.0")
        sanitization = _extract_pretty_sanitization(checkout)
        assert sanitization.has_unsanitized_concat
        assert not sanitization.uses_stringify

    def test_pug_3_0_1_has_sanitization(self, cache_dir):
        """pug@3.0.1 should use stringify() for sanitization."""
        checkout = _ensure_pug_checkout(cache_dir, "pug@3.0.1")
        sanitization = _extract_pretty_sanitization(checkout)
        # Fixed version should not have unsanitized concat
        # (or if it does, it should also use stringify)
        assert sanitization.uses_stringify


class TestPugProver:
    def test_pug_3_0_0_is_vulnerable(self):
        """pug@3.0.0 should be detected as vulnerable."""
        witness = prove_witness("pug@3.0.0")
        assert witness is not None
        assert witness.vuln.advisory == "CVE-2021-21353"
        assert witness.vuln.cwe == "CWE-94"
        assert witness.vuln.kind == "template-injection/rce"

    def test_pug_3_0_1_is_not_vulnerable(self):
        """pug@3.0.1 should be detected as fixed."""
        assert prove_witness("pug@3.0.1") is None


class TestPugCLI:
    def test_cli_analyze_vulnerable(self):
        """CLI should detect vulnerable version."""
        from isa.cli import main
        result = main(["analyze", "--benchmark", "pug_pretty", "--rev", "pug@3.0.0"])
        assert result == 0

    def test_cli_analyze_fixed(self):
        """CLI should detect fixed version."""
        from isa.cli import main
        result = main(["analyze", "--benchmark", "pug_pretty", "--rev", "pug@3.0.1"])
        assert result == 0

    def test_cli_output_json(self):
        """CLI should output valid JSON."""
        import sys
        from io import StringIO
        from isa.cli import main
        
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = captured = StringIO()
        
        try:
            main(["analyze", "--benchmark", "pug_pretty", "--rev", "pug@3.0.0", "--output", "json"])
            output = captured.getvalue()
            data = json.loads(output)
            assert data["ok"] is True
            assert data["vulnerable"] is True
        finally:
            sys.stdout = old_stdout
