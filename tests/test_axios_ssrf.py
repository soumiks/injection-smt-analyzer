"""Tests for Axios CVE-2020-28168 SSRF benchmark."""
import json
import pytest
from pathlib import Path
from isa.benchmarks.axios_ssrf_proof import (
    prove_witness,
    _extract_proxy_handling,
    _ensure_axios_checkout,
)
from isa.witness import Witness


class TestProxyHandlingExtraction:
    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"

    def test_v0_21_0_has_no_before_redirect(self, cache_dir):
        """v0.21.0 should have proxy settings but no beforeRedirect."""
        checkout = _ensure_axios_checkout(cache_dir, "v0.21.0")
        handling = _extract_proxy_handling(checkout)
        assert handling.sets_proxy_options
        assert not handling.has_before_redirect

    def test_v0_21_1_has_before_redirect(self, cache_dir):
        """v0.21.1 should have beforeRedirect callback."""
        checkout = _ensure_axios_checkout(cache_dir, "v0.21.1")
        handling = _extract_proxy_handling(checkout)
        assert handling.sets_proxy_options
        assert handling.has_before_redirect


class TestAxiosProver:
    def test_v0_21_0_is_vulnerable(self):
        """v0.21.0 should be detected as vulnerable."""
        witness = prove_witness("v0.21.0")
        assert witness is not None
        assert witness.vuln.advisory == "CVE-2020-28168"
        assert witness.vuln.cwe == "CWE-918"
        assert witness.vuln.kind == "ssrf"

    def test_v0_21_1_is_not_vulnerable(self):
        """v0.21.1 should be detected as fixed."""
        assert prove_witness("v0.21.1") is None


class TestAxiosCLI:
    def test_cli_analyze_vulnerable(self):
        """CLI should detect vulnerable version."""
        from isa.cli import main
        result = main(["analyze", "--benchmark", "axios_ssrf", "--rev", "v0.21.0"])
        assert result == 0

    def test_cli_analyze_fixed(self):
        """CLI should detect fixed version."""
        from isa.cli import main
        result = main(["analyze", "--benchmark", "axios_ssrf", "--rev", "v0.21.1"])
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
            main(["analyze", "--benchmark", "axios_ssrf", "--rev", "v0.21.0", "--output", "json"])
            output = captured.getvalue()
            data = json.loads(output)
            assert data["ok"] is True
            assert data["vulnerable"] is True
        finally:
            sys.stdout = old_stdout
