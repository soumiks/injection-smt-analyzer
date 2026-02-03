"""Tests for Nodemailer CVE-2020-7769 command injection benchmark."""
import json, pytest
from pathlib import Path
from isa.benchmarks.nodemailer_sendmail_proof import prove_witness, _extract_address_validation, _ensure_nodemailer_checkout
from isa.witness import Witness

class TestAddressValidationExtraction:
    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"
    def test_v6_4_15_has_no_validation(self, cache_dir):
        checkout = _ensure_nodemailer_checkout(cache_dir, "v6.4.15")
        validation = _extract_address_validation(checkout)
        assert not (validation.blocks_dash_prefix and validation.validates_addresses)
    def test_v6_4_16_has_validation(self, cache_dir):
        checkout = _ensure_nodemailer_checkout(cache_dir, "v6.4.16")
        validation = _extract_address_validation(checkout)
        assert validation.blocks_dash_prefix and validation.validates_addresses

class TestNodemailerProver:
    def test_v6_4_15_is_vulnerable(self):
        witness = prove_witness("v6.4.15")
        assert witness is not None and witness.vuln.advisory == "CVE-2020-7769"
    def test_v6_4_16_is_not_vulnerable(self):
        assert prove_witness("v6.4.16") is None

class TestNodemailerCLI:
    def test_cli_analyze_vulnerable(self):
        from isa.cli import main
        assert main(["analyze", "--benchmark", "nodemailer_sendmail", "--rev", "v6.4.15"]) == 0
