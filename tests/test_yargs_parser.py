"""Tests for yargs-parser CVE-2020-7608 prototype pollution benchmark."""
import pytest
from pathlib import Path
from isa.benchmarks.yargs_parser_proof import prove_witness, _extract_key_validation, _ensure_yargs_checkout

class TestKeyValidationExtraction:
    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"
    def test_v18_1_0_has_no_sanitization(self, cache_dir):
        checkout = _ensure_yargs_checkout(cache_dir, "v18.1.0")
        validation = _extract_key_validation(checkout)
        assert not (validation.has_sanitize_key and validation.checks_proto)
    def test_v18_1_1_has_sanitization(self, cache_dir):
        checkout = _ensure_yargs_checkout(cache_dir, "v18.1.1")
        validation = _extract_key_validation(checkout)
        assert validation.has_sanitize_key and validation.checks_proto

class TestYargsParserProver:
    def test_v18_1_0_is_vulnerable(self):
        assert prove_witness("v18.1.0") is not None
    def test_v18_1_1_is_not_vulnerable(self):
        assert prove_witness("v18.1.1") is None
