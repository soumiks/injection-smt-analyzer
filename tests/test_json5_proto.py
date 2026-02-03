"""Tests for JSON5 CVE-2022-46175 prototype pollution benchmark."""
import pytest
from pathlib import Path
from isa.benchmarks.json5_proto_proof import prove_witness, _extract_proto_validation, _ensure_json5_checkout

class TestProtoValidationExtraction:
    @pytest.fixture(scope="class")
    def cache_dir(self):
        return Path.cwd() / ".isa_cache"
    def test_v2_2_1_has_no_protection(self, cache_dir):
        checkout = _ensure_json5_checkout(cache_dir, "v2.2.1")
        validation = _extract_proto_validation(checkout)
        assert not validation.uses_define_property
    def test_v2_2_2_has_protection(self, cache_dir):
        checkout = _ensure_json5_checkout(cache_dir, "v2.2.2")
        validation = _extract_proto_validation(checkout)
        assert validation.uses_define_property

class TestJSON5Prover:
    def test_v2_2_1_is_vulnerable(self):
        assert prove_witness("v2.2.1") is not None
    def test_v2_2_2_is_not_vulnerable(self):
        assert prove_witness("v2.2.2") is None
