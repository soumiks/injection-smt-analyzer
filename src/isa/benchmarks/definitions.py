"""
Benchmark definitions using the config-driven system.

This module registers all benchmarks with the framework.
"""

from isa.core.config import (
    BenchmarkConfig,
    Language,
    RevisionSpec,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
    VulnType,
    register_benchmark,
)


# =============================================================================
# Benchmark: undici CRLF injection (CVE-2022-35948)
# =============================================================================

UNDICI_CRLF = BenchmarkConfig(
    id="undici_crlf",
    name="undici CRLF injection",
    repo="https://github.com/nodejs/undici",
    language=Language.JAVASCRIPT,
    vuln_type=VulnType.CRLF_INJECTION,
    advisory="CVE-2022-35948",
    cwe="CWE-93",
    
    sources=[
        SourceSpec(
            kind="external_input",
            pattern="property:headers",
            description="HTTP headers from external input",
        ),
        SourceSpec(
            kind="function_param",
            pattern="param:headers",
            description="Headers parameter in request functions",
        ),
    ],
    
    sinks=[
        SinkSpec(
            kind="http_serialization",
            pattern="template:`${key}: ${val}\\r\\n`",
            description="Header value serialized into HTTP request",
        ),
        SinkSpec(
            kind="http_serialization",
            pattern="call:request.headers",
            description="Headers added to outbound request",
        ),
    ],
    
    sanitizers=[
        SanitizerSpec(
            pattern="headerCharRegex.exec",
            description="Regex validation that rejects CR/LF characters",
        ),
        SanitizerSpec(
            pattern="headerCharRegex.test",
            description="Regex validation that rejects CR/LF characters",
        ),
    ],
    
    target_files=[
        "lib/core/request.js",
        "lib/core/util.js",
    ],
    
    revisions=[
        RevisionSpec(
            tag="v5.8.0",
            expected_vulnerable=True,
            notes="No headerCharRegex check on content-type",
        ),
        RevisionSpec(
            tag="v5.8.2",
            expected_vulnerable=False,
            notes="Added headerCharRegex.exec(val) === null check",
        ),
    ],
)


# =============================================================================
# Benchmark: Django SQL injection (CVE-2020-9402)
# =============================================================================

DJANGO_SQL = BenchmarkConfig(
    id="django_sql",
    name="Django GIS SQL injection",
    repo="https://github.com/django/django",
    language=Language.PYTHON,
    vuln_type=VulnType.SQL_INJECTION,
    advisory="CVE-2020-9402",
    cwe="CWE-89",
    
    sources=[
        SourceSpec(
            kind="function_param",
            pattern="param:tolerance",
            description="Tolerance parameter in GIS functions",
        ),
        SourceSpec(
            kind="dict_access",
            pattern="self.extra.get('tolerance')",
            description="Tolerance from extra kwargs",
        ),
    ],
    
    sinks=[
        SinkSpec(
            kind="sql_template",
            pattern="template:%(tolerance)s",
            description="Tolerance interpolated into SQL template",
        ),
        SinkSpec(
            kind="sql_template",
            pattern="%s)\\\" % tol",
            description="String formatting into SQL query",
        ),
    ],
    
    sanitizers=[
        SanitizerSpec(
            pattern="Value(tolerance)",
            description="Wrapping in Value() properly escapes the parameter",
        ),
        SanitizerSpec(
            pattern="Value(self._handle_param",
            description="Using _handle_param with Value() for proper escaping",
        ),
    ],
    
    target_files=[
        "django/contrib/gis/db/models/aggregates.py",
        "django/contrib/gis/db/models/functions.py",
    ],
    
    revisions=[
        RevisionSpec(
            tag="3.0.3",
            expected_vulnerable=True,
            notes="Tolerance directly interpolated into SQL",
        ),
        RevisionSpec(
            tag="3.0.4",
            expected_vulnerable=False,
            notes="Tolerance wrapped in Value() for proper escaping",
        ),
    ],
)


def register_all_benchmarks() -> None:
    """Register all benchmark configurations."""
    register_benchmark(UNDICI_CRLF)
    register_benchmark(DJANGO_SQL)


# Auto-register when module is imported
register_all_benchmarks()
