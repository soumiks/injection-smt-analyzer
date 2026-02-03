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


# =============================================================================
# Benchmark: Apache Log4j JNDI injection (CVE-2021-44228 / Log4Shell)
# =============================================================================

LOG4J_JNDI = BenchmarkConfig(
    id="log4j_jndi",
    name="Apache Log4j JNDI injection (Log4Shell)",
    repo="https://github.com/apache/logging-log4j2",
    language=Language.JAVA,
    vuln_type=VulnType.JNDI_INJECTION,
    advisory="CVE-2021-44228",
    cwe="CWE-917",
    
    sources=[
        SourceSpec(
            kind="external_input",
            pattern="param:message",
            description="Log messages from external sources",
        ),
        SourceSpec(
            kind="string_interpolation",
            pattern="${jndi:",
            description="JNDI lookup in string interpolation",
        ),
    ],
    
    sinks=[
        SinkSpec(
            kind="jndi_lookup",
            pattern="call:context.lookup",
            description="JNDI Context.lookup() execution",
        ),
        SinkSpec(
            kind="jndi_lookup",
            pattern="call:JndiManager.lookup",
            description="JndiManager.lookup() execution",
        ),
    ],
    
    sanitizers=[
        SanitizerSpec(
            pattern="allowedProtocols.contains",
            description="Protocol allowlist check",
        ),
        SanitizerSpec(
            pattern="allowedHosts.contains",
            description="Host allowlist check for LDAP",
        ),
        SanitizerSpec(
            pattern="allowedClasses.contains",
            description="Class allowlist for deserialization",
        ),
    ],
    
    target_files=[
        "log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java",
        "log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java",
    ],
    
    revisions=[
        RevisionSpec(
            tag="rel/2.14.1",
            expected_vulnerable=True,
            notes="No JNDI restrictions - Log4Shell vulnerable",
        ),
        RevisionSpec(
            tag="rel/2.15.0",
            expected_vulnerable=False,
            notes="Added protocol/host/class allowlists",
        ),
    ],
)


# =============================================================================
# Benchmark: Spring Framework data binding injection (CVE-2022-22965 / Spring4Shell)
# =============================================================================

SPRING4SHELL = BenchmarkConfig(
    id="spring4shell",
    name="Spring Framework data binding injection (Spring4Shell)",
    repo="https://github.com/spring-projects/spring-framework",
    language=Language.JAVA,
    vuln_type=VulnType.CODE_INJECTION,
    advisory="CVE-2022-22965",
    cwe="CWE-94",
    
    sources=[
        SourceSpec(
            kind="http_parameter",
            pattern="param:*",
            description="HTTP request parameters bound to objects",
        ),
    ],
    
    sinks=[
        SourceSpec(
            kind="property_setter",
            pattern="call:setProperty",
            description="Property setter via data binding",
        ),
    ],
    
    sanitizers=[
        SanitizerSpec(
            pattern="ClassLoader.class.isAssignableFrom",
            description="ClassLoader type blocking",
        ),
        SanitizerSpec(
            pattern="ProtectionDomain.class.isAssignableFrom",
            description="ProtectionDomain type blocking",
        ),
    ],
    
    target_files=[
        "spring-beans/src/main/java/org/springframework/beans/CachedIntrospectionResults.java",
    ],
    
    revisions=[
        RevisionSpec(
            tag="v5.3.17",
            expected_vulnerable=True,
            notes="No ClassLoader/ProtectionDomain blocking - Spring4Shell vulnerable",
        ),
        RevisionSpec(
            tag="v5.3.18",
            expected_vulnerable=False,
            notes="Added ClassLoader/ProtectionDomain type blocking",
        ),
    ],
)


# =============================================================================
# Benchmark: Laravel Ignition code injection (CVE-2021-3129)
# =============================================================================

LARAVEL_IGNITION = BenchmarkConfig(
    id="laravel_ignition",
    name="Laravel Ignition code injection",
    repo="https://github.com/facade/ignition",
    language=Language.PHP,
    vuln_type=VulnType.CODE_INJECTION,
    advisory="CVE-2021-3129",
    cwe="CWE-94",
    
    sources=[
        SourceSpec(
            kind="http_parameter",
            pattern="param:viewFile",
            description="viewFile parameter from HTTP request",
        ),
    ],
    
    sinks=[
        SinkSpec(
            kind="file_operation",
            pattern="call:file_get_contents",
            description="file_get_contents on unsanitized path",
        ),
    ],
    
    sanitizers=[
        SanitizerSpec(
            pattern="isSafePath",
            description="Path validation blocking stream wrappers",
        ),
    ],
    
    target_files=[
        "src/Solutions/MakeViewVariableOptionalSolution.php",
    ],
    
    revisions=[
        RevisionSpec(
            tag="2.5.1",
            expected_vulnerable=True,
            notes="No path validation - allows stream wrappers",
        ),
        RevisionSpec(
            tag="2.5.2",
            expected_vulnerable=False,
            notes="Added isSafePath() validation",
        ),
    ],
)


# =============================================================================
# Benchmark: Handlebars.js prototype pollution (CVE-2019-19919)
# =============================================================================

HANDLEBARS_LOOKUP = BenchmarkConfig(
    id="handlebars_lookup",
    name="Handlebars.js prototype pollution via lookup",
    repo="https://github.com/handlebars-lang/handlebars.js",
    language=Language.JAVASCRIPT,
    vuln_type=VulnType.PROTOTYPE_POLLUTION,
    advisory="CVE-2019-19919",
    cwe="CWE-1321",
    
    sources=[
        SourceSpec(
            kind="template_input",
            pattern="{{lookup",
            description="Handlebars template with lookup helper",
        ),
    ],
    
    sinks=[
        SinkSpec(
            kind="property_access",
            pattern="obj[field]",
            description="Dynamic property access in lookup helper",
        ),
    ],
    
    sanitizers=[
        SanitizerSpec(
            pattern="field === 'constructor'",
            description="Constructor property blocking",
        ),
        SanitizerSpec(
            pattern="propertyIsEnumerable",
            description="Enumerable property check",
        ),
    ],
    
    target_files=[
        "lib/handlebars/helpers/lookup.js",
    ],
    
    revisions=[
        RevisionSpec(
            tag="v4.0.13",
            expected_vulnerable=True,
            notes="No constructor blocking in lookup helper",
        ),
        RevisionSpec(
            tag="v4.0.14",
            expected_vulnerable=False,
            notes="Added constructor blocking via propertyIsEnumerable",
        ),
    ],
)


# =============================================================================
# Benchmark: Nodemailer command injection (CVE-2020-7769)
# =============================================================================

NODEMAILER_SENDMAIL = BenchmarkConfig(
    id="nodemailer_sendmail",
    name="Nodemailer sendmail command injection",
    repo="https://github.com/nodemailer/nodemailer",
    language=Language.JAVASCRIPT,
    vuln_type=VulnType.COMMAND_INJECTION,
    advisory="CVE-2020-7769",
    cwe="CWE-77",
    
    sources=[
        SourceSpec(
            kind="email_address",
            pattern="envelope.to",
            description="Email address from mail options",
        ),
    ],
    
    sinks=[
        SinkSpec(
            kind="command_execution",
            pattern="sendmail",
            description="sendmail command execution",
        ),
    ],
    
    sanitizers=[
        SanitizerSpec(
            pattern="/^-/",
            description="Dash prefix validation",
        ),
    ],
    
    target_files=[
        "lib/sendmail-transport/index.js",
    ],
    
    revisions=[
        RevisionSpec(
            tag="v6.4.15",
            expected_vulnerable=True,
            notes="No dash prefix validation",
        ),
        RevisionSpec(
            tag="v6.4.16",
            expected_vulnerable=False,
            notes="Added hasInvalidAddresses check",
        ),
    ],
)


def register_all_benchmarks() -> None:
    """Register all benchmark configurations."""
    register_benchmark(UNDICI_CRLF)
    register_benchmark(DJANGO_SQL)
    register_benchmark(LOG4J_JNDI)
    register_benchmark(SPRING4SHELL)
    register_benchmark(LARAVEL_IGNITION)
    register_benchmark(HANDLEBARS_LOOKUP)
    register_benchmark(NODEMAILER_SENDMAIL)


# Auto-register when module is imported
register_all_benchmarks()
