"""
Benchmark configuration system.

Defines a config-driven approach where benchmarks are specified declaratively
and the analysis engine handles the rest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from pathlib import Path


class Language(Enum):
    JAVASCRIPT = "javascript"
    PYTHON = "python"
    JAVA = "java"
    PHP = "php"
    GO = "go"


class VulnType(Enum):
    CRLF_INJECTION = "crlf-injection"
    SQL_INJECTION = "sql-injection"
    COMMAND_INJECTION = "command-injection"
    PATH_TRAVERSAL = "path-traversal"
    JNDI_INJECTION = "jndi-injection"
    CODE_INJECTION = "code-injection"
    PROTOTYPE_POLLUTION = "prototype-pollution"
    TEMPLATE_INJECTION = "template-injection"
    SSRF = "ssrf"


@dataclass(frozen=True)
class SourceSpec:
    """Specification for a taint source."""
    kind: str  # e.g., "external_input", "http_header", "function_param"
    pattern: str  # AST pattern or function name
    description: str


@dataclass(frozen=True)
class SinkSpec:
    """Specification for a dangerous sink."""
    kind: str  # e.g., "sql_query", "http_serialization", "command_exec"
    pattern: str  # AST pattern or function name
    description: str


@dataclass(frozen=True)
class SanitizerSpec:
    """Specification for a sanitizer that blocks taint flow."""
    pattern: str  # Regex or AST pattern
    description: str


@dataclass(frozen=True)
class RevisionSpec:
    """Specification for a particular revision to analyze."""
    tag: str
    expected_vulnerable: bool
    notes: Optional[str] = None


@dataclass
class BenchmarkConfig:
    """Configuration for a benchmark."""
    id: str
    name: str
    repo: str
    language: Language
    vuln_type: VulnType
    advisory: Optional[str] = None
    cwe: Optional[str] = None
    
    # Source/sink/sanitizer specs
    sources: list[SourceSpec] = field(default_factory=list)
    sinks: list[SinkSpec] = field(default_factory=list)
    sanitizers: list[SanitizerSpec] = field(default_factory=list)
    
    # Files to analyze (relative to repo root)
    target_files: list[str] = field(default_factory=list)
    
    # Revisions to test
    revisions: list[RevisionSpec] = field(default_factory=list)
    
    # Custom validation function (for complex cases)
    custom_validator: Optional[Callable[[Path, str], bool]] = None


# Registry of all benchmarks
BENCHMARK_REGISTRY: dict[str, BenchmarkConfig] = {}


def register_benchmark(config: BenchmarkConfig) -> None:
    """Register a benchmark configuration."""
    BENCHMARK_REGISTRY[config.id] = config


def get_benchmark(id: str) -> Optional[BenchmarkConfig]:
    """Get a benchmark by ID."""
    return BENCHMARK_REGISTRY.get(id)


def list_benchmarks() -> list[str]:
    """List all registered benchmark IDs."""
    return list(BENCHMARK_REGISTRY.keys())
