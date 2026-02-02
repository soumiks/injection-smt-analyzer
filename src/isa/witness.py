from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Optional


@dataclass(frozen=True)
class Location:
    file: str
    line: Optional[int] = None
    col: Optional[int] = None
    function: Optional[str] = None


@dataclass(frozen=True)
class Endpoint:
    kind: str
    location: Location
    notes: Optional[str] = None


@dataclass(frozen=True)
class Target:
    repo: str
    rev: str


@dataclass(frozen=True)
class Vuln:
    kind: str
    advisory: Optional[str] = None
    cwe: Optional[str] = None


@dataclass(frozen=True)
class Witness:
    target: Target
    vuln: Vuln
    source: Endpoint
    sink: Endpoint
    call_chain: list[Location]
    path_constraints: list[str]
    smt2: Optional[str] = None
    z3_model: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
