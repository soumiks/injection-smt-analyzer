"""
Interprocedural taint analysis.

Tracks data flow from sources to sinks across function boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional, Set

from isa.core.config import Language, SanitizerSpec, SinkSpec, SourceSpec
from isa.core.parser import ASTNode, get_parser
from isa.witness import Location


class TaintState(Enum):
    TAINTED = "tainted"
    SANITIZED = "sanitized"
    UNKNOWN = "unknown"


@dataclass
class TaintedValue:
    """Represents a tainted value flowing through the program."""
    name: str
    source: SourceSpec
    source_location: Location
    state: TaintState = TaintState.TAINTED
    
    # Track how it flows
    flow_path: list[Location] = field(default_factory=list)
    
    def add_flow(self, loc: Location) -> None:
        self.flow_path.append(loc)
    
    def sanitize(self) -> None:
        self.state = TaintState.SANITIZED


@dataclass
class TaintFlow:
    """A complete taint flow from source to sink."""
    source: SourceSpec
    source_location: Location
    sink: SinkSpec
    sink_location: Location
    call_chain: list[Location]
    tainted_values: list[str]


@dataclass
class FunctionInfo:
    """Information about a function for interprocedural analysis."""
    name: str
    file: str
    line: int
    params: list[str]
    node: ASTNode
    
    # Track which params are taint sources/sinks
    tainted_params: Set[int] = field(default_factory=set)
    returns_tainted: bool = False


class TaintAnalyzer:
    """Interprocedural taint analyzer."""
    
    def __init__(
        self,
        sources: list[SourceSpec],
        sinks: list[SinkSpec],
        sanitizers: list[SanitizerSpec],
        language: Language,
    ):
        self.sources = sources
        self.sinks = sinks
        self.sanitizers = sanitizers
        self.language = language
        self.parser = get_parser()
        
        # Analysis state
        self.functions: dict[str, FunctionInfo] = {}
        self.tainted_values: dict[str, TaintedValue] = {}
        self.flows: list[TaintFlow] = []
        self.call_graph: dict[str, list[str]] = {}  # caller -> callees
    
    def analyze_file(self, path: Path) -> list[TaintFlow]:
        """Analyze a single file for taint flows."""
        root = self.parser.parse_file(path, self.language)
        if root is None:
            return []
        
        # Phase 1: Collect function definitions
        self._collect_functions(root)
        
        # Phase 2: Find sources and initial tainted values
        self._find_sources(root)
        
        # Phase 3: Propagate taint through the code
        self._propagate_taint(root)
        
        # Phase 4: Check for flows to sinks
        self._check_sinks(root)
        
        return self.flows
    
    def analyze_files(self, paths: list[Path]) -> list[TaintFlow]:
        """Analyze multiple files."""
        all_flows = []
        for path in paths:
            all_flows.extend(self.analyze_file(path))
        return all_flows
    
    def _collect_functions(self, root: ASTNode) -> None:
        """Collect all function definitions."""
        if self.language == Language.JAVASCRIPT:
            func_types = ("function_declaration", "arrow_function", "method_definition")
        else:
            func_types = ("function_definition", "async_function_definition")
        
        for node in root.find_all(*func_types):
            info = self._extract_function_info(node)
            if info:
                self.functions[info.name] = info
    
    def _extract_function_info(self, node: ASTNode) -> Optional[FunctionInfo]:
        """Extract function information from an AST node."""
        if self.language == Language.JAVASCRIPT:
            return self._extract_js_function_info(node)
        else:
            return self._extract_py_function_info(node)
    
    def _extract_js_function_info(self, node: ASTNode) -> Optional[FunctionInfo]:
        """Extract function info from JavaScript AST."""
        name = None
        params = []
        
        if node.type == "function_declaration":
            name_node = node.child_by_field("name")
            if name_node:
                name = name_node.text
        elif node.type == "method_definition":
            name_node = node.child_by_field("name")
            if name_node:
                name = name_node.text
        elif node.type == "arrow_function":
            # Try to get name from parent assignment
            parent = node.parent()
            if parent and parent.type == "variable_declarator":
                name_node = parent.child_by_field("name")
                if name_node:
                    name = name_node.text
        
        if not name:
            return None
        
        # Extract parameters
        params_node = node.child_by_field("parameters")
        if params_node:
            for param in params_node.children_by_type("identifier", "shorthand_property_identifier_pattern"):
                params.append(param.text)
        
        return FunctionInfo(
            name=name,
            file=node.file_path,
            line=node.start_line,
            params=params,
            node=node,
        )
    
    def _extract_py_function_info(self, node: ASTNode) -> Optional[FunctionInfo]:
        """Extract function info from Python AST."""
        name_node = node.child_by_field("name")
        if not name_node:
            return None
        
        name = name_node.text
        params = []
        
        params_node = node.child_by_field("parameters")
        if params_node:
            for param in params_node.find_all("identifier"):
                # Skip 'self' and type annotations
                text = param.text
                if text not in ("self", "cls"):
                    params.append(text)
        
        return FunctionInfo(
            name=name,
            file=node.file_path,
            line=node.start_line,
            params=params,
            node=node,
        )
    
    def _find_sources(self, root: ASTNode) -> None:
        """Find taint sources in the AST."""
        for source in self.sources:
            for node in self._find_source_matches(root, source):
                loc = Location(
                    file=node.file_path,
                    line=node.start_line,
                    col=node.start_col,
                )
                
                # Determine what variable is tainted
                var_name = self._get_tainted_var_from_source(node)
                if var_name:
                    self.tainted_values[var_name] = TaintedValue(
                        name=var_name,
                        source=source,
                        source_location=loc,
                    )
    
    def _find_source_matches(self, root: ASTNode, source: SourceSpec) -> Iterator[ASTNode]:
        """Find AST nodes matching a source specification."""
        pattern = source.pattern
        
        # Handle different pattern types
        if pattern.startswith("param:"):
            # Function parameter pattern
            param_name = pattern[6:]
            for func in self.functions.values():
                if param_name in func.params:
                    yield func.node
        elif pattern.startswith("call:"):
            # Function call pattern
            func_name = pattern[5:]
            for node in root.find_all("call_expression", "call"):
                callee = self._get_callee_name(node)
                if callee and func_name in callee:
                    yield node
        elif pattern.startswith("property:"):
            # Property access pattern
            prop = pattern[9:]
            for node in root.find_all("member_expression", "attribute"):
                if prop in node.text:
                    yield node
        else:
            # Literal text search
            for node in root.find_all("identifier", "string"):
                if pattern in node.text:
                    yield node
    
    def _get_callee_name(self, node: ASTNode) -> Optional[str]:
        """Get the name of a called function."""
        if self.language == Language.JAVASCRIPT:
            callee = node.child_by_field("function")
            if callee:
                return callee.text
        else:
            callee = node.child_by_field("function")
            if callee:
                return callee.text
        return None
    
    def _get_tainted_var_from_source(self, node: ASTNode) -> Optional[str]:
        """Determine which variable is tainted from a source node."""
        # Look for assignment context
        parent = node.parent()
        while parent:
            if parent.type in ("variable_declarator", "assignment_expression", "assignment"):
                left = parent.child_by_field("left") or parent.child_by_field("name")
                if left:
                    return left.text
            parent = parent.parent()
        
        # If it's an identifier itself, return it
        if node.type == "identifier":
            return node.text
        
        return None
    
    def _propagate_taint(self, root: ASTNode) -> None:
        """Propagate taint through assignments and function calls."""
        # Find all assignments
        for node in root.find_all("variable_declarator", "assignment_expression", "assignment"):
            self._handle_assignment(node)
        
        # Find all function calls
        for node in root.find_all("call_expression", "call"):
            self._handle_call(node)
    
    def _handle_assignment(self, node: ASTNode) -> None:
        """Handle taint propagation through an assignment."""
        left = node.child_by_field("left") or node.child_by_field("name")
        right = node.child_by_field("right") or node.child_by_field("value")
        
        if not left or not right:
            return
        
        left_name = left.text
        
        # Check if right side contains any tainted values
        for name, tainted in self.tainted_values.items():
            if name in right.text and tainted.state == TaintState.TAINTED:
                # Check for sanitization
                if self._is_sanitized(right):
                    continue
                
                # Propagate taint
                loc = Location(file=node.file_path, line=node.start_line)
                self.tainted_values[left_name] = TaintedValue(
                    name=left_name,
                    source=tainted.source,
                    source_location=tainted.source_location,
                    flow_path=tainted.flow_path + [loc],
                )
                break
    
    def _handle_call(self, node: ASTNode) -> None:
        """Handle taint propagation through a function call."""
        callee = self._get_callee_name(node)
        if not callee:
            return
        
        # Check if any arguments are tainted
        args_node = node.child_by_field("arguments")
        if not args_node:
            return
        
        for i, arg in enumerate(args_node.children()):
            for name, tainted in self.tainted_values.items():
                if name in arg.text and tainted.state == TaintState.TAINTED:
                    # Record in call graph
                    if callee not in self.call_graph:
                        self.call_graph[callee] = []
                    
                    # Mark the called function's param as tainted
                    if callee in self.functions:
                        self.functions[callee].tainted_params.add(i)
    
    def _is_sanitized(self, node: ASTNode) -> bool:
        """Check if a value is sanitized."""
        text = node.text
        for sanitizer in self.sanitizers:
            if sanitizer.pattern in text:
                return True
        return False
    
    def _check_sinks(self, root: ASTNode) -> None:
        """Check if tainted values reach sinks."""
        for sink in self.sinks:
            for node in self._find_sink_matches(root, sink):
                # Check if any tainted value reaches this sink
                for name, tainted in self.tainted_values.items():
                    if name in node.text and tainted.state == TaintState.TAINTED:
                        if not self._is_sanitized(node):
                            sink_loc = Location(
                                file=node.file_path,
                                line=node.start_line,
                                col=node.start_col,
                            )
                            
                            self.flows.append(TaintFlow(
                                source=tainted.source,
                                source_location=tainted.source_location,
                                sink=sink,
                                sink_location=sink_loc,
                                call_chain=tainted.flow_path + [sink_loc],
                                tainted_values=[name],
                            ))
    
    def _find_sink_matches(self, root: ASTNode, sink: SinkSpec) -> Iterator[ASTNode]:
        """Find AST nodes matching a sink specification."""
        pattern = sink.pattern
        
        if pattern.startswith("call:"):
            func_name = pattern[5:]
            for node in root.find_all("call_expression", "call"):
                callee = self._get_callee_name(node)
                if callee and func_name in callee:
                    yield node
        elif pattern.startswith("template:"):
            # Template string with interpolation
            for node in root.find_all("template_string", "f_string"):
                yield node
        else:
            # Generic pattern match
            for node in root.find_all("call_expression", "call", "string"):
                if pattern in node.text:
                    yield node
