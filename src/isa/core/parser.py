"""
AST parsing utilities using tree-sitter.

Provides a unified interface for parsing JavaScript and Python code.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

import tree_sitter
import tree_sitter_javascript
import tree_sitter_python

from isa.core.config import Language


@dataclass(frozen=True)
class ASTNode:
    """Wrapper around tree-sitter node with convenience methods."""
    node: tree_sitter.Node
    source: bytes
    file_path: str
    
    @property
    def type(self) -> str:
        return self.node.type
    
    @property
    def text(self) -> str:
        return self.node.text.decode("utf-8")
    
    @property
    def start_line(self) -> int:
        return self.node.start_point.row + 1
    
    @property
    def end_line(self) -> int:
        return self.node.end_point.row + 1
    
    @property
    def start_col(self) -> int:
        return self.node.start_point.column
    
    def children(self) -> Iterator[ASTNode]:
        for child in self.node.children:
            yield ASTNode(child, self.source, self.file_path)
    
    def children_by_type(self, *types: str) -> Iterator[ASTNode]:
        for child in self.node.children:
            if child.type in types:
                yield ASTNode(child, self.source, self.file_path)
    
    def find_all(self, *types: str) -> Iterator[ASTNode]:
        """Recursively find all descendants of given types."""
        if self.node.type in types:
            yield self
        for child in self.node.children:
            yield from ASTNode(child, self.source, self.file_path).find_all(*types)
    
    def find_first(self, *types: str) -> Optional[ASTNode]:
        """Find first descendant of given type."""
        for node in self.find_all(*types):
            return node
        return None
    
    def parent(self) -> Optional[ASTNode]:
        if self.node.parent:
            return ASTNode(self.node.parent, self.source, self.file_path)
        return None
    
    def child_by_field(self, name: str) -> Optional[ASTNode]:
        child = self.node.child_by_field_name(name)
        if child:
            return ASTNode(child, self.source, self.file_path)
        return None
    
    def __repr__(self) -> str:
        return f"ASTNode({self.type}, line={self.start_line}, text={self.text[:50]!r})"


class Parser:
    """Multi-language parser using tree-sitter."""
    
    def __init__(self):
        js_lang = tree_sitter.Language(tree_sitter_javascript.language())
        py_lang = tree_sitter.Language(tree_sitter_python.language())
        self._js_parser = tree_sitter.Parser(js_lang)
        self._py_parser = tree_sitter.Parser(py_lang)
    
    def parse_file(self, path: Path, language: Optional[Language] = None) -> Optional[ASTNode]:
        """Parse a file and return the root AST node."""
        if not path.exists():
            return None
        
        # Auto-detect language from extension
        if language is None:
            ext = path.suffix.lower()
            if ext in (".js", ".mjs", ".cjs", ".ts"):
                language = Language.JAVASCRIPT
            elif ext == ".py":
                language = Language.PYTHON
            else:
                return None
        
        source = path.read_bytes()
        parser = self._js_parser if language == Language.JAVASCRIPT else self._py_parser
        tree = parser.parse(source)
        
        return ASTNode(tree.root_node, source, str(path))
    
    def parse_string(self, code: str, language: Language, file_path: str = "<string>") -> ASTNode:
        """Parse a code string and return the root AST node."""
        source = code.encode("utf-8")
        parser = self._js_parser if language == Language.JAVASCRIPT else self._py_parser
        tree = parser.parse(source)
        
        return ASTNode(tree.root_node, source, file_path)


# Singleton parser instance
_parser: Optional[Parser] = None


def get_parser() -> Parser:
    """Get or create the global parser instance."""
    global _parser
    if _parser is None:
        _parser = Parser()
    return _parser
