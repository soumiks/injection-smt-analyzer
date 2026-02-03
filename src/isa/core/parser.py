"""
AST parsing utilities using tree-sitter.

Provides a unified interface for parsing JavaScript, Python, Java, PHP, and Go code.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

import tree_sitter
import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_java
import tree_sitter_go

# PHP has a different module structure
try:
    import tree_sitter_php
    HAS_PHP = True
except ImportError:
    HAS_PHP = False

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
        # Initialize parsers for each supported language
        js_lang = tree_sitter.Language(tree_sitter_javascript.language())
        py_lang = tree_sitter.Language(tree_sitter_python.language())
        java_lang = tree_sitter.Language(tree_sitter_java.language())
        go_lang = tree_sitter.Language(tree_sitter_go.language())
        
        self._js_parser = tree_sitter.Parser(js_lang)
        self._py_parser = tree_sitter.Parser(py_lang)
        self._java_parser = tree_sitter.Parser(java_lang)
        self._go_parser = tree_sitter.Parser(go_lang)
        
        # PHP parser (optional, module structure differs)
        self._php_parser = None
        if HAS_PHP:
            try:
                # tree-sitter-php exposes php_language() or language()
                if hasattr(tree_sitter_php, 'language_php'):
                    php_lang = tree_sitter.Language(tree_sitter_php.language_php())
                elif hasattr(tree_sitter_php, 'language'):
                    php_lang = tree_sitter.Language(tree_sitter_php.language())
                else:
                    php_lang = None
                if php_lang:
                    self._php_parser = tree_sitter.Parser(php_lang)
            except Exception:
                pass
    
    def _get_parser(self, language: str) -> Optional[tree_sitter.Parser]:
        """Get parser for a language."""
        lang_lower = language.lower() if isinstance(language, str) else language.value.lower()
        
        if lang_lower in ("javascript", "js"):
            return self._js_parser
        elif lang_lower in ("python", "py"):
            return self._py_parser
        elif lang_lower == "java":
            return self._java_parser
        elif lang_lower == "go":
            return self._go_parser
        elif lang_lower == "php":
            return self._php_parser
        return None
    
    def _detect_language(self, path: Path) -> Optional[str]:
        """Auto-detect language from file extension."""
        ext = path.suffix.lower()
        ext_map = {
            ".js": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".ts": "javascript",  # Basic TS support via JS parser
            ".py": "python",
            ".java": "java",
            ".go": "go",
            ".php": "php",
        }
        return ext_map.get(ext)
    
    def parse_file(self, path: Path, language: Optional[str] = None) -> Optional[ASTNode]:
        """Parse a file and return the root AST node."""
        if not path.exists():
            return None
        
        # Auto-detect language from extension
        if language is None:
            language = self._detect_language(path)
        
        if language is None:
            return None
        
        # Handle Language enum from config
        if hasattr(language, 'value'):
            language = language.value
        
        parser = self._get_parser(language)
        if parser is None:
            return None
        
        source = path.read_bytes()
        tree = parser.parse(source)
        
        return ASTNode(tree.root_node, source, str(path))
    
    def parse_string(self, code: str, language: str, file_path: str = "<string>") -> Optional[ASTNode]:
        """Parse a code string and return the root AST node."""
        # Handle Language enum
        if hasattr(language, 'value'):
            language = language.value
            
        parser = self._get_parser(language)
        if parser is None:
            return None
            
        source = code.encode("utf-8")
        tree = parser.parse(source)
        
        return ASTNode(tree.root_node, source, file_path)
    
    def supports_language(self, language: str) -> bool:
        """Check if a language is supported."""
        return self._get_parser(language) is not None


# Singleton parser instance
_parser: Optional[Parser] = None


def get_parser() -> Parser:
    """Get or create the global parser instance."""
    global _parser
    if _parser is None:
        _parser = Parser()
    return _parser
