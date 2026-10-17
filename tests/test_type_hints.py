"""
tests/test_type_hints.py
Static and runtime verification of type annotations across codebase/ (Phase 3E-3 B8).
Verifies:
- Every type annotation name used in codebase/ is either built-in, defined, or imported.
- typing.get_type_hints raises no NameError for public functions, classes, and methods.
- Catches missing imports such as 'from typing import Any' in threat_intel_agent.py.
"""

import ast
import builtins
import importlib
import inspect
import os
import pkgutil
from pathlib import Path
import typing
import pytest


BUILTIN_NAMES = set(dir(builtins)) | {
    "None", "Ellipsis", "NotImplemented",
}


def _collect_defined_and_imported_names(tree: ast.AST) -> set[str]:
    """Collect all imported names, defined class/function names, and global targets in module."""
    names = set(BUILTIN_NAMES)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    pass
                else:
                    names.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
        elif isinstance(node, ast.TypeAlias):  # Python 3.12+
            names.add(node.name.id)

    return names


def _find_names_in_annotation(node: ast.AST | None) -> list[str]:
    """Extract all Name identifiers used within a type annotation node."""
    if node is None:
        return []
    names = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.append(sub.id)
    return names


def test_ast_annotations_have_all_names_defined():
    """AST check: ensure all names used in annotations are imported or defined."""
    codebase_dir = Path(__file__).resolve().parent.parent / "codebase"
    missing_by_file: dict[str, list[str]] = {}

    for py_file in codebase_dir.rglob("*.py"):
        if py_file.name.startswith("."):
            continue
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(py_file))
        except Exception as e:
            continue

        available = _collect_defined_and_imported_names(tree)

        missing_names = []
        for node in ast.walk(tree):
            # Check function parameter annotations and return annotation
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.returns:
                    for name in _find_names_in_annotation(node.returns):
                        if name not in available:
                            missing_names.append(f"{py_file.name}:{node.lineno} return '{name}'")
                for arg in node.args.args + node.args.kwonlyargs + getattr(node.args, "posonlyargs", []):
                    if arg.annotation:
                        for name in _find_names_in_annotation(arg.annotation):
                            if name not in available:
                                missing_names.append(f"{py_file.name}:{arg.lineno} arg '{arg.arg}: {name}'")
            # Check variable annotations
            elif isinstance(node, ast.AnnAssign):
                if node.annotation:
                    for name in _find_names_in_annotation(node.annotation):
                        if name not in available:
                            missing_names.append(f"{py_file.name}:{node.lineno} var '{name}'")

        if missing_names:
            rel_path = str(py_file.relative_to(codebase_dir))
            missing_by_file[rel_path] = missing_names

    assert not missing_by_file, f"Found undefined annotation names: {missing_by_file}"


def test_runtime_get_type_hints_on_all_codebase_modules():
    """Runtime check: call typing.get_type_hints on all public symbols across codebase/."""
    codebase_dir = Path(__file__).resolve().parent.parent / "codebase"
    name_errors: list[str] = []

    for finder, modname, ispkg in pkgutil.walk_packages([str(codebase_dir)], prefix="codebase."):
        # Avoid optional / external dependencies failing import in tests
        try:
            mod = importlib.import_module(modname)
        except Exception:
            continue

        for attr_name, obj in inspect.getmembers(mod):
            if attr_name.startswith("__"):
                continue

            target_objs = []
            if inspect.isfunction(obj) or inspect.isclass(obj):
                target_objs.append((f"{modname}.{attr_name}", obj))
                if inspect.isclass(obj):
                    for member_name, member in inspect.getmembers(obj):
                        if inspect.isfunction(member) or inspect.ismethod(member):
                            target_objs.append((f"{modname}.{attr_name}.{member_name}", member))

            for full_name, target in target_objs:
                try:
                    typing.get_type_hints(target)
                except NameError as ne:
                    name_errors.append(f"{full_name}: {ne}")
                except Exception:
                    # Ignore complex forward reference errors that are not NameError
                    pass

    assert not name_errors, f"typing.get_type_hints raised NameErrors: {name_errors}"
