"""Every signature annotated, every annotation resolvable, every loaded name bound.

Carried over from FiniexRAGEngine's own contract, and doing one more job here. `get_type_hints`
forces every annotation to evaluate — which is exactly what Python 3.12 does eagerly at definition
time and 3.14 (PEP 649) defers. So a green run of this sweep on 3.14 also covers the most likely way
a 3.14-verified package breaks on the 3.12 floor: a name used in an annotation and never imported.

Names bound under `if TYPE_CHECKING:` are honoured as resolvable — the sanctioned pattern for an
import needed only by an annotation (`route_walk` uses it for the test client).
"""
import ast
import builtins
import importlib
import inspect
import pathlib
import typing
from typing import Dict, List, Set

_PACKAGE = pathlib.Path(__file__).resolve().parents[1] / 'finiex_auth'
_MODULE_DUNDERS = {'__file__', '__name__', '__doc__', '__package__', '__spec__',
                   '__loader__', '__builtins__', '__class__'}


def _module_name(path: pathlib.Path) -> str:
    return '.'.join(path.relative_to(_PACKAGE.parent).with_suffix('').parts)


def _deferred_names(tree: ast.AST) -> Set[str]:
    """Names bound inside `if TYPE_CHECKING:` — legitimately absent at runtime."""
    names: Set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not ((isinstance(test, ast.Name) and test.id == 'TYPE_CHECKING')
                or (isinstance(test, ast.Attribute) and test.attr == 'TYPE_CHECKING')):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, (ast.Import, ast.ImportFrom)):
                for alias in inner.names:
                    names.add(alias.asname or alias.name.split('.')[0])
    return names


def test_the_sweep_sees_the_package() -> None:
    # A glob that matched nothing would make the two checks below pass vacuously.
    assert len(list(_PACKAGE.rglob('*.py'))) >= 10


def test_every_parameter_and_return_is_annotated() -> None:
    missing: List[str] = []
    for path in sorted(_PACKAGE.rglob('*.py')):
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = node.args
            for index, arg in enumerate(args.posonlyargs + args.args + args.kwonlyargs):
                if arg.arg in ('self', 'cls') and index == 0:
                    continue
                if arg.annotation is None:
                    missing.append(f'{path.name}:{node.lineno} {node.name}({arg.arg})')
            for extra in (args.vararg, args.kwarg):
                if extra is not None and extra.annotation is None:
                    missing.append(f'{path.name}:{node.lineno} {node.name}(*{extra.arg})')
            if node.returns is None:
                missing.append(f'{path.name}:{node.lineno} {node.name} -> no return annotation')
    assert not missing, 'unannotated signatures:\n  ' + '\n  '.join(missing)


def test_every_annotation_resolves() -> None:
    deferred: Dict[str, Set[str]] = {
        _module_name(path): _deferred_names(ast.parse(path.read_text(encoding='utf-8')))
        for path in _PACKAGE.rglob('*.py')}
    unresolved: List[str] = []
    for module_name in sorted(deferred):
        module = importlib.import_module(module_name)
        localns = {name: typing.Any for name in deferred[module_name]}
        for obj in vars(module).values():
            if getattr(obj, '__module__', None) != module_name:
                continue
            functions = ([obj] if inspect.isfunction(obj)
                         else [value for value in vars(obj).values() if inspect.isfunction(value)]
                         if inspect.isclass(obj) else [])
            for function in functions:
                try:
                    typing.get_type_hints(function, localns=localns)
                except Exception as exc:       # noqa: BLE001 — any failure is the finding
                    unresolved.append(f'{module_name}.{function.__qualname__}: {exc}')
    assert not unresolved, 'annotations that do not resolve:\n  ' + '\n  '.join(unresolved)


def test_no_undefined_names() -> None:
    """A name loaded but never bound is a NameError waiting on the path nobody has run yet."""
    undefined: List[str] = []
    for path in sorted(_PACKAGE.rglob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        bound: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                bound.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                bound.add(node.id)
            elif isinstance(node, ast.arg):
                bound.add(node.arg)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                bound.add(node.name)
        allowed = bound | set(dir(builtins)) | _MODULE_DUNDERS
        undefined += [f'{path.name}:{node.lineno} {node.id}' for node in ast.walk(tree)
                      if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                      and node.id not in allowed]
    assert not undefined, 'names used but never bound:\n  ' + '\n  '.join(undefined)
