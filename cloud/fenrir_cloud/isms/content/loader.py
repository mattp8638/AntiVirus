"""Reads packs from disk without validating them. Validation is in ``validate.py``."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PACKS_ROOT = Path(__file__).resolve().parent.parent / "packs"
PACK_FILES = ("groups", "requirements", "controls", "mappings", "questions", "rules")
NOT_PACKS = ("questionnaires",)  # loaded by questionnaires.py, not a pack


class _PackLoader(yaml.SafeLoader):
    """YAML as the standalone app read it: only true/false are booleans (not yes, no, on, off) and keys are unique."""


_PackLoader.yaml_implicit_resolvers = {
    first: [(tag, rx) for tag, rx in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_PackLoader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
                                  list("tTfF"))


def _unique_mapping(loader: _PackLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    seen: set = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(None, None, f'duplicate key "{key}"', key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_PackLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def parse_yaml(source: str, where: str, errors: list[str]) -> Any:
    try:
        return yaml.load(source, Loader=_PackLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as e:
        errors.append(f"{where}: {e}")
        return None


@dataclass
class RawTemplate:
    path: Path
    front_matter: Any
    body: str


@dataclass
class RawPack:
    """A pack as read from disk, before validation."""
    dir: Path
    meta: Any
    files: dict[str, Any] = field(default_factory=dict)
    templates: list[RawTemplate] = field(default_factory=list)
    text: list[tuple[Path, str]] = field(default_factory=list)  # every text file, for checks such as the em dash rule
    load_errors: list[str] = field(default_factory=list)


_FRONT_MATTER = re.compile(r"^---\n(.*?)\n---\n?(.*)$", re.S)


def parse_template(path: Path, source: str, errors: list[str]) -> RawTemplate:
    m = _FRONT_MATTER.match(source.replace("\r\n", "\n"))
    if not m:
        errors.append(f"{path}: template must start with YAML front matter between --- lines")
        return RawTemplate(path, None, source)
    before = len(errors)
    fm = parse_yaml(m.group(1), str(path), errors)
    return RawTemplate(path, fm if len(errors) == before else None, m.group(2))


def load_pack(directory: Path | str) -> RawPack:
    directory = Path(directory)
    raw = RawPack(directory, None)
    meta_path = directory / "pack.yaml"
    if meta_path.exists():
        raw.meta = parse_yaml(meta_path.read_text(encoding="utf-8"), str(meta_path), raw.load_errors)
    else:
        raw.load_errors.append(f"{directory}: missing pack.yaml")
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        raw.text.append((path, content))
        if path.name == "pack.yaml":
            continue
        if path.suffix in (".yaml", ".yml"):
            key = path.stem
            if key not in PACK_FILES:
                raw.load_errors.append(f"{path}: unknown pack file (expected one of {', '.join(PACK_FILES)})")
                continue
            raw.files[key] = parse_yaml(content, str(path), raw.load_errors)
        elif path.suffix == ".md":
            raw.templates.append(parse_template(path, content, raw.load_errors))
    return raw


def find_pack_dirs(root: Path | str = PACKS_ROOT, exclude: tuple[str, ...] = ()) -> list[Path]:
    """Every directory under root that holds a pack.yaml, skipping excluded and hidden directory names."""
    out: list[Path] = []

    def walk(d: Path) -> None:
        if (d / "pack.yaml").exists():
            out.append(d)
        for child in sorted(d.iterdir()):
            if child.is_dir() and child.name not in exclude and not child.name.startswith((".", "__")):
                walk(child)

    walk(Path(root))
    return out
