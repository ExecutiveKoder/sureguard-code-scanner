"""Manifest parsing for SCA.

We intentionally parse only the formats Sureguard supports natively. Lockfiles
are preferred over loose manifests because they pin versions, which is what
OSV needs to give an accurate vuln set.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Ecosystem, PackageRef

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=)\s*([A-Za-z0-9_.\-+!]+)")


def parse_requirements_txt(content: str) -> list[PackageRef]:
    out: list[PackageRef] = []
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_LINE.match(line)
        if m:
            out.append(PackageRef(name=m.group(1), version=m.group(2), ecosystem=Ecosystem.PYPI))
        else:
            # Bare name with no pin — still record so we can warn.
            name = re.split(r"[<>=!~ ]", line, maxsplit=1)[0].strip()
            if name:
                out.append(PackageRef(name=name, version=None, ecosystem=Ecosystem.PYPI))
    return out


def parse_package_json(content: str) -> list[PackageRef]:
    data = json.loads(content)
    out: list[PackageRef] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, version in (data.get(section) or {}).items():
            cleaned = re.sub(r"^[\^~>=<]+", "", str(version)).strip() or None
            out.append(PackageRef(name=name, version=cleaned, ecosystem=Ecosystem.NPM))
    return out


def parse_package_lock_json(content: str) -> list[PackageRef]:
    data = json.loads(content)
    out: list[PackageRef] = []
    packages = data.get("packages") or {}
    for path, info in packages.items():
        if not path or path == "":
            continue
        name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
        ver = info.get("version")
        if name and ver:
            out.append(PackageRef(name=name, version=ver, ecosystem=Ecosystem.NPM))
    return out


def parse_pyproject_toml(content: str) -> list[PackageRef]:
    try:
        import tomllib
    except ImportError:  # pragma: no cover — Python 3.10 fallback
        import tomli as tomllib  # type: ignore[no-redef]
    data = tomllib.loads(content)
    deps_lists: list[list[str]] = []
    project = data.get("project") or {}
    if isinstance(project.get("dependencies"), list):
        deps_lists.append(project["dependencies"])
    optional = project.get("optional-dependencies") or {}
    for group in optional.values():
        if isinstance(group, list):
            deps_lists.append(group)
    out: list[PackageRef] = []
    for deps in deps_lists:
        for entry in deps:
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=)\s*([A-Za-z0-9_.\-+!]+)", str(entry))
            if m:
                out.append(PackageRef(name=m.group(1), version=m.group(2), ecosystem=Ecosystem.PYPI))
            else:
                name = re.split(r"[<>=!~\[ ]", str(entry), maxsplit=1)[0].strip()
                if name:
                    out.append(PackageRef(name=name, version=None, ecosystem=Ecosystem.PYPI))
    return out


def parse_manifest_by_name(filename: str, content: str) -> list[PackageRef]:
    base = Path(filename).name.lower()
    if base == "requirements.txt" or base.endswith(".requirements.txt"):
        return parse_requirements_txt(content)
    if base == "package-lock.json":
        return parse_package_lock_json(content)
    if base == "package.json":
        return parse_package_json(content)
    if base == "pyproject.toml":
        return parse_pyproject_toml(content)
    raise ValueError(
        f"Unsupported manifest '{filename}'. Supported: requirements.txt, "
        "package.json, package-lock.json, pyproject.toml."
    )
