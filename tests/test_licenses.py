"""Every package safemaxxing installs (and the menu-bar extra, when present) is under a
permissive license compatible with its own MIT license; docs/THIRD_PARTY_LICENSES.md lists
them. A new dependency under GPL, AGPL, LGPL, SSPL or an unknown license fails here."""

from __future__ import annotations

import re
from importlib import metadata

import pytest

# SPDX ids (or classifier wording) accepted for a dependency of an MIT-licensed tool.
PERMISSIVE = ("MIT", "BSD", "ISC", "PSF", "Python Software Foundation", "Apache")
COPYLEFT = re.compile(r"\b(A?GPL|LGPL|SSPL|EUPL|MPL|CC-BY-SA)\b|General Public", re.I)


def _key(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def closure(root: str) -> dict[str, metadata.Distribution]:
    """`root` and every distribution its unconditional requirements pull in."""
    seen: dict[str, metadata.Distribution] = {}
    stack = [root]
    while stack:
        name = stack.pop()
        if _key(name) in seen:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue  # a marker excluded it on this platform
        seen[_key(name)] = dist
        for requirement in dist.requires or []:
            if "extra ==" in requirement:
                continue
            stack.append(re.split(r"[ ;<>=!~\[(]", requirement, maxsplit=1)[0])
    return seen


def license_of(dist: metadata.Distribution) -> str:
    """The SPDX expression, else the license classifiers, else the License field's first line."""
    meta = dist.metadata
    if expression := meta.get("License-Expression"):
        return expression
    classifiers = [
        c.split("::")[-1].strip()
        for c in meta.get_all("Classifier") or []
        if c.startswith("License ::")
    ]
    if classifiers:
        return " / ".join(classifiers)
    return (meta.get("License") or "").strip().splitlines()[0] if meta.get("License") else ""


def _roots() -> list[str]:
    roots = ["safemaxxing"]
    try:
        metadata.distribution("rumps")
    except metadata.PackageNotFoundError:
        pass
    else:
        roots.append("rumps")
    return roots


@pytest.mark.parametrize("root", _roots())
def test_every_dependency_is_permissively_licensed(root: str) -> None:
    problems = {}
    for name, dist in closure(root).items():
        found = license_of(dist)
        if not any(p.lower() in found.lower() for p in PERMISSIVE) or COPYLEFT.search(found):
            problems[name] = found or "no license metadata"
    assert problems == {}


def test_the_runtime_closure_stays_small() -> None:
    # No compiled validation stack (pydantic-core) or other heavy addition by accident: a new
    # runtime package should be a decision, made here and in docs/THIRD_PARTY_LICENSES.md.
    runtime = set(closure("safemaxxing")) - {"safemaxxing"}
    assert "pydantic-core" not in runtime
    assert len(runtime) <= 14, sorted(runtime)
