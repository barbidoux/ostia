"""SEC-05, proved on the dependency graph (cargo metadata): content is parsed in workers, never by the
orchestrator. The triage worker lives in `ostia-workers`; no other shipped crate depends on it, nor on any crate
that identifies file types or opens archives."""

import json
import shutil
from typing import Any

import pytest

from tooling_support import REPO, run

WORKERS = "ostia-workers"
# Type detection, archives, compression, executable and document parsers: the work of sandboxed workers.
CONTENT_PARSERS = {
    "infer",
    "tree_magic",
    "tree_magic_mini",
    "file-format",
    "magic",
    "filemagic",
    "zip",
    "async_zip",
    "tar",
    "flate2",
    "libflate",
    "miniz_oxide",
    "bzip2",
    "xz2",
    "lzma-rs",
    "zstd",
    "sevenz-rust",
    "sevenz-rust2",
    "unrar",
    "compress-tools",
    "cab",
    "cfb",
    "msi",
    "goblin",
    "object",
    "pelite",
    "pdf",
    "lopdf",
    "image",
    "png",
}


def metadata() -> dict[str, Any]:
    cargo = shutil.which("cargo")
    assert cargo is not None, "cargo not found"
    result = run([cargo, "metadata", "--format-version", "1", "--locked", "--offline"], cwd=REPO)
    assert result.returncode == 0, result.stderr
    data: dict[str, Any] = json.loads(result.stdout)
    return data


def packages(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {p["id"]: p for p in data["packages"]}


def shipped(data: dict[str, Any]) -> dict[str, str]:
    """Name → id of the workspace crates under crates/ (tests/fakes are test doubles, never shipped)."""
    by_id = packages(data)
    return {
        by_id[i]["name"]: i
        for i in data["workspace_members"]
        if "/crates/" in by_id[i]["manifest_path"]
    }


def linked(data: dict[str, Any], root: str) -> set[str]:
    """Names of every crate `root` links: normal dependencies, transitively (not dev, not build)."""
    nodes = {n["id"]: n for n in data["resolve"]["nodes"]}
    by_id = packages(data)
    seen: set[str] = set()
    stack = [root]
    while stack:
        for dep in nodes[stack.pop()]["deps"]:
            if any(kind["kind"] is None for kind in dep["dep_kinds"]) and dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                stack.append(dep["pkg"])
    return {by_id[i]["name"] for i in seen}


@pytest.fixture(scope="module")
def graph() -> dict[str, Any]:
    return metadata()


@pytest.mark.req("SEC-05")
def test_the_triage_worker_lives_in_the_workers_crate(graph: dict[str, Any]) -> None:
    crates = shipped(graph)
    assert WORKERS in crates, sorted(crates)
    targets = {(t["name"], tuple(t["kind"])) for t in packages(graph)[crates[WORKERS]]["targets"]}
    assert ("ostia-triage", ("bin",)) in targets, targets


@pytest.mark.req("SEC-05")
def test_no_orchestrator_crate_links_the_workers(graph: dict[str, Any]) -> None:
    crates = shipped(graph)
    assert WORKERS in crates, sorted(crates)
    for name, crate in crates.items():
        if name != WORKERS:
            assert WORKERS not in linked(graph, crate), name


@pytest.mark.req("SEC-05")
def test_no_orchestrator_crate_links_a_content_parser(graph: dict[str, Any]) -> None:
    for name, crate in shipped(graph).items():
        if name != WORKERS:
            assert linked(graph, crate) & CONTENT_PARSERS == set(), name
