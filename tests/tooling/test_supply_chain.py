"""Supply-chain gates (WP-0.8): licences, sources and advisories of the Rust dependencies, pinned and
hash-verified Python dependencies, licences of the Python dependencies, CycloneDX SBOMs.

UPD-07: Python dependencies are installed only with verified hashes; Rust dependencies are checked by
cargo-deny (licences, sources, advisories).
NFR-11: dependencies are pinned, audited and licence-checked; an SBOM is produced (cargo-deny, cargo-audit,
pip-audit, CycloneDX).

Every test here is offline: the seeded crates use path dependencies or a local git repository, and the
Python checks read files. The advisory databases are only fetched by `just audit`.
"""

import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

from tooling_support import REPO, run

DENY = REPO / "deny.toml"
CHECK_PINS = REPO / "tools" / "supply" / "check_pins.py"
PY_LICENCES = REPO / "tools" / "supply" / "python_licences.py"
PY_LICENCE_CONFIG = REPO / "tools" / "supply" / "python-licences.toml"
SBOM = REPO / "tools" / "supply" / "sbom.py"
CRATES_IO = "https://github.com/rust-lang/crates.io-index"

# prompts/P0.md (WP-0.8) plus MPL-2.0 (Q-26) and the permissive licences of the approved Python tools
# (Q-25: MIT-0, 0BSD, PSF-2.0).
ALLOWED = {
    "Apache-2.0",
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
    "MPL-2.0",
    "MIT-0",
    "0BSD",
    "PSF-2.0",
}
HASH_A = "a" * 64
HASH_B = "b" * 64


def deny_config() -> dict[str, Any]:
    assert DENY.is_file(), "deny.toml is missing"
    with DENY.open("rb") as f:
        return tomllib.load(f)


def tool(name: str) -> str:
    path = shutil.which(name)
    assert path, f"{name} is not on PATH (tools/dev/versions.env, docs/dev-setup.md)"
    return path


def no_colour_env(**extra: str) -> dict[str, str]:
    return {**os.environ, "CARGO_TERM_COLOR": "never", **extra}


# --- deny.toml ------------------------------------------------------------------------------------


@pytest.mark.req("UPD-07")
def test_licence_allowlist_is_exactly_the_approved_set() -> None:
    licences = deny_config()["licenses"]
    assert set(licences["allow"]) == ALLOWED
    assert len(licences["allow"]) == len(ALLOWED)
    assert licences["confidence-threshold"] >= 0.8


@pytest.mark.req("UPD-07")
def test_ncsa_is_only_an_exception_for_libfuzzer_sys() -> None:
    licences = deny_config()["licenses"]
    assert "NCSA" not in licences["allow"]
    assert licences["exceptions"] == [{"crate": "libfuzzer-sys", "allow": ["NCSA"]}]


@pytest.mark.req("UPD-07")
def test_our_own_crates_are_licence_checked_too() -> None:
    assert deny_config()["licenses"]["private"]["ignore"] is False


@pytest.mark.req("UPD-07")
def test_sources_are_crates_io_only() -> None:
    sources = deny_config()["sources"]
    assert sources["unknown-registry"] == "deny"
    assert sources["unknown-git"] == "deny"
    assert sources["allow-registry"] == [CRATES_IO]
    assert sources.get("allow-git", []) == []


@pytest.mark.req("UPD-07")
def test_advisories_deny_and_ignore_nothing() -> None:
    advisories = deny_config()["advisories"]
    assert advisories.get("ignore", []) == []
    assert advisories["yanked"] == "deny"
    assert advisories["unmaintained"] == "all"
    assert advisories["unsound"] == "all"


@pytest.mark.req("UPD-07")
def test_bans_refuse_wildcard_versions_except_private_paths() -> None:
    bans = deny_config()["bans"]
    assert bans["wildcards"] == "deny"
    assert bans["allow-wildcard-paths"] is True


@pytest.mark.req("UPD-07")
def test_graph_covers_every_feature() -> None:
    assert deny_config()["graph"]["all-features"] is True


# --- seeded crates checked by cargo-deny ----------------------------------------------------------


def crate(directory: Path, name: str, licence: str, dependencies: str = "") -> None:
    (directory / "src").mkdir(parents=True)
    (directory / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n'
        f'license = "{licence}"\npublish = false\n\n[dependencies]\n{dependencies}'
    )
    (directory / "src" / "lib.rs").write_text("//! Seeded crate.\n")


def workspace(root: Path) -> Path:
    (root / "Cargo.toml").write_text('[workspace]\nmembers = ["app"]\nresolver = "2"\n')
    shutil.copy(REPO / "rust-toolchain.toml", root / "rust-toolchain.toml")
    return root


def cargo_deny(root: Path, *check: str, offline: bool = True) -> subprocess.CompletedProcess[str]:
    # Without the file, cargo-deny falls back to its defaults (nothing allowed, any source): a seeded
    # rejection would then prove nothing about our configuration.
    assert DENY.is_file(), "deny.toml is missing"
    cmd = [tool("cargo-deny"), "--manifest-path", str(root / "Cargo.toml"), "--config", str(DENY)]
    if offline:
        cmd.append("--offline")
    cmd += ["check", *check]
    return run(cmd, cwd=root, env=no_colour_env(CARGO_HOME=str(root / "cargo-home")))


def path_dependency_workspace(root: Path, dependency_licence: str) -> Path:
    workspace(root)
    crate(root / "app", "app", "Apache-2.0", 'dep = { path = "../dep" }\n')
    crate(root / "dep", "dep", dependency_licence)
    return root


@pytest.mark.req("UPD-07")
def test_seeded_gpl_path_dependency_is_rejected(tmp_path: Path) -> None:
    result = cargo_deny(path_dependency_workspace(tmp_path, "GPL-3.0-only"), "licenses")
    assert result.returncode != 0
    assert "error[rejected]" in result.stderr
    assert "GPL-3.0-only" in result.stderr


@pytest.mark.req("UPD-07")
def test_mit_twin_of_the_seeded_dependency_is_accepted(tmp_path: Path) -> None:
    result = cargo_deny(path_dependency_workspace(tmp_path, "MIT"), "licenses")
    assert result.returncode == 0, result.stderr


@pytest.mark.req("UPD-07")
def test_ncsa_is_refused_for_any_other_crate(tmp_path: Path) -> None:
    result = cargo_deny(path_dependency_workspace(tmp_path, "NCSA"), "licenses")
    assert result.returncode != 0
    assert "error[rejected]" in result.stderr
    assert "NCSA" in result.stderr


def git_dependency_workspace(root: Path) -> Path:
    repo = root / "gitdep"
    crate(repo, "gitdep", "MIT")
    git = tool("git")
    identity = ["-c", "user.name=Ostia Tests", "-c", "user.email=tests@ostia.invalid"]
    for args in (
        ["init", "-q", "-b", "main"],
        ["add", "."],
        [*identity, "commit", "-q", "-m", "seed"],
    ):
        assert run([git, *args], cwd=repo).returncode == 0
    workspace(root)
    crate(root / "app", "app", "Apache-2.0", f'gitdep = {{ git = "{repo.as_uri()}" }}\n')
    return root


@pytest.mark.req("UPD-07")
def test_seeded_git_dependency_is_rejected(tmp_path: Path) -> None:
    # Fetching a file:// repository is local; cargo refuses git sources in offline mode.
    result = cargo_deny(git_dependency_workspace(tmp_path), "sources", offline=False)
    assert result.returncode != 0
    assert "error[source-not-allowed]" in result.stderr


@pytest.mark.req("UPD-07")
def test_path_only_workspace_passes_the_sources_check(tmp_path: Path) -> None:
    result = cargo_deny(path_dependency_workspace(tmp_path, "MIT"), "sources")
    assert result.returncode == 0, result.stderr


# --- pinned Python dependencies -------------------------------------------------------------------


def check_pins(*args: str) -> subprocess.CompletedProcess[str]:
    return run([sys.executable, str(CHECK_PINS), *args], cwd=REPO)


def pyproject(path: Path, dependencies: list[str], groups: dict[str, list[str]]) -> Path:
    lines = [
        "[project]",
        'name = "sample"',
        'version = "0.0.0"',
        f"dependencies = {json.dumps(dependencies)}",
    ]
    lines.append("[dependency-groups]")
    lines += [f"{name} = {json.dumps(entries)}" for name, entries in groups.items()]
    path.write_text("\n".join(lines) + "\n")
    return path


PINNED_GROUPS = {"dev": ["pytest==9.1.1", "mypy[faster-cache]==2.4.0 ; python_version >= '3.12'"]}


@pytest.mark.req("UPD-07")
def test_exactly_pinned_pyproject_passes(tmp_path: Path) -> None:
    path = pyproject(tmp_path / "pyproject.toml", ["protobuf==7.36.2"], PINNED_GROUPS)
    result = check_pins("--pyproject", str(path))
    assert result.returncode == 0, result.stderr


@pytest.mark.req("UPD-07")
def test_include_group_entries_are_not_requirements(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        '[project]\nname = "s"\nversion = "0"\ndependencies = []\n'
        '[dependency-groups]\ndev = ["pytest==9.1.1"]\nall = [{include-group = "dev"}]\n'
    )
    result = check_pins("--pyproject", str(path))
    assert result.returncode == 0, result.stderr


@pytest.mark.req("UPD-07")
@pytest.mark.parametrize(
    ("table", "requirement"),
    [
        ("project.dependencies", "protobuf>=7"),
        ("project.dependencies", "protobuf"),
        ("dependency-groups.dev", "pytest~=9.1"),
        ("dependency-groups.dev", "pytest==9.*"),
        ("dependency-groups.dev", "pytest==9.1.1,<10"),
        ("dependency-groups.dev", "pytest===9.1.1"),
        ("dependency-groups.dev", "pytest @ https://example.invalid/pytest-9.1.1.whl"),
        ("project.optional-dependencies.extra", "rich>=12"),
    ],
)
def test_seeded_unpinned_pyproject_dependency_fails(
    tmp_path: Path, table: str, requirement: str
) -> None:
    path = tmp_path / "pyproject.toml"
    dependencies = [requirement] if table == "project.dependencies" else ["protobuf==7.36.2"]
    groups = {"dev": [requirement] if table == "dependency-groups.dev" else ["pytest==9.1.1"]}
    pyproject(path, dependencies, groups)
    if table == "project.optional-dependencies.extra":
        path.write_text(
            path.read_text().replace(
                "[dependency-groups]",
                f"[project.optional-dependencies]\nextra = {json.dumps([requirement])}\n"
                "[dependency-groups]",
            )
        )
    result = check_pins("--pyproject", str(path))
    assert result.returncode == 1
    assert f"{table}: {requirement!r} is not pinned with ==" in result.stderr


REQUIREMENTS = f"""# This file was autogenerated by uv
protobuf==7.36.2 \\
    --hash=sha256:{HASH_A} \\
    --hash=sha256:{HASH_B}
    # via ostia
pytest==9.1.1 ; python_version >= '3.12' \\
    --hash=sha256:{HASH_A}
"""


def requirements(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text(text)
    return path


@pytest.mark.req("UPD-07")
def test_pinned_and_hashed_requirements_pass(tmp_path: Path) -> None:
    result = check_pins("--requirements", str(requirements(tmp_path, REQUIREMENTS)))
    assert result.returncode == 0, result.stderr


@pytest.mark.req("UPD-07")
@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("six==1.17.0\n", ":1: 'six==1.17.0' has no sha256 hash"),
        (f"six==1.17.0 --hash=md5:{HASH_A[:32]}\n", ":1: 'six==1.17.0' has no sha256 hash"),
        (f"six>=1.0 \\\n    --hash=sha256:{HASH_A}\n", ":1: 'six>=1.0' is not pinned with =="),
        (f"six \\\n    --hash=sha256:{HASH_A}\n", ":1: 'six' is not pinned with =="),
        (
            f"# header\nsix==1.17.0 --hash=sha256:{HASH_A[:10]}\n",
            ":2: 'six==1.17.0' has no sha256 hash",
        ),
        ("-e ./local\n", ":1: unsupported line '-e ./local'"),
        ("--index-url https://example.invalid/simple\n", ":1: unsupported line"),
        ("./local-0.1-py3-none-any.whl\n", ":1: unsupported line"),
    ],
)
def test_seeded_unpinned_or_unhashed_requirement_fails(
    tmp_path: Path, text: str, message: str
) -> None:
    result = check_pins("--requirements", str(requirements(tmp_path, text)))
    assert result.returncode == 1
    assert message in result.stderr


@pytest.mark.req("UPD-07")
def test_one_bad_requirement_among_good_ones_fails(tmp_path: Path) -> None:
    text = REQUIREMENTS + "six==1.17.0\n"
    result = check_pins("--requirements", str(requirements(tmp_path, text)))
    assert result.returncode == 1
    assert ":8: 'six==1.17.0' has no sha256 hash" in result.stderr
    assert "protobuf" not in result.stderr


@pytest.mark.req("UPD-07")
def test_requirements_without_any_requirement_fail(tmp_path: Path) -> None:
    result = check_pins("--requirements", str(requirements(tmp_path, "# nothing\n")))
    assert result.returncode == 1
    assert "no requirements" in result.stderr


@pytest.mark.req("UPD-07")
def test_check_pins_needs_something_to_check() -> None:
    result = check_pins()
    assert result.returncode == 2
    assert "nothing to check: give --pyproject, --requirements or both" in result.stderr


@pytest.mark.req("UPD-07")
def test_missing_file_is_a_usage_error(tmp_path: Path) -> None:
    absent = tmp_path / "absent.txt"
    result = check_pins("--requirements", str(absent))
    assert result.returncode == 2
    assert f"check_pins: cannot read {absent}" in result.stderr


@pytest.mark.req("UPD-07")
def test_repository_pins_and_locked_export_pass(tmp_path: Path) -> None:
    exported = tmp_path / "requirements.txt"
    export = run(
        [
            tool("uv"),
            "export",
            "--frozen",
            "--all-groups",
            "--no-emit-project",
            "--format",
            "requirements-txt",
            "--output-file",
            str(exported),
        ],
        cwd=REPO,
    )
    assert export.returncode == 0, export.stderr
    result = check_pins(
        "--pyproject", str(REPO / "pyproject.toml"), "--requirements", str(exported)
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.req("NFR-11")
def test_audit_tools_are_a_locked_uv_group_installed_by_default() -> None:
    with (REPO / "pyproject.toml").open("rb") as f:
        project = tomllib.load(f)
    groups = project["dependency-groups"]
    assert groups.get("audit") == ["pip-audit==2.10.1", "cyclonedx-bom==7.5.0"]
    assert set(project["tool"]["uv"].get("default-groups", [])) == {"dev", "audit"}


# --- licences of the Python dependencies ----------------------------------------------------------


def component(name: str, version: str, licences: list[dict[str, Any]] | None) -> dict[str, Any]:
    entry: dict[str, Any] = {"type": "library", "name": name, "version": version}
    if licences is not None:
        entry["licenses"] = licences
    return entry


def spdx(identifier: str) -> dict[str, Any]:
    return {"license": {"acknowledgement": "declared", "id": identifier}}


def named(name: str) -> dict[str, Any]:
    return {"license": {"acknowledgement": "declared", "name": name}}


def expression(text: str) -> dict[str, Any]:
    return {"acknowledgement": "declared", "expression": text}


def py_licences(
    tmp_path: Path, components: list[dict[str, Any]], *extra: str
) -> subprocess.CompletedProcess[str]:
    sbom = tmp_path / "env.cdx.json"
    sbom.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components})
    )
    return run([sys.executable, str(PY_LICENCES), "--sbom", str(sbom), *extra], cwd=REPO)


@pytest.mark.req("NFR-11")
@pytest.mark.parametrize(
    "licences",
    [
        [spdx("MIT")],
        [spdx("MPL-2.0")],
        [expression("MIT OR GPL-3.0-only")],
        [expression("(MIT OR Apache-2.0) AND Unicode-3.0")],
        [expression("Apache-2.0 WITH LLVM-exception")],
        [named("License :: OSI Approved :: Apache Software License")],
        [spdx("MIT"), spdx("Apache-2.0")],
    ],
)
def test_allowed_python_licences_pass(tmp_path: Path, licences: list[dict[str, Any]]) -> None:
    result = py_licences(tmp_path, [component("good", "1.0", licences)])
    assert result.returncode == 0, result.stderr


@pytest.mark.req("NFR-11")
@pytest.mark.parametrize(
    ("licences", "shown"),
    [
        ([spdx("GPL-3.0-only")], "'GPL-3.0-only'"),
        ([expression("MIT AND GPL-3.0-only")], "'MIT AND GPL-3.0-only'"),
        ([named("Some Custom License")], "'Some Custom License'"),
        ([spdx("MIT"), spdx("GPL-3.0-only")], "'GPL-3.0-only'"),
        ([spdx("NCSA")], "'NCSA'"),
    ],
)
def test_seeded_disallowed_python_licence_fails(
    tmp_path: Path, licences: list[dict[str, Any]], shown: str
) -> None:
    components = [component("good", "1.0", [spdx("MIT")]), component("bad", "2.0", licences)]
    result = py_licences(tmp_path, components)
    assert result.returncode == 1
    assert f"bad 2.0: {shown} is not allowed" in result.stderr
    assert "good 1.0" not in result.stderr


@pytest.mark.req("NFR-11")
@pytest.mark.parametrize("licences", [None, []])
def test_python_package_without_licence_fails(
    tmp_path: Path, licences: list[dict[str, Any]] | None
) -> None:
    result = py_licences(tmp_path, [component("nolicence", "1.0", licences)])
    assert result.returncode == 1
    assert "nolicence 1.0: no licence" in result.stderr


@pytest.mark.req("NFR-11")
@pytest.mark.parametrize("text", ["MIT OR", "(MIT", "MIT Apache-2.0", "AND MIT", ""])
def test_unparsable_licence_expression_fails(tmp_path: Path, text: str) -> None:
    result = py_licences(tmp_path, [component("odd", "1.0", [expression(text)])])
    assert result.returncode == 1
    assert "odd 1.0: cannot parse licence expression" in result.stderr


@pytest.mark.req("NFR-11")
def test_package_override_applies_to_its_exact_version_only(tmp_path: Path) -> None:
    config = tmp_path / "python-licences.toml"
    config.write_text('[aliases]\n\n[packages]\n"oldmeta==1.2.3" = "BSD-3-Clause"\n')
    same = py_licences(tmp_path, [component("oldmeta", "1.2.3", None)], "--config", str(config))
    assert same.returncode == 0, same.stderr
    bumped = py_licences(tmp_path, [component("oldmeta", "1.2.4", None)], "--config", str(config))
    assert bumped.returncode == 1
    assert "oldmeta 1.2.4: no licence" in bumped.stderr


@pytest.mark.req("NFR-11")
def test_package_override_must_itself_be_allowed(tmp_path: Path) -> None:
    config = tmp_path / "python-licences.toml"
    config.write_text('[aliases]\n\n[packages]\n"copyleft==1.0" = "GPL-2.0-only"\n')
    result = py_licences(tmp_path, [component("copyleft", "1.0", None)], "--config", str(config))
    assert result.returncode == 1
    assert "copyleft 1.0: 'GPL-2.0-only' is not allowed" in result.stderr


@pytest.mark.req("NFR-11")
def test_python_allowlist_is_read_from_deny_toml(tmp_path: Path) -> None:
    deny = tmp_path / "deny.toml"
    deny.write_text('[licenses]\nallow = ["GPL-3.0-only"]\n')
    components = [
        component("gpl", "1.0", [spdx("GPL-3.0-only")]),
        component("mit", "1.0", [spdx("MIT")]),
    ]
    result = py_licences(tmp_path, components, "--deny", str(deny))
    assert result.returncode == 1
    assert "mit 1.0: 'MIT' is not allowed" in result.stderr
    assert "gpl 1.0" not in result.stderr


@pytest.mark.req("NFR-11")
@pytest.mark.parametrize(
    "text", ["not json", '{"bomFormat": "SPDX"}', '{"bomFormat": "CycloneDX"}']
)
def test_unreadable_sbom_is_a_usage_error(tmp_path: Path, text: str) -> None:
    sbom = tmp_path / "env.cdx.json"
    sbom.write_text(text)
    result = run([sys.executable, str(PY_LICENCES), "--sbom", str(sbom)], cwd=REPO)
    assert result.returncode == 2
    assert f"python_licences: {sbom} is not a CycloneDX JSON document with components" in (
        result.stderr
    )


@pytest.mark.req("NFR-11")
def test_repository_python_environment_licences_pass(tmp_path: Path) -> None:
    cyclonedx = Path(sys.executable).parent / "cyclonedx-py"
    assert cyclonedx.is_file(), "cyclonedx-py is not installed (uv group audit)"
    sbom = tmp_path / "env.cdx.json"
    made = run(
        [
            str(cyclonedx),
            "environment",
            "--pyproject",
            str(REPO / "pyproject.toml"),
            "--output-file",
            str(sbom),
            str(Path(sys.prefix)),
        ],
        cwd=REPO,
    )
    assert made.returncode == 0, made.stderr
    result = run([sys.executable, str(PY_LICENCES), "--sbom", str(sbom)], cwd=REPO)
    assert result.returncode == 0, result.stderr


# --- CycloneDX SBOMs ------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str]:
    """Runs the SBOM generator once; each test checks its outcome (a failure fails the test)."""
    out = tmp_path_factory.mktemp("sbom")
    result = run([sys.executable, str(SBOM), "--out", str(out)], cwd=REPO)
    return out, "" if result.returncode == 0 else f"exit {result.returncode}: {result.stderr}"


def produced(generated: tuple[Path, str]) -> Path:
    out, failure = generated
    assert failure == "", failure
    return out


def bom(path: Path) -> dict[str, Any]:
    assert path.is_file(), f"{path.name} was not produced"
    loaded: dict[str, Any] = json.loads(path.read_text())
    assert loaded["bomFormat"] == "CycloneDX"
    return loaded


def names(document: dict[str, Any]) -> set[str]:
    return {entry["name"] for entry in document.get("components", [])}


@pytest.mark.req("NFR-11")
def test_rust_sbom_per_shipped_crate(generated: tuple[Path, str]) -> None:
    rust = produced(generated) / "rust"
    # Shipped crates live under crates/; test doubles (tests/fakes) are not part of a release.
    assert {path.name for path in rust.iterdir()} == {
        "ostia-contracts.cdx.json",
        "ostia-core-domain.cdx.json",
        "ostia-traceability.cdx.json",
    }
    contracts = bom(rust / "ostia-contracts.cdx.json")
    assert contracts["metadata"]["component"]["name"] == "ostia-contracts"
    assert "prost" in names(contracts)


@pytest.mark.req("NFR-11")
def test_python_sbom_lists_runtime_dependencies_only(generated: tuple[Path, str]) -> None:
    document = bom(produced(generated) / "python" / "ostia-python.cdx.json")
    assert document["metadata"]["component"]["name"] == "ostia"
    found = names(document)
    assert "protobuf" in found
    assert not found & {"pytest", "hypothesis", "mypy", "pip-audit", "cyclonedx-bom", "pip"}


@pytest.mark.req("NFR-11")
def test_sbom_generation_leaves_no_file_in_the_source_tree(generated: tuple[Path, str]) -> None:
    produced(generated)
    status = run(
        [tool("git"), "status", "--porcelain", "--untracked-files=all", "--ignored"], cwd=REPO
    )
    assert status.returncode == 0, status.stderr
    leftovers = [line for line in status.stdout.splitlines() if line.endswith(".cdx.json")]
    assert leftovers == []


# --- just recipes and installed tools -------------------------------------------------------------


def recipe(name: str) -> list[str]:
    result = run([tool("just"), "--show", name], cwd=REPO)
    assert result.returncode == 0, result.stderr
    return [line.strip() for line in result.stdout.splitlines()]


AUDIT_STEPS = [
    "cargo deny --workspace --locked --config deny.toml check",
    "cargo deny --manifest-path fuzz/Cargo.toml --locked --config deny.toml check",
    "cargo audit --deny warnings",
    "cargo audit --deny warnings --file fuzz/Cargo.lock",
    "uv lock --locked",
    (
        "uv export --frozen --all-groups --no-emit-project --format requirements-txt "
        "--output-file target/supply/requirements.txt"
    ),
    (
        "python3 tools/supply/check_pins.py --pyproject pyproject.toml "
        "--requirements target/supply/requirements.txt"
    ),
    (
        "uv run pip-audit --strict --require-hashes --disable-pip "
        "--requirement target/supply/requirements.txt"
    ),
    (
        "uv run cyclonedx-py environment --pyproject pyproject.toml "
        "--output-file target/supply/python-environment.cdx.json .venv"
    ),
    "uv run python tools/supply/python_licences.py --sbom target/supply/python-environment.cdx.json",
    "just sbom",
]


@pytest.mark.req("NFR-11")
def test_audit_recipe_runs_every_supply_chain_gate() -> None:
    lines = recipe("audit")
    for step in AUDIT_STEPS:
        assert step in lines, step


@pytest.mark.req("NFR-11")
def test_sbom_recipe_writes_target_sbom() -> None:
    assert "uv run python tools/supply/sbom.py --out target/sbom" in recipe("sbom")


@pytest.mark.req("NFR-11")
def test_check_runs_the_audit() -> None:
    header = [line for line in recipe("check") if line.startswith("check:")]
    assert len(header) == 1
    assert "audit" in header[0].split()


@pytest.mark.req("NFR-11")
@pytest.mark.parametrize(
    ("variable", "version"),
    [
        ("CARGO_DENY_VERSION", "0.20.2"),
        ("CARGO_AUDIT_VERSION", "0.22.2"),
        ("CARGO_CYCLONEDX_VERSION", "0.5.9"),
    ],
)
def test_cargo_supply_chain_tools_are_pinned(variable: str, version: str) -> None:
    entries = dict(
        line.split("=", 1)
        for line in (REPO / "tools" / "dev" / "versions.env").read_text().splitlines()
        if "=" in line
    )
    assert entries.get(variable) == version
