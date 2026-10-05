"""The Rust `#[req("ID", ...)]` attribute (crates/traceability): a pass-through attribute that checks the
format of each requirement id at compile time.

Each test builds a throwaway crate, with the repository lints, that depends on crates/traceability.
"""

from pathlib import Path

import pytest

from tooling_support import REPO, cargo, make_workspace

TRACEABILITY = REPO / "crates" / "traceability"


def crate_with_tests(tmp_path: Path, attribute: str) -> Path:
    lib = f"""//! Sample crate using the req attribute.

/// The answer.
#[must_use]
pub fn answer() -> u32 {{
    42
}}

#[cfg(test)]
mod tests {{
    use ostia_traceability::req;

    {attribute}
    #[test]
    fn answer_is_forty_two() {{
        assert_eq!(super::answer(), 42);
    }}
}}
"""
    workspace = make_workspace(tmp_path, lib)
    manifest = workspace / "sample" / "Cargo.toml"
    assert (TRACEABILITY / "Cargo.toml").is_file(), "crates/traceability is missing"
    manifest.write_text(
        manifest.read_text()
        + f'\n[dev-dependencies]\nostia-traceability = {{ path = "{TRACEABILITY}" }}\n'
    )
    return workspace


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    "attribute",
    [
        '#[req("FR-06")]',
        '#[req("NFR-09")]',
        '#[req("TOOLING")]',
        '#[req("FR-06", "SEC-10", "CTR-03")]',
        '#[req("DEEP-09")]',
    ],
    ids=["functional", "non-functional", "tooling", "several ids", "four-letter family"],
)
def test_valid_ids_compile_and_the_test_still_runs(tmp_path: Path, attribute: str) -> None:
    result = cargo(crate_with_tests(tmp_path, attribute), "test", "--quiet")
    assert result.returncode == 0, result.stderr
    assert "1 passed" in result.stdout


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("attribute", "message"),
    [
        ('#[req("FR-6")]', 'invalid requirement id "FR-6"'),
        ('#[req("fr-06")]', 'invalid requirement id "fr-06"'),
        ('#[req("XYZ-01")]', 'invalid requirement id "XYZ-01"'),
        ('#[req("")]', 'invalid requirement id ""'),
        ('#[req("FR-06", "FR-100")]', 'invalid requirement id "FR-100"'),
        ("#[req]", "#[req] needs at least one requirement id"),
        ("#[req()]", "#[req] needs at least one requirement id"),
        ("#[req(FR_06)]", "#[req] takes string literals"),
    ],
    ids=[
        "one digit",
        "lower case",
        "unknown family",
        "empty",
        "three digits after a valid id",
        "no arguments",
        "empty parentheses",
        "not a literal",
    ],
)
def test_invalid_ids_are_compile_errors(tmp_path: Path, attribute: str, message: str) -> None:
    result = cargo(crate_with_tests(tmp_path, attribute), "test", "--quiet")
    assert result.returncode != 0
    assert message in result.stderr
