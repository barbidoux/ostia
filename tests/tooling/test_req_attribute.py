"""The Rust `#[req("ID", ...)]` attribute (crates/traceability): placed above `#[test]`, it checks the format
of each requirement id at compile time and makes the test print one `ostia-req: <ids>` line, which the
nextest JUnit report keeps (.config/nextest.toml) for the traceability matrix.

Each test builds a throwaway crate, with the repository lints, that depends on crates/traceability.
"""

import os
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from tooling_support import REPO, cargo, make_workspace, run

TRACEABILITY = REPO / "crates" / "traceability"
PLACEMENT = "#[req] goes on a test function, above its #[test] attribute"


def crate_with_tests(tmp_path: Path, attribute: str, item: str | None = None) -> Path:
    if item is None:
        item = f"""{attribute}
    #[test]
    fn answer_is_forty_two() {{
        assert_eq!(super::answer(), 42);
    }}"""
    lib = f"""//! Sample crate using the req attribute.

/// The answer.
#[must_use]
pub fn answer() -> u32 {{
    42
}}

#[cfg(test)]
mod tests {{
    use ostia_traceability::req;

    {item}
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


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    "item",
    [
        '#[test]\n    #[req("FR-06")]\n    fn answer_is_forty_two() {}',
        '#[req("FR-06")]\n    fn helper() {}\n\n    #[test]\n    fn answer_is_forty_two() { helper(); }',
        '#[req("FR-06")]\n    mod inner {}\n\n    #[test]\n    fn answer_is_forty_two() {}',
        '#[req("FR-06")]\n    struct Marker;\n\n    #[test]\n    fn answer_is_forty_two() {}',
    ],
    ids=["below #[test]", "on a helper function", "on a module", "on a struct"],
)
def test_req_outside_a_test_function_is_a_compile_error(tmp_path: Path, item: str) -> None:
    result = cargo(crate_with_tests(tmp_path, "", item), "test", "--quiet")
    assert result.returncode != 0
    assert PLACEMENT in result.stderr


@pytest.mark.req("TOOLING")
def test_tests_written_through_a_macro_keep_their_tag(tmp_path: Path) -> None:
    # proptest! (and any macro_rules taking `$(#[$m:meta])*`) passes #[test] as an opaque fragment.
    item = """macro_rules! passthrough {
        ($(#[$m:meta])* fn $name:ident() $body:block) => { $(#[$m])* fn $name() $body };
    }

    passthrough! {
        #[req("FR-06")]
        #[test]
        fn answer_is_forty_two() {
            assert_eq!(super::answer(), 42);
        }
    }"""
    result = cargo(crate_with_tests(tmp_path, "", item), "test", "--quiet", "--", "--nocapture")
    assert result.returncode == 0, result.stderr
    assert "1 passed" in result.stdout
    assert "ostia-req: FR-06" in result.stdout.splitlines()


@pytest.mark.req("TOOLING")
def test_a_body_starting_with_an_inner_attribute_compiles(tmp_path: Path) -> None:
    item = """#[req("FR-06")]
    #[test]
    fn answer_is_forty_two() {
        #![allow(clippy::unreadable_literal)]
        assert_eq!(super::answer() * 100_000, 4200000);
    }"""
    result = cargo(crate_with_tests(tmp_path, "", item), "test", "--quiet")
    assert result.returncode == 0, result.stderr
    assert "1 passed" in result.stdout


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("threads", [None, "1"], ids=["default threads", "one test thread"])
def test_nextest_report_keeps_the_ids_of_each_test(tmp_path: Path, threads: str | None) -> None:
    # With one test thread, libtest prints "test <name> ... " before the test's own output, on the
    # same line: the marker must still be a line of its own.
    item = """#[req("FR-06", "SEC-10")]
    #[test]
    fn answer_is_forty_two() {
        assert_eq!(super::answer(), 42);
    }

    mod inner {
        use ostia_traceability::req;

        #[req("TOOLING")]
        #[test]
        #[should_panic(expected = "a]")]
        fn answer_is_forty_two() {
            panic!("a]");
        }
    }"""
    workspace = crate_with_tests(tmp_path, "", item)
    (workspace / ".config").mkdir()
    shutil.copyfile(REPO / ".config" / "nextest.toml", workspace / ".config" / "nextest.toml")
    env = {**os.environ, "CARGO_TERM_COLOR": "never"}
    if threads:
        env["RUST_TEST_THREADS"] = threads
    result = run(["cargo", "nextest", "run", "--profile", "ci"], cwd=workspace, env=env)
    assert result.returncode == 0, result.stderr
    cases = {
        (case.get("classname"), case.get("name")): case.findtext("system-out", "")
        for case in ET.parse(workspace / "target/nextest/ci/junit.xml").getroot().iter("testcase")
    }
    assert set(cases) == {
        ("sample", "tests::answer_is_forty_two"),
        ("sample", "tests::inner::answer_is_forty_two"),
    }
    markers = {
        name: [line for line in out.splitlines() if line.startswith("ostia-req:")]
        for (_, name), out in cases.items()
    }
    assert markers == {
        "tests::answer_is_forty_two": ["ostia-req: FR-06,SEC-10"],
        "tests::inner::answer_is_forty_two": ["ostia-req: TOOLING"],
    }
