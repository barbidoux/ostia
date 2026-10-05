"""The fuzz regression inputs (fuzz/regressions/*.hex) give the Python decoder the same outcome as the Rust
one (crates/contracts/tests/fuzz_regressions.rs) and never raise anything but ContractError (NFR-06, CTR-02).
"""

from pathlib import Path

import pytest

from ostia_common.framing import ContractError, decode_frame, decode_request, decode_response

REGRESSIONS = Path(__file__).resolve().parents[3] / "fuzz" / "regressions"
EXPECTED = {
    "group_storm.hex": "ok",
    "oversized_header.hex": "oversized",
    "varint_overflow.hex": "malformed",
}


def unhex(path: Path) -> bytes:
    lines = path.read_text().splitlines()
    return bytes.fromhex("".join(line for line in lines if not line.lstrip().startswith("#")))


@pytest.mark.req("NFR-06", "CTR-02")
def test_regression_inputs_give_the_rust_outcomes() -> None:
    inputs = {path.name: unhex(path) for path in sorted(REGRESSIONS.glob("*.hex"))}
    assert sorted(inputs) == sorted(EXPECTED)
    for name, data in inputs.items():
        for decode in (decode_request, decode_response):
            try:
                decode(data)
            except ContractError:
                pass
        try:
            decode_response(decode_frame(data))
            outcome = "ok"
        except ContractError as error:
            outcome = error.kind
        assert outcome == EXPECTED[name], name
