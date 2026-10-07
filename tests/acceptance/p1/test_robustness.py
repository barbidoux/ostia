"""NFR-05: no file can stop the orchestrator. An engine that crashes, is killed by a signal, writes garbage or
hangs past the policy's engine timeout yields UNSCANNABLE (R1) for that object; the engine keeps serving the
other objects and the scan completes."""

import time
from dataclasses import dataclass

import pytest
from common import (
    Planted,
    Scan,
    build_image,
    fake_engine_config,
    on_sha256,
    policy_document,
    scan,
    sha256,
    text_bytes,
    write_signed_policy,
)

ENGINES = {"av": {"role": "detector", "trusted_alone": False}}
# Long enough for a normal fake-engine run under load; far below the hang and the default 30 s.
ENGINE_TIMEOUT = 5
HANG_MS = 120_000


@dataclass(frozen=True)
class Fault:
    name: str
    action: dict[str, object]
    status: str

    def planted(self) -> Planted:
        return Planted(self.name, text_bytes(f"engine fault {self.name}"))


FAULTS = [
    Fault("crash-exit.txt", {"crash": {"exit_code": 3}}, "ERROR"),
    Fault("crash-segv.txt", {"signal": "SIGSEGV"}, "ERROR"),
    Fault("crash-kill.txt", {"signal": "SIGKILL"}, "ERROR"),
    Fault("crash-abort.txt", {"signal": "SIGABRT"}, "ERROR"),
    Fault("garbage.txt", {"garbage": "deadbeef00ff"}, "ERROR"),
    Fault("hang.txt", {"delay_ms": HANG_MS, "status": "OK", "hint": "CLEAN"}, "TIMEOUT"),
]
HEALTHY = Planted("healthy.txt", text_bytes("the engine answers normally"))


@dataclass
class Timed:
    scan: Scan
    elapsed: float


@pytest.fixture(scope="module")
def faults(tmp_path_factory: pytest.TempPathFactory) -> Timed:
    work = tmp_path_factory.mktemp("robustness")
    files = [fault.planted() for fault in FAULTS] + [HEALTHY]
    image = build_image("ext4", files)
    rules = [on_sha256(sha256(f.planted().content), **f.action) for f in FAULTS]
    engine = fake_engine_config(work, "av", default={"status": "OK", "hint": "CLEAN"}, rules=rules)
    document = policy_document(ENGINES, limits={"engine_timeout_seconds": ENGINE_TIMEOUT})
    policy = write_signed_policy(work / "policy", document)
    started = time.monotonic()
    found = scan(work / "scan", image, policy, [engine], timeout=300)
    return Timed(found, time.monotonic() - started)


def name(fault: Fault) -> str:
    return fault.name


@pytest.mark.req("NFR-05")
@pytest.mark.parametrize("fault", FAULTS, ids=name)
def test_faulty_engine_run_makes_the_object_unscannable(faults: Timed, fault: Fault) -> None:
    listed = faults.scan.file(fault.name)
    assert (listed["verdict"], listed["rule"]) == ("UNSCANNABLE", "R1")
    assert listed["contributing_engines"] == ["av"]


@pytest.mark.req("NFR-05")
@pytest.mark.parametrize("fault", FAULTS, ids=name)
def test_faulty_engine_run_is_recorded_with_its_status(faults: Timed, fault: Fault) -> None:
    result = faults.scan.engine_result(faults.scan.file(fault.name), "av")
    assert (result["engine_id"], result["status"]) == ("av", fault.status)


@pytest.mark.req("NFR-05")
def test_engine_keeps_serving_after_faults(faults: Timed) -> None:
    healthy = faults.scan.file("healthy.txt")
    assert faults.scan.engine_result(healthy, "av")["status"] == "OK"
    assert (healthy["verdict"], healthy["rule"]) == ("CLEAN", "R7")


@pytest.mark.req("NFR-05")
def test_scan_completes_despite_faulty_engines(faults: Timed) -> None:
    assert faults.scan.result.returncode == 0, faults.scan.result.stderr
    assert len(faults.scan.files()) == len(FAULTS) + 1


@pytest.mark.req("NFR-05")
def test_hung_engine_is_stopped_at_its_timeout(faults: Timed) -> None:
    # The hang lasts 120 s and the policy timeout is 5 s: a scan that honoured another timeout (the
    # 30 s of a default policy, say) would take longer than this bound.
    assert faults.scan.result.returncode == 0, faults.scan.result.stderr
    assert faults.elapsed < 25
