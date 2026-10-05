"""Generate the Python code of the ostia.engine.v1 contract (ADR-15).

Usage: gen_python.py [--out DIR] [--check]

Runs the protoc bundled in grpcio-tools (no network, no system protoc) on
proto/ostia/engine/v1/engine.proto and writes `engine_pb2.py` and its typed stub `engine_pb2.pyi`
(mypy-protobuf plugin) to DIR (default: the
committed copy in workers-py/common/src/ostia_common/engine_v1). With --check, compares instead of writing
and fails when the copy in DIR is missing or out of date.
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROTO_ROOT = REPO / "proto"
PROTO = "ostia/engine/v1/engine.proto"
DEFAULT_OUT = REPO / "workers-py" / "common" / "src" / "ostia_common" / "engine_v1"
FILES = ("engine_pb2.py", "engine_pb2.pyi")
# mypy-protobuf's plugin, installed next to this interpreter: its stub passes mypy --strict (Q-20).
MYPY_PLUGIN = Path(sys.executable).parent / "protoc-gen-mypy"


def generate() -> dict[str, bytes]:
    """The generated files, by name."""
    with tempfile.TemporaryDirectory() as tmp:
        command = [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            f"-I{PROTO_ROOT}",
            f"--plugin=protoc-gen-mypy={MYPY_PLUGIN}",
            f"--python_out={tmp}",
            f"--mypy_out={tmp}",
            PROTO,
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"protoc failed: {result.stderr.strip()}")
        generated = Path(tmp) / "ostia" / "engine" / "v1"
        return {name: (generated / name).read_bytes() for name in FILES}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate the Python code of ostia.engine.v1")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    out: Path = args.out
    files = generate()
    if args.check:
        stale = []
        for name, content in files.items():
            if not (out / name).is_file():
                stale.append(f"{name} is missing: run `just proto`")
            elif (out / name).read_bytes() != content:
                stale.append(f"{name} is out of date: run `just proto`")
        for line in stale:
            print(line)
        if stale:
            return 1
        print("generated Python code is up to date")
        return 0
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out / name).write_bytes(content)
    print(f"wrote {', '.join(FILES)} to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
