"""CTR-04: check that ostia.engine.v1 still holds every field and enum value of its frozen v1 shape.

Usage: compat.py [--snapshot FILE] [--base REF | --base-snapshot FILE]

Compares the snapshot with the descriptors of the generated Python code (kept in sync with the .proto by
tools/contracts/gen_python.py --check): every message, field (number, name, type, label) and enum value of
the snapshot must exist unchanged, and every current one must be in the snapshot. Then compares the snapshot
with its copy at the merge base of the base branch (default origin/main, read with git; CI checks out the
full history) and HEAD: entries
can only be added, so a field cannot leave the .proto and the snapshot in the same change. A breaking change
needs a new major package.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from google.protobuf.descriptor import Descriptor, FieldDescriptor, FileDescriptor

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "workers-py" / "common" / "src"))

from ostia_common.engine_v1 import engine_pb2

SNAPSHOT = REPO / "proto" / "ostia" / "engine" / "v1" / "compat.json"
SNAPSHOT_PATH = "proto/ostia/engine/v1/compat.json"
SCALARS = {
    FieldDescriptor.TYPE_DOUBLE: "double",
    FieldDescriptor.TYPE_FLOAT: "float",
    FieldDescriptor.TYPE_INT64: "int64",
    FieldDescriptor.TYPE_UINT64: "uint64",
    FieldDescriptor.TYPE_INT32: "int32",
    FieldDescriptor.TYPE_UINT32: "uint32",
    FieldDescriptor.TYPE_BOOL: "bool",
    FieldDescriptor.TYPE_STRING: "string",
    FieldDescriptor.TYPE_BYTES: "bytes",
}


def field_shape(field: FieldDescriptor) -> list[str]:
    """[name, type, label] as written in compat.json."""
    if field.message_type is not None:
        kind = f"message {field.message_type.name}"
    elif field.enum_type is not None:
        kind = f"enum {field.enum_type.name}"
    else:
        kind = SCALARS.get(field.type, f"type {field.type}")
    if field.is_repeated:
        label = "repeated"
    elif field.has_presence and field.type != FieldDescriptor.TYPE_MESSAGE:
        label = "optional"
    else:
        label = ""
    return [field.name, kind, label]


def describe(shape: list[str]) -> str:
    return ", ".join(part for part in shape if part)


def check_message(name: str, expected: dict[str, list[str]], message: Descriptor) -> list[str]:
    problems = []
    for number, shape in expected.items():
        field = message.fields_by_number.get(int(number))
        if field is None:
            problems.append(f"{name} field {number} ({shape[0]}) is missing")
        elif field_shape(field) != shape:
            current = describe(field_shape(field))
            problems.append(f"{name} field {number} is {current}; v1 has {describe(shape)}")
    return problems


def check(snapshot: dict[str, Any], descriptor: FileDescriptor) -> list[str]:
    """Every breaking difference between the snapshot and the descriptor."""
    problems = []
    if descriptor.package != snapshot["package"]:
        problems.append(
            f"package is {descriptor.package}; the snapshot is for {snapshot['package']}"
        )
    for name, fields in snapshot["messages"].items():
        message = descriptor.message_types_by_name.get(name)
        if message is None:
            problems.append(f"message {name} is missing")
        else:
            problems += check_message(name, fields, message)
    for name, values in snapshot["enums"].items():
        enum = descriptor.enum_types_by_name.get(name)
        if enum is None:
            problems.append(f"enum {name} is missing")
            continue
        for number, value_name in values.items():
            value = enum.values_by_number.get(int(number))
            if value is None:
                problems.append(f"{name} value {number} ({value_name}) is missing")
            elif value.name != value_name:
                problems.append(f"{name} value {number} is {value.name}; v1 has {value_name}")
    return problems


def unfrozen(snapshot: dict[str, Any], descriptor: FileDescriptor) -> list[str]:
    """Current messages, fields, enums and enum values missing from the snapshot."""
    problems = []
    for name, message in descriptor.message_types_by_name.items():
        frozen = snapshot["messages"].get(name)
        if frozen is None:
            problems.append(f"message {name} is not frozen in compat.json")
            continue
        for field in message.fields:
            if str(field.number) not in frozen:
                problems.append(
                    f"{name} field {field.number} ({field.name}) is not frozen in compat.json"
                )
    for name, enum in descriptor.enum_types_by_name.items():
        frozen_values = snapshot["enums"].get(name)
        if frozen_values is None:
            problems.append(f"enum {name} is not frozen in compat.json")
            continue
        for value in enum.values:
            if str(value.number) not in frozen_values:
                problems.append(
                    f"{name} value {value.number} ({value.name}) is not frozen in compat.json"
                )
    return problems


def dropped(snapshot: dict[str, Any], base: dict[str, Any]) -> list[str]:
    """Entries of the base snapshot that the snapshot no longer holds unchanged."""
    problems = []
    for name, fields in base["messages"].items():
        current = snapshot["messages"].get(name, {})
        for number, shape in fields.items():
            if current.get(number) != shape:
                problems.append(
                    f"compat.json drops {name} field {number} ({shape[0]}) frozen on the base"
                )
    for name, values in base["enums"].items():
        current_values = snapshot["enums"].get(name, {})
        for number, value_name in values.items():
            if current_values.get(number) != value_name:
                problems.append(
                    f"compat.json drops {name} value {number} ({value_name}) frozen on the base"
                )
    return problems


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=False)


def base_snapshot(ref: str) -> tuple[dict[str, Any] | None, str]:
    """The snapshot at the merge base of `ref` and HEAD (None before the first version) and that commit.

    The merge base, not the tip of `ref`: entries added on `ref` after this branch forked are not
    "dropped" by it. Any git failure other than "the file does not exist there" is an error.
    """
    resolved = git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    if resolved.returncode != 0:
        raise ValueError(f"cannot read the base snapshot at {ref}: unknown revision")
    commit = resolved.stdout.strip()
    merge_base = git("merge-base", commit, "HEAD")
    base = merge_base.stdout.strip() if merge_base.returncode == 0 else commit
    listed = git("ls-tree", "--name-only", base, "--", SNAPSHOT_PATH)
    if listed.returncode != 0:
        raise ValueError(f"cannot read the base snapshot at {ref}: {listed.stderr.strip()}")
    if not listed.stdout.strip():
        return None, base
    shown = git("show", f"{base}:{SNAPSHOT_PATH}")
    if shown.returncode != 0:
        raise ValueError(f"cannot read the base snapshot at {ref}: {shown.stderr.strip()}")
    document: dict[str, Any] = json.loads(shown.stdout)
    return document, base


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check ostia.engine.v1 against its v1 snapshot")
    parser.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    bases = parser.add_mutually_exclusive_group()
    bases.add_argument("--base", default="origin/main", help="git revision of the base snapshot")
    bases.add_argument("--base-snapshot", type=Path, help="base snapshot file (instead of git)")
    args = parser.parse_args(argv)
    snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    try:
        if args.base_snapshot is not None:
            base = json.loads(Path(args.base_snapshot).read_text(encoding="utf-8"))
        else:
            base, commit = base_snapshot(args.base)
            if base is None:
                print(f"compat: no compat.json at the base ({commit[:12]}) yet: first version")
    except (OSError, ValueError) as error:
        print(f"compat: {error}")
        print("ostia.engine.v1 breaks compat.json: a breaking change needs a new major")
        return 1
    problems = check(snapshot, engine_pb2.DESCRIPTOR)
    problems += unfrozen(snapshot, engine_pb2.DESCRIPTOR)
    if base is not None:
        problems += dropped(snapshot, base)
    for problem in problems:
        print(f"compat: {problem}")
    if problems:
        print("ostia.engine.v1 breaks compat.json: a breaking change needs a new major")
        return 1
    messages, enums = len(snapshot["messages"]), len(snapshot["enums"])
    print(f"ostia.engine.v1 is compatible with compat.json ({messages} messages, {enums} enums)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
