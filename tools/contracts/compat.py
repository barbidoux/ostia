"""CTR-04: check that ostia.engine.v1 still holds every field and enum value of its frozen v1 shape.

Usage: compat.py [--snapshot proto/ostia/engine/v1/compat.json]

Compares the snapshot with the descriptors of the generated Python code (kept in sync with the .proto by
tools/contracts/gen_python.py --check). Every message, field (number, name, type, label) and enum value of
the snapshot must exist unchanged; additions are allowed. A breaking change needs a new major package.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from google.protobuf.descriptor import Descriptor, FieldDescriptor, FileDescriptor

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "workers-py" / "common" / "src"))

from ostia_common.engine_v1 import engine_pb2

SNAPSHOT = REPO / "proto" / "ostia" / "engine" / "v1" / "compat.json"
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check ostia.engine.v1 against its v1 snapshot")
    parser.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    args = parser.parse_args(argv)
    snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    problems = check(snapshot, engine_pb2.DESCRIPTOR)
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
