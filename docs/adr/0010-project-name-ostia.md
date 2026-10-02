# ADR-10: Project name "Ostia" (working name)

- Status: accepted (working name; trademark search pending)
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §2

## Context and problem statement

The project needs a name for the repository, the binaries (`ostia`), the Protobuf package
(`ostia.engine.v1`) and the documentation, before any trademark search is done.

## Decision drivers

- Short, pronounced the same in most languages.
- Not already used by security products.
- Meaning tied to the product: a controlled entry point.

## Considered options

1. "Ostia": the Roman port, from Latin *ostium*, the door; two syllables read the same in most languages.
2. "Lazaret".
3. "Pratique".
4. "Kordon", "Cordon", "Vigil".

## Decision outcome

Chosen option 1, as a **working name until a trademark search is done**. "Lazaret" and "Pratique" are
too French; "Lazaret", "Kordon", "Cordon" and "Vigil" are already used by security projects (spec §2,
§22 sources).

## Consequences

- Good: a stable name for code identifiers from phase 0.
- Bad: renaming after the search would touch crate names, the binary, the Protobuf package and the docs.
- Follow-up: open question "Confirm the name after a trademark search, or pick another" (spec §21;
  docs/questions.md Q-1).

## Links

- Related: none.
