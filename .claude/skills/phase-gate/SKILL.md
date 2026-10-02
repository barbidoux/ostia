---
name: phase-gate
description: Collect the evidence for an Ostia phase exit gate (plan §14) and draft the gate report and retrospective. The owner reviews and ticks the gate; this skill never ticks it.
argument-hint: P<n>
disable-model-invocation: true
---

# Gate evidence for $ARGUMENTS

Produce `docs/gates/$ARGUMENTS.md` (create `docs/gates/` if needed) on a branch `gate/<phase lowercase>`,
with one section per checklist item of plan §14 and the evidence for it. Run every command yourself
and paste the relevant output; write "NOT RUN" with the reason when you cannot run something.
Never write that a check passed if you did not see it pass.

1. **Acceptance tests unchanged and passing.** `python3 tools/lock/ostia_lock.py verify --require-tags`,
   then `python3 tools/lock/ostia_lock.py gate <dir>` for the phase's own acceptance directory
   (P0 has none: its evidence is that `p1` is locked and tagged). For P4 and P5 the gate must run on the
   Debian bench: ask the owner to run it there and paste the output.
2. **Traceability.** `just trace`: every MUST requirement of the phase (`python3 tools/kit/req.py phase $ARGUMENTS`)
   has at least one passing test. List any gap.
3. **Coverage.** Thresholds of NFR-14 on code touched by the phase (Rust ≥ 90 %, Python ≥ 85 % unless the
   spec says otherwise): `just coverage`.
4. **Static analysis, advisories, licences.** `just lint`, `just audit` — zero warnings, zero advisories,
   no licence outside the allowlist.
5. **Fuzzing.** Nightly campaign results for the phase's fuzz targets; open crashes = gate fails.
6. **Performance budgets** of the phase on the reference machine (which one, measured how).
7. **Decision records** for every choice made in the phase (list ADRs added or changed, with status).
8. **Spec changes.** If the phase changed a requirement, the spec version was bumped by the owner and
   the affected packages re-planned. List them or write "none".
9. **Next phase locked.** `tests/acceptance/<next>/LOCK.sha256` exists and tag `lock-<next>` exists.
10. **Retrospective draft.** Sessions per package (from git history and notes), median per size S and M,
    surprises, plan adjustments proposed, questions still open in `docs/questions.md`.

End the report with a summary table (item, status PASS/FAIL/NOT RUN, evidence link) and a list of what
blocks the gate. Commit `docs($ARGUMENTS): gate evidence`, then tell the owner the report is ready.
The owner ticks the gate in `docs/phase-status.md` and in the gate issue, and changes "Current phase".
