# 00 — Bootstrap prompt (first Claude Code session)

Paste the block below as the first message in Claude Code, at the root of the new repository,
after the owner has unpacked the kit and made the initial commit (see GUIDE-FR.md).

---

You are starting the Ostia project: an open-source media kiosk ("station blanche"), Rust core and
Python workers, developed strictly test-first along locked acceptance tests. I am the owner,
Matthias. Speak French with me (tu), write everything in the repository in English.

The repository currently holds only the rails kit: `CLAUDE.md`, `AGENTS.md`, `.claude/` (settings,
guard hooks, rules, skills, subagents), `prompts/`, `tools/kit/`, `tools/lock/`, `docs/spec.md`,
`docs/plan.md`, `docs/phase-status.md`, `docs/questions.md`, `.github/`, a starter `justfile` importing
`tools/kit/rails.just`.

Do this, in order, and stop at the end:

1. Read `CLAUDE.md` and `AGENTS.md` fully. Do not read `docs/spec.md` or `docs/plan.md` whole.
2. Verify the rails work:
   - `python3 -m unittest tools/kit/test_kit.py` must pass (some lock-gate tests are skipped
     when pytest is not installed yet; say which).
   - `python3 tools/kit/req.py check` must report 0 dangling references.
   - `python3 tools/lock/ostia_lock.py rails-verify` must report "rails OK".
   - `python3 tools/kit/req.py WP-0.1` prints the first work package.
   - Try to edit `CLAUDE.md` with a harmless change: it must be refused (permission rule or guard hook).
     Then try `echo test >> AGENTS.md` in the shell: the Bash guard must block it. Report both messages.
3. Check the environment and report a table (tool, required, found version, OK/missing):
   git, python3 (≥ 3.12 preferred), uv, rustup/cargo (stable), just, buf, protoc (optional),
   clang/lld (optional), Node.js (≥ 20, needed from P7), pnpm, mkfs.vfat, mkfs.exfat, mkfs.ntfs,
   mkfs.ext4, losetup, ntfs-3g and fuse3 (NTFS alternate data streams need ntfs-3g), exfat-fuse,
   sudo (non-interactive for `tools/dev/` only), bubblewrap (bwrap), clamd,
   The Sleuth Kit (mmls), and whether systemd is PID 1 (WSL `[boot] systemd=true`).
   Also check the kernel can mount exFAT and NTFS read-only (look at `/proc/filesystems` and
   `modinfo exfat ntfs3` without mounting anything). Do not install anything yet: list what is missing
   and the exact `apt`/`curl` commands you would run, and wait for my go.
4. Read `prompts/P0.md`. Summarise in French, in at most 15 lines: the P0 goal, the order of work
   packages you propose, the points where you will need me, and any question you have.
5. Stop and wait for my go before starting WP-0.1 with `/wp-start WP-0.1`.
