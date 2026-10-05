# Development setup

Ostia is developed on WSL2 (Debian stable, or Ubuntu LTS) and targets Debian stable x86-64 (NFR-15).
CI runs the same checks in a `debian:13` container; `.devcontainer/` builds the same environment locally.
Debian packages come from `tools/dev/packages.txt`; tool versions from `tools/dev/versions.env` and
`rust-toolchain.toml`.

## 1. System packages and the mount helper (once, as root)

```bash
sudo tools/dev/setup-debian.sh --install
```

This installs `tools/dev/packages.txt` with apt and copies `tools/dev/loopmount.sh` to
`/usr/local/sbin/ostia-loopmount` (owned by root, mode 0755). Run it again after `loopmount.sh` changes:
the disk-image tests refuse a stale copy. It then checks only the system part (root has no user-level
`PATH`) and ends with `system part OK; now run tools/dev/setup-debian.sh --check as your user`.

## 2. Sudoers rule for the mount helper (once, as root)

The disk-image tests mount images through the helper with `sudo -n`. Allow exactly that copy, for your
user only:

```bash
sudo visudo -f /etc/sudoers.d/ostia
```

and write this single line (replace `alice` with your user name):

```text
alice ALL=(root) NOPASSWD: /usr/local/sbin/ostia-loopmount
```

The rule names the root-owned copy, never the script in the repository: a sudoers rule on a file your
user can edit would amount to unrestricted root. The helper accepts only regular image files under a
`target/` directory and owned by you; it opens the image once and works on that open file, refuses any
`/dev/...` path, and mounts on `/run/ostia-loopmount/<your uid>/<name>` (directories owned by root) with
`noexec,nosuid,nodev`, plus `ro` on a read-only loop device for scan mounts:

```bash
tools/dev/mkimage.sh ext4 16 target/demo.img
sudo -n /usr/local/sbin/ostia-loopmount ro "$PWD/target/demo.img" demo
ls /run/ostia-loopmount/$(id -u)/demo
sudo -n /usr/local/sbin/ostia-loopmount umount demo
```

Residual risk, accepted for development: root parses the images you give it (libblkid, then the kernel
or FUSE file-system driver), so a crafted image that exploits one of those parsers would give root to
your account. Keep the sudoers rule on development machines only. The production mount helper (WP-4.5)
is a separate, minimal, fuzzed binary.

## 3. User-level tools (once, as your user)

```bash
. tools/dev/versions.env
curl --proto '=https' --tlsv1.2 -sSfo /tmp/rustup-init.sh https://sh.rustup.rs
sh /tmp/rustup-init.sh -y --default-toolchain none --profile minimal
rustup toolchain install
curl --proto '=https' --tlsv1.2 -LsSfo /tmp/uv-install.sh "https://astral.sh/uv/${UV_VERSION}/install.sh"
sh /tmp/uv-install.sh
uv tool install "rust-just==${JUST_VERSION}"
cargo install --locked "cargo-nextest@${NEXTEST_VERSION}" cargo-llvm-cov@0.9.1
rustup toolchain install "${NIGHTLY_TOOLCHAIN}" --profile minimal   # fuzzing only (WP-0.6)
cargo install --locked "cargo-fuzz@${CARGO_FUZZ_VERSION}"
uv sync
uvx pre-commit@4.6.2 install --hook-type pre-commit --hook-type commit-msg
```

Read the two installer scripts before running them. The pinned versions live in `tools/dev/versions.env`
and `rust-toolchain.toml`; `--check` reports any other version as `wrong version`. `cargo-llvm-cov` and
`pre-commit` are pinned on this page only; `--check` does not verify them.
Make `~/.cargo/bin` and `~/.local/bin` visible to non-interactive shells too (for example
`. "$HOME/.cargo/env"` at the top of `~/.bashrc`).

## 4. Check

```bash
tools/dev/setup-debian.sh --check
```

It lists every tool with its version, the loop devices, how each file system is mounted (kernel driver or
FUSE), the helper copy and the sudoers rule, and ends with `environment OK` or `environment incomplete`.

## 5. Fuzzing (NFR-06)

`just test-fuzz` runs the fuzz suite: the frame decoder target for `FUZZ_SECONDS` seconds (default 60, at
most 5 s per input), the harness self-test (a crash and a hang planted after decoding must be reported) and
the regression inputs. `just fuzz 3600` fuzzes longer and grows `fuzz/corpus/frame_decoder` (git-ignored).
CI runs `just test-fuzz` on every push and pull request, and for 30 minutes every night
(`.github/workflows/fuzz-nightly.yml`, which uploads any crash or timeout input as `fuzz-artifacts`).
A crash input goes into `fuzz/regressions/` as a `.hex` file (hex digits, `#` comments); add its name and
expected outcome to `crates/contracts/tests/fuzz_regressions.rs` and
`workers-py/common/tests/test_fuzz_regressions.py`, which replay it on every `just test` (they fail until
the new file is listed).

## WSL notes

- The stock WSL kernel has no exFAT or NTFS module. The helper then mounts those images with the FUSE
  drivers `exfat-fuse` and `ntfs-3g` (installed by step 1). Which driver was used is printed by the
  helper (`kernel driver` or `fuse driver`); in CI it depends on the modules of the runner's kernel. The
  production kernel path is checked on the Debian bench (phases 4 and 5).
- systemd should be PID 1: `[boot] systemd=true` in `/etc/wsl.conf`.
- USB devices are not used before phase 4; they need the dedicated Debian machine (spec §19).

## Dev container

Open the repository in a dev container (VS Code "Reopen in Container", or `devcontainer up`). It runs as
root with `--privileged`, like the CI container, so the disk-image tests run there without sudo.
