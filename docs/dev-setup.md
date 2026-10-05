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
the disk-image tests refuse a stale copy.

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
`target/` directory, owned by you, mounts them on `target/mnt/<name>` with `noexec,nosuid,nodev`, and
refuses any `/dev/...` path.

## 3. User-level tools (once, as your user)

```bash
curl --proto '=https' --tlsv1.2 -sSfo /tmp/rustup-init.sh https://sh.rustup.rs
sh /tmp/rustup-init.sh -y --default-toolchain none --profile minimal
curl --proto '=https' --tlsv1.2 -LsSfo /tmp/uv-install.sh "https://astral.sh/uv/0.12.22/install.sh"
sh /tmp/uv-install.sh
uv tool install rust-just==1.58.0
cargo install --locked cargo-nextest@0.9.146 cargo-llvm-cov@0.9.1
uv sync
uvx pre-commit@4.6.2 install --hook-type pre-commit --hook-type commit-msg
```

Read the two installer scripts before running them. Keep the versions in step with `tools/dev/versions.env`.
Make `~/.cargo/bin` and `~/.local/bin` visible to non-interactive shells too (for example
`. "$HOME/.cargo/env"` at the top of `~/.bashrc`).

## 4. Check

```bash
tools/dev/setup-debian.sh --check
```

It lists every tool with its version, the loop devices, how each file system is mounted (kernel driver or
FUSE), the helper copy and the sudoers rule, and ends with `environment OK` or `environment incomplete`.

## WSL notes

- The stock WSL kernel has no exFAT or NTFS module. The helper then mounts those images with the FUSE
  drivers `exfat-fuse` and `ntfs-3g` (installed by step 1); the kernel drivers are exercised in CI and on
  the Debian bench (phases 4 and 5).
- systemd should be PID 1: `[boot] systemd=true` in `/etc/wsl.conf`.
- USB devices are not used before phase 4; they need the dedicated Debian machine (spec §19).

## Dev container

Open the repository in a dev container (VS Code "Reopen in Container", or `devcontainer up`). It runs as
root with `--privileged`, like the CI container, so the disk-image tests run there without sudo.
