#!/usr/bin/env bash
# Development environment for Ostia on Debian stable (or WSL2 Debian/Ubuntu).
#
#   setup-debian.sh [--check]   verify every tool, its version, loop devices and file-system support
#   setup-debian.sh --install   as root: install tools/dev/packages.txt with apt, install the root-owned
#                               mount helper /usr/local/sbin/ostia-loopmount, then check the system part
#                               (root has no user-level PATH: the user runs --check afterwards)
#
# --install is idempotent and is run by the owner (`sudo tools/dev/setup-debian.sh --install`), never by
# an agent. User-level tools (rustup, cargo, uv, just, cargo-nextest, cargo-fuzz,
# cargo-deny, cargo-audit, cargo-cyclonedx) are installed as in docs/dev-setup.md.
# OSTIA_AS_USER=1 checks the helper and sudoers rule even when running as root (it only adds checks).
# Test hooks, honoured only with OSTIA_TEST_HOOKS=1: OSTIA_EXTRA_PATH, OSTIA_PROC_FILESYSTEMS,
# OSTIA_LOOP_CONTROL, OSTIA_HELPER (so a stray variable cannot make --check report a false OK).
set -uo pipefail

script_dir="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
repo="$(cd "$script_dir/../.." && pwd)"
if [[ "${OSTIA_TEST_HOOKS:-}" == 1 ]]; then
    PATH="$PATH${OSTIA_EXTRA_PATH-:/usr/sbin:/sbin}"
    proc_filesystems="${OSTIA_PROC_FILESYSTEMS:-/proc/filesystems}"
    loop_control="${OSTIA_LOOP_CONTROL:-/dev/loop-control}"
    helper="${OSTIA_HELPER:-/usr/local/sbin/ostia-loopmount}"
else
    PATH="$PATH:/usr/sbin:/sbin"
    proc_filesystems=/proc/filesystems
    loop_control=/dev/loop-control
    helper=/usr/local/sbin/ostia-loopmount
fi
readonly MIN_PYTHON_MINOR=12

# tool:package:version arguments
APT_TOOLS=(
    "git:git:--version" "curl:curl:--version" "python3:python3:--version" "gcc:build-essential:--version"
    "mkfs.vfat:dosfstools:@package" "mkfs.exfat:exfatprogs:-V" "mkfs.ntfs:ntfs-3g:--version"
    "mkfs.ext4:e2fsprogs:-V" "debugfs:e2fsprogs:-V" "losetup:mount:--version" "blkid:util-linux:--version"
    "findmnt:util-linux:--version" "setpriv:util-linux:--version" "ntfs-3g:ntfs-3g:--version"
    "mount.exfat-fuse:exfat-fuse:-V" "fusermount3:fuse3:-V" "bwrap:bubblewrap:--version"
    "clamd:clamav-daemon:--version" "mmls:sleuthkit:-V"
)
USER_TOOLS=("rustup:--version" "rustc:--version" "cargo:--version" "uv:--version" "just:--version"
    "cargo-nextest:nextest --version" "cargo-fuzz:--version" "cargo-deny:--version" "cargo-audit:--version"
    "cargo-cyclonedx:cyclonedx --version")

# Pinned versions: tools/dev/versions.env and the channel of rust-toolchain.toml.
declare -A PINNED=()
while IFS='=' read -r key value; do
    [[ "$key" =~ ^[A-Z_]+$ ]] && PINNED["$key"]="$value"
done <"$script_dir/versions.env"
PINNED[RUST]="$(sed -n 's/^channel *= *"\([0-9.]*\)".*/\1/p' "$repo/rust-toolchain.toml")"
declare -A PIN_OF=([uv]=UV_VERSION [just]=JUST_VERSION [cargo-nextest]=NEXTEST_VERSION [cargo-fuzz]=CARGO_FUZZ_VERSION
    [cargo-deny]=CARGO_DENY_VERSION [cargo-audit]=CARGO_AUDIT_VERSION [cargo-cyclonedx]=CARGO_CYCLONEDX_VERSION [rustc]=RUST)

is_root() { [[ "$(id -u)" == 0 ]]; }
# file system:kernel module:FUSE helper, as tools/dev/loopmount.sh mounts them (ADR-17: NTFS only through
# ntfs-3g, no kernel module)
FILE_SYSTEMS=("vfat:vfat:" "exfat:exfat:mount.exfat-fuse" "ntfs::ntfs-3g" "ext4:ext4:")

missing=0
report_missing() {
    echo "missing: $*"
    missing=$((missing + 1))
}

# First non-empty line of the tool's version output; `@package` (tools without a version option, such
# as mkfs.vfat) reports the Debian package version instead.
version_of() {
    local tool="$1" args_text="$2" package="$3" out args
    if [[ "$args_text" == @package ]]; then
        out="$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null)"
        if [[ -n "$out" ]]; then echo "$package $out"; else echo "unknown version"; fi
        return
    fi
    read -r -a args <<<"$args_text"
    out="$("$tool" "${args[@]}" 2>&1 | grep -m 1 -v '^[[:space:]]*$')"
    echo "${out:-unknown version}"
}

check_tool() {
    local tool="$1" hint="$2" args="$3" version
    if ! command -v "$tool" >/dev/null 2>&1; then
        report_missing "$tool ($hint)"
        return
    fi
    version="$(version_of "$tool" "$args" "${hint#package }")"
    if [[ "$tool" == python3 ]]; then
        local minor
        minor="$(echo "$version" | sed -n 's/^Python 3\.\([0-9][0-9]*\).*/\1/p')"
        if [[ -z "$minor" || "$minor" -lt $MIN_PYTHON_MINOR ]]; then
            echo "too old: python3: $version (3.$MIN_PYTHON_MINOR or newer required)"
            missing=$((missing + 1))
            return
        fi
    fi
    local pin="${PIN_OF[$tool]:-}"
    if [[ -n "$pin" ]]; then
        local expected="${PINNED[$pin]:-}" pattern
        # The exact release: no other digits around it, no pre-release or build suffix.
        pattern="(^|[^0-9.])${expected//./\\.}([^0-9.+-]|$)"
        if [[ -z "$expected" || ! "$version" =~ $pattern ]]; then
            echo "wrong version: $tool: $version (${expected:-?} required)"
            missing=$((missing + 1))
            return
        fi
    fi
    echo "ok: $tool: $version"
}

kernel_has() {
    [[ -n "$1" ]] || return 1
    grep -qw -- "$1" "$proc_filesystems" 2>/dev/null && return 0
    command -v modinfo >/dev/null 2>&1 && modinfo -- "$1" >/dev/null 2>&1
}

# check [system]: `system` leaves out the user-level tools, the helper and the sudoers rule.
check() {
    local scope="${1:-all}" entry tool package args fs module fuse
    for entry in "${APT_TOOLS[@]}"; do
        IFS=: read -r tool package args <<<"$entry"
        check_tool "$tool" "package $package" "$args"
    done
    if [[ "$scope" == all ]]; then
        for entry in "${USER_TOOLS[@]}"; do
            IFS=: read -r tool args <<<"$entry"
            check_tool "$tool" "see docs/dev-setup.md" "$args"
        done
    fi
    for entry in "${FILE_SYSTEMS[@]}"; do
        IFS=: read -r fs module fuse <<<"$entry"
        if kernel_has "$module"; then
            echo "ok: fs $fs: kernel"
        elif [[ -n "$fuse" ]] && command -v "$fuse" >/dev/null 2>&1; then
            echo "ok: fs $fs: fuse ($fuse)"
        elif [[ -n "$fuse" && -z "$module" ]]; then
            report_missing "fs $fs: $fuse not installed"
        elif [[ -n "$fuse" ]]; then
            report_missing "fs $fs: no kernel module $module and $fuse not installed"
        else
            report_missing "fs $fs: no kernel module $module"
        fi
    done
    if [[ -e "$loop_control" ]]; then
        echo "ok: loop devices: available"
    else
        report_missing "loop devices: no loop-control node"
    fi
    if [[ "$scope" == all ]] && { ! is_root || [[ "${OSTIA_AS_USER:-}" == 1 ]]; }; then
        if [[ ! -f "$helper" ]]; then
            report_missing "helper $helper is not installed"
        elif ! cmp -s -- "$helper" "$repo/tools/dev/loopmount.sh"; then
            report_missing "helper $helper differs from tools/dev/loopmount.sh"
        else
            echo "ok: helper $helper"
        fi
        if command -v sudo >/dev/null 2>&1 && sudo -n -l -- "$helper" >/dev/null 2>&1; then
            echo "ok: sudoers rule for $helper"
        else
            report_missing "sudoers rule for $helper (see docs/dev-setup.md)"
        fi
    fi
    if [[ $missing -eq 0 && "$scope" == system ]]; then
        echo "system part OK; now run tools/dev/setup-debian.sh --check as your user"
        return 0
    elif [[ $missing -eq 0 ]]; then
        echo "environment OK"
        return 0
    fi
    echo "hint: sudo tools/dev/setup-debian.sh --install, then docs/dev-setup.md for the user-level tools"
    echo "environment incomplete"
    return 1
}

install_failed() {
    echo "setup-debian: $1 failed" >&2
    exit 1
}

do_install() {
    if ! is_root; then
        echo "setup-debian: --install must run as root (sudo tools/dev/setup-debian.sh --install)" >&2
        exit 2
    fi
    local packages
    mapfile -t packages < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$script_dir/packages.txt")
    apt-get update || install_failed "apt-get update"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}" ||
        install_failed "apt-get install"
    install -o root -g root -m 0755 "$script_dir/loopmount.sh" /usr/local/sbin/ostia-loopmount ||
        install_failed "installing /usr/local/sbin/ostia-loopmount"
    echo "installed /usr/local/sbin/ostia-loopmount; add the sudoers line from docs/dev-setup.md"
}

case "${1:---check}" in
    --check) check ;;
    --install) do_install && check system ;;
    *)
        echo "usage: setup-debian.sh [--check | --install]" >&2
        exit 2
        ;;
esac
