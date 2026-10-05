#!/usr/bin/env bash
# Development environment for Ostia on Debian stable (or WSL2 Debian/Ubuntu).
#
#   setup-debian.sh [--check]   verify every tool, its version, loop devices and file-system support
#   setup-debian.sh --install   as root: install tools/dev/packages.txt with apt, install the root-owned
#                               mount helper /usr/local/sbin/ostia-loopmount, then run --check
#
# --install is idempotent and is run by the owner (`sudo tools/dev/setup-debian.sh --install`), never by
# an agent. User-level tools (rustup, cargo, uv, just, cargo-nextest) are installed as in docs/dev-setup.md.
# Test hooks (--check only): OSTIA_EXTRA_PATH, OSTIA_PROC_FILESYSTEMS, OSTIA_LOOP_CONTROL, OSTIA_HELPER,
# OSTIA_AS_USER=1 (check the helper and sudoers rule even when running as root).
set -uo pipefail

script_dir="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
repo="$(cd "$script_dir/../.." && pwd)"
PATH="$PATH${OSTIA_EXTRA_PATH-:/usr/sbin:/sbin}"
proc_filesystems="${OSTIA_PROC_FILESYSTEMS:-/proc/filesystems}"
loop_control="${OSTIA_LOOP_CONTROL:-/dev/loop-control}"
helper="${OSTIA_HELPER:-/usr/local/sbin/ostia-loopmount}"
readonly MIN_PYTHON_MINOR=12

# tool:package:version arguments
APT_TOOLS=(
    "git:git:--version" "curl:curl:--version" "python3:python3:--version" "gcc:build-essential:--version"
    "mkfs.vfat:dosfstools:--version" "mkfs.exfat:exfatprogs:-V" "mkfs.ntfs:ntfs-3g:--version"
    "mkfs.ext4:e2fsprogs:-V" "losetup:mount:--version" "blkid:util-linux:--version"
    "findmnt:util-linux:--version" "setpriv:util-linux:--version" "ntfs-3g:ntfs-3g:--version"
    "mount.exfat-fuse:exfat-fuse:-V" "fusermount3:fuse3:-V" "bwrap:bubblewrap:--version"
    "clamd:clamav-daemon:--version" "mmls:sleuthkit:-V"
)
USER_TOOLS=("rustup:--version" "cargo:--version" "uv:--version" "just:--version" "cargo-nextest:nextest --version")
# file system:kernel module:FUSE helper
FILE_SYSTEMS=("vfat:vfat:" "exfat:exfat:mount.exfat-fuse" "ntfs:ntfs3:ntfs-3g" "ext4:ext4:")

missing=0
report_missing() {
    echo "missing: $*"
    missing=$((missing + 1))
}

version_of() {
    local out args
    read -r -a args <<<"$2"
    out="$("$1" "${args[@]}" 2>&1 | head -n 1)"
    echo "${out:-unknown version}"
}

check_tool() {
    local tool="$1" hint="$2" args="$3" version
    if ! command -v "$tool" >/dev/null 2>&1; then
        report_missing "$tool ($hint)"
        return
    fi
    version="$(version_of "$tool" "$args")"
    if [[ "$tool" == python3 ]]; then
        local minor
        minor="$(echo "$version" | sed -n 's/^Python 3\.\([0-9][0-9]*\).*/\1/p')"
        if [[ -z "$minor" || "$minor" -lt $MIN_PYTHON_MINOR ]]; then
            echo "too old: python3: $version (3.$MIN_PYTHON_MINOR or newer required)"
            missing=$((missing + 1))
            return
        fi
    fi
    echo "ok: $tool: $version"
}

kernel_has() {
    grep -qw -- "$1" "$proc_filesystems" 2>/dev/null && return 0
    command -v modinfo >/dev/null 2>&1 && modinfo -- "$1" >/dev/null 2>&1
}

check() {
    local entry tool package args fs module fuse
    for entry in "${APT_TOOLS[@]}"; do
        IFS=: read -r tool package args <<<"$entry"
        check_tool "$tool" "package $package" "$args"
    done
    for entry in "${USER_TOOLS[@]}"; do
        IFS=: read -r tool args <<<"$entry"
        check_tool "$tool" "see docs/dev-setup.md" "$args"
    done
    for entry in "${FILE_SYSTEMS[@]}"; do
        IFS=: read -r fs module fuse <<<"$entry"
        if kernel_has "$module"; then
            echo "ok: fs $fs: kernel"
        elif [[ -n "$fuse" ]] && command -v "$fuse" >/dev/null 2>&1; then
            echo "ok: fs $fs: fuse ($fuse)"
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
    if [[ $EUID -ne 0 || "${OSTIA_AS_USER:-}" == 1 ]]; then
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
    if [[ $missing -eq 0 ]]; then
        echo "environment OK"
        return 0
    fi
    echo "hint: sudo tools/dev/setup-debian.sh --install, then docs/dev-setup.md for the user-level tools"
    echo "environment incomplete"
    return 1
}

install() {
    if [[ $EUID -ne 0 ]]; then
        echo "setup-debian: --install must run as root (sudo tools/dev/setup-debian.sh --install)" >&2
        exit 2
    fi
    local packages
    mapfile -t packages < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$script_dir/packages.txt")
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
    install -o root -g root -m 0755 "$script_dir/loopmount.sh" /usr/local/sbin/ostia-loopmount
    echo "installed /usr/local/sbin/ostia-loopmount; add the sudoers line from docs/dev-setup.md"
}

case "${1:---check}" in
    --check) check ;;
    --install) install && check ;;
    *)
        echo "usage: setup-debian.sh [--check | --install]" >&2
        exit 2
        ;;
esac
