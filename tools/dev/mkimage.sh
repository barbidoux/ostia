#!/usr/bin/env bash
# Create an empty disk image of a given file-system type, for development and tests.
#
#   mkimage.sh <type> <size-MiB> <output>
#
# type:   fat12 fat16 fat32 exfat ntfs ext2 ext3 ext4
# size:   1 to 4096 MiB
# output: <dir>/target/<name>.img or <dir>/target/fixtures/<name>.img, a new regular file.
# No root needed: mkfs runs on a regular file, never on a block device.
set -euo pipefail

readonly TYPES="fat12 fat16 fat32 exfat ntfs ext2 ext3 ext4"
readonly MAX_MIB=4096
readonly OUTPUT_RE='^/(.+/)?target/(fixtures/)?[a-z0-9_.-]+\.img$'

refuse() {
    echo "mkimage: $*" >&2
    exit 2
}

[[ $# -eq 3 ]] || refuse "usage: mkimage.sh <type> <size-MiB> <output>"
type="$1" size="$2" output="$3"

[[ " $TYPES " == *" $type "* ]] || refuse "unknown file-system type '$type' ($TYPES)"
[[ "$size" =~ ^[0-9]+$ ]] && ((10#$size >= 1 && 10#$size <= MAX_MIB)) ||
    refuse "size must be an integer from 1 to $MAX_MIB MiB, got '$size'"
[[ "$output" != /dev/* ]] || refuse "refusing device path '$output'"

# Normalise without following a missing final component; `..` is resolved before the pattern check.
absolute="$(realpath -m -- "$output")"
[[ "$absolute" =~ $OUTPUT_RE ]] || refuse "output must be <dir>/target/[fixtures/]<name>.img, got '$output'"
[[ ! -e "$absolute" && ! -L "$absolute" ]] || refuse "refusing to overwrite existing '$output'"

case "$type" in
    fat12) tool=mkfs.vfat package=dosfstools args=(-F 12 -n OSTIA) ;;
    fat16) tool=mkfs.vfat package=dosfstools args=(-F 16 -n OSTIA) ;;
    fat32) tool=mkfs.vfat package=dosfstools args=(-F 32 -n OSTIA) ;;
    exfat) tool=mkfs.exfat package=exfatprogs args=(-L OSTIA) ;;
    ntfs) tool=mkfs.ntfs package=ntfs-3g args=(--quiet --fast --force --label OSTIA) ;;
    ext2 | ext3 | ext4) tool="mkfs.$type" package=e2fsprogs args=(-q -F -L OSTIA) ;;
esac

PATH="$PATH:/usr/sbin:/sbin"
command -v "$tool" >/dev/null ||
    { echo "mkimage: $tool not found: install $package (sudo tools/dev/setup-debian.sh --install)" >&2; exit 1; }

mkdir -p -- "$(dirname -- "$absolute")"
truncate -s "${size}M" -- "$absolute"
if ! "$tool" "${args[@]}" "$absolute" >/dev/null; then
    rm -f -- "$absolute"
    echo "mkimage: $tool failed on '$output'" >&2
    exit 1
fi
echo "mkimage: created $type image $absolute (${size} MiB)"
