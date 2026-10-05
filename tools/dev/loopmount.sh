#!/usr/bin/env bash
# Development mount helper for disk images. Runs as root: in the CI container directly, on a developer
# machine through `sudo -n /usr/local/sbin/ostia-loopmount` (a root-owned copy installed by
# `tools/dev/setup-debian.sh --install`; see docs/dev-setup.md).
#
#   loopmount.sh ro       <dir>/target/[fixtures/]<name>.img <mount-name>   read-only scan mount
#   loopmount.sh rw-image <dir>/target/fixtures/<name>.img   <mount-name>   fixture generator only
#   loopmount.sh umount   <dir>/target/mnt/<mount-name>
#
# The image is attached to a loop device (read-only for `ro`) and mounted on <dir>/target/mnt/<mount-name>
# with noexec,nosuid,nodev. The kernel driver is used when the kernel offers the file system, otherwise
# the FUSE driver (exfat-fuse, ntfs-3g) runs on the loop device. Every argument is validated before
# anything privileged happens; device paths are refused outright. Development use only: the production
# mount helper is WP-4.5.
set -euo pipefail
PATH="/usr/sbin:/usr/bin:/sbin:/bin"

readonly IMAGE_RE='^/(.+/)?target/(fixtures/)?[a-z0-9_.-]+\.img$'
readonly FIXTURE_RE='^/(.+/)?target/fixtures/[a-z0-9_.-]+\.img$'
readonly MOUNT_RE='^/(.+/)?target/mnt/[a-z0-9_-]{1,32}$'
readonly NAME_RE='^[a-z0-9_-]{1,32}$'
readonly USAGE="usage: loopmount.sh ro|rw-image <image> <name> | umount <mount point>"

refuse() {
    echo "loopmount: $*" >&2
    exit 2
}

fail() {
    echo "loopmount: $*" >&2
    exit 1
}

[[ $# -ge 1 ]] || refuse "$USAGE"
mode="$1"
case "$mode" in
    ro | rw-image) [[ $# -eq 3 ]] || refuse "$USAGE" ;;
    umount) [[ $# -eq 2 ]] || refuse "$USAGE" ;;
    *) refuse "unknown mode '$mode' (ro, rw-image, umount)" ;;
esac
for arg in "${@:2}"; do
    [[ "$arg" != /dev/* ]] || refuse "refusing device path '$arg'"
done

needs_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "loopmount: needs root: run \`sudo -n /usr/local/sbin/ostia-loopmount $*\`" \
            "(see docs/dev-setup.md)" >&2
        exit 3
    fi
}

invoking_uid() { echo "${SUDO_UID:-$(id -u)}"; }
invoking_gid() { echo "${SUDO_GID:-$(id -g)}"; }

# --- umount -----------------------------------------------------------------------------------------
if [[ "$mode" == umount ]]; then
    mount_point="$(realpath -m -- "$2")"
    [[ "$mount_point" =~ $MOUNT_RE ]] || refuse "umount only accepts <dir>/target/mnt/<name>, got '$2'"
    needs_root "$@"
    mountpoint -q -- "$mount_point" || fail "$mount_point is not mounted"
    source="$(findmnt -n -o SOURCE --mountpoint "$mount_point")"
    umount -- "$mount_point"
    if [[ "$source" == /dev/loop* ]]; then
        losetup -d "$source"
    fi
    rmdir -- "$mount_point"
    echo "loopmount: unmounted $mount_point"
    exit 0
fi

# --- ro / rw-image: validate ------------------------------------------------------------------------
image_arg="$2" name="$3"
[[ -f "$image_arg" && ! -L "$image_arg" ]] ||
    refuse "image must be a regular file, not a symlink: '$image_arg'"
image="$(realpath -e -- "$image_arg")"
[[ "$image" =~ $IMAGE_RE ]] || refuse "image must be <dir>/target/[fixtures/]<name>.img, got '$image_arg'"
if [[ "$mode" == rw-image ]]; then
    [[ "$image" =~ $FIXTURE_RE ]] ||
        refuse "rw-image only accepts <dir>/target/fixtures/<name>.img, got '$image_arg'"
fi
[[ "$name" =~ $NAME_RE ]] || refuse "mount name must match [a-z0-9_-]{1,32}, got '$name'"
needs_root "$@"
[[ "$(stat -c %u -- "$image")" == "$(invoking_uid)" ]] || refuse "image is not owned by the invoking user"

target_dir="${image%/*}"
target_dir="${target_dir%/fixtures}"
mount_point="$target_dir/mnt/$name"
! mountpoint -q -- "$mount_point" 2>/dev/null || fail "$mount_point is already a mount point"

# --- detect the file system and choose a driver -----------------------------------------------------
fs="$(blkid -p -o value -s TYPE -- "$image" || true)"
case "$fs" in
    vfat) module=vfat kernel_type=vfat fuse="" ;;
    exfat) module=exfat kernel_type=exfat fuse=mount.exfat-fuse ;;
    ntfs) module=ntfs3 kernel_type=ntfs3 fuse=ntfs-3g ;;
    ext2 | ext3 | ext4) module="$fs" kernel_type="$fs" fuse="" ;;
    *) fail "unsupported or unrecognised file system '${fs:-none}' in $image" ;;
esac

kernel_has() { grep -qw -- "$1" /proc/filesystems || modprobe -q -- "$1" 2>/dev/null; }

driver=""
if [[ "$mode" == rw-image && "$fs" == ntfs ]] && command -v ntfs-3g >/dev/null; then
    driver=fuse # alternate data streams are planted through ntfs-3g
elif kernel_has "$module"; then
    driver=kernel
elif [[ -n "$fuse" ]] && command -v "$fuse" >/dev/null; then
    driver=fuse
else
    fail "the kernel has no $module module${fuse:+ and $fuse is not installed}: cannot mount $fs" \
        "(see tools/dev/setup-debian.sh --check)"
fi

options="noexec,nosuid,nodev"
if [[ "$mode" == ro ]]; then
    options="ro,$options"
    loop="$(losetup --find --show --read-only -- "$image")"
else
    options="rw,$options"
    case "$fs" in
        vfat | exfat | ntfs) options="$options,uid=$(invoking_uid),gid=$(invoking_gid)" ;;
    esac
    loop="$(losetup --find --show -- "$image")"
fi

mkdir -p -- "$mount_point"
mounted=0
if [[ "$driver" == kernel ]]; then
    mount -t "$kernel_type" -o "$options" -- "$loop" "$mount_point" && mounted=1
else
    "$fuse" -o "$options" "$loop" "$mount_point" && mounted=1
fi
if [[ $mounted -ne 1 ]]; then
    losetup -d "$loop"
    rmdir -- "$mount_point"
    fail "mounting $image ($fs, $driver driver) failed"
fi
echo "loopmount: mounted $image ($fs, $driver driver, $options) on $mount_point"
