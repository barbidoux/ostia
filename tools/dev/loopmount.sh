#!/bin/bash
# Development mount helper for disk images. Runs as root: in the CI container directly, on a developer
# machine through `sudo -n /usr/local/sbin/ostia-loopmount` (a root-owned copy installed by
# `tools/dev/setup-debian.sh --install`; see docs/dev-setup.md).
#
#   loopmount.sh ro       <dir>/target/[fixtures/]<name>.img <mount-name>   read-only scan mount
#   loopmount.sh rw-image <dir>/target/fixtures/<name>.img   <mount-name>   fixture generator only
#   loopmount.sh umount   <mount-name>
#
# Mount points are /run/ostia-loopmount/<uid>/<mount-name>, in directories owned by root, so the caller
# cannot redirect a mount with a symlink (docs/questions.md Q-15). The image is opened once, then checked
# and used only through that open descriptor (regular file, owned by the caller, under a target/ dir), so
# it cannot be swapped for a device between the check and the use. It is attached to a loop device
# (read-only for `ro`) and mounted with noexec,nosuid,nodev (and ro for `ro`); the effective per-mount
# options are verified. The kernel driver is used when the kernel offers the file system, otherwise the
# FUSE driver (exfat-fuse, ntfs-3g) runs on the loop device.
#
# Residual risk, accepted for development use: root parses the caller's image (libblkid, the kernel or
# FUSE file-system driver). The production mount helper is WP-4.5.
set -euo pipefail
PATH="/usr/sbin:/usr/bin:/sbin:/bin"

readonly BASE=/run/ostia-loopmount
readonly IMAGE_RE='^/(.+/)?target/(fixtures/)?[a-z0-9_.-]+\.img$'
readonly FIXTURE_RE='^/(.+/)?target/fixtures/[a-z0-9_.-]+\.img$'
readonly NAME_RE='^[a-z0-9_-]{1,32}$'
readonly USAGE="usage: loopmount.sh ro|rw-image <image> <name> | umount <name>"

refuse() {
    echo "loopmount: $*" >&2
    exit 2
}

fail() {
    echo "loopmount: $*" >&2
    exit 1
}

# --- validation, before anything privileged ------------------------------------------------------
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

if [[ "$mode" == umount ]]; then
    name="$2"
else
    image_arg="$2" name="$3"
    [[ -f "$image_arg" && ! -L "$image_arg" ]] ||
        refuse "image must be a regular file, not a symlink: '$image_arg'"
    [[ "$(realpath -e -- "$image_arg")" =~ $IMAGE_RE ]] ||
        refuse "image must be <dir>/target/[fixtures/]<name>.img, got '$image_arg'"
    if [[ "$mode" == rw-image ]]; then
        [[ "$(realpath -e -- "$image_arg")" =~ $FIXTURE_RE ]] ||
            refuse "rw-image only accepts <dir>/target/fixtures/<name>.img, got '$image_arg'"
    fi
fi
[[ "$name" =~ $NAME_RE ]] || refuse "mount name must match [a-z0-9_-]{1,32}, got '$name'"

if [[ $EUID -ne 0 ]]; then
    echo "loopmount: needs root: run \`sudo -n /usr/local/sbin/ostia-loopmount $*\`" \
        "(see docs/dev-setup.md)" >&2
    exit 3
fi

uid="${SUDO_UID:-0}" gid="${SUDO_GID:-0}"
[[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || refuse "invalid SUDO_UID or SUDO_GID"
user_dir="$BASE/$uid"
mount_point="$user_dir/$name"

# Root-owned directories: the caller can read them but never replace them.
for dir in "$BASE" "$user_dir"; do
    [[ ! -L "$dir" ]] || fail "$dir is a symlink"
    [[ -d "$dir" ]] || mkdir -m 0755 -- "$dir"
    chown root:root -- "$dir"
    chmod 0755 -- "$dir"
done

# --- umount ----------------------------------------------------------------------------------------
if [[ "$mode" == umount ]]; then
    mountpoint -q -- "$mount_point" || fail "$mount_point is not mounted"
    source="$(findmnt -n -o SOURCE --mountpoint "$mount_point" | head -n 1)"
    umount -- "$mount_point"
    if [[ "$source" == /dev/loop* ]]; then
        loop_name="${source#/dev/}"
        losetup -d -- "$source" 2>/dev/null || true
        # A FUSE driver may close the device just after umount returns: wait for the detach.
        for _ in $(seq 50); do
            [[ -e "/sys/block/$loop_name/loop/backing_file" ]] || break
            sleep 0.1
            losetup -d -- "$source" 2>/dev/null || true
        done
        [[ ! -e "/sys/block/$loop_name/loop/backing_file" ]] || fail "$source is still attached"
    fi
    rmdir -- "$mount_point"
    echo "loopmount: unmounted $mount_point"
    exit 0
fi

# --- ro / rw-image ---------------------------------------------------------------------------------
loop="" created_mount_point=0 mounted=0 done=0
cleanup() {
    if [[ $done -eq 1 ]]; then return 0; fi
    if [[ $mounted -eq 1 ]]; then umount -- "$mount_point" || true; fi
    if [[ -n "$loop" ]]; then losetup -d -- "$loop" 2>/dev/null || true; fi
    if [[ $created_mount_point -eq 1 ]]; then rmdir -- "$mount_point" 2>/dev/null || true; fi
}
trap cleanup EXIT

if [[ "$mode" == ro ]]; then
    exec {image_fd}<"$image_arg"
else
    exec {image_fd}<>"$image_arg"
fi
image_fd_path="/proc/self/fd/$image_fd"
[[ -f "$image_fd_path" ]] || refuse "image must be a regular file: '$image_arg'"
image="$(readlink -- "$image_fd_path")"
[[ "$image" =~ $IMAGE_RE ]] || refuse "image must be <dir>/target/[fixtures/]<name>.img, got '$image'"
if [[ "$mode" == rw-image ]]; then
    [[ "$image" =~ $FIXTURE_RE ]] ||
        refuse "rw-image only accepts <dir>/target/fixtures/<name>.img, got '$image'"
fi
[[ "$(stat -L -c %u -- "$image_fd_path")" == "$uid" ]] || refuse "image is not owned by the invoking user"
! mountpoint -q -- "$mount_point" 2>/dev/null || fail "$mount_point is already a mount point"

fs="$(blkid -p -o value -s TYPE -- "$image_fd_path" || true)"
case "$fs" in
    vfat) module=vfat kernel_type=vfat fuse="" ;;
    exfat) module=exfat kernel_type=exfat fuse=mount.exfat-fuse ;;
    ntfs) module=ntfs3 kernel_type=ntfs3 fuse=ntfs-3g ;;
    ext2 | ext3 | ext4) module="$fs" kernel_type="$fs" fuse="" ;;
    *) fail "unsupported or unrecognised file system '${fs:-none}' in $image" ;;
esac

kernel_has() { grep -qw -- "$1" /proc/filesystems || modprobe -q -- "$1" 2>/dev/null; }

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

if [[ "$mode" == ro ]]; then
    required="ro,noexec,nosuid,nodev" options="$required"
    loop="$(losetup --find --show --read-only -- "$image_fd_path")"
else
    required="noexec,nosuid,nodev" options="rw,$required"
    case "$fs" in
        vfat | exfat | ntfs) options="$options,uid=$uid,gid=$gid" ;;
    esac
    loop="$(losetup --find --show -- "$image_fd_path")"
fi

if [[ ! -d "$mount_point" ]]; then
    mkdir -m 0755 -- "$mount_point"
    created_mount_point=1
fi
if [[ "$driver" == kernel ]]; then
    mount --no-canonicalize -t "$kernel_type" -o "$options" -- "$loop" "$mount_point" ||
        fail "mounting $image ($fs, kernel driver) failed"
    mounted=1
else
    "$fuse" -o "$options" "$loop" "$mount_point" || fail "mounting $image ($fs, fuse driver) failed"
    mounted=1
    # FUSE drivers do not all apply the generic flags: set them on the mount itself.
    mount --no-canonicalize -o "remount,bind,$required" -- "$mount_point" ||
        fail "could not apply $required to $mount_point"
fi
effective="$(findmnt -n -o VFS-OPTIONS --mountpoint "$mount_point" | head -n 1)"
for flag in ${required//,/ }; do
    [[ ",$effective," == *",$flag,"* ]] || fail "$mount_point lacks $flag (effective: $effective)"
done
done=1
echo "loopmount: mounted $image ($fs, $driver driver, $options) on $mount_point"
