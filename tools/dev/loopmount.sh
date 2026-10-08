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
# cannot redirect a mount with a symlink (docs/questions.md Q-15). The image is opened once (no final
# symlink, non-blocking, never created), checked on that descriptor (regular file, owned by the caller,
# under a target/ dir) and attached to a loop device from that same descriptor (LOOP_SET_FD), so it
# cannot be swapped for a device between the check and the use. The loop device is read-only for `ro`;
# the file system type is read from the loop device. Mounts get noexec,nosuid,nodev (and ro for `ro`);
# the effective per-mount options are verified. Runs are serialised per user with a lock. The kernel driver is used when the kernel offers the file system, otherwise the
# FUSE driver (exfat-fuse) runs on the loop device; NTFS always goes through ntfs-3g, ext2/3/4 through the
# ext4 driver (ADR-17).
#
# Exit codes: 0 mounted (the last line names the file system as fat12, fat16, fat32, exfat, ntfs, ext2,
# ext3 or ext4, and the mount point), 1 failure, 2 refused arguments, 3 not root, 4 unsupported or
# unrecognised file system (nothing mounted).
#
# Residual risk, accepted for development use: root parses the caller's image (libblkid, the kernel or
# FUSE file-system driver). The production mount helper is WP-4.5.
set -euo pipefail
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
# Absolute image path, then leave the caller's directory: nothing run as root may pick files from it.
if [[ $# -ge 2 && "$2" != /* && "${1:-}" != umount ]]; then
    set -- "$1" "$PWD/$2" "${@:3}"
fi
cd /

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
    mkdir -m 0755 -- "$dir" 2>/dev/null || [[ -d "$dir" ]] || fail "cannot create $dir"
    chown root:root -- "$dir"
    chmod 0755 -- "$dir"
done
# One run at a time per user: no two runs race on the same mount name.
exec {lock_fd}>"$user_dir/.lock"
flock -w 60 "$lock_fd" || fail "another loopmount run holds $user_dir/.lock"

# --- umount ----------------------------------------------------------------------------------------
if [[ "$mode" == umount ]]; then
    mountpoint -q -- "$mount_point" || fail "$mount_point is not mounted"
    source="$(findmnt -n -o SOURCE --mountpoint "$mount_point" | tail -n 1)"
    [[ "$source" =~ ^/dev/loop[0-9]+$ ]] || fail "$mount_point is not a loop mount (source '$source')"
    backing="$(cat "/sys/block/${source#/dev/}/loop/backing_file" 2>/dev/null || true)"
    umount -- "$mount_point"
    if [[ -n "$backing" ]]; then
        # One detach request: if a FUSE driver still holds the device, the kernel detaches it when the
        # driver closes it. Wait for that, watching only this device with this backing file.
        # No `--`: util-linux 2.39 takes the next word as the device of -d.
        losetup -d "$source" || fail "could not detach $source"
        for _ in $(seq 50); do
            [[ "$(cat "/sys/block/${source#/dev/}/loop/backing_file" 2>/dev/null || true)" == "$backing" ]] ||
                break
            sleep 0.1
        done
        [[ "$(cat "/sys/block/${source#/dev/}/loop/backing_file" 2>/dev/null || true)" != "$backing" ]] ||
            fail "$source is still attached to $backing"
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
    if [[ -n "$loop" ]]; then losetup -d "$loop" || true; fi
    if [[ $created_mount_point -eq 1 ]]; then rmdir -- "$mount_point" 2>/dev/null || true; fi
}
trap cleanup EXIT

! mountpoint -q -- "$mount_point" 2>/dev/null || fail "$mount_point is already a mount point"
image="$image_arg"

# Open, check and attach in one process, from one descriptor: the image is opened without following a
# final symlink and without blocking or creating anything, checked on that descriptor, reopened
# read-write through /proc/self/fd only for rw-image, and handed to the loop driver with LOOP_SET_FD.
# No path is looked up again after the checks. A read-only descriptor gives a read-only loop device.
loop="$(
    python3 -I - "$mode" "$image_arg" "$uid" "$gid" "$IMAGE_RE" "$FIXTURE_RE" <<'PY'
import errno, fcntl, os, pwd, re, stat, sys

mode, path = sys.argv[1], sys.argv[2]
uid, gid, image_re, fixture_re = int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6]
LOOP_SET_FD, LOOP_CTL_GET_FREE, LOOP_MAJOR = 0x4C00, 0x4C82, 7


def refuse(message: str) -> None:
    print(f"loopmount: {message}", file=sys.stderr)
    sys.exit(2)


def fail(message: str) -> None:
    print(f"loopmount: {message}", file=sys.stderr)
    sys.exit(1)


# Open with the caller's rights: root opens nothing the caller could not open (no device side effects,
# no files behind directories the caller cannot traverse). Root is restored for the loop ioctls only.
access = os.O_RDWR if mode == "rw-image" else os.O_RDONLY
flags = access | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
saved_groups = os.getgroups()
if uid != 0:
    os.initgroups(pwd.getpwuid(uid).pw_name, gid)
    os.setegid(gid)
    os.seteuid(uid)
try:
    image_fd = os.open(path, flags)
except OSError as exc:
    refuse(f"image must be a regular file, not a symlink: '{path}' ({exc.strerror})")
finally:
    if uid != 0:
        os.seteuid(0)
        os.setegid(0)
        os.setgroups(saved_groups)
info = os.fstat(image_fd)
if not stat.S_ISREG(info.st_mode):
    refuse(f"image must be a regular file: '{path}'")
real = os.readlink(f"/proc/self/fd/{image_fd}")
if not re.fullmatch(image_re, real):
    refuse(f"image must be <dir>/target/[fixtures/]<name>.img, got '{real}'")
if mode == "rw-image" and not re.fullmatch(fixture_re, real):
    refuse(f"rw-image only accepts <dir>/target/fixtures/<name>.img, got '{real}'")
if info.st_uid != uid:
    refuse("image is not owned by the invoking user")

control = os.open("/dev/loop-control", os.O_RDWR | os.O_CLOEXEC)
for _ in range(20):
    number = fcntl.ioctl(control, LOOP_CTL_GET_FREE)
    device = f"/dev/loop{number}"
    if not os.path.exists(device):  # a privileged container may lack nodes created after it started
        try:
            os.mknod(device, 0o660 | stat.S_IFBLK, os.makedev(LOOP_MAJOR, number))
        except FileExistsError:  # created meanwhile by another run
            pass
    loop_fd = os.open(device, os.O_RDWR | os.O_CLOEXEC)
    try:
        fcntl.ioctl(loop_fd, LOOP_SET_FD, image_fd)
    except OSError as exc:
        os.close(loop_fd)
        if exc.errno == errno.EBUSY:  # taken by someone else since LOOP_CTL_GET_FREE: try again
            continue
        fail(f"cannot attach {path} to {device}: {exc.strerror}")
    print(device)
    sys.exit(0)
fail("no free loop device")
PY
)"

# The file system is reported in the report's vocabulary (report.md `medium.file_system`): the mount layer
# never reads the image itself (SEC-05, docs/questions.md Q-46).
fs="$(blkid -p -o value -s TYPE -- "$loop" || true)"
variant="$fs"
case "$fs" in
    vfat)
        module=vfat kernel_type=vfat fuse=""
        case "$(blkid -p -o value -s VERSION -- "$loop" || true)" in
            FAT12) variant=fat12 ;;
            FAT16) variant=fat16 ;;
            FAT32) variant=fat32 ;;
            *) fail "FAT file system of unknown version in $image" ;;
        esac
        ;;
    exfat) module=exfat kernel_type=exfat fuse=mount.exfat-fuse ;;
    # ntfs-3g shows alternate data streams as user.* attributes; the kernel ntfs3 driver does not.
    ntfs) module="" kernel_type="" fuse=ntfs-3g ;;
    # The ext2 driver may be built without xattr support (WSL2); the ext4 driver reads all three (Q-45).
    ext2 | ext3 | ext4) module=ext4 kernel_type=ext4 fuse="" ;;
    *)
        echo "loopmount: unsupported file system '${fs:-none}' in $image" >&2
        exit 4
        ;;
esac

kernel_has() { [[ -n "$1" ]] && { grep -qw -- "$1" /proc/filesystems || modprobe -q -- "$1" 2>/dev/null; }; }

if kernel_has "$module"; then
    driver=kernel
elif [[ -n "$fuse" ]] && command -v "$fuse" >/dev/null; then
    driver=fuse
else
    fail "no driver for $variant (${module:+kernel module $module}${module:+${fuse:+, }}${fuse:+$fuse})" \
        "(see tools/dev/setup-debian.sh --check)"
fi

if [[ "$mode" == ro ]]; then
    required="ro,noexec,nosuid,nodev" options="$required"
    [[ "$(cat "/sys/block/${loop#/dev/}/ro")" == 1 ]] || fail "$loop is not read-only"
else
    required="noexec,nosuid,nodev" options="rw,$required"
    case "$fs" in
        vfat | exfat | ntfs) options="$options,uid=$uid,gid=$gid" ;;
    esac
fi
# FAT keeps names in UTF-16 and times without a zone: names as UTF-8 (the kernel default is ASCII) and times
# as UTC, whatever the kernel's time zone (docs/questions.md Q-44).
if [[ "$fs" == vfat ]]; then
    options="$options,utf8,tz=UTC"
fi

if [[ ! -d "$mount_point" ]]; then
    mkdir -m 0755 -- "$mount_point"
    created_mount_point=1
fi
if [[ "$driver" == kernel ]]; then
    mount --no-canonicalize -t "$kernel_type" -o "$options" -- "$loop" "$mount_point" ||
        fail "mounting $image ($variant, kernel driver) failed"
    mounted=1
else
    # The FUSE driver stays running as a daemon: it must not inherit the lock.
    "$fuse" -o "$options" "$loop" "$mount_point" {lock_fd}>&- ||
        fail "mounting $image ($variant, fuse driver) failed"
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
echo "loopmount: mounted $image ($variant, $driver driver, $options) on $mount_point"
