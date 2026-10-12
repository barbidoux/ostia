# Unsafe allowlist

`unsafe` Rust is forbidden workspace-wide (`unsafe_code = "forbid"`, NFR-09). A crate may use it only if it is
listed here by the owner, with the reason, the reviewer and the date. The guard hook reads this file.

| Crate | Reason | Reviewed by | Date |
|---|---|---|---|
| ostia-fat-attributes | One `ioctl(FAT_IOCTL_GET_ATTRIBUTES)` on a descriptor the inventory opened on a vfat mount: the kernel returns the FAT attribute byte it already parsed for the mount (Q-48) | Matthias Vaytet | 2026-10-12 |
