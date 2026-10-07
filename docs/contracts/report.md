# Scan report — contract v1

Status: proposed in WP-0.12 (P1 lock). Schema: `schemas/report.schema.json` (JSON Schema draft 2020-12,
`report_version` 1.x.y). Adding an optional field is a minor version; changing or removing a field, or changing
a meaning below, is a breaking change (new major version, owner decision, CTR-04). The P1 acceptance tests
validate every report against the schema and rely on the meanings below.
- New values of an enumeration (origin, kind, rule, limit, refusal code, attribute, detected type) arrive in
  minor versions; a consumer treats a value it does not know as blocking.
- Later phases may make fewer objects transferable only through settings that are off by default (for example
  the FR-11 business-format allowlist), so that the meanings below keep holding with default settings.

The report carries metadata, hashes and verdicts, never file content.

## Top level

| Field | Meaning |
|---|---|
| `report_version` | `1.<minor>.<patch>`. |
| `session` | `id` (unique per run), `mode` (`compliant`, `selective`, `scan-only`; default `compliant`), `compliant` (true only in `compliant` mode). |
| `timing` | `started`, `ended` (RFC 3339), `max_scan_time_seconds` (600 unless `--max-scan-time`), `on_expiry` (`block` unless `--on-expiry`), `expired` (the budget ran out), `aborted` (the session stopped: expiry action `abort`). |
| `medium` | `image` (path as given), `size` (bytes of the image file), `file_system` (`fat12`, `fat16`, `fat32`, `exfat`, `ntfs`, `ext2`, `ext3`, `ext4`, or null when refused or unknown). |
| `refusal` | Null, or why the input was refused (exit 4): see [Refusal](#refusal). |
| `policy` | `version` (the policy's `version`, null when the policy was refused) and `sha256` (hex SHA-256 of the exact policy file bytes given). |
| `engines` | Identity of every analysis engine of the session (id, version, content version). |
| `objects` | Every object of the inventory and every extracted object, as a flat list forming a tree through `parent_id`. Empty when refused. |
| `medium_verdict` | See [Medium verdict](#medium-verdict). |

## Refusal

| `code` | When |
|---|---|
| `unsupported_file_system` | The image holds no file system or one outside FR-03 (FAT12/16/32, exFAT, NTFS, ext2/3/4). |
| `policy_signature_invalid` | The signature does not verify with the trusted key over the exact policy bytes: altered policy, other key, malformed signature or key file. |
| `policy_invalid` | The signature verifies but the content is refused: not JSON, not `ostia.policy.v1`, unknown key, out-of-range value ([policy.md](policy.md)). |

The policy is checked before the image is opened. A refused report has `objects: []`, a medium verdict
`UNSCANNABLE` with `blocked: true`, and nothing is transferred.

## Objects

| Field | Meaning |
|---|---|
| `id` | Unique in the report. |
| `parent_id` | Null for a file of the medium; the container for an extracted object; the host file for a stream. |
| `origin` | `FILE` (file of the medium), `EXTRACTED` (from an archive), `ALT_STREAM` (NTFS alternate data stream), `XATTR` (extended attribute value, ext2/3/4 `user.*` namespace). Engines receive an `XATTR` object with origin `ALT_STREAM` (`ostia.engine.v1` has no XATTR value). |
| `kind` | `file` (regular file, stream or attribute value), `symlink` (symbolic link, NTFS reparse point or junction, archive link entry) or `special` (FIFO, socket, device node). A `symlink` or `special` object is never followed, opened or read: size 0, hashes null, no engine run, UNSCANNABLE through R1, never transferable. Each name of a hard-linked file is its own `file` object. |
| `depth` | 0 for a file of the medium; parent's depth + 1 otherwise. |
| `path` | UTF-8; a byte that is not valid UTF-8 is written `\xNN` (two lower-case hex digits) and a literal backslash `\\`, so two different names never share a path. `FILE`: path from the medium root, `/`-separated, no leading `/` (`docs/report.pdf`). `EXTRACTED`: the entry's path inside its container, `/`-separated (`dir/b.bin`); for a gzip member, the name in its header, else the container's name without its last extension. `ALT_STREAM`, `XATTR`: the host file's path. |
| `stream` | Null, or the stream name (`Zone.Identifier`) or the attribute name (`user.comment`). |
| `size`, `sha256`, `sha1` | Of the object's bytes as read once and copied into the workspace (SEC-10). Hashes are lower-case hex; null only when the object was not read (`symlink`, `special`) or could not be read (then UNSCANNABLE, R1). |
| `modified` | Last modification time in UTC (RFC 3339), null when the source has none. FAT and exFAT times without a zone are read as UTC. |
| `attributes` | `hidden` (file-system hidden attribute, or a name starting with `.` on any file system), `system`, `read_only`, `archive` (FAT, exFAT and NTFS attributes). |
| `detected_type` | Type from content, never from the name (FR-05): see [Types](#types). |
| `extension_mismatch` | The name's last extension is not one of the extensions of `detected_type`. Never true for `unknown` or for a name without extension (a name whose only dot is the first character, `.profile`, has none). |
| `double_extension` | The name has at least two extensions after a non-empty stem and the last one is executable: `exe scr com bat cmd pif cpl vbs vbe js jse wsf wsh ps1 msi hta lnk jar dll` (case-insensitive). `invoice.pdf.exe`: true; `backup.tar.gz`: false. |
| `verdict`, `rule` | The first matching policy rule and its verdict ([policy.md](policy.md)). |
| `limit` | The limit that made the object UNSCANNABLE (`depth`, `ratio`, `total_size`, `entry_count`, `path_length`, `scan_time`), else null. |
| `score` | The highest score among the scorer engines' results with status `OK`, else null. |
| `contributing_engines` | The engines whose results made the rule match ([policy.md](policy.md)); empty when no engine did (R7, flags of the name, limits). |
| `explanation` | Non-empty readable sentence: rule, engines, scores, limit (NFR-12). |
| `engine_results` | One entry per engine run on the object, as answered (`AnalyzeResponse` of `ostia.engine.v1`) or as synthesised by the worker host on crash or timeout. |
| `transferable` | See below. |

### Transferable

An object is transferable only if all of these hold:
- its origin is `FILE` and its kind is `file`;
- its path has no absolute, empty, `.` or `..` component;
- its verdict is CLEAN, and so is the verdict of every `EXTRACTED` descendant;
- the mode is not `scan-only` and the session is not aborted;
- in `compliant` mode, the medium is not blocked.

Alternate data streams and extended attributes are scanned but never transferable and never copied (DEEP-05).
Extracted objects travel inside their container. `--output` receives exactly the transferable objects, under
their original name bytes.

### Types

`detected_type` names used by the contract (more may be added in a minor version; these keep their names). A more
specific type may replace `zip` for zip-based formats (OOXML, ODF, JAR, APK, EPUB) in a minor version, keeping their
extensions consistent:

| Type | Recognised by | Extensions |
|---|---|---|
| `pe` | `MZ` header whose `e_lfanew` points to `PE\0\0` | `exe dll sys scr com cpl ocx efi drv mui pyd ax` |
| `elf` | `\x7fELF` | `so elf bin ko o`; a versioned shared object `name.so.1.2` counts as `so` |
| `pdf` | `%PDF-` | `pdf` |
| `png` | `\x89PNG\r\n\x1a\n` | `png` |
| `zip` | `PK\x03\x04` (or an empty archive's `PK\x05\x06`) | `zip docx docm dotx xlsx xlsm pptx pptm odt ods odp jar apk epub` |
| `gzip` | `\x1f\x8b` | `gz tgz` |
| `tar` | `ustar` at offset 257 | `tar` |
| `7z` | `7z\xbc\xaf\x27\x1c` | `7z` |
| `rar` | `Rar!\x1a\x07` | `rar` |
| `cab` | `MSCF` | `cab` |
| `iso9660` | `CD001` at offset 32769 | `iso` |
| `msi` | Compound file whose root CLSID is the Windows Installer package one | `msi` |
| `unknown` | None of the above | (never a mismatch) |

## Medium verdict

| Field | Meaning |
|---|---|
| `verdict` | Worst object verdict, counting an UNSCANNABLE for the unanalysed rest of the medium when the scan expired (`timing.expired`). The rank of MALICIOUS against UNSCANNABLE is fixed in WP-1.1 (ADR); both block. No object: CLEAN, unless refused, aborted or expired (UNSCANNABLE). |
| `blocked` | Compliant and scan-only modes: true if any object is MALICIOUS or UNSCANNABLE, or the scan expired. Every mode: true if refused or aborted. Selective mode otherwise: false (only the CLEAN objects that were analysed are transferable). |
| `blocking_objects` | Ids of the MALICIOUS and UNSCANNABLE objects. |
| `findings` | Device-level findings (D1, D2; P4 and P5). Empty in P1. |
