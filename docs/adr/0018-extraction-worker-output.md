# ADR-18: Extraction worker — extracted objects streamed back over the worker's standard output

- Status: proposed (2026-10-14; the owner chose option 1 in Q-57, the crates in Q-58, the tree driver in Q-59, the literal ratio in Q-60 and the Windows path forms in Q-61; for WP-1.9, `rars` in Q-62, the crates in Q-63 and the shared-stream ratio in Q-64)
- Date: 2026-10-14
- Deciders: Matthias Vaytet (owner)
- Source: FR-06, FR-08, SEC-05, SEC-10, CTR-04; prompts/P1.md WP-1.8, WP-1.9; `docs/contracts/policy.md`
  "Limits"; `docs/contracts/report.md` "Objects"; ADR-03; `docs/questions.md` Q-57 to Q-60

## Context and problem statement

The extraction worker (WP-1.8: zip, tar, gzip; WP-1.9: 7z, rar, cab, iso, msi) opens a container passed as
descriptor 3 and must hand back every entry as a new object (origin `EXTRACTED`): its path inside the container,
its kind, its modification time and its bytes. The orchestrator then hashes each entry, copies it into the
workspace (SEC-10), types it with the triage worker and extracts it again if it is a container, under the
policy's limits on depth, ratio, total size, entry count and path length (policy.md "Limits").
`ostia.engine.v1` today carries one request and one response, and the object never travels in a message. Nothing
in it can return entries. In P2 the worker runs in a sandbox with no network, a read-only root, a private tmpfs
and no view of the workspace (SEC-01 to SEC-04).

## Decision drivers

- The orchestrator never parses content (SEC-05): it may count, hash and copy bytes, never interpret them.
- Limits hold even against a compromised worker: the orchestrator counts what it receives itself.
- Limits are enforced while streaming, never after (prompts/P1.md): no unbounded buffer on either side.
- The P2 sandbox stays simple: no directory shared between worker and orchestrator.
- Additive change to `ostia.engine.v1` only (CTR-04).

## Considered options

1. **Stream over standard output**: after the request, the worker writes a sequence of frames: per entry a
   header (path bytes, kind, size, modification time), then the entry's bytes in chunks under the frame cap,
   then one final response. The host checks each chunk sequence against the declared size and counts entries
   and bytes against the tree's remaining budget.
2. **Output file on descriptor 4**: the host creates a file in the workspace (`O_EXCL`, write-only) and passes
   it as descriptor 4; the worker writes every entry's bytes into it; the response lists entries with offsets
   and lengths. The host checks the ranges, then copies each entry into its own workspace file. A large entry
   list does not fit in one 16 MiB response frame (100,000 entries of up to 4,096-byte paths).
3. **Output directory**: the host passes a directory descriptor; the worker creates one file per entry. The
   sandbox needs a writable directory the orchestrator later reads, and file names come from the worker.

## Decision outcome

Chosen option: 1 (Q-57), because no file system is shared with the worker and the host's own counts enforce
the total size and entry count whatever the worker claims.

### Contract (`ostia.engine.v1`, minor 2, additive)

- `AnalyzeRequest.extraction` (`ExtractionBudget`, field 8): `max_ratio`, `remaining_bytes`,
  `remaining_entries`, `max_path_length`. Set only for the extraction worker.
- New message `ExtractFrame`, the extraction worker's output frames: `oneof { Entry entry = 1; bytes data = 2;
  AnalyzeResponse done = 3; }`. `Entry`: `bytes path` (empty for an entry its container does not name: a
  gzip member without a name, which the host names after the container), `EntryKind kind` (`REGULAR`, `LINK`,
  `SPECIAL`), `uint64 size`, `optional int64 modified` (seconds since the epoch, UTC).
- `AnalyzeResponse.limit` (`string`, field 10): the limit that stopped the extraction, in report.md's words
  (`ratio`, `total_size`, `entry_count`, `path_length`), empty otherwise.

### Roles

- **Host (orchestrator side)**:
  - It does not run the worker on a container at depth `max_depth`; the container gets limit `depth`.
  - It refuses a frame sequence that does not match the declared sizes, or that goes over the remaining bytes
    or entries (then the limit is `total_size` or `entry_count`). A final `ERROR` response may abandon an
    entry in the middle (the worker stopped on a limit or a malformation); a final `OK` may not.
  - It hashes and copies each entry into the workspace as it streams.
  - It keeps no entry of a container whose extraction failed. A failed container is UNSCANNABLE through R1,
    with its limit, or as malformed: a worker `ERROR` without a known limit name, `UNSUPPORTED` (a container
    type without an extractor yet, 7z to msi before WP-1.9), a crash, a timeout or a protocol fault.
  - What it received counts against the tree's budget, kept or not.
  - It checks every entry path again with the same rule (a compromised worker is not trusted with them), and
    refuses a final `OK` that names a limit.
- **Worker**: it enforces the ratio per entry and per container, the path length, the remaining budget, and
  the declared sizes. It refuses as malformed:
  - an encrypted entry, or one compressed with another method than stored or deflated (zip);
  - an entry path that leaves its container: absolute, with a `..` component, a NUL byte, in Unix or Windows
    form, or naming a Windows device (Q-61, `ostia_core_domain::entry::check_entry_path`);
  - a zip whose bytes before the central directory do not each belong to exactly one entry (its local header,
    its bytes, an optional data descriptor): a name listed twice, an entry listed only by its local header,
    bytes between entries, entries sharing bytes, a compressed size that lies, a local header that disagrees with
    its central record (name, flags, method, CRC, sizes); a deflate stream that does not consume every declared
    byte;
  - a directory, link or special entry carrying bytes; anything but zeros after a tar's end marker;
  - sizes that do not match the declared ones;
  - a truncated or corrupt stream.

  Directory entries are not objects. Symbolic and hard links are `LINK` entries; device, FIFO and socket
  entries are `SPECIAL`. A gzip file's concatenated members form one entry, as gunzip reads them.
- **Tree driver** (Q-59, `ostia_orchestrator::extraction::expand`): it runs triage then extraction on each
  object of one medium file's tree, breadth first, keeping the cumulative budget. An object the triage worker
  cannot type (an `ERROR`, a polyglot, a type name the domain does not know) is malformed. Links and special
  entries are objects that are never read or typed.

### Formats of part 2 (WP-1.9)

The worker's identity becomes `formats-2`. Each format keeps the rules above; what is particular to each:

- **Ratio of a shared stream** (Q-64): where entries are decoded from one compressed stream (a 7z folder, a
  cabinet folder, a solid run of rar members), each entry's ratio is the ratio of that stream: the bytes decoded
  from it so far over its packed size, checked per chunk. The container's ratio is unchanged. A bomb that
  shares a folder with incompressible bytes is diluted by them; in a folder of its own it is not.
- **7z** (`sevenz-rust2`, Q-63): each folder is decoded once, front to back. An AES coder or an encrypted header
  is malformed as encrypted; a coder this build lacks (PPMd, bzip2, zstd and others) as an unsupported method.
  Empty files are entries without bytes; directories and anti-items are not entries, their paths are checked.
- **rar** (`rars`, Q-62), one volume: its extraction writes into `'static` writers, so it runs on a helper
  thread handing each member header and chunk over a rendezvous channel; the worker's thread checks every
  limit before the sink, answers each member before it is decoded (a member larger than the remaining bytes is
  refused then) and stops the decoder by closing the channel. Encrypted members are encrypted; a member
  continued in another volume is malformed; a member asking for a dictionary over 1 GiB is an unsupported
  method; redirections are `LINK` entries.
- **cab**, read by this code (Q-63; MSZIP through `flate2`, LZX through `lzxd`): the object is the whole
  cabinet (`cbCabinet` equals its size); a cabinet continued from or into another one is malformed; every data
  block lies in the cabinet, decodes to at most 32 KiB and passes its checksum when it has one; the files of a
  folder cover its decoded bytes exactly, in order (no bytes outside a file, no shared bytes). Quantum is an
  unsupported method. `\` in names becomes `/`.
- **iso**, read by this code (Q-63): the Joliet tree when a supplementary descriptor carries a Joliet escape,
  else the primary tree; names lose their `;<version>` (and a primary file name its trailing dot). A both-endian
  value whose two halves disagree, an extent outside the image or a directory reached twice is malformed;
  multi-extent and interleaved files and extended attribute records are unsupported methods. Rock Ridge names,
  El Torito boot images and UDF trees are not read.
- **msi** (`cfb`, Q-63): every stream of the compound file is an entry, under its storages' path and its name
  decoded from the MSI stream-name encoding, a table name shown as `!<table>`. An embedded cabinet is an entry
  the tree extracts one level deeper; cabinets outside the package are not reachable.

### Consequences

- Good: no shared writable storage in the sandbox; limits are double-checked; bounded memory on both sides.
- Good: WP-1.9's formats reuse the same frames.
- Bad: the extraction worker speaks a second output protocol; the host needs a streaming exchange beside the
  one-response exchange of WP-1.6.
- Bad: entry bytes cross a pipe, so they are copied once more than with option 2.
- Neutral: the triage and extraction answers are not engine results (as for triage in WP-1.7); a failed
  extraction is a `Failure` (policy `Failure::Limit` or `Failure::Malformed`) for the container.

## Links

- Q-57 (channel), Q-58 (archive crates), Q-59 (tree driver in WP-1.8), Q-60 (ratio floor), Q-61 (Windows path
  forms), Q-62 (rar), Q-63 (crates of part 2), Q-64 (ratio of a shared stream).
