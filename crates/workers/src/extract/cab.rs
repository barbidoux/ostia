//! Cabinet (WP-1.9), read by this code (Q-63): the header, the folders and the files, then each folder's
//! data blocks in turn, bounds and checksums checked, decoded stored, MSZIP (deflate blocks sharing one
//! window, through `flate2`) or LZX (`lzxd`). Every byte of the cabinet belongs to something: its header,
//! folder and file tables, then the folders' data blocks, back to back to its end. A folder's files must cover
//! its decoded bytes exactly, in order: bytes no file accounts for, files sharing bytes, and folders continued
//! in another cabinet are malformed. A folder's ratio is the ratio of every file decoded from it (Q-64).

use std::io::{self, Read, Seek, SeekFrom};

use flate2::{Decompress, FlushDecompress, Status};
use lzxd::{Lzxd, WindowSize};

use super::{ARCHIVE, Header, Kind, Malformed, Packed, Run, Stop, dos_time};

/// The largest decoded data block (MS-CAB: 32 KiB), also the deflate window.
const FRAME: usize = 32_768;
const PREV_CABINET: u16 = 0x0001;
const NEXT_CABINET: u16 = 0x0002;
const RESERVE_PRESENT: u16 = 0x0004;
/// A file name of at most 256 bytes, then its NUL.
const NAME: usize = 257;

/// A folder: where its first data block is, how many blocks it has, how they are compressed.
struct Folder {
    first: u64,
    blocks: u16,
    compression: u16,
}

/// A file: its bytes are `size` bytes at `offset` of its folder's decoded stream.
struct File {
    size: u32,
    offset: u32,
    folder: u16,
    date: u16,
    time: u16,
    name: Vec<u8>,
}

/// What the header and the tables of a cabinet say.
struct Layout {
    /// The cabinet's size, which is also the object's.
    total: u32,
    /// Reserved bytes in each data block header.
    data_reserve: u64,
    /// Where the file table ends: the first data block follows.
    tables_end: u64,
    folders: Vec<Folder>,
    files: Vec<File>,
}

pub(super) fn extract<R: Read + Seek>(object: &mut R, run: &mut Run<'_>) -> Result<(), Stop> {
    let layout = layout(object, run.container)?;
    let mut by_folder: Vec<Vec<&File>> = layout.folders.iter().map(|_| Vec::new()).collect();
    for file in &layout.files {
        by_folder
            .get_mut(usize::from(file.folder))
            .ok_or(ARCHIVE)?
            .push(file);
    }
    let mut sizes = Vec::with_capacity(layout.folders.len());
    let mut at = layout.tables_end;
    for folder in &layout.folders {
        // The folders' blocks follow the tables and each other, and end the cabinet.
        if folder.first != at {
            return Err(ARCHIVE);
        }
        let (packed, decoded, end) =
            scan_blocks(object, folder, layout.data_reserve, layout.total)?;
        sizes.push((packed, decoded));
        at = end;
    }
    if at != u64::from(layout.total) {
        return Err(ARCHIVE);
    }
    for ((folder, mut files), (packed, decoded)) in layout.folders.iter().zip(by_folder).zip(sizes)
    {
        files.sort_by_key(|file| file.offset);
        // The files cover the folder's decoded bytes exactly, in order.
        let mut expected: u64 = 0;
        for file in &files {
            if u64::from(file.offset) != expected {
                return Err(ARCHIVE);
            }
            expected += u64::from(file.size);
        }
        if expected != decoded {
            return Err(ARCHIVE);
        }
        let mut reader = FolderReader {
            object: &mut *object,
            next: folder.first,
            left: folder.blocks,
            reserve: layout.data_reserve,
            codec: Codec::of(folder.compression)?,
            out: Vec::new(),
            at: 0,
        };
        let mut packed = Packed::new(packed);
        for file in files {
            let header = Header {
                path: file.name.clone(),
                kind: Kind::Regular,
                size: u64::from(file.size),
                modified: dos_time(file.date, file.time),
            };
            run.begin(&header, false)?;
            let mut bytes = (&mut reader).take(header.size);
            run.stream_from(&mut bytes, &mut packed, header.size, Malformed::Archive)?;
        }
    }
    Ok(())
}

/// The header, the folders and the files of a cabinet of `container` bytes.
fn layout<R: Read + Seek>(object: &mut R, container: u64) -> Result<Layout, Stop> {
    let head: [u8; 36] = read_array(object, 0)?;
    let total = u32::from_le_bytes([head[8], head[9], head[10], head[11]]);
    let files_at = u32::from_le_bytes([head[16], head[17], head[18], head[19]]);
    let folders = u16::from_le_bytes([head[26], head[27]]);
    let files = u16::from_le_bytes([head[28], head[29]]);
    let flags = u16::from_le_bytes([head[30], head[31]]);
    // The whole object is the cabinet (no bytes after it), version 1, not part of a cabinet set.
    if head[..4] != *b"MSCF"
        || u64::from(total) != container
        || head[25] != 1
        || flags & (PREV_CABINET | NEXT_CABINET) != 0
    {
        return Err(ARCHIVE);
    }
    let mut at: u64 = 36;
    let (folder_reserve, data_reserve) = if flags & RESERVE_PRESENT == 0 {
        (0, 0)
    } else {
        let [low, high, folder, data] = read_array(object, at)?;
        at += 4 + u64::from(u16::from_le_bytes([low, high]));
        (u64::from(folder), u64::from(data))
    };
    let mut table = Vec::with_capacity(usize::from(folders));
    for _ in 0..folders {
        let [f0, f1, f2, f3, b0, b1, c0, c1] = read_array(object, at)?;
        table.push(Folder {
            first: u64::from(u32::from_le_bytes([f0, f1, f2, f3])),
            blocks: u16::from_le_bytes([b0, b1]),
            compression: u16::from_le_bytes([c0, c1]),
        });
        at += 8 + folder_reserve;
    }
    let mut entries = Vec::with_capacity(usize::from(files));
    let mut at = u64::from(files_at);
    for _ in 0..files {
        let raw: [u8; 16] = read_array(object, at)?;
        let tail = read_up_to(object, at + 16, NAME)?;
        let name = tail
            .iter()
            .position(|&b| b == 0)
            .and_then(|end| tail.get(..end))
            .ok_or(ARCHIVE)?;
        at += 16 + u64::try_from(name.len()).map_err(|_| ARCHIVE)? + 1;
        entries.push(File {
            size: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
            offset: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
            folder: u16::from_le_bytes([raw[8], raw[9]]),
            date: u16::from_le_bytes([raw[10], raw[11]]),
            time: u16::from_le_bytes([raw[12], raw[13]]),
            name: name
                .iter()
                .map(|&b| if b == b'\\' { b'/' } else { b })
                .collect(),
        });
    }
    // A file in no folder of this cabinet (continued from or into another one) cannot be read here.
    if entries
        .iter()
        .any(|file| usize::from(file.folder) >= table.len())
    {
        return Err(ARCHIVE);
    }
    Ok(Layout {
        total,
        data_reserve,
        tables_end: at,
        folders: table,
        files: entries,
    })
}

/// The compressed and decoded sizes of a folder's data blocks, each one checked to lie in the cabinet, and
/// where the last one ends.
fn scan_blocks<R: Read + Seek>(
    object: &mut R,
    folder: &Folder,
    reserve: u64,
    total: u32,
) -> Result<(u64, u64, u64), Stop> {
    let (mut packed, mut decoded) = (0_u64, 0_u64);
    let mut at = folder.first;
    for _ in 0..folder.blocks {
        let [_, _, _, _, d0, d1, s0, s1] = read_array(object, at)?;
        let data = u16::from_le_bytes([d0, d1]);
        let size = u16::from_le_bytes([s0, s1]);
        if size == 0 || usize::from(size) > FRAME {
            return Err(ARCHIVE);
        }
        at += 8 + reserve + u64::from(data);
        if at > u64::from(total) {
            return Err(ARCHIVE);
        }
        packed += u64::from(data);
        decoded += u64::from(size);
    }
    Ok((packed, decoded, at))
}

/// `N` bytes at `at`; fewer is a cut cabinet.
fn read_array<const N: usize, R: Read + Seek>(object: &mut R, at: u64) -> Result<[u8; N], Stop> {
    let mut out = [0_u8; N];
    object.seek(SeekFrom::Start(at)).map_err(|_| ARCHIVE)?;
    object.read_exact(&mut out).map_err(|_| ARCHIVE)?;
    Ok(out)
}

/// Up to `len` bytes at `at`, fewer at the end of the object.
fn read_up_to<R: Read + Seek>(object: &mut R, at: u64, len: usize) -> Result<Vec<u8>, Stop> {
    object.seek(SeekFrom::Start(at)).map_err(|_| ARCHIVE)?;
    let mut out = Vec::with_capacity(len);
    object
        .take(u64::try_from(len).map_err(|_| ARCHIVE)?)
        .read_to_end(&mut out)
        .map_err(|_| ARCHIVE)?;
    Ok(out)
}

/// How a folder's blocks are decoded.
enum Codec {
    Stored,
    MsZip(Box<MsZip>),
    Lzx(Box<Lzxd>),
}

impl Codec {
    fn of(compression: u16) -> Result<Self, Stop> {
        match compression & 0x000F {
            0 => Ok(Self::Stored),
            1 => Ok(Self::MsZip(Box::new(MsZip {
                inflate: Decompress::new(false),
                window: Vec::new(),
            }))),
            2 => Err(Stop::Malformed(Malformed::Method)),
            3 => {
                let window = match (compression >> 8) & 0x1F {
                    15 => WindowSize::KB32,
                    16 => WindowSize::KB64,
                    17 => WindowSize::KB128,
                    18 => WindowSize::KB256,
                    19 => WindowSize::KB512,
                    20 => WindowSize::MB1,
                    21 => WindowSize::MB2,
                    _ => return Err(ARCHIVE),
                };
                Ok(Self::Lzx(Box::new(Lzxd::new(window))))
            }
            _ => Err(ARCHIVE),
        }
    }

    fn decode(&mut self, data: Vec<u8>, size: usize) -> io::Result<Vec<u8>> {
        match self {
            Self::Stored if data.len() == size => Ok(data),
            Self::Stored => Err(io::Error::other("stored block size")),
            Self::MsZip(mszip) => mszip.block(&data, size),
            Self::Lzx(lzx) => lzx
                .decompress_next(&data, size)
                .map(<[u8]>::to_vec)
                .map_err(io::Error::other),
        }
    }
}

/// MSZIP: each block is `CK` then a deflate stream that may refer to the previous 32 KiB of output.
struct MsZip {
    inflate: Decompress,
    window: Vec<u8>,
}

impl MsZip {
    fn block(&mut self, data: &[u8], size: usize) -> io::Result<Vec<u8>> {
        let bad = || io::Error::other("bad MSZIP block");
        let body = data.strip_prefix(b"CK").ok_or_else(bad)?;
        self.inflate.reset(false);
        if !self.window.is_empty() {
            // The previous output, replayed as a stored deflate block, primes the window.
            let len = u16::try_from(self.window.len()).map_err(|_| bad())?;
            let mut stored = vec![0];
            stored.extend_from_slice(&len.to_le_bytes());
            stored.extend_from_slice(&(!len).to_le_bytes());
            stored.extend_from_slice(&self.window);
            let mut primed = Vec::with_capacity(self.window.len());
            let status = self
                .inflate
                .decompress_vec(&stored, &mut primed, FlushDecompress::Sync)
                .map_err(|_| bad())?;
            if status != Status::Ok || primed.len() != self.window.len() {
                return Err(bad());
            }
        }
        let before = self.inflate.total_in();
        let mut out = Vec::with_capacity(size);
        let status = self
            .inflate
            .decompress_vec(body, &mut out, FlushDecompress::Finish)
            .map_err(|_| bad())?;
        let consumed = self.inflate.total_in() - before;
        if status != Status::StreamEnd
            || out.len() != size
            || consumed != u64::try_from(body.len()).map_err(|_| bad())?
        {
            return Err(bad());
        }
        self.window.extend_from_slice(&out);
        let excess = self.window.len().saturating_sub(FRAME);
        self.window.drain(..excess);
        Ok(out)
    }
}

/// A folder's decoded bytes, block after block.
struct FolderReader<'r, R> {
    object: &'r mut R,
    /// Where the next block's header is.
    next: u64,
    /// Blocks not decoded yet.
    left: u16,
    /// Reserved bytes in each block header.
    reserve: u64,
    codec: Codec,
    out: Vec<u8>,
    at: usize,
}

impl<R: Read + Seek> FolderReader<'_, R> {
    fn load(&mut self) -> io::Result<()> {
        let bad = || io::Error::other("bad data block");
        self.object.seek(SeekFrom::Start(self.next))?;
        let mut header = [0_u8; 8];
        self.object.read_exact(&mut header)?;
        let checksum = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let packed = u16::from_le_bytes([header[4], header[5]]);
        let size = usize::from(u16::from_le_bytes([header[6], header[7]]));
        if size == 0 || size > FRAME {
            return Err(bad());
        }
        self.object.seek(SeekFrom::Current(
            i64::try_from(self.reserve).map_err(|_| bad())?,
        ))?;
        let mut data = vec![0_u8; usize::from(packed)];
        self.object.read_exact(&mut data)?;
        if checksum != 0 && sum(header.get(4..8).unwrap_or_default(), sum(&data, 0)) != checksum {
            return Err(bad());
        }
        self.next += 8 + self.reserve + u64::from(packed);
        self.left -= 1;
        self.out = self.codec.decode(data, size)?;
        self.at = 0;
        Ok(())
    }
}

impl<R: Read + Seek> Read for FolderReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.at == self.out.len() {
            if self.left == 0 {
                return Ok(0);
            }
            self.load()?;
        }
        let rest = self.out.get(self.at..).unwrap_or_default();
        let count = rest.len().min(buffer.len());
        buffer
            .get_mut(..count)
            .unwrap_or_default()
            .copy_from_slice(rest.get(..count).unwrap_or_default());
        self.at += count;
        Ok(count)
    }
}

/// The cabinet checksum (MS-CAB 2.4, as libmspack computes it): XOR of the little-endian 32-bit words of
/// `data`, a short tail taken most significant byte first, starting from `seed`.
fn sum(data: &[u8], seed: u32) -> u32 {
    let (words, tail) = data.as_chunks::<4>();
    let checksum = words
        .iter()
        .fold(seed, |checksum, word| checksum ^ u32::from_le_bytes(*word));
    let tail = tail
        .iter()
        .fold(0_u32, |tail, &byte| (tail << 8) | u32::from(byte));
    checksum ^ tail
}
