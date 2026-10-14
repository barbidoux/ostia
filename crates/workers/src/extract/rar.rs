//! RAR 1.3 to RAR 7, one volume (WP-1.9, Q-62), read by `rars`. Its extraction writes each member into a
//! boxed `'static` writer, so it runs on a helper thread that hands every member header and chunk over a
//! rendezvous channel: this thread applies the limits before the sink sees a byte, answers each member before
//! the decoder starts on it, and stops the decoder by dropping its end of the channel. A solid run of members
//! shares one compressed stream for the ratio (Q-64). Encrypted members are malformed as encrypted, members
//! continued in another volume as malformed archives; links are entries without bytes.

use std::io::{self, Read, Seek, Write};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;

use rars::{
    Archive, ArchiveMember, ArchiveReadOptions, ArchiveReader, ErrorKind, ExtractionDecision,
    StoredTimestamp,
};

use ostia_core_domain::verdict::Limit;

use super::{ARCHIVE, CHUNK, Header, Kind, Malformed, Packed, Run, Stop, dos_time};

/// The largest dictionary a member may ask for: RAR5's largest (RAR 7 allows 64 GiB).
const DICTIONARY: u64 = 1 << 30;

/// What the decoding thread hands over, in archive order.
enum Message {
    /// A member begins (its header, its compressed size, whether it continues the previous member's
    /// stream); the decoding thread waits for the answer before reading it.
    Member(Header, u64, bool),
    /// A directory, for its path only.
    Directory(Vec<u8>),
    /// The next bytes of the current member.
    Data(Vec<u8>),
    /// A member that cannot be extracted.
    Refused(Malformed),
}

pub(super) fn extract<R: Read + Seek + Send + 'static>(
    object: R,
    run: &mut Run<'_>,
) -> Result<(), Stop> {
    let options = ArchiveReadOptions::new()
        .with_rar50_dictionary_size_limit(DICTIONARY)
        .with_max_member_output_bytes(run.budget.remaining_bytes)
        .with_max_total_output_bytes(run.budget.remaining_bytes);
    let archive = ArchiveReader::read_reader_with_options(object, options)
        .map_err(|error| refused(&error))?;
    thread::scope(|scope| {
        let (messages, received) = sync_channel(0);
        let (answers, answered) = sync_channel(0);
        let thread = scope.spawn(move || decode(&archive, options, &messages, &answered));
        let driven = drive(run, &received, &answers);
        drop(received);
        drop(answers);
        let decoded = thread.join();
        match (driven, decoded) {
            (Err(stop), _) => Err(stop),
            (Ok(_), Err(_)) => Err(ARCHIVE),
            (Ok(_), Ok(Err(error))) => Err(refused(&error)),
            // The last member ended where its header said.
            (Ok(Some((declared, got))), Ok(Ok(()))) if declared != got => {
                Err(Stop::Malformed(Malformed::Size))
            }
            (Ok(_), Ok(Ok(()))) => Ok(()),
        }
    })
}

/// The decoding thread: every member in turn, each one announced and answered before it is read.
fn decode(
    archive: &Archive,
    options: ArchiveReadOptions<'_>,
    messages: &SyncSender<Message>,
    answered: &Receiver<bool>,
) -> rars::Result<()> {
    archive
        .extract_with_control(options, |member| {
            let message = announce(member).unwrap_or_else(Message::Refused);
            let directory = matches!(message, Message::Directory(_));
            let link = matches!(&message, Message::Member(header, ..) if header.kind == Kind::Link);
            let refused = matches!(message, Message::Refused(_));
            // A closed channel or a refusal means this thread's work is over.
            if messages.send(message).is_err() || refused {
                return Ok(ExtractionDecision::Stop);
            }
            if directory {
                return Ok(ExtractionDecision::Skip);
            }
            if answered.recv() != Ok(true) {
                return Ok(ExtractionDecision::Stop);
            }
            if link {
                return Ok(ExtractionDecision::Skip);
            }
            Ok(ExtractionDecision::Extract(Box::new(Forward(
                messages.clone(),
            ))))
        })
        .map(|_| ())
}

/// What to announce for `member`, or why it cannot be extracted.
fn announce(member: &ArchiveMember) -> Result<Message, Malformed> {
    let meta = &member.meta;
    if meta.is_split_before || meta.is_split_after {
        return Err(Malformed::Archive);
    }
    if meta.is_encrypted {
        return Err(Malformed::Encrypted);
    }
    if meta.is_directory {
        return Ok(Message::Directory(meta.name.clone()));
    }
    let kind = if meta.is_redirection {
        Kind::Link
    } else {
        Kind::Regular
    };
    let modified = meta.stored_modification_time().and_then(|time| match time {
        StoredTimestamp::UnixSeconds(seconds) => Some(i64::from(seconds)),
        StoredTimestamp::DosLocal(raw) => dos_time(
            u16::try_from(raw >> 16).ok()?,
            u16::try_from(raw & 0xFFFF).ok()?,
        ),
        _ => None,
    });
    let header = Header {
        path: meta.name.clone(),
        kind,
        size: if kind == Kind::Regular {
            meta.unpacked_size
        } else {
            0
        },
        modified,
    };
    Ok(Message::Member(header, meta.packed_size, member.is_solid()))
}

/// This thread's side: every message checked against the limits, in order. Returns the current member's
/// declared and received sizes when the decoding thread is done.
fn drive(
    run: &mut Run<'_>,
    received: &Receiver<Message>,
    answers: &SyncSender<bool>,
) -> Result<Option<(u64, u64)>, Stop> {
    let mut packed = Packed::new(0);
    let mut current: Option<(u64, u64)> = None;
    for message in received {
        match message {
            Message::Member(header, size, solid) => {
                complete(current.take())?;
                run.begin(&header, false)?;
                // A member larger than what remains is refused before it is decoded.
                if run.produced.saturating_add(header.size) > run.budget.remaining_bytes {
                    return Err(Stop::Limit(Limit::TotalSize));
                }
                if solid {
                    packed.size = packed.size.saturating_add(size);
                } else {
                    packed = Packed::new(size);
                }
                if header.kind == Kind::Regular {
                    current = Some((header.size, 0));
                }
                if answers.send(true).is_err() {
                    return Err(ARCHIVE);
                }
            }
            Message::Directory(path) => {
                complete(current.take())?;
                run.check_path(&path, false)?;
            }
            Message::Data(bytes) => {
                let (declared, got) = current.as_mut().ok_or(ARCHIVE)?;
                run.accept(&mut packed, got, *declared, &bytes)?;
            }
            Message::Refused(why) => return Err(Stop::Malformed(why)),
        }
    }
    Ok(current)
}

/// A member's bytes ended where its header said.
fn complete(member: Option<(u64, u64)>) -> Result<(), Stop> {
    match member {
        Some((declared, got)) if declared != got => Err(Stop::Malformed(Malformed::Size)),
        _ => Ok(()),
    }
}

/// The writer `rars` decodes a member into: chunks go over the channel, and a closed channel stops it.
struct Forward(SyncSender<Message>);

impl Write for Forward {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for chunk in bytes.chunks(CHUNK) {
            self.0
                .send(Message::Data(chunk.to_vec()))
                .map_err(|_| io::Error::other("extraction stopped"))?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The malformation behind a `rars` error.
fn refused(error: &rars::Error) -> Stop {
    Stop::Malformed(match error.kind() {
        ErrorKind::PasswordRequired | ErrorKind::BadPassword => Malformed::Encrypted,
        ErrorKind::UnsupportedFeature | ErrorKind::UnsupportedFormat | ErrorKind::ResourceLimit => {
            Malformed::Method
        }
        ErrorKind::UnsafePath => Malformed::Path,
        _ => Malformed::Archive,
    })
}
