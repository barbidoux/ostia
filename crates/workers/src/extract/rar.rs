//! RAR 1.3 to RAR 7, one volume (WP-1.9, Q-62), read by `rars`. Its extraction writes each member into a
//! boxed `'static` writer, so it runs on a helper thread that hands every member header and chunk over a
//! rendezvous channel: this thread applies the limits before the sink sees a byte, answers each member before
//! the decoder starts on it, and stops the decoder by dropping its end of the channel. A solid run of members
//! shares one compressed stream for the ratio (Q-64). Encrypted members are malformed as encrypted, members
//! continued in another volume as malformed archives; links are entries without bytes, and a directory or a
//! link carrying bytes is malformed.
//!
//! Service headers (Q-66): the archive comment is an entry, `[comment]`, after the members; quick-open and
//! recovery data are checked by the crate and kept out; any other service or unknown block carrying data
//! (an NTFS alternate stream, a comment attached to a file) is an unsupported method.

use std::io::{self, Read, Seek, Write};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;

use rars::rar15_40::{self, NewSubKind};
use rars::{
    Archive, ArchiveMember, ArchiveReadOptions, ArchiveReader, ErrorKind, ExtractionDecision,
    ExtractionOutcome, StoredTimestamp, rar50,
};

use ostia_core_domain::verdict::Limit;

use super::{ARCHIVE, CHUNK, DICTIONARY, Header, Kind, Malformed, Packed, Run, Stop, dos_time};

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
    check_blocks(&archive, run.container)?;
    let comment = archive
        .comment_with_options(options)
        .map_err(|error| refused(&error))?;
    let members = thread::scope(|scope| {
        let (messages, received) = sync_channel(0);
        let (answers, answered) = sync_channel(0);
        let archive = &archive;
        let thread = scope.spawn(move || decode(archive, options, &messages, &answered));
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
    });
    members?;
    if let Some(comment) = comment {
        let header = Header {
            path: COMMENT.to_vec(),
            kind: Kind::Regular,
            size: u64::try_from(comment.len()).map_err(|_| ARCHIVE)?,
            modified: None,
        };
        run.begin(&header, false)?;
        run.stream(
            &mut comment.as_slice(),
            header.size,
            header.size,
            Malformed::Archive,
        )?;
    }
    Ok(())
}

/// The entry holding the archive comment.
const COMMENT: &[u8] = b"[comment]";

/// RAR5 services the crate reads and checks itself: quick open, recovery record, the archive comment.
const KEPT: [&[u8]; 3] = [b"QO", b"RR", b"CMT"];

/// Refuses data the extraction would not see: a service or an unknown block carrying data, other than the
/// quick-open copy, the recovery record and the one archive comment (read as an entry); bytes after the
/// end-of-archive block of a `container`-byte object, or an end block announcing another volume.
fn check_blocks(archive: &Archive, container: u64) -> Result<(), Stop> {
    let method = Stop::Malformed(Malformed::Method);
    let ends_at = |end: usize| u64::try_from(end).ok() == Some(container);
    match archive {
        Archive::Rar50Plus(archive) => {
            let mut files = false;
            let mut ended = false;
            for block in &archive.blocks {
                match block {
                    rar50::Block::End(end) => {
                        if end.has_next_volume() || !ends_at(end.block.header_range.end) {
                            return Err(ARCHIVE);
                        }
                        ended = true;
                    }
                    rar50::Block::File(_) => files = true,
                    rar50::Block::Service(service) => {
                        let carries = service.block.data_size.is_some_and(|size| size > 0);
                        let kept = KEPT.contains(&service.name.as_slice());
                        // Only a comment before any file is the archive's; one after a file is not read.
                        let attached = service.name == b"CMT" && files;
                        if carries && (!kept || attached) {
                            return Err(method);
                        }
                    }
                    rar50::Block::Unknown(header) if header.data_size.is_some_and(|s| s > 0) => {
                        return Err(method);
                    }
                    _ => {}
                }
            }
            if !ended {
                return Err(ARCHIVE);
            }
        }
        Archive::Rar15To40(archive) => {
            for block in &archive.blocks {
                match block {
                    rar15_40::Block::NewSub(sub)
                        if matches!(sub.kind, NewSubKind::Unknown(_)) && sub.file.pack_size > 0 =>
                    {
                        return Err(method);
                    }
                    rar15_40::Block::Unknown(header) if header.add_size.is_some_and(|s| s > 0) => {
                        return Err(method);
                    }
                    // An end block (optional before RAR 3) closes the object.
                    rar15_40::Block::End(end) => {
                        let close = end.offset.checked_add(usize::from(end.head_size));
                        if !close.is_some_and(ends_at) {
                            return Err(ARCHIVE);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(())
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
        .and_then(|outcome| match outcome {
            ExtractionOutcome::Complete => Ok(()),
            // Stopped only after this thread's side failed or refused a member: never a success.
            ExtractionOutcome::Stopped => Err(rars::Error::from(io::Error::other("stopped"))),
        })
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
    // A directory or a link has no bytes: any is hidden data.
    if (meta.is_directory || meta.is_redirection)
        && (meta.packed_size > 0 || meta.unpacked_size > 0)
    {
        return Err(Malformed::Archive);
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
                // A member larger than what remains is refused before it is announced or decoded.
                if run.produced.saturating_add(header.size) > run.budget.remaining_bytes {
                    return Err(Stop::Limit(Limit::TotalSize));
                }
                run.begin(&header, false)?;
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
