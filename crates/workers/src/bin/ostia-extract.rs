//! The extraction worker (FR-06, ADR-18): one framed `AnalyzeRequest` carrying an `ExtractionBudget` on
//! standard input, the container on descriptor 3, a stream of `ExtractFrame`s on standard output: for each entry
//! an `entry` frame then its bytes in `data` frames, then one `done` frame, the worker's response.
//!
//! The response's status is OK when every entry was streamed; ERROR when a limit was reached (`limit` names
//! it) or the container is malformed (a finding says why), the stream then ending where the extraction
//! stopped; UNSUPPORTED for a type this worker does not extract. Exit 0 after the response; exit 2, with
//! nothing on standard output, when the request is not a valid frame or has no budget; exit 1 when the output
//! cannot be written.
//!
//! Descriptor 3 is opened again through `/proc/self/fd/3`, which needs no unsafe code; the sandbox of P2 must
//! give the worker `/proc` for it.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::process::ExitCode;
use std::time::Instant;

use ostia_contracts::v1::extract_frame::Frame;
use ostia_contracts::v1::{
    AnalyzeResponse, Entry, EntryKind, ExtractFrame, ExtractionBudget, Finding, Hint, Status,
};
use ostia_contracts::{
    DEFAULT_MAX_FRAME, current_version, decode_request, read_frame, write_frame,
};
use ostia_core_domain::types::DetectedType;
use ostia_workers::extract::{Budget, Format, Header, Kind, Malformed, Sink, Stop, extract};

/// Identity of this worker (CTR-03): zip, tar and gzip (version 1), then 7z, rar, cab, iso and msi (version 2).
const ENGINE_ID: &str = "ostia-extract";
const CONTENT_VERSION: &str = "formats-2";

/// The object's descriptor (ADR-03).
const OBJECT: &str = "/proc/self/fd/3";

/// Writes entries as frames on standard output.
struct Frames<W: Write> {
    out: W,
}

impl<W: Write> Frames<W> {
    fn send(&mut self, frame: Frame) -> io::Result<()> {
        let frame = ExtractFrame {
            frame: Some(frame),
            version: Some(current_version()),
        };
        write_frame(&mut self.out, &frame, DEFAULT_MAX_FRAME).map_err(io::Error::other)
    }
}

impl<W: Write> Sink for Frames<W> {
    fn entry(&mut self, header: &Header) -> io::Result<()> {
        let kind = match header.kind {
            Kind::Regular => EntryKind::Regular,
            Kind::Link => EntryKind::Link,
            Kind::Special => EntryKind::Special,
        };
        self.send(Frame::Entry(Entry {
            path: header.path.clone(),
            kind: kind.into(),
            size: header.size,
            modified: header.modified,
        }))
    }

    fn data(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.send(Frame::Data(bytes.to_vec()))
    }
}

/// The finding of a malformed container: why, never content.
fn malformed(why: Malformed) -> Finding {
    let (id, title) = match why {
        Malformed::Archive => ("extract.archive", "container cannot be read"),
        Malformed::Encrypted => ("extract.encrypted", "encrypted entry"),
        Malformed::Method => (
            "extract.method",
            "entry compressed with an unsupported method",
        ),
        Malformed::Path => ("extract.path", "entry path leaving its container"),
        Malformed::Size => (
            "extract.size",
            "entry size does not match its declared size",
        ),
    };
    Finding {
        id: id.into(),
        title: title.into(),
        severity: 2,
        evidence: String::new(),
        attack_ids: Vec::new(),
    }
}

fn budget(budget: &ExtractionBudget) -> Budget {
    Budget {
        max_ratio: budget.max_ratio,
        remaining_bytes: budget.remaining_bytes,
        remaining_entries: budget.remaining_entries,
        max_path_length: budget.max_path_length,
    }
}

fn main() -> ExitCode {
    let started = Instant::now();
    let request = read_frame(&mut io::stdin().lock(), DEFAULT_MAX_FRAME)
        .and_then(|body| decode_request(&body));
    let request = match request {
        Ok(request) => request,
        Err(error) => {
            eprintln!("ostia-extract: request refused: {error}");
            return ExitCode::from(2);
        }
    };
    let Some(limits) = request.extraction.as_ref().map(budget) else {
        eprintln!("ostia-extract: request refused: no extraction budget");
        return ExitCode::from(2);
    };
    let mut frames = Frames {
        out: BufWriter::new(io::stdout().lock()),
    };
    let format = DetectedType::from_name(&request.detected_type).and_then(Format::of);
    let (status, limit, findings) = match format {
        None => (Status::Unsupported, String::new(), Vec::new()),
        Some(format) => {
            let extracted = File::open(OBJECT)
                .map_err(|_| Stop::Malformed(Malformed::Archive))
                .and_then(|object| extract(format, BufReader::new(object), &limits, &mut frames));
            match extracted {
                Ok(()) => (Status::Ok, String::new(), Vec::new()),
                Err(Stop::Limit(limit)) => (Status::Error, limit.code().to_owned(), Vec::new()),
                Err(Stop::Malformed(why)) => (Status::Error, String::new(), vec![malformed(why)]),
                Err(Stop::Sink(error)) => {
                    eprintln!("ostia-extract: cannot write the output: {error}");
                    return ExitCode::from(1);
                }
            }
        }
    };
    let done = AnalyzeResponse {
        engine_id: ENGINE_ID.into(),
        engine_version: env!("CARGO_PKG_VERSION").into(),
        content_version: CONTENT_VERSION.into(),
        status: status.into(),
        hint: Hint::None.into(),
        score: None,
        findings,
        duration_ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
        detected_type: String::new(),
        limit,
        version: Some(current_version()),
    };
    match frames
        .send(Frame::Done(done))
        .and_then(|()| frames.out.flush())
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ostia-extract: cannot write the output: {error}");
            ExitCode::from(1)
        }
    }
}
