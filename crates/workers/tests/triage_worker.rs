//! FR-05 and CTR-01 through the worker host: the triage worker reads the object on descriptor 3 and answers
//! one framed response carrying the type found in the content. It never sees a name, so a renamed file keeps
//! its content's type.

mod samples;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ostia_contracts::v1::{AnalyzeRequest, ContractVersion, Hint, Origin, Status};
use ostia_sandbox::{EngineIdentity, HostLimits, WorkerCommand, WorkerHost, WorkerRun};
use ostia_traceability::req;

static OBJECTS: AtomicU32 = AtomicU32::new(0);

fn worker() -> WorkerCommand {
    WorkerCommand::new(env!("CARGO_BIN_EXE_ostia-triage"), Vec::<String>::new())
}

fn identity() -> EngineIdentity {
    EngineIdentity {
        id: "ostia-triage".into(),
        version: "0.0.0".into(),
        content_version: "magic-1".into(),
    }
}

fn request() -> AnalyzeRequest {
    AnalyzeRequest {
        session_id: "session-1".into(),
        object_id: "object-1".into(),
        sha256: vec![0; 32],
        detected_type: String::new(),
        size: 0,
        origin: Origin::File.into(),
        limits: None,
        version: Some(ContractVersion { major: 1, minor: 1 }),
    }
}

/// Runs the triage worker on `bytes`, written to a file called `name`.
fn triage(name: &str, bytes: &[u8]) -> WorkerRun {
    let dir = std::env::temp_dir().join(format!(
        "ostia-triage-{}-{}",
        std::process::id(),
        OBJECTS.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("directory");
    let object: PathBuf = dir.join(name);
    std::fs::write(&object, bytes).expect("object");
    let host = WorkerHost::unconfined(HostLimits::new(Duration::from_secs(30)));
    let done = host.run(&worker(), &identity(), &request(), &object);
    let _ = std::fs::remove_dir_all(&dir);
    done
}

#[req("FR-05", "CTR-01")]
#[test]
fn typed_corpus_is_identified_through_the_worker_host() {
    for (name, bytes) in samples::typed()
        .into_iter()
        .chain(samples::untyped().into_iter().map(|(_, b)| ("unknown", b)))
    {
        let done = triage("object", &bytes);
        assert_eq!(done.failure, None, "{name}: {:?}", done.stderr);
        let response = done.response;
        assert_eq!(response.detected_type, name, "{name}");
        assert_eq!(
            (
                response.engine_id.as_str(),
                response.engine_version.as_str(),
                response.content_version.as_str()
            ),
            ("ostia-triage", "0.0.0", "magic-1")
        );
        assert_eq!(
            (response.status, response.hint, response.score),
            (i32::from(Status::Ok), i32::from(Hint::None), None),
            "{name}"
        );
        assert!(response.findings.is_empty(), "{name}");
        assert_eq!(
            response.version,
            Some(ContractVersion { major: 1, minor: 1 })
        );
    }
}

#[req("FR-05")]
#[test]
fn renamed_files_keep_the_type_of_their_content() {
    let png = samples::typed()
        .into_iter()
        .find(|(name, _)| *name == "png")
        .expect("png sample")
        .1;
    for name in ["report.pdf", "photo.png", "no-extension", "setup.exe"] {
        assert_eq!(triage(name, &png).response.detected_type, "png", "{name}");
    }
}

#[req("CTR-01")]
#[test]
fn request_that_is_not_a_valid_frame_gets_no_answer() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ostia-triage"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("triage worker");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&[0xde, 0xad, 0xbe, 0xef, 0x00])
        .expect("garbage written");
    let output = child.wait_with_output().expect("worker ends");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
}
