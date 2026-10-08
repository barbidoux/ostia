//! CTR-01: the worker gets its standard streams and the object, nothing else. A descriptor of the host without
//! close-on-exec would reach the worker, so the host refuses to launch while one exists.
//!
//! This test makes a descriptor of its whole process inheritable, which would make every concurrent run of the
//! process refuse to launch: it lives alone in this test binary, a process of its own under both nextest and
//! the standard `cargo test` harness.

use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::Duration;

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use ostia_contracts::v1::{AnalyzeRequest, ContractVersion, Hint, Origin, Status};
use ostia_sandbox::{EngineIdentity, Failure, HostLimits, WorkerCommand, WorkerHost};
use ostia_traceability::req;

#[req("CTR-01")]
#[test]
fn inheritable_descriptor_of_the_host_stops_the_launch() {
    let dir: PathBuf = std::env::temp_dir().join(format!("ostia-inherited-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("directory");
    let object = dir.join("object");
    std::fs::write(&object, b"ostia object\n").expect("object");
    let script = dir.join("worker.sh");
    std::fs::write(&script, format!("touch '{}/started'\n", dir.display())).expect("script");

    let stray = std::fs::File::open(&object).expect("stray descriptor");
    fcntl(&stray, FcntlArg::F_SETFD(FdFlag::empty())).expect("inheritable");
    let fd = u32::try_from(stray.as_raw_fd()).expect("descriptor number");
    let identity = EngineIdentity {
        id: "av".into(),
        version: "1.0.0".into(),
        content_version: "rules-1".into(),
    };
    let request = AnalyzeRequest {
        session_id: "session-1".into(),
        object_id: "object-7".into(),
        sha256: vec![0x86; 32],
        detected_type: "text".into(),
        size: 13,
        origin: Origin::File.into(),
        limits: None,
        version: Some(ContractVersion { major: 1, minor: 0 }),
    };
    let host = WorkerHost::unconfined(HostLimits::new(Duration::from_secs(30)));
    let done = host.run(
        &WorkerCommand::new("/bin/sh", [&script]),
        &identity,
        &request,
        &object,
    );
    drop(stray);
    let started = dir.join("started").exists();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(done.failure, Some(Failure::InheritedDescriptors(vec![fd])));
    assert_eq!(
        (
            done.response.engine_id.as_str(),
            done.response.status,
            done.response.hint
        ),
        ("av", i32::from(Status::Error), i32::from(Hint::None))
    );
    assert!(!started, "the worker ran");
}
