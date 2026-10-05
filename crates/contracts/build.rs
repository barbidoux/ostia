//! Generates the Rust types of `proto/ostia/engine/v1/engine.proto` with prost, compiling the `.proto`
//! with protox (a Protobuf compiler written in Rust): no `protoc` and no network at build time (ADR-15).

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../proto");
    let proto = "ostia/engine/v1/engine.proto";
    println!(
        "cargo:rerun-if-changed={}",
        proto_root.join(proto).display()
    );
    let descriptors = protox::compile([proto], [&proto_root])?;
    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
