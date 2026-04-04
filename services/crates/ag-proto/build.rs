use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    // proto/ is at the repo root: ../../ from crates/ag-proto/
    let proto_root = manifest_dir.join("../../../proto");
    let proto_root = proto_root.canonicalize().unwrap_or(proto_root);

    let protos = [
        "agentguard/common.proto",
        "agentguard/registry.proto",
        "agentguard/intent.proto",
        "agentguard/policy.proto",
        "agentguard/token.proto",
        "agentguard/kill.proto",
        "agentguard/risk.proto",
        "agentguard/control.proto",
    ];

    let proto_files: Vec<PathBuf> = protos.iter().map(|p| proto_root.join(p)).collect();

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&proto_files, &[&proto_root])?;

    Ok(())
}
