//! Generates `src/autogen` from Google's API definitions.
//!
//! You need to run this from the project's top-level directory. It needs
//! `protoc` installed and needs the `googleapis` submodule checked out. Then,
//! run `cargo run -p codegen`.

use std::env;
use std::fs;
use std::io;
use std::path::Path;

fn main() {
    let input = Path::new("googleapis");
    let output = Path::new("google/src/autogen");

    if let Err(e) = fs::metadata(input) {
        let cwd = env::current_dir().unwrap();
        panic!("need {input:?} submodule relative to current working directory {cwd:?}: {e:?}");
    }

    match fs::remove_dir_all(output) {
        Ok(()) => { /* ok */ }
        Err(e) if e.kind() == io::ErrorKind::NotFound => { /* ok */ }
        Err(e) => panic!("failed to remove {output:?} dir: {e:?}"),
    }
    fs::create_dir_all(output).unwrap_or_else(|e| panic!("failed to create {output:?} dir: {e:?}"));

    tonic_build::configure()
        .build_server(false)
        .emit_rerun_if_changed(false)
        .include_file("mod.rs")
        .out_dir(output)
        // See
        // <https://protobuf.dev/programming-guides/field_presence/#protoc-invocation>.
        // This flag is no longer necessary starting with protoc v3.15.0.
        // Debian 11 ("Bullseye") includes v3.12 and Debian 12 ("Bookworm")
        // includes v3.21.
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(
            &[
                input.join("google/bigtable/v2/bigtable.proto"),
                input.join("google/bigtable/admin/v2/bigtable_table_admin.proto"),
                input.join("google/cloud/secretmanager/v1/service.proto"),
                input.join("google/rpc/code.proto"),
            ],
            &[input], // root location to search proto dependencies
        )
        .expect("tonic build failed");
}
