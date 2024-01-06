use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{copy, Write};
use std::path::PathBuf;

fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=/opt/nfast/c/csd/include-see/module/seelib.h");

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for.
        .header("/opt/nfast/c/csd/include-see/module/seelib.h")
        .use_core()
        .prepend_enum_name(false)
        .derive_default(true)
        .impl_debug(true)
        .layout_tests(false)
        .generate_comments(false)
        .allowlist_function("SEElib.*(init|InitComplete|AwaitJobEx|ReturnJob|Transact|FreeReply)")
        .allowlist_var("SEELIB_JOB_REQUEUE")
        .allowlist_var("Command_flags_.*")
        .clang_arg("--target=powerpc-unknown-linux-gnu")
        .clang_arg("-I/opt/nfast/c/csd/include-see/cutils")
        .clang_arg("-I/opt/nfast/c/csd/include-see/module/")
        .clang_arg("-I/opt/nfast/c/csd/include-see/module/rtlib")
        .clang_arg("-I/opt/nfast/gcc/powerpc-codesafe-linux-gnu/include/")
        .clang_arg("-fno-builtin")
        .clang_arg("-nobuiltininc")
        .clang_arg("-DNF_CROSSCC_PPC_GCC=1")
        // Tell cargo to invalidate the built crate whenever any of the included
        // header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = out_path.join("bindings.rs");
    bindings
        .write_to_file(&out_file)
        .expect("Couldn't write bindings!");

    let mut hasher = WritableHash(Sha256::new());
    let mut file = File::open(&out_file).expect("Failed to open file {out_file}");
    copy(&mut file, &mut hasher).expect("Couldn't hash bindings!");
    let hash = hasher.0.finalize();
    assert_eq!(
        hex::encode(hash),
        "07fe0cfa4e37f3f77cfcc7c579918c51d4e220723ad84f90e4921556b566fb8b",
        "SHA-256 of {out_file:?} (left) doesn't match expected (right)"
    );
}

struct WritableHash(Sha256);

impl Write for WritableHash {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
