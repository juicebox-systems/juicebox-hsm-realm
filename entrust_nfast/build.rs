use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{copy, Write};
use std::path::PathBuf;

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search=/opt/nfast/c/csd/gcc/lib/");

    // Tell cargo to tell rustc to link the entrust libraries.
    for lib in ["rqcard", "nfkm", "nfstub", "nflog", "cutils"] {
        println!("cargo:rustc-link-lib={lib}");
    }

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=src/bindgen.h");

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for.
        .header("src/bindgen.h")
        .use_core()
        .prepend_enum_name(false)
        .derive_default(true)
        .impl_debug(true)
        .generate_comments(false)
        .allowlist_function("NF.*(Init|Connect|Disconnect|Transact|Submit|Query|Wait|Free_Reply|FreeACL|Lookup)")
        .allowlist_function("NFKM_(findkey|freekey|recordkey|cmd_loadblob|getinfo|.*newkey.*|loadadminkeys.*|cert.*|getusablemodule)")
        .allowlist_function("RQCard.*")
        .allowlist_var("Cmd_CreateSEEWorld_Args.*")
        .allowlist_var("Cmd_LoadBuffer.*")
        .allowlist_var("Cmd_GenerateKey.*_flags.*")
        .allowlist_var("NFastApp_ConnectionFlags.*")
        .allowlist_var("Key_flags_.*")
        .allowlist_var("Command_flags.*")
        .allowlist_var("StatInfo_flags_.*")
        .allowlist_var(".*_(enum)?table")
        .allowlist_var(".*PermissionGroup.*")
        .allowlist_var("Act_.*_Details_.*")
        .allowlist_var("FileDevice.*")
        .allowlist_var("NFKM_NKF_.*")
        .allowlist_type("NFKM_(Admin.*|LoadAdminKeysHandle)")
        .allowlist_type("M_SEEInitStatus")
        .allowlist_type("M_KeyMgmtEntType")
        .allowlist_type("M_StatNodeTag")
        .clang_arg("-I/opt/nfast/c/csd/include-see/cutils/")
        .clang_arg("-I/opt/nfast/c/csd/gcc/include/cutils/")
        .clang_arg("-I/opt/nfast/c/csd/gcc/include/hilibs")
        .clang_arg("-I/opt/nfast/c/csd/gcc/include/sworld/")

        // Tell cargo to invalidate the built crate whenever any of the included
        // header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
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
        "d42d17efbf4b75b3b53434c79822126c21d4398bcbebb53d59c750af033be451",
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
