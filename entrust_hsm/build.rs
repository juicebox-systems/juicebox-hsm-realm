use std::env;
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
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
