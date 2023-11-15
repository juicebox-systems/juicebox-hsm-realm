use clap::ValueEnum;

use crate::{join_path, Context, Error, Process};

/// Compile HSM-related programs from source.
#[derive(clap::Args, Debug)]
pub struct Args {
    /// What to build.
    #[clap(required = true)]
    targets: Vec<Target>,
}

/// Things that can be built.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Target {
    /// The `entrust_init` program, which runs on the host computer to create
    /// HSM keys and initialize HSM NVRAM with appropriate ACLs.
    #[clap(name = "init", alias = "entrust_init", alias = "entrust-init")]
    EntrustInit,

    /// The `entrust_hsm.elf` HSM program which must be signed, and the signed
    /// archive can be executed on the HSM.
    #[clap(
        name = "hsm",
        alias = "entrust-hsm",
        alias = "entrust-hsm.elf",
        alias = "entrust_hsm",
        alias = "entrust_hsm.elf"
    )]
    EntrustHsm,
}

pub fn run(args: &Args, context: &Context) -> Result<(), Error> {
    for target in &args.targets {
        match target {
            Target::EntrustInit => build_init(context)?,
            Target::EntrustHsm => build_hsm(context)?,
        }
    }
    Ok(())
}

fn build_init(context: &Context) -> Result<(), Error> {
    assert_eq!(
        context.paths.entrust_init,
        join_path(
            &context.paths.juicebox_hsm_realm_dir,
            "target/release/entrust_init"
        )
    );
    context.exec(
        Process::new(
            "cargo",
            &[
                "build",
                "--frozen",
                "--release",
                "--package",
                "entrust_init",
            ],
        )
        .dir(&context.paths.juicebox_hsm_realm_dir),
    )?;
    context.print_file_digest(&context.paths.entrust_init)
}

fn build_hsm(context: &Context) -> Result<(), Error> {
    assert_eq!(
        context.paths.signing_dir,
        join_path(
            &context.paths.juicebox_hsm_realm_dir,
            "target/powerpc-unknown-linux-gnu/release"
        )
    );
    context.exec(
        Process::new("entrust_hsm/compile_linux.sh", &["--frozen"])
            .dir(&context.paths.juicebox_hsm_realm_dir),
    )?;
    context.print_file_digest(&join_path(&context.paths.signing_dir, "entrust_hsm.elf"))
}
