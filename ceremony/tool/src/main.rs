//! This tool is used during HSM key ceremonies to run pre-determined commands.

use clap::Parser;
use std::process::ExitCode;

use ceremony::{commands, Args, Context, Paths};

/// Runs the program.
fn main() -> ExitCode {
    let args = Args::parse();
    println!("{args:#?}");
    println!();

    let context = Context {
        common_args: args.common,
        paths: Paths::get(),
    };

    match commands::run(&args.command, &context) {
        Ok(()) => ExitCode::SUCCESS,

        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}
