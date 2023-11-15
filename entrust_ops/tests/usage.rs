use clap::CommandFactory;
use std::fmt::Write;
use std::fs;
use std::io;
use std::process;

use entrust_ops::Args;

fn get_usage(args: &[&str]) -> String {
    let bin = env!("CARGO_BIN_EXE_entrust_ops");

    let output = process::Command::new(bin)
        .args(args)
        .arg("--help")
        .env_clear()
        .env("HOME", "/home/ceremony-test")
        .output()
        .unwrap_or_else(|err| panic!("failed to run {bin} {} --help: {err}", args.join(" ")));

    assert!(
        output.status.success(),
        "non-zero status {bin} {} --help: {:?}",
        args.join(" "),
        output
    );
    assert_eq!(
        output.stderr,
        b"",
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn get_all_usage() -> String {
    fn recursive_usage(buf: &mut String, argv: &[&str], command: &mut clap::Command) {
        command.set_bin_name(argv.join(" "));
        let heading_level = "#".repeat(argv.len());
        writeln!(buf, "{heading_level} {}", argv.join(" ")).unwrap();
        writeln!(buf).unwrap();
        writeln!(buf, "```").unwrap();
        // This could almost do `command.render_long_help()`, but then the
        // usage is unreproducible because `$HOME` varies. Instead, use a child
        // process to override $HOME.
        write!(buf, "{}", get_usage(&argv[1..])).unwrap();
        writeln!(buf, "```").unwrap();
        writeln!(buf).unwrap();

        for subcommand in command.get_subcommands_mut() {
            let name = subcommand.get_name();
            if name == "help" {
                continue;
            }
            let name = name.to_owned();
            let mut child_args = argv.to_vec();
            child_args.push(&name);
            recursive_usage(buf, &child_args, subcommand);
        }
    }

    let mut all_usage = String::new();

    let that = "This";
    writeln!(&mut all_usage, "_{that} file is automatically generated._").unwrap();
    writeln!(&mut all_usage).unwrap();

    recursive_usage(&mut all_usage, &["ceremony"], &mut Args::command());
    all_usage
}

/// Snapshot test for usage output. See `usage.md`.
#[test]
fn test_usage() {
    let expected = fs::read_to_string("usage.md").unwrap();
    let actual = get_all_usage();
    if expected == actual {
        if let Err(err) = fs::remove_file("usage.actual.md") {
            if err.kind() != io::ErrorKind::NotFound {
                panic!("failed to delete `usage.actual.md`: {err}");
            }
        }
    } else {
        fs::write("usage.actual.md", &actual).unwrap();
        panic!("usage differs: compare expected (`usage.md`) with actual (`usage.actual.md`)");
    }
}
