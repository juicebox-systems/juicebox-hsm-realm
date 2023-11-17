use clap::CommandFactory;
use expect_test::expect_file;
use std::fmt::Write;
use std::process;

use entrust_ops::Args;

fn get_usage(args: &[&str]) -> String {
    let bin = env!("CARGO_BIN_EXE_entrust_ops");

    let output = process::Command::new(bin)
        .args(args)
        .arg("--help")
        .env_clear()
        .env(
            "ENTRUST_INIT",
            "/home/entrust_ops_test/juicebox-hsm-realm/target/release/entrust_init",
        )
        .env(
            "SIGNING_DIR",
            "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release",
        )
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
        // usage is unreproducible because the paths vary depending on where
        // you run this. Instead, use a child process to override environment
        // variables to control the paths.
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

    recursive_usage(&mut all_usage, &["entrust_ops"], &mut Args::command());
    all_usage
}

/// Snapshot test for usage output. See `usage.md`.
#[test]
fn test_usage() {
    let actual = get_all_usage();
    expect_file!["../usage.md"].assert_eq(&actual);
}
