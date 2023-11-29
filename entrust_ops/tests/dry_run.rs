use expect_test::expect_file;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{self, Stdio};

struct TestCase {
    args: &'static [&'static str],
    stdin: &'static str,
}

impl TestCase {
    const fn new(args: &'static [&'static str]) -> Self {
        Self { args, stdin: "" }
    }

    fn name(&self) -> String {
        format!("entrust_ops {}", self.args.join(" "))
    }
}

const TEST_CASES: &[TestCase] = &[
    TestCase::new(&["feature", "activate", "certificate.txt"]),
    TestCase::new(&["feature", "info"]),
    TestCase::new(&[
        "firmware",
        "file-info",
        "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff",
    ]),
    TestCase::new(&[
        "firmware",
        "write",
        "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff",
    ]),
    TestCase::new(&["hsm", "create-world"]),
    TestCase::new(&["hsm", "create-world", "--debugging"]),
    TestCase::new(&["hsm", "erase"]),
    TestCase::new(&["hsm", "info"]),
    TestCase::new(&["hsm", "join-world"]),
    TestCase::new(&["hsm", "restart"]),
    TestCase::new(&["hsm", "restart", "--mode", "initialization"]),
    TestCase::new(&["hsm", "restart", "--mode", "maintenance"]),
    TestCase::new(&["hsm", "world-info"]),
    TestCase::new(&["meta", "hash"]),
    TestCase::new(&["meta", "paths"]),
    TestCase::new(&[
        "realm",
        "create-nvram-file",
        "--signing-key-hash",
        "bdbef7d2e6a0dfefb7af3074adbaed97553e64cc",
    ]),
    TestCase::new(&["realm", "create-keys"]),
    TestCase::new(&["realm", "noise-public-key"]),
    TestCase::new(&["realm", "print-acl", "noise"]),
    TestCase::new(&["sign", "create-key"]),
    TestCase::new(&["sign", "key-info"]),
    TestCase::new(&["sign", "software"]),
    TestCase::new(&["sign", "userdata"]),
    TestCase::new(&["smartcard", "erase"]),
    TestCase::new(&["smartcard", "info"]),
    TestCase::new(&["smartcard", "write-ocs"]),
];

// The output isn't perl, but its syntax highlighting is better than nothing.
const LANG: &str = "perl";

fn dry_run() -> String {
    let bin = env!("CARGO_BIN_EXE_entrust_ops");
    let mut buf = String::new();

    let that = "This";
    writeln!(buf, "_{that} file is automatically generated._").unwrap();
    writeln!(buf).unwrap();

    for test in TEST_CASES {
        writeln!(buf, "## `{}`", test.name()).unwrap();
        writeln!(buf).unwrap();

        if !test.stdin.is_empty() {
            writeln!(buf, "#### stdin").unwrap();
            writeln!(buf).unwrap();
            writeln!(buf, "```{LANG}").unwrap();
            write!(buf, "{}", test.stdin).unwrap();
            if !test.stdin.ends_with('\n') {
                writeln!(buf).unwrap();
                writeln!(buf, "[missing newline]").unwrap();
            }
            writeln!(buf, "```").unwrap();
            writeln!(buf).unwrap();
        }

        let mut child = process::Command::new(bin)
            .arg("--dry-run")
            .args(test.args)
            .env_clear()
            .env(
                "ENTRUST_INIT",
                "/home/entrust_ops_test/juicebox-hsm-realm/target/release/entrust_init",
            )
            .env(
                "SIGNING_DIR",
                "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn {:?}: {err}", test.name()));

        {
            let mut stdin = child.stdin.take().unwrap();
            stdin
                .write_all(test.stdin.as_bytes())
                .unwrap_or_else(|err| {
                    panic!("failed to write to stdin for {:?}: {err}", test.name())
                });
        }

        let output = child
            .wait_with_output()
            .unwrap_or_else(|err| panic!("failed to run {:?}: {err}", test.name()));

        assert!(
            output.status.success(),
            "non-zero status {:?}: {:?}",
            test.name(),
            output
        );

        if !output.stderr.is_empty() {
            writeln!(buf, "#### stderr").unwrap();
            writeln!(buf).unwrap();
            writeln!(buf, "```{LANG}").unwrap();
            write!(buf, "{}", &String::from_utf8_lossy(&output.stderr)).unwrap();
            if !output.stderr.ends_with(b"\n") {
                writeln!(buf).unwrap();
                writeln!(buf, "[missing newline]").unwrap();
            }
            writeln!(buf, "```").unwrap();
            writeln!(buf).unwrap();
        }

        writeln!(buf, "#### stdout").unwrap();
        writeln!(buf).unwrap();
        writeln!(buf, "```{LANG}").unwrap();
        write!(buf, "{}", &String::from_utf8_lossy(&output.stdout)).unwrap();
        if !output.stdout.ends_with(b"\n") {
            writeln!(buf).unwrap();
            writeln!(buf, "[missing newline]").unwrap();
        }
        writeln!(buf, "```").unwrap();
        writeln!(buf).unwrap();
    }

    buf
}

/// Snapshot test for dry run output. See `dry_run.md`.
#[test]
fn test_dry_run() {
    let actual = dry_run();
    expect_file!["dry_run.md"].assert_eq(&actual);
}
