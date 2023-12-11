use std::process::{Command, Stdio};

fn main() {
    println!("cargo:rustc-env=BUILD_USERNAME={}", env!("USER"));

    let hostname =
        run_output(&mut Command::new("hostname")).unwrap_or_else(|| String::from("localhost"));
    println!("cargo:rustc-env=BUILD_HOSTNAME={hostname}");

    if let Some(git_dir) = run_output(Command::new("git").args(["rev-parse", "--absolute-git-dir"]))
    {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        println!("cargo:rerun-if-changed={git_dir}/refs");

        if let Some(git_hash) = run_output(Command::new("git").args(["rev-parse", "HEAD"])) {
            println!("cargo:rustc-env=BUILD_GIT_HASH={git_hash}");
        }

        if let Some(git_branch) = run_output(Command::new("git").args(["branch", "--show-current"]))
        {
            println!("cargo:rustc-env=BUILD_GIT_BRANCH={git_branch}");
        }

        if let Some(git_tag) =
            run_output(Command::new("git").args(["describe", "--exact-match", "--tags"]))
        {
            println!("cargo:rustc-env=BUILD_GIT_TAG={git_tag}");
        }

        if let Some(description) =
            run_output(Command::new("git").args(["describe", "--long", "--tags"]))
        {
            if let Some((git_ancestor_tag, _)) = description.rsplit_once('-') {
                println!("cargo:rustc-env=BUILD_GIT_ANCESTOR_TAG={git_ancestor_tag}");
            }
        }
    }
}

fn run_output(command: &mut Command) -> Option<String> {
    let result = command.stderr(Stdio::inherit()).output();
    match result {
        Err(err) => eprintln!("command failed ({command:?}) with: {err}"),

        Ok(result) if !result.status.success() => {
            eprintln!("command failed ({command:?}) with: {}", result.status);
        }

        Ok(result) => {
            if let Ok(mut stdout) = String::from_utf8(result.stdout) {
                if stdout.ends_with('\n') {
                    stdout.pop();
                }
                if !stdout.is_empty() {
                    return Some(stdout);
                }
            } else {
                eprintln!("command ({command:?}) output invalid UTF-8");
            }
        }
    }

    None
}
