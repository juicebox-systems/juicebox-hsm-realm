use std::fmt::{self, Write};

/// Returns a [`BuildInfo`] struct.
///
/// To minimize build churn, this should be called from a top-level crate,
/// which will need to include:
///
/// ```toml
/// [package]
/// build = "../build_info/build_script.rs"
///
/// [dependencies]
/// build_info = { workspace = true }
/// ```
///
/// in its `Cargo.toml`, adjusting the relative path accordingly.
#[macro_export]
macro_rules! get {
    () => {
        $crate::BuildInfo {
            git_ancestor_tag: option_env!("BUILD_GIT_ANCESTOR_TAG"),
            git_branch: option_env!("BUILD_GIT_BRANCH"),
            git_hash: option_env!("BUILD_GIT_HASH"),
            git_tag: option_env!("BUILD_GIT_TAG"),
            hostname: env!("BUILD_HOSTNAME"),
            rustc_version: env!("BUILD_RUSTC_VERSION"),
            username: env!("BUILD_USERNAME"),
            version: env!("CARGO_PKG_VERSION"),
        }
    };
}

/// Returns a version string for convenient use with clap.
///
/// Example:
///
/// ```ignore
/// #[command(version = build_info::clap!())]
/// struct Args {
///     // ...
/// }
/// ```
#[macro_export]
macro_rules! clap {
    () => {
        $crate::get!().clap()
    };
}

/// Describes the environment where/when this code was built.
#[derive(Debug)]
pub struct BuildInfo {
    /// Tag name of an ancestor commit, along with distance to that commit, if
    /// any. The format is "{name}-{count}". See `git help describe`.
    ///
    /// This can be `None` if no such tag exists, if outside of a git
    /// repo, or if the `git` program was unavailable.
    pub git_ancestor_tag: Option<&'static str>,

    /// Git branch name, if any.
    ///
    /// This can be `None` in the detached head state, if outside of a git
    /// repo, or if the `git` program was unavailable.
    pub git_branch: Option<&'static str>,

    /// Git SHA-1 commit hash.
    ///
    /// This can be `None` if outside of a git repo or if the `git` program was
    /// unavailable.
    pub git_hash: Option<&'static str>,

    /// Tag name of this commit, if any.
    ///
    /// When multiple tags describe the commit, this will choose one,
    /// preferring annotated tags and newer tags. See `git help describe`.
    ///
    /// This can be `None` if there is no such tag, if outside of a git repo,
    /// or if the `git` program was unavailable.
    pub git_tag: Option<&'static str>,

    /// Short hostname (section before the dot).
    pub hostname: &'static str,

    /// Compiler version, like `rustc 1.74.1 (a28077b28 2023-12-04)`.
    pub rustc_version: &'static str,

    /// Username.
    pub username: &'static str,

    /// Semver version number from `Cargo.toml` (for the crate running the
    /// build script and invoking the macro).
    pub version: &'static str,
}

impl BuildInfo {
    pub fn clap(&self) -> String {
        self.write_clap(String::new()).unwrap()
    }

    fn write_clap<W: Write>(&self, mut w: W) -> Result<W, fmt::Error> {
        let BuildInfo {
            git_ancestor_tag,
            git_branch,
            git_hash,
            git_tag,
            hostname,
            rustc_version,
            username,
            version,
        } = self;

        // The first line has the program name on it already.
        writeln!(w, "{version}")?;
        if let Some(git_hash) = git_hash {
            writeln!(w, "git hash: {git_hash}")?;
        }
        if let Some(git_tag) = git_tag {
            writeln!(w, "git tag: {git_tag}")?;
        }
        if let Some(git_ancestor_tag) = git_ancestor_tag {
            writeln!(w, "git ancestor tag: {git_ancestor_tag}")?;
        }
        if let Some(git_branch) = git_branch {
            writeln!(w, "git branch: {git_branch}")?;
        }
        writeln!(w, "build host: {hostname}")?;
        writeln!(w, "build user: {username}")?;
        write!(w, "compiler: {rustc_version}")?;
        // clap will add a newline.

        Ok(w)
    }

    pub fn livez(&self) -> String {
        self.write_livez(String::new()).unwrap()
    }

    fn write_livez<W: Write>(&self, mut w: W) -> Result<W, fmt::Error> {
        let BuildInfo {
            git_ancestor_tag,
            git_branch,
            git_hash,
            git_tag,
            hostname,
            rustc_version,
            username,
            version,
        } = self;
        writeln!(w, "version: {version}")?;
        writeln!(w, "git hash: {}", git_hash.unwrap_or("(none)"))?;
        writeln!(w, "git tag: {}", git_tag.unwrap_or("(none)"))?;
        writeln!(
            w,
            "git ancestor tag: {}",
            git_ancestor_tag.unwrap_or("(none)")
        )?;
        writeln!(w, "git branch: {}", git_branch.unwrap_or("(none)"))?;
        writeln!(w, "build host: {hostname}")?;
        writeln!(w, "build user: {username}")?;
        writeln!(w, "compiler: {rustc_version}")?;
        Ok(w)
    }
}

#[cfg(test)]
mod tests {
    use super::BuildInfo;

    struct TestCase {
        name: &'static str,
        info: BuildInfo,
        clap: &'static str,
        livez: &'static str,
    }

    const TEST_CASES: &[TestCase] = &[
        TestCase {
            name: "full",
            info: BuildInfo {
                git_ancestor_tag: Some("0.1.2-49"),
                git_branch: Some("main"),
                git_hash: Some("9c1748107712146689e44da2302882fda307d26b"),
                // This example doesn't make much sense because ancestor tag
                // would also show this.
                git_tag: Some("0.1.3"),
                hostname: "dl3",
                rustc_version: "rustc 1.76.0-nightly (21cce21d8 2023-12-11)",
                username: "teyla",
                version: "0.1.2",
            },
            clap: "0.1.2
git hash: 9c1748107712146689e44da2302882fda307d26b
git tag: 0.1.3
git ancestor tag: 0.1.2-49
git branch: main
build host: dl3
build user: teyla
compiler: rustc 1.76.0-nightly (21cce21d8 2023-12-11)",
            livez: "version: 0.1.2
git hash: 9c1748107712146689e44da2302882fda307d26b
git tag: 0.1.3
git ancestor tag: 0.1.2-49
git branch: main
build host: dl3
build user: teyla
compiler: rustc 1.76.0-nightly (21cce21d8 2023-12-11)
",
        },
        TestCase {
            name: "detached",
            info: BuildInfo {
                git_ancestor_tag: Some("0.1.2-49"),
                git_branch: None,
                git_hash: Some("9c1748107712146689e44da2302882fda307d26b"),
                git_tag: None,
                hostname: "dl3",
                rustc_version: "rustc 1.74.1 (a28077b28 2023-12-04)",
                username: "teyla",
                version: "0.1.2",
            },
            clap: "0.1.2
git hash: 9c1748107712146689e44da2302882fda307d26b
git ancestor tag: 0.1.2-49
build host: dl3
build user: teyla
compiler: rustc 1.74.1 (a28077b28 2023-12-04)",
            livez: "version: 0.1.2
git hash: 9c1748107712146689e44da2302882fda307d26b
git tag: (none)
git ancestor tag: 0.1.2-49
git branch: (none)
build host: dl3
build user: teyla
compiler: rustc 1.74.1 (a28077b28 2023-12-04)
",
        },
        TestCase {
            name: "sparse",
            info: BuildInfo {
                git_ancestor_tag: None,
                git_branch: None,
                git_hash: None,
                git_tag: None,
                hostname: "dl3",
                rustc_version: "rustc 1.74.1 (a28077b28 2023-12-04)",
                username: "teyla",
                version: "0.1.2",
            },
            clap: "0.1.2
build host: dl3
build user: teyla
compiler: rustc 1.74.1 (a28077b28 2023-12-04)",
            livez: "version: 0.1.2
git hash: (none)
git tag: (none)
git ancestor tag: (none)
git branch: (none)
build host: dl3
build user: teyla
compiler: rustc 1.74.1 (a28077b28 2023-12-04)
",
        },
    ];

    #[test]
    fn test_clap() {
        for test in TEST_CASES {
            assert_eq!(
                test.clap,
                test.info.clap(),
                "{} clap {:?}",
                test.name,
                test.info
            );
        }
    }

    #[test]
    fn test_livez() {
        for test in TEST_CASES {
            assert_eq!(
                test.livez,
                test.info.livez(),
                "{} livez {:?}",
                test.name,
                test.info
            );
        }
    }
}
