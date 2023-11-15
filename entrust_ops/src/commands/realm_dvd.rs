use clap::{self, Subcommand};
use std::collections::HashSet;

use crate::{join_path, system::FileMode, Context, Error, Paths, Process, Sha256Sum};

/// A description of a file on the realm DVD that is copied to/from the host.
///
/// Note: There is no dvd_dir or dvd_path because all the files are at the
/// root.
#[derive(Debug)]
struct DvdFile {
    /// The path to the directory containing `filename` on the host.
    host_dir: String,
    /// The name of the file.
    filename: &'static str,
    /// The path to the file on the host (`{host_dir}/{filename}`).
    host_path: String,
    /// The permissions to use when restoring the file onto the host.
    permissions: FileMode,
}

impl DvdFile {
    fn new(host_dir: String, filename: &'static str, permissions: FileMode) -> Self {
        let host_path = join_path(&host_dir, filename);
        Self {
            host_dir,
            filename,
            host_path,
            permissions,
        }
    }
}

// In the returned list, the filenames must be unique (this is checked by a
// unit test).
fn file_list(context: &Context) -> Vec<DvdFile> {
    let entrust_init = DvdFile::new(
        join_path(&context.paths.juicebox_hsm_realm_dir, "target/release"),
        "entrust_init",
        FileMode::RX,
    );
    assert_eq!(entrust_init.host_path, context.paths.entrust_init);

    vec![
        DvdFile::new(
            context.paths.world_dir.clone(),
            "key_simple_jbox-mac",
            FileMode::R,
        ),
        DvdFile::new(
            context.paths.world_dir.clone(),
            "key_simple_jbox-noise",
            FileMode::R,
        ),
        DvdFile::new(
            context.paths.world_dir.clone(),
            "key_simple_jbox-record",
            FileMode::R,
        ),
        DvdFile::new(context.paths.world_dir.clone(), "world", FileMode::R),
        DvdFile::new(
            context.paths.signing_dir.clone(),
            "entrust_hsm.sar",
            FileMode::R,
        ),
        DvdFile::new(
            context.paths.signing_dir.clone(),
            "userdata.sar",
            FileMode::R,
        ),
        entrust_init,
    ]
}

/// Create or verify a "Realm DVD" containing encrypted keys and signed HSM
/// software.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Collect the files into a disc image file.
    CreateIso {
        #[clap(
            long,
            value_name = "FILE",
            default_value_t = Paths::get().realm_iso.clone()
        )]
        output: String,
    },

    /// Mount the DVD onto /run/dvd.
    Mount,

    /// Copy the expected files from the DVD onto the host filesystem.
    ///
    /// This mounts and unmounts the DVD if needed. It also lists the files and
    /// their hashes.
    Restore,

    /// Unmount the DVD.
    #[clap(alias = "umount")]
    Unmount,

    /// Check that a DVD contains exactly the expected files as found on the host
    /// filesystem.
    ///
    /// This mounts and unmounts the DVD if needed. It also lists the files and
    /// their hashes.
    Verify,

    /// Burn an ISO file to a DVD.
    Write {
        #[clap(
            long,
            value_name = "FILE",
            default_value_t = Paths::get().realm_iso.clone()
        )]
        iso: String,
    },
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::CreateIso { output } => create_iso(output, context),

        Command::Mount => {
            if context.is_mounted(&context.paths.mount_dir)? && !context.common_args.dry_run {
                println!("Disc was already mounted at {:?}", context.paths.mount_dir);
            } else {
                context.mount_readonly(&context.paths.dvd_device, &context.paths.mount_dir)?;
            }
            Ok(())
        }

        Command::Restore => with_mount(context, restore),

        Command::Unmount => {
            if context.is_mounted(&context.paths.mount_dir)? || context.common_args.dry_run {
                context.unmount(&context.paths.mount_dir)?;
            } else {
                println!("Disc was not mounted at {:?}", context.paths.mount_dir);
            }
            Ok(())
        }

        Command::Verify => with_mount(context, verify),

        Command::Write { iso } => context.exec(Process::new(
            "xorriso",
            &[
                "-as",
                "cdrecord",
                "-v",
                "-eject",
                "-sao",
                &format!("dev={}", context.paths.dvd_device),
                context.check_file_readable(iso)?,
            ],
        )),
    }
}

fn create_iso(output: &str, context: &Context) -> Result<(), Error> {
    let mut args = vec![
        "-abort_on",
        "WARNING",
        "-indev",
        "stdio:/dev/null",
        "-outdev",
        output,
        "-charset",
        "ISO-8859-1",
        // The filenames are checked by a unit test. It allows lowercase and
        // dashes, which the standard prohibits.
        "-compliance",
        "clear:iso_9660_level=2:lowercase:7bit_ascii:always_gmt:no_emul_toc",
        "-disk_pattern",
        "off",
        "-rockridge",
        "off",
        "-volid",
        "REALM",
    ];

    let file_list = file_list(context);
    for file in &file_list {
        context.check_file_readable(&file.host_path)?;
        args.extend(["-map", &file.host_path, file.filename]);
    }

    context.remove_file(output)?;

    context.exec(Process::new("xorriso", &args))?;

    context.print_file_digest(output)
}

fn restore(context: &Context) -> Result<(), Error> {
    let file_list = file_list(context);

    // Tracks which host directories have already been created to avoid
    // redundancy in output.
    let mut created: HashSet<&str> = HashSet::new();

    for file in &file_list {
        let dvd_path = join_path(&context.paths.mount_dir, file.filename);
        context.print_file_digest(&dvd_path)?;

        if created.insert(&file.host_dir) {
            context.create_dir_all(&file.host_dir)?;
        }

        if context.common_args.dry_run {
            println!(
                "Not copying {:?} to {:?} with mode {:?} because --dry-run",
                &dvd_path, &file.host_path, file.permissions,
            );
        } else {
            println!(
                "Copying {:?} to {:?} with mode {:?}",
                &dvd_path, &file.host_path, file.permissions,
            );
        }
        let contents = context.read(&dvd_path)?;
        context.remove_file(&file.host_path)?;
        context.create_file(&file.host_path, &contents, file.permissions)?;
    }

    Ok(())
}

fn verify(context: &Context) -> Result<(), Error> {
    let mut host_files: Vec<(DvdFile, Sha256Sum)> = file_list(context)
        .into_iter()
        .map(|file| {
            let digest = context.file_digest(&file.host_path)?;
            Ok((file, digest))
        })
        .collect::<Result<_, Error>>()?;
    host_files.sort_by(|a, b| a.0.filename.cmp(b.0.filename));

    let mut dvd_files: Vec<(String, Sha256Sum)> = if context.common_args.dry_run {
        println!("Not listing DVD files because --dry-run");
        file_list(context)
            .iter()
            .map(|file| (file.filename.to_owned(), Sha256Sum::DUMMY))
            .collect()
    } else {
        context
            .list_dir(&context.paths.mount_dir)?
            .into_iter()
            .map(|entry| {
                if entry.metadata.is_file() {
                    let path = join_path(&context.paths.mount_dir, &entry.filename);
                    Ok((entry.filename, context.file_digest(&path)?))
                } else {
                    Err(Error::new(format!(
                        "expected file (not dir or symlink) at {:?} on DVD",
                        entry.filename,
                    )))
                }
            })
            .collect::<Result<_, Error>>()?
    };
    dvd_files.sort_by(|a, b| a.0.cmp(&b.0));

    if host_files.len() != dvd_files.len() {
        return Err(Error::new(format!(
            "expected {} files, found {} files",
            host_files.len(),
            dvd_files.len()
        )));
    }

    for ((expected_file, expected_hash), (dvd_name, dvd_hash)) in host_files.iter().zip(&dvd_files)
    {
        if expected_file.filename != dvd_name {
            return Err(Error::new(format!(
                "expected file {:?}, found {dvd_name:?}",
                expected_file.filename
            )));
        }

        println!("File {dvd_name:?}:");
        println!("    {expected_hash} {:?}", expected_file.host_dir);
        println!("    {dvd_hash} {:?}", context.paths.mount_dir);
        if expected_hash != dvd_hash {
            return Err(Error::new("hash mismatch"));
        }
        println!("    ok");
        println!();
    }

    Ok(())
}

fn with_mount<F>(context: &Context, f: F) -> Result<(), Error>
where
    F: Fn(&Context) -> Result<(), Error>,
{
    let already_mounted =
        context.is_mounted(&context.paths.mount_dir)? && !context.common_args.dry_run;

    if already_mounted {
        println!("Disc was already mounted at {:?}", context.paths.mount_dir);
    } else {
        context.mount_readonly(&context.paths.dvd_device, &context.paths.mount_dir)?;
    }

    f(context)?;

    if !already_mounted {
        context.unmount(&context.paths.mount_dir)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CommonArgs;

    #[test]
    fn test_file_list_filenames() {
        let context = Context {
            common_args: CommonArgs { dry_run: true },
            paths: Paths::get(),
        };
        let file_list = file_list(&context);
        let filenames = file_list.iter().map(|f| f.filename).collect::<HashSet<_>>();

        assert_eq!(
            file_list.len(),
            filenames.len(),
            "filenames not unique: {file_list:#?}"
        );

        for name in filenames {
            // The standard may allow for 31 bytes, at least by some
            // interpretations, but 30 seems more conservative and sufficient.
            assert!(
                name.len() < 30,
                "filename {name:?} longer than 30 bytes (got {} bytes)",
                name.len()
            );

            // We allow lowercase and dashes even though ISO 9660 prohibits them.
            assert!(
                name.bytes().all(|char| matches!(char,
                   | b'-'
                   | b'.'
                   | b'0'..=b'9'
                   | b'A'..=b'Z'
                   | b'_'
                   | b'a'..=b'z'
                )),
                "invalid filename character in {name:?}"
            );
            assert!(!matches!(name, "" | "."), "invalid filename: {name:?}");
            assert!(
                name.matches('.').count() <= 1,
                "filename {name:?} can't have more than one dot"
            );

            // The standard probably allows these, but just to be conservative:
            assert!(
                !name.starts_with('.') && !name.ends_with('.'),
                "filename {name:?} shouldn't start or end with dot"
            );
        }
    }

    #[test]
    fn test_mount_docstring() {
        assert_eq!(Paths::get().mount_dir, "/run/dvd");
    }
}
