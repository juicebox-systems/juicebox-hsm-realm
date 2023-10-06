# Reproducible Builds

Use the scripts and build images in this directory to verify that the software
built and deployed during the key ceremony matches that which is in this repo.

## Using the build image

A Docker image is used to provide a consistent and reproducible environment in
which to perform builds. This image extends from the base images provided by the
Rust project.

`build_docker_image.sh` can be used to build the docker image used for the
reproducible builds.

Once the build image is available, the build can be run with `build.sh`. This
will run the build inside the docker image and print the sha256 checksums
of the resulting binaries. The results are placed in `target/reproducible`.

`build.sh` assumes you have provided the correct version of the Entrust Codesafe SDK in
the root project directory as a ZIP file. The current version of the SDK used is 13.4.3.

```
7d6eaff0548d90143d35834f1ea1cf092321e9003e10e14895a01a6f412adadb  Codesafe_Lin64-13.4.3.iso.zip
```

The build currently relies on access to some forks that are on github rather than
crates.io. For github access the SSH agent is mapped into the docker container.
You'll need to have ssh agent running and a key that can access github added to it.
Typically this is done with `eval $(ssh-agent -s)` and then `ssh-add`.


## Challenges

Generating bit identical builds comes with come some challenges, including
file paths, versions of compilers & linkers, as well as 3rd party SDKs. Our
build scripts address most of these by using a fairly reproducible Docker
environment. This section describes the issues that came up before we
switched to using Docker.

### Linker

Rust uses the system linker to produce its final binaries. The build output
depends on both the version of rust and the toolchain and version of the linker
that rust calls.

### Source file references

Rust binaries also include many strings that reference source files even for
release builds (e.g. for panic messages). The `--remap-path-prefix` RUSTFLAG can
be used to change strings that appear in the binary that reference the local
filesystem. This results in builds that are the same regardless of the username
and where the repo is checked out to. e.g
`RUSTFLAGS="--remap-path-prefix=$HOME=/remap-home
--remap-path-prefix=$PWD=/remap-pwd" cargo build --release`.

Due to feature unification, you have to build the same set of projects to get the
same binary. The remapping of `PWD` means that you have to build from the same
directory inside the project to get the same binary.

There are references to both `$HOME/.cargo` and `$HOME/.rustup` in the outputs. These
2 should be also be remapped as the builder may not use the default locations
for Cargo or Rustup.

Multiple dependencies depend on the [ring](https://github.com/briansmith/ring)
rust library. Ring has a complex build and the resulting binaries that use ring
have strings in them that aren't fixed up by --remap-path-prefix. e.g.

```
/home/simon/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.16.20/pregenerated/x86_64-mont-elf.S
/home/simon/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.16.20/pregenerated/x86_64-mont5-elf.S
/home/simon/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.16.20/pregenerated/chacha-x86_64-elf.S
/home/simon/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.16.20/pregenerated/p256-x86_64-asm-elf.S
/home/simon/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.16.20/pregenerated/aesni-gcm-x86_64-elf.S
```

### Rust Nightly

Because it has to rebuild the std library, the `entrust_hsm` project requires a
Rust toolchain with nightly features in order to build.

### Entrust SDK

The parts of the project that specifically target the Entrust HSMs depend on the
Entrust SDK including headers, libraries and compilers. The specific version of
the SDK along with its checksums for verification is typically available from
Entrust customer support for Entrust customers.
