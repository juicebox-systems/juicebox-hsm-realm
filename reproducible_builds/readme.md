# Reproducible Builds

Use the scripts and build images in this directory you can verify that the
software built & deployed during the key ceremony matches that which is in this
repo.

## Using the build image

A Docker image is used to provide a consistent and reproducible environment in
which to perform builds. This image extends from the base images provided by the
Rust project. As we can't redistribute the Entrust SDK it is mapped into the
image with a volume mount.

`build_docker_image.sh` can be used to build the docker image used for the
reproducible builds.

Once the build image is available, the build can be run with `build.sh` This
will run the build inside the docker image and print the sha256 checksums
of the resulting binaries.

`build.sh` assumes you have the correct version of the Entrust SDK installed in
the default location of /opt/nfast. The current version of the SDK used is 12.80.4.

```
SHA256(Codesafe_Lin64-12.80.4.zip)= a048cf90ac94b30ed3f8958256a842259aa6899c607ca53f146f880ea7a08e1
SHA256(SecWorld_Lin64-12.80.4.zip)= 1c800c6c933c1e5e8a5d4c4e9916ebe383fe26e30a027f2535a85e57dab5b6d7
```

The build currently relies on access to some forks that are on github rather than
crates.io. For github access the SSH agent is mapped into the docker container.
You'll need to have ssh agent running and a key that can access github added to it.
Typically this is done with `eval $(ssh-agent -s)` and then `ssh-add`


## Challenges

Generating bit identical builds comes with come some challenges, including
file paths, versions of compilers & linkers as well as 3rd party SDKs.

### Linker

Rust uses the system linker to produce its final binaries. The build output
depends on both the version of rust and the toolchain and version of the linker
that rust calls.

### Source file references

Rust binaries also include many strings that reference source files even for
release builds (e.g. for panic messages). The `--remap-path-prefix` RUSTFLAG can
be used to change strings that appear in the binary that reference the local
filesystem. This results in builds that are the same regardless of the username
and where the repro is checked out to. e.g
`RUSTFLAGS="--remap-path-prefix=$HOME=/remap-home
--remap-path-prefix=$PWD=/remap-pwd" cargo build --release`.

Due feature unification you have to build the same set of projects to get the
same binary. The remapping of `PWD` means that you have to build from the same
directory inside the project to get the same binary.

There are references to both $HOME/.cargo & $HOME/.rustup in the outputs. These
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

Because it has to rebuild the std library the entrust_hsm project requires a
rust nightly toolchain in order to build. We need to pin the specific version
of nightly used.

### Entrust SDK

The parts of the project that specifically target the Entrust HSMs depend on the
Entrust SDK including headers, libraries and compilers. The specific version of
the SDK along with its checksums for verification is typically available from
Entrust customer support for Entrust customers.