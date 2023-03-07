## Builds

* `cargo test --all` run the unit tests
* `cargo run --bin demo` run the demo aka "integration test"

### Cross Compile

Cross compile to powerpc to run on Entrust HSM. The PowerPC CPU in the HSM doesn't support Altivec
which the rust prebuilt libraries for powerPC assume is available. So we need to build std ourselves
(or hopefully just core later on). This currently requires the nightly toolchain.

Install pre-requisites

```sh
rustup target add powerpc-unknown-linux-gnu
rustup toolchain install nightly --component rust-src
sudo apt install qemu qemu-user qemu-user-binfmt gcc-9-powerpc-linux-gnu
```

The `build-ppc.sh` and `test-ppc.sh` scripts can be used to perform the build or tests for the PPC version.


In addition to the options set in the scripts the .cargo/config.toml file is used to set the linker and CPU target.


## Local Bigtable emulator

You'll need the Bigtable emulator to run offline. You may also want the Cloud
Bigtable CLI tool, which works with the emulator and is installed the same way.
You can install these either using the hefty `gcloud` SDK or using the Go
compiler.

### Option 1: Install using the `gcloud` SDK:

Follow the [gcloud CLI installation instructions](https://cloud.google.com/sdk/docs/install).

Run:

```sh
gcloud components update beta
gcloud components install cbt
```

And start the emulator:

```sh
gcloud beta emulators bigtable start --host-port localhost:9000
```

### Option 2: Install using Go:

Run:

```sh
go install cloud.google.com/go/bigtable/cmd/emulator@latest
go install cloud.google.com/go/cbt@latest
```

And start the emulator:

```sh
emulator -host localhost -port 9000
```

### Using cbt

`cbt` is a Cloud Bigtable CLI tool. We'll make an alias for using it with the
local emulator, then create a table.

```sh
alias lbt='BIGTABLE_EMULATOR_HOST=localhost:9000 cbt -creds /dev/null -project prj -instance inst'
```

List tables:
```sh
lbt ls
```

You can create tables like this:
```sh
lbt createtable tab families=fam
```