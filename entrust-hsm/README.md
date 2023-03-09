# Entrust HSM

This builds a nCipher seemachine executable that can be run on an Entrust HSM.

You'll need the Entrust/nCipher SDK to be installed (On linux)

`./compile_linux.sh` will compile using the powerpc / linux target

`./compile_ncipherxc.sh` will compile using our custom powerpc / ncipher target. 

This generates a entrust-hsm.elf file in the relevant target/$TARGET/release directory.
This then needs packing and loading into the HSM.

`/opt/nfast/bin/tct2 --pack --infile=entrust-hsm.elf --outfile=hsm.sar --machine-type=PowerPCELF`

`/opt/nfast/bin/loadmache hsm.sar`

Once loaded, the entrust-agent host process can be run. This will use the APIs to have
the HSM start the process, and start handling requests. Alternatively the entrust-agent
can be started with the `--image` flag to have it load the SEEMachine automatically.

## Rust bindings to the seelib library

The `bindgen.sh` script will run the [bindgen](https://rust-lang.github.io/rust-bindgen/)
tool to generate rust binding to the C based seelib headers and libraries. You'll need
the entrust SDK and the bindgen tool installed to run this script. Bindgen can be installed
with `cargo install bindgen-cli`. You only need to run this script if you need to adjust
the bindgen script to import more of the library.

## CPU

The HSM uses a PowerPC CPU, the e5500 in 32bit mode. This CPU does not have Altivec
support. The standard Rust builds for the powerpc-unknown-linux-gnu target are
compiled with a powerPC CPU target that includes Altivec. For this reason the compile
scripts build their own versions or core and/or std.


## ncipherxc target

The HSM runs a stripped down version of Linux. It has an allow list of syscalls that the
seemachine can make. If it makes a syscall not on the allow list the process is terminated.
The ncipherxc target exists to stop dependencies that think it's running on Linux and make
a syscall thats not allowed. (The [getrandom](https://crates.io/crates/getrandom) crate
is an example of how this can happen).

The ncipherxc target is still very much a work in progress. For example it'd be nice if
it could get data into the tracebuffer for debugging. The code can still be built for a linux
target using `compile_linux.sh` which is handy for debugging.


## Debugging

The entrust-agent supports a --trace flag which'll collect and print logging
written to the trace buffer on the HSM. This requires that the security world
was created with the 'dseeall' feature enabled. On the HSM side, stdout and stderr are
routed to the trace buffer. The linux target includes the rust std library so
can support having `println!()` in the HSM code. In a future version the ncipherxc
target should also support this.
