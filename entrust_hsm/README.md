# Entrust HSM

This builds a nCipher seemachine executable that can be run on an Entrust HSM.

You'll need the Entrust/nCipher SDK to be installed (On linux)

`./compile_linux.sh` will compile using the powerpc / linux target

`./compile_ncipherxc.sh` will compile using our custom powerpc / ncipher target.

This generates an `entrust_hsm.elf` file in the relevant `target/$TARGET/release`
directory. Once correctly code signed (see below) the entrust_agent host process
can be run. This will use the APIs to have the HSM load and start the SEEMachine
world, and then start handling requests.

## Insecure features

By default the compile scripts build production builds. If you want a build with
the insecure features (currently just per request metrics) enabled you add
`--features insecure` to the relevant compile call, e.g.
`./compile_linux.sh --features insecure`

# HSM and Security World configuration

The HSM and Security World need to be configured so that our HSM software can
access the NVRAM and realm keys. Both the NVRAM and realm keys should have ACL's
on them that restrict access to just the seemachine. (this is called seeinteg
in the entrust tools). This requires that both the seemachine image and userdata
file are signed.

Our `entrust_init` tool is used to configure NVRAM access and create realm keys.

The code signing key (aka seeinteg) is required to be an OCS protected key.

Create the Security World (if needed). Note that you'd want to disable Security
World debugging for production and possibly use a larger ACS quorum.

 ```sh
sudo target/release/entrust_ops hsm restart --initialization
sudo target/release/entrust_ops hsm create-world --debugging
sudo target/release/entrust_ops hsm restart --operational
```

Create an OCS cardset:
```sh
sudo target/release/entrust_ops smartcard write-ocs
```

Create a signing key:

```sh
sudo target/release/entrust_ops sign create-key
```

Sign the SEEMachine software:

```sh
sudo target/release/entrust_ops sign software
```

Create and sign a dummy userdata file (the exact contents of this file don't matter).

```sh
target/release/entrust_ops sign userdata
```

Signing will require the OCS card(s) from above to be loaded.

Create the NVRAM file `entrust_init nvram` this will need the ACS card(s).

Create the realm keys. This only needs doing once per realm, the NVRAM needs doing per HSM. `sudo entrust_init keys`

We use our own tools for the NVRAM & realm keys to ensure they get a restrictive
ACL on them. The Entrust tools tend to give admins lots of rights in the ACLs
they generate.

You should now be able to run the agent manually and see the seeworld & hsm startup.
```sh
LOGLEVEL=debug ./entrust_agent --bigtable-project crucial-limiter-377716 --bigtable-instance simon-ssd -i entrust_hsm.sar -u userdata.sar -t

 INFO src/logging.rs:144: initialized logging to terminal and telemetry to OTLP/Jaeger. you can set verbosity with env var LOGLEVEL. max_level=DEBUG
 INFO src/google_auth.rs:22: initializing Google Cloud authentication with Application Default Credentials
DEBUG /home/simon/.cargo/git/checkouts/gcp_auth-0a7a4d6a48633ebe/579fae9/src/authentication_manager.rs:44: Initializing gcp_auth
DEBUG /home/simon/.cargo/git/checkouts/gcp_auth-0a7a4d6a48633ebe/579fae9/src/authentication_manager.rs:52: Using GCloudAuthorizedUser
 INFO src/realm/store/bigtable.rs:85: Connecting to Bigtable Data instance="simon-ssd" project="crucial-limiter-377716" data_url=https://bigtable.googleapis.com/
 INFO src/realm/store/bigtable.rs:106: Connecting to Bigtable Admin inst="simon-ssd" project="crucial-limiter-377716" admin_url=https://bigtableadmin.googleapis.com/
 INFO entrust_agent/src/main.rs:414: Successfully started SEEWorld
DEBUG entrust_agent/src/main.rs:326: Trying to find key in security world app="simple" ident="jbox-noise"
DEBUG entrust_nfast/src/lib.rs:181: found key app="simple" ident="jbox-noise" key_hash=045f3884d76f004592dd50279316425ec0bff268
DEBUG entrust_agent/src/main.rs:365: Generated key ticket app="simple" ident="jbox-noise"
DEBUG entrust_agent/src/main.rs:326: Trying to find key in security world app="simple" ident="jbox-noise"
DEBUG entrust_nfast/src/lib.rs:181: found key app="simple" ident="jbox-noise" key_hash=045f3884d76f004592dd50279316425ec0bff268
DEBUG entrust_agent/src/main.rs:365: Generated key ticket app="simple" ident="jbox-noise"
DEBUG entrust_agent/src/main.rs:326: Trying to find key in security world app="simple" ident="jbox-mac"
DEBUG entrust_nfast/src/lib.rs:181: found key app="simple" ident="jbox-mac" key_hash=fd16169ae11bababa274aaf69f4e553a613e9c21
DEBUG entrust_agent/src/main.rs:365: Generated key ticket app="simple" ident="jbox-mac"
DEBUG entrust_agent/src/main.rs:326: Trying to find key in security world app="simple" ident="jbox-record"
DEBUG entrust_nfast/src/lib.rs:181: found key app="simple" ident="jbox-record" key_hash=afcda0ad6f3b2aeae9b7d072a47150be8cab54e4
DEBUG entrust_agent/src/main.rs:365: Generated key ticket app="simple" ident="jbox-record"
 INFO entrust_agent/src/main.rs:281: HSMCore started and ready for work
DEBUG entrust_agent/src/main.rs:241: Entrust HSM request transacted dur=1.213141ms req="Status"
 INFO entrust_agent/src/main.rs:137: Agent started url=http://127.0.0.1:8082/
DEBUG entrust_agent/src/main.rs:241: Entrust HSM request transacted dur=737.381µs req="Status"
 INFO src/realm/agent.rs:341: registering agent with service discovery hsm=34f65c62af130da099a5c7563221fb63 url=http://127.0.0.1:8082/
DEBUG entrust_agent/src/main.rs:241: Entrust HSM request transacted dur=731.44µs req="PersistState"
DEBUG entrust_agent/src/main.rs:241: Entrust HSM request transacted dur=1.042124ms req="PersistState"
```

### About Keys

The `entrust_init` tool creates unrecoverable module protected keys in the
security world. These have an ACL that restricts access to SEEMachine code
signed with a specific signing key. The security world organizes keys into
groups called "applications" which is like a namespace / categorization /
functionality bucket. The 2 "apps" you are likely to see mentioned are "simple"
where the realm keys are stored and "seeinteg" where the code signing key is
stored. Inside this app namespace keys are given an string id called an "ident"
and optionally a name.

The agent at startup will use the security world APIs (they start with NFKM_) to
load the keys from the "simple" app namespace with the idents: jbox-mac,
jbox-record and jbox-noise. It now has a reference to the key in the HSM. It
generates a ticket for each key and sends the tickets to the SEEMachine as part
of the StartRequest message.

The SEEMachine when it receives the tickets from the StartRequest message will
first redeem the ticket. This gives it a reference to the key it can use to then
export it so that it has the actual key bytes. (which are needed as all the
cryptography is currently done inside the SEEMachine software)


## Rust bindings to the seelib library

The `build.rs` script will use [bindgen](https://rust-lang.github.io/rust-bindgen/)
to generate rust binding to the C based seelib headers and libraries. You'll need
the entrust codesafe SDK installed to run the build.

## CPU

The HSM uses a PowerPC CPU, the e5500 in 32bit mode. This CPU does not have Altivec
support. The standard Rust builds for the powerpc-unknown-linux-gnu target are
compiled with a powerPC CPU target that includes Altivec. For this reason the compile
scripts build their own versions of core and/or std.


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

The entrust_agent supports a `--trace` flag which'll collect and print logging
written to the trace buffer on the HSM. This requires that the security world
was created with the 'dseeall' feature enabled. On the HSM side, stdout and stderr are
routed to the trace buffer. The linux target includes the rust std library so
can support having `println!()` in the HSM code.
