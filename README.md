## Builds

System dependencies:

* [Rust](https://rustup.rs/)
* [Protocol Buffers compiler](https://github.com/protocolbuffers/protobuf#protocol-compiler-installation),
  as located and used by
  [prost-build](https://docs.rs/prost-build/latest/prost_build/#sourcing-protoc).
  This is needed for `opentelemetry-otlp` and can also be used to regenerate
  the Google Cloud API messages.  On Debian, `apt install protobuf-compiler` is
  sufficient.
* See the section on the Bigtable emulator below, which you'll also need.

Then:

* `cargo test --all` to run the unit tests
* `cargo build && cargo run --bin demo_runner -- --demo target/debug/demo` to run the rust demo aka "integration test"
* to run the swift demo:
```sh
cd sdk/swift
./ffi.sh
cd demo
swift build
cd ../../..
cargo run --bin demo_runner -- --demo sdk/swift/demo/.build/debug/demo
```

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

## OpenTelemetry traces

The code sends OpenTelemetry traces over OTLP (GRPC) to `http://localhost:4317`.
You can run a Jaeger instance, for example, to receive these and view them:

Follow the [instructions](https://www.jaegertracing.io/docs/latest/getting-started/)
to get an all-in-one Docker image or executable binary.

Run:

```sh
COLLECTOR_OTLP_ENABLED=true ./jaeger-1.42.0-linux-amd64/jaeger-all-in-one --collector.otlp.grpc.host-port=:4317
```

Open <http://localhost:16686/>.

## Datadog

Traces & metrics can be sent to Datadog. Follow the
[instructions](https://docs.datadoghq.com/agent/) to install the datadog agent.
Update the `/etc/datadog-agent/datadog.yaml` file to enable the open telemetry
collector. To do this find the open telemetry section and uncomment out the
otlp_config, receiver, protocols, grpc, endpoint lines. It should look like this
when done

```yaml
otlp_config:

  ## @param receiver - custom object - optional
  ## The receiver configuration. It follows the OpenTelemetry Collector's OTLP Receiver Configuration.
  ## This template lists the most commonly used settings; see the OpenTelemetry Collector documentation
  ## for a full list of available settings:
  ## https://github.com/open-telemetry/opentelemetry-collector/blob/main/receiver/otlpreceiver/config.md
  #
  receiver:

    ## @param protocols - custom object - optional
    ## Configuration for the supported protocols.
    #
    protocols:

        ## @param grpc - custom object - optional
        ## Configuration for OTLP/gRPC listener.
        ## Setting this as an empty section enables the OTLP/gRPC listener with default options.
        #
        grpc:

          ## @param endpoint - string - optional - default: 0.0.0.0:4317
          ## @env DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT - string - optional - default: 0.0.0.0:4317
          ## The OTLP/gRPC listener endpoint.
          #
          endpoint: 0.0.0.0:4317
```


## TLS Certificates

The load balancer requires connections to use TLS. The load_balancer process takes cmdline arguments
to specify where the key & cert files are.

Demo and hsm_bench will generate a self signed cert for use during these runs. This requires you to have
`openssl` in your `$PATH`.
