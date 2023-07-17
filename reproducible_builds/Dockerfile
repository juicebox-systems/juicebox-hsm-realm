FROM rust:1.70.0-bullseye

RUN apt-get update && apt-get install --yes p7zip-full protobuf-compiler
RUN rustup toolchain install nightly-2023-06-01
RUN rustup component add rust-src --toolchain nightly-2023-06-01-x86_64-unknown-linux-gnu

RUN mkdir -m 700 /root/.ssh
COPY known_hosts /root/.ssh/known_hosts
RUN chmod 0700 /root/.ssh/known_hosts
