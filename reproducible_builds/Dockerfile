FROM rust:1.72.1-bullseye

# bindgen needs libclang-dev and rustfmt
RUN apt-get update && apt-get install --yes libclang-dev p7zip-full protobuf-compiler
RUN rustup component add rustfmt rust-src

RUN mkdir -m 700 /root/.ssh
COPY known_hosts /root/.ssh/known_hosts
RUN chmod 0700 /root/.ssh/known_hosts
