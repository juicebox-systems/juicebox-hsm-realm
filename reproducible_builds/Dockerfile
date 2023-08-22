FROM rust:1.71.1-bullseye

RUN apt-get update && apt-get install --yes p7zip-full protobuf-compiler
RUN rustup component add rust-src

RUN mkdir -m 700 /root/.ssh
COPY known_hosts /root/.ssh/known_hosts
RUN chmod 0700 /root/.ssh/known_hosts
