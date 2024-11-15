FROM rust:1-slim-bookworm AS builder

RUN apt update && apt install -y make pkg-config clang libsodium-dev

COPY . /sources
WORKDIR /sources
RUN cargo build --release
RUN chown nobody:nogroup /sources/target/release/gitlab-cargo-shim

FROM debian:bookworm-slim
RUN apt update && apt install -y libsodium23 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /sources/target/release/gitlab-cargo-shim /gitlab-cargo-shim

USER nobody
ENTRYPOINT ["/gitlab-cargo-shim"]
