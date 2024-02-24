FROM rust:1-slim-bookworm AS builder

RUN apt update && apt install -y make pkg-config clang

COPY . /sources
WORKDIR /sources
RUN cargo build --release
RUN chown nobody:nogroup /sources/target/release/gitlab-cargo-shim

FROM debian:bookworm-slim
COPY --from=builder /sources/target/release/gitlab-cargo-shim /gitlab-cargo-shim

USER nobody
ENTRYPOINT ["/gitlab-cargo-shim"]
