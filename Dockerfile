FROM rust:1-slim AS builder

RUN apt update && apt install -y make

COPY . /sources
WORKDIR /sources
RUN cargo build --release
RUN chown nobody:nogroup /sources/target/release/gitlab-cargo-shim

FROM debian:bullseye-slim
COPY --from=builder /sources/target/release/gitlab-cargo-shim /gitlab-cargo-shim

USER nobody
ENTRYPOINT ["/gitlab-cargo-shim"]
