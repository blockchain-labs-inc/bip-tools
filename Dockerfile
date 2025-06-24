FROM rust:1.85 AS builder

WORKDIR /usr/src/bip-tools
COPY . .

RUN cargo install --path . 

FROM debian:bookworm-slim 

COPY --from=builder /usr/local/cargo/bin/bip-tools /usr/local/bin/bip-tools

ENTRYPOINT ["bip-tools"]