# Shared builder image for the eval transport binaries. Built ONCE (compose
# `transport` service); every protocol image then COPY --from=transport the
# binaries it needs, so the Rust crate compiles once and doesn't bloat the
# per-protocol build cache.
FROM rust:1-bookworm AS build
WORKDIR /build/transport
COPY . ./
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=build /build/transport/target/release/tcp-sender    /usr/local/bin/tcp-sender
COPY --from=build /build/transport/target/release/tcp-sink      /usr/local/bin/tcp-sink
COPY --from=build /build/transport/target/release/udp-sender    /usr/local/bin/udp-sender
COPY --from=build /build/transport/target/release/udp-sink      /usr/local/bin/udp-sink
COPY --from=build /build/transport/target/release/socks5-sender /usr/local/bin/socks5-sender
COPY --from=build /build/transport/target/release/tls-sender    /usr/local/bin/tls-sender
COPY --from=build /build/transport/target/release/tls-sink      /usr/local/bin/tls-sink
COPY --from=build /build/transport/target/release/tor-sender    /usr/local/bin/tor-sender
COPY --from=build /build/transport/target/release/tor-sink      /usr/local/bin/tor-sink
