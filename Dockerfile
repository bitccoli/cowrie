FROM rust:1.85-bookworm AS builder

WORKDIR /src
COPY . .

RUN cargo build --release --workspace --bins

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/cowried /usr/local/bin/cowried
COPY --from=builder /src/target/release/cowrie-cli /usr/local/bin/cowrie-cli
COPY --from=builder /src/target/release/blind-seal-server /usr/local/bin/blind-seal-server
COPY --from=builder /src/target/release/cowrie-fedimintd /usr/local/bin/cowrie-fedimintd

EXPOSE 3100 3338 8173
CMD ["cowried", "--bind", "0.0.0.0:3338", "--data-dir", "/data"]
