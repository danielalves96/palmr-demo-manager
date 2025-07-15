FROM rust:1.82 as builder

WORKDIR /usr/src/app

COPY . .

RUN cargo install --path .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/palmr-demo-manager /usr/local/bin/palmr-demo-manager

CMD ["palmr-demo-manager"]