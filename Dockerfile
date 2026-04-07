FROM rust:1-bookworm AS builder

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock* ./

RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY src src/

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    chromium \
    fonts-liberation \
    fonts-noto-color-emoji \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Tell headless_chrome where to find Chromium
ENV CHROME_PATH=/usr/bin/chromium

COPY --from=builder /usr/src/app/target/release/titanium /usr/local/bin/

EXPOSE 3000

CMD ["titanium"]
