# Build trickshot on bookworm-based rust so the binary matches the bookworm-slim
# runtime glibc.
FROM rust:1.90-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p trickshot

# ── Runtime: trickshot + the Chromium it drives over CDP ─────────────────────
FROM debian:bookworm-slim

# Runtime deps. trickshot itself only needs ca-certificates/libssl3; `chromium`
# backs the /shot (CDP) endpoint and pulls its own large dep tree. The font set
# (incl. CJK) is what Chromium needs to render text correctly headless.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 \
      chromium \
      fontconfig fonts-liberation fonts-noto-cjk libfreetype6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/trickshot /usr/local/bin/trickshot

ENV TRICKSHOT_BIND=0.0.0.0:8900 \
    TRICKSHOT_CHROME_BIN=/usr/bin/chromium
EXPOSE 8900
CMD ["trickshot"]
