# Build trickshot on bookworm-based rust so the binary matches the bookworm-slim
# runtime glibc.
FROM rust:1.90-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

# ── Runtime: trickshot + the Servo nightly it shells out to ──────────────────
FROM debian:bookworm-slim

# Pinned Servo nightly (overridable at build: --build-arg SERVO_VERSION=YYYY-MM-DD).
ARG SERVO_VERSION=2026-06-14
ARG SERVO_URL=https://github.com/servo/servo-nightly-builds/releases/download/${SERVO_VERSION}/servo-x86_64-linux-gnu.tar.gz

# Runtime deps for trickshot (ca-certificates, libssl3) plus Servo's needs
# (fonts/fontconfig/freetype for text, mesa/EGL/X libs for its renderer).
# NOTE: the Servo runtime dep set is best-effort and may need trimming/extending
# once validated in-cluster.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libssl3 \
      fontconfig fonts-liberation fonts-noto-cjk libfreetype6 \
      libgl1 libegl1 libgles2 libgl1-mesa-dri \
      libx11-6 libxcb1 libxext6 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/servo \
    && curl -sL --fail "${SERVO_URL}" -o /tmp/servo.tar.gz \
    && tar xzf /tmp/servo.tar.gz -C /opt/servo --strip-components=1 \
    && rm /tmp/servo.tar.gz \
    && ln -s /opt/servo/servoshell /usr/local/bin/servoshell

COPY --from=builder /app/target/release/trickshot /usr/local/bin/trickshot

ENV TRICKSHOT_BIND=0.0.0.0:8900 \
    TRICKSHOT_SERVO_BIN=servoshell
EXPOSE 8900
CMD ["trickshot"]
