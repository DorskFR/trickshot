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

# Runtime deps. Derived from `ldd servoshell`: trickshot itself only needs
# ca-certificates/libssl3, but servoshell links GStreamer + EGL/GBM/DRM/Wayland/X
# and needs fonts (incl. CJK) and the Mesa software (llvmpipe) driver to render
# headless.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libssl3 \
      fontconfig fonts-liberation fonts-noto-cjk libfreetype6 \
      gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
      libgstreamer1.0-0 libgstreamer-plugins-base1.0-0 libgstreamer-plugins-bad1.0-0 \
      libgstreamer-gl1.0-0 \
      libgl1 libglx-mesa0 libegl1 libgl1-mesa-dri libgbm1 libdrm2 \
      libwayland-client0 libwayland-cursor0 libwayland-egl1 \
      libx11-6 libx11-xcb1 libxcb1 libxau6 libxdmcp6 libxext6 \
      libgudev-1.0-0 libunwind8 libdw1 libelf1 libbsd0 libbrotli1 liborc-0.4-0 \
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
