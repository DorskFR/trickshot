TRICKSHOT_BIND     ?= 0.0.0.0:8900
TRICKSHOT_SERVO_BIN ?= $(PWD)/vendor/servo/servoshell

export TRICKSHOT_BIND
export TRICKSHOT_SERVO_BIN

# Pinned Servo nightly used for local dev + the container image.
SERVO_VERSION ?= 2026-06-14
SERVO_URL     ?= https://github.com/servo/servo-nightly-builds/releases/download/$(SERVO_VERSION)/servo-x86_64-linux-gnu.tar.gz

# Published to GitHub Container Registry. Override IMAGE_REGISTRY to publish elsewhere.
IMAGE_REGISTRY ?= ghcr.io/dorskfr
IMAGE_REPO     ?= trickshot
IMAGE_VERSION  ?= $(shell awk -F'"' '/^\[package\]/{f=1} f && /^version/{print $$2; exit}' Cargo.toml)
IMAGE          ?= $(IMAGE_REGISTRY)/$(IMAGE_REPO)

.PHONY: build check test fmt lint clean run servo
.PHONY: image/build image/push image/release

# ── Build ──────────────────────────────────────────────────

build:  ## Build in release mode
	cargo build --release

check:  ## Type check
	cargo check

# ── Format & Lint ──────────────────────────────────────────

fmt:  ## Auto-format (nightly rustfmt for unstable options)
	cargo +nightly fmt

lint:  ## Run clippy with deny warnings
	cargo clippy --all-targets -- -D warnings

# ── Test ───────────────────────────────────────────────────

test:  ## Run tests
	cargo test

# ── Run ────────────────────────────────────────────────────

servo:  ## Download the pinned Servo nightly into vendor/
	mkdir -p vendor
	curl -sL --fail -o vendor/servo.tar.gz "$(SERVO_URL)"
	tar xzf vendor/servo.tar.gz -C vendor
	rm -f vendor/servo.tar.gz
	@echo "servoshell at vendor/servo/servoshell"

run:  ## Run the server locally (needs servoshell; run `make servo` first)
	cargo run

# ── Image ──────────────────────────────────────────────────

image/build:  ## Build container image tagged with the Cargo.toml version (no :latest)
	docker build --platform linux/amd64 -f deploy/Dockerfile \
	  --build-arg SERVO_VERSION=$(SERVO_VERSION) \
	  -t $(IMAGE):$(IMAGE_VERSION) .

image/push:  ## Push the versioned image tag
	docker push $(IMAGE):$(IMAGE_VERSION)

image/release: image/build image/push  ## Build + push container image

# ── Clean ──────────────────────────────────────────────────

clean:  ## Remove build artifacts
	cargo clean

# ── Help ───────────────────────────────────────────────────

help:  ## Show this help
	@grep -E '^[a-zA-Z_/]+:.*##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*##"}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
