TRICKSHOT_BIND     ?= 0.0.0.0:8900

export TRICKSHOT_BIND

# Published to GitHub Container Registry. Override IMAGE_REGISTRY to publish elsewhere.
IMAGE_REGISTRY ?= ghcr.io/dorskfr
IMAGE_REPO     ?= trickshot
IMAGE_VERSION  ?= $(shell awk -F'"' '/^\[workspace.package\]/{f=1} f && /^version/{print $$2; exit}' Cargo.toml)
IMAGE          ?= $(IMAGE_REGISTRY)/$(IMAGE_REPO)

.PHONY: build check test fmt lint clean run
.PHONY: image/build image/push image/release

# ── Build ──────────────────────────────────────────────────

build:  ## Build in release mode
	cargo build --release -p trickshot

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

run:  ## Run the server locally (needs a Chrome/Chromium binary)
	cargo run -p trickshot

# ── Image ──────────────────────────────────────────────────

image/build:  ## Build container image tagged with the Cargo.toml version (no :latest)
	docker build --platform linux/amd64 -f crates/trickshot-server/deploy/Dockerfile \
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
