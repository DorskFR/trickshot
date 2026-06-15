# trickshot

Fast screenshot-as-API: `GET /shot?url=…` renders a page and returns the image.
Rendering is backed by [Servo](https://servo.org) (Rust, no Chromium).

## API

| Route | Description |
|-------|-------------|
| `GET /health` | liveness, returns `ok` |
| `GET /shot?url=<URL>` | render `URL`, returns `image/png` |

`/shot` query params: `url` (required), `w`/`width`, `h`/`height`, `dpr`/`device_pixel_ratio`, `timeout` (seconds).

```
curl 'http://localhost:8900/shot?url=https://example.com&w=1280&h=900' -o shot.png
```

## Develop

```
make servo   # fetch the pinned Servo nightly into vendor/
make run      # cargo run (uses vendor/servo/servoshell)
make fmt lint test
```

Config is via env (see `.env.example`): `TRICKSHOT_BIND`, `TRICKSHOT_SERVO_BIN`,
`TRICKSHOT_DEFAULT_WIDTH/HEIGHT`, `TRICKSHOT_RENDER_TIMEOUT_SECS`,
`TRICKSHOT_MAX_CONCURRENCY`, `RUST_LOG`.

## Design

The HTTP layer depends only on `ServoRenderer::render() -> Result<Vec<u8>>`.
Phase 1 drives the `servoshell` headless binary as a subprocess — one cold
process per shot, simple and correct. `max_concurrency` caps simultaneous Servo
processes to bound memory (each is ~300–800MB).

Phase 2 swaps that seam for an embedded, warm renderer built on the `servo`
crate (reuse the engine across requests, kill per-shot startup), then tunneling
to reach services the renderer can't route to directly.

Images push to `ghcr.io/dorskfr/trickshot`, tag-driven (`v*`).
