# trickshot

Fast screenshot-as-API: `GET /shot?url=…` renders a page and returns the image.
A pool of **always-warm [Servo](https://servo.org) engines** (Rust, no Chromium)
is driven over WebDriver, so a shot is just navigate + screenshot — no per-request
browser startup.

## API

| Route | Description |
|-------|-------------|
| `GET /health` | liveness, returns `ok` |
| `GET /shot?url=<URL>` | render `URL`, returns `image/png` |

`/shot` query params: `url` (required), `w`/`width`, `h`/`height`, `timeout` (seconds).

```
curl 'http://localhost:8900/shot?url=https://example.com' -o shot.png
```

## Develop

```
make servo   # fetch the pinned Servo nightly into vendor/
make run      # cargo run (boots a warm pool using vendor/servo/servoshell)
make fmt lint test
```

Config is via env (see `.env.example`): `TRICKSHOT_BIND`, `TRICKSHOT_SERVO_BIN`,
`TRICKSHOT_POOL_SIZE`, `TRICKSHOT_WEBDRIVER_BASE_PORT`,
`TRICKSHOT_DEFAULT_WIDTH/HEIGHT`, `TRICKSHOT_RENDER_TIMEOUT_SECS`,
`TRICKSHOT_WORKER_READY_TIMEOUT_SECS`, `TRICKSHOT_CHECKOUT_TIMEOUT_SECS`, `RUST_LOG`.

## Design

On startup trickshot launches `POOL_SIZE` headless `servoshell` processes, each
with a WebDriver server on its own port, and keeps a session open on each. A
request checks a warm worker out of the pool, navigates, screenshots, and returns
it. A worker that errors is killed and respawned on its port, so the pool
self-heals without leaking a slot.

Warm light pages return in tens of milliseconds. Heavy pages are bounded by
Servo's software rasterizer, which is also viewport-sensitive: its headless
screenshot degrades sharply above ~1024px wide, hence the conservative default
viewport and a one-shot screenshot retry.

Next: tunneling to reach services the renderer can't route to directly.

Images build + publish to `ghcr.io/dorskfr/trickshot` via GitHub Actions,
tag-driven (`v*`).
