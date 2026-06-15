# trickshot

Fast screenshot-as-API: `GET /shot?url=…` renders a page and returns the image.
A pool of **always-warm [Servo](https://servo.org) engines** (Rust, no Chromium)
is driven over WebDriver, so a shot is just navigate + screenshot — no per-request
browser startup.

## API

| Route | Description |
|-------|-------------|
| `GET /health` | liveness, returns `ok` |
| `GET /shot?url=<URL>` | render `URL` via the Servo pool, returns `image/png` |
| `GET /shot2?url=<URL>` | render `URL` via always-warm headless Chrome (CDP), returns `image/png` |

Both endpoints share the same query params: `url` (required), `w`/`width`,
`h`/`height`, `timeout` (seconds). `/shot2` uses Chrome for accurate image/font
rendering where Servo falls short.

```
curl 'http://localhost:8900/shot?url=https://example.com'  -o shot.png
curl 'http://localhost:8900/shot2?url=https://example.com' -o shot.png
```

## Develop

```
make servo   # fetch the pinned Servo nightly into vendor/
make run      # cargo run (boots the Servo pool + warm Chrome)
make fmt lint test
```

`/shot2` needs a Chrome/Chromium binary. The container ships `chromium`; for
local runs install one and point `TRICKSHOT_CHROME_BIN` at it (or let it
auto-detect). Chrome is launched once at startup and kept warm, so booting the
server requires it to be present.

Config is via env (see `.env.example`): `TRICKSHOT_BIND`, `TRICKSHOT_SERVO_BIN`,
`TRICKSHOT_POOL_SIZE`, `TRICKSHOT_WEBDRIVER_BASE_PORT`,
`TRICKSHOT_DEFAULT_WIDTH/HEIGHT`, `TRICKSHOT_RENDER_TIMEOUT_SECS`,
`TRICKSHOT_WORKER_READY_TIMEOUT_SECS`, `TRICKSHOT_CHECKOUT_TIMEOUT_SECS`,
`TRICKSHOT_CHROME_BIN`, `TRICKSHOT_CHROME_MAX_CONCURRENCY`, `RUST_LOG`.

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

`/shot2` takes a different shape: one headless Chrome launched once at startup
and driven over the DevTools Protocol. Instead of one engine per worker, the
single browser multiplexes requests through cheap, isolated pages (tabs) — each
request opens a fresh page, sets its viewport, navigates, screenshots, and
closes it — with a semaphore (`CHROME_MAX_CONCURRENCY`) bounding simultaneous
renders. Chrome is slower to boot and heavier in memory than Servo, but renders
images, fonts, and modern CSS faithfully.

Next: tunneling to reach services the renderer can't route to directly.

Images build + publish to `ghcr.io/dorskfr/trickshot` via GitHub Actions,
tag-driven (`v*`).
