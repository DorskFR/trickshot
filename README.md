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

Both endpoints share the same query params:

| Param | Aliases | Required | Default | Description |
|-------|---------|----------|---------|-------------|
| `url` | — | yes | — | page to render |
| `width` | `w` | no | `TRICKSHOT_DEFAULT_WIDTH` | viewport width in px |
| `height` | `h` | no | `TRICKSHOT_DEFAULT_HEIGHT` | viewport height in px |
| `timeout` | — | no | `TRICKSHOT_RENDER_TIMEOUT_SECS` | render timeout in seconds |

`/shot2` uses Chrome for accurate image/font rendering where Servo falls short.

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

Config is via env (see `.env.example`).
