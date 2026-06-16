# trickshot

Fast screenshot-as-API: `GET /shot?url=…` renders a page and returns the image.
An **always-warm headless Chrome** driven over the DevTools Protocol (CDP) backs
it — one process multiplexes requests across cheap, isolated tabs, so a shot is
just navigate + screenshot with no per-request browser startup.

## API

| Route | Description |
|-------|-------------|
| `GET /health` | liveness, returns `ok` |
| `GET /shot?url=<URL>` | render `URL` via headless Chrome (CDP), returns `image/png` |

Query params:

| Param | Aliases | Required | Default | Description |
|-------|---------|----------|---------|-------------|
| `url` | — | yes | — | page to render |
| `width` | `w` | no | `TRICKSHOT_DEFAULT_WIDTH` | viewport width in px |
| `height` | `h` | no | `TRICKSHOT_DEFAULT_HEIGHT` | viewport height in px |
| `scale` | `dpr` | no | `1.0` | device pixel ratio; `2` = crisp 2x retina render |
| `timeout` | — | no | `TRICKSHOT_RENDER_TIMEOUT_SECS` | render timeout in seconds |

```
curl 'http://localhost:8900/shot?url=https://example.com' -o shot.png
```

## Develop

```
make run      # cargo run (boots the warm Chrome)
make fmt lint test
```

`/shot` needs a Chrome/Chromium binary. The container ships `chromium`; for
local runs install one and point `TRICKSHOT_CHROME_BIN` at it (or let it
auto-detect). Chrome is launched once at startup and kept warm, so booting the
server requires it to be present.

Config is via env (see `.env.example`).
