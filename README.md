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
curl -H 'X-API-Key: <key>' \
  'http://localhost:8900/shot?url=https://example.com' -o shot.png
```

## Authentication

`/shot` requires an API key (`/health` stays open). Present it as a header
(`X-API-Key: <key>` or `Authorization: Bearer <key>`) or as a query param
(`?api_key=<key>`, composes with the existing `GET /shot?url=…`). A missing or
invalid key returns `401` with a JSON body. Keys are stored as SHA-256 hashes
only, never plaintext; the matched key id/label is logged per request for
attribution.

Keys live in a JSON file at `TRICKSHOT_KEYS_FILE` (default `/data/keys.json`),
on a writable volume in the pod. The server hot-reloads the file on change and
on `SIGHUP`, so keys can be added or revoked without a restart (fallback:
restart the pod).

### Key-management CLI

The same binary manages keys against `TRICKSHOT_KEYS_FILE`. `kubectl exec` into
the pod and run:

```
trickshot keys create --label ci   # generates a key, prints the secret ONCE
trickshot keys list                # id, label, created, status (never the secret)
trickshot keys disable <id>        # revoke without deleting
trickshot keys enable <id>
trickshot keys delete <id>
```

## SSRF protection

Defense in depth on top of auth: after the target URL is parsed its host is
resolved and any **private/reserved** IP is rejected — RFC1918 (`10/8`,
`172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), link-local
(`169.254/16` incl. cloud metadata `169.254.169.254`, `fe80::/10`), `0.0.0.0`,
ULA `fc00::/7`, and CGNAT `100.64/10`. Set
`TRICKSHOT_ALLOW_PRIVATE_TARGETS=true` to permit them (default deny). The check
is on the resolved IP, not just the literal host; a resolve-then-connect
TOCTOU/DNS-rebinding gap remains and full connect-time pinning is out of scope
for v1.

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
