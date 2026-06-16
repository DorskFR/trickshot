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
| `GET /tunnel` | WebSocket upgrade; opens a reverse tunnel for private/VPN URLs (auth required) |

Query params:

| Param | Aliases | Required | Default | Description |
|-------|---------|----------|---------|-------------|
| `url` | — | yes | — | page to render |
| `width` | `w` | no | `TRICKSHOT_DEFAULT_WIDTH` | viewport width in px |
| `height` | `h` | no | `TRICKSHOT_DEFAULT_HEIGHT` | viewport height in px |
| `scale` | `dpr` | no | `1.0` | device pixel ratio; `2` = crisp 2x retina render |
| `timeout` | — | no | `TRICKSHOT_RENDER_TIMEOUT_SECS` | render timeout in seconds |
| `tunnel` | — | no | — | id of an open reverse tunnel to route this shot through (see below) |

```
curl -H 'X-API-Key: <key>' \
  'http://localhost:8900/shot?url=https://example.com' -o shot.png
```

## `ts` — CLI client

`ts` is a small standalone binary (no Chrome dependency) that talks to a running
trickshot server: it requests a screenshot and saves the PNG, and with
`--tunnel` it doubles as the reverse-tunnel agent (see below) so a URL only
reachable from *your* network can be screenshotted.

Install: download the binary for your platform from the
[Releases](https://github.com/dorskfr/trickshot/releases) page and put it on
your `PATH`:

```
# pick the asset matching your OS/arch: ts-linux-amd64, ts-linux-arm64, ts-darwin-arm64
curl -fsSL -o ts https://github.com/dorskfr/trickshot/releases/latest/download/ts-linux-amd64
chmod +x ts && sudo mv ts /usr/local/bin/
# verify against SHA256SUMS on the same release
```

Usage:

```
export TRICKSHOT_URL=https://shot.example.com
export TRICKSHOT_API_KEY=<key>

ts https://www.cryptact.io -w 1920 --height 1080 --dpr 2 -o shot.png
ts https://internal.svc/dashboard --tunnel --height 1080 --dpr 2 -o shot.png
```

| Flag | Default | Description |
|------|---------|-------------|
| `<URL>` | — | page to screenshot (positional, required) |
| `--server` / `TRICKSHOT_URL` | — | trickshot server base URL |
| `--api-key` / `TRICKSHOT_API_KEY` | — | API key, sent as `X-API-Key` |
| `-w`, `--width` | server default | viewport width in px |
| `--height` | server default | viewport height in px (no `-h` short — that's `--help`) |
| `--dpr` (alias `--scale`) | `1.0` | device pixel ratio; long-only (a `-dpr` short would parse as `-d -p -r`) |
| `--timeout` | server default | render timeout in seconds |
| `-o`, `--output` | `<host>.png` | output file, or `-` for stdout |
| `--tunnel` | off | open a reverse tunnel for this shot |

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

## Reverse tunnels (private/VPN URLs)

The pod egresses straight to the public internet, so a URL only reachable over a
VPN or on a private network can't be screenshotted directly. A **requester** who
*does* have that reachability can open a reverse tunnel the browser then uses:

```
requester agent ──wss──> /tunnel ──> per-tunnel loopback SOCKS5 ──> Chrome context
       │                                                                  │
       └── dials the private URL on its own network <── tunneled TCP <─────┘
```

1. The agent (`ts --tunnel`) opens a WebSocket to `GET /tunnel` (authenticated
   with the same API key as `/shot`). The server binds a per-tunnel SOCKS5 proxy
   on loopback and sends back the `tunnel_id` as the first WS frame (a text
   message `{"tunnel_id":"…"}`).
2. `GET /shot?url=https://internal.svc/&tunnel=<id>` renders that URL through a
   Chrome browser context whose `proxyServer` is the tunnel's loopback SOCKS5
   listener. Chrome resolves DNS *at the proxy*, so the private hostname is
   resolved on the requester's side. Without `tunnel=`, behaviour is unchanged
   (direct egress + the SSRF block below).

The tunnel's lifetime is tied to the WebSocket: when it drops (or idles out per
`TRICKSHOT_TUNNEL_IDLE_SECS`) the SOCKS listener is torn down and the port
freed. Concurrent tunnels are capped by `TRICKSHOT_MAX_TUNNELS`. The SOCKS
listener binds loopback only, so it is never externally reachable. Because
reachability is delegated to the requester's own network, the SSRF private-IP
block is intentionally **skipped** for tunneled shots.

The wire protocol (a text hello with the `tunnel_id`, then one WS multiplexing
TCP streams via a `[op][stream_id]` binary framing) is documented at the top of
`crates/trickshot-server/src/tunnel.rs`. The requester-side agent that dials
targets and pipes bytes back ships in the `ts` CLI (`ts --tunnel`, see above).

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
