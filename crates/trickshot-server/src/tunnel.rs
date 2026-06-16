//! Requester-established reverse tunnels (TRI-5, server side).
//!
//! A requester who already has VPN/private-network reachability opens a
//! WebSocket to `GET /tunnel`. The server then binds a *per-tunnel* SOCKS5
//! proxy on loopback (`127.0.0.1:0`) and registers it under a freshly minted
//! `tunnel_id`. A later `GET /shot?...&tunnel=<id>` renders the page through a
//! Chrome browser context whose `proxyServer` points at that loopback SOCKS5
//! listener, so every TCP connection Chrome makes is framed over the WebSocket
//! and dialed *from the requester's network* — reaching hosts the pod itself
//! cannot.
//!
//! ## Why SOCKS5
//! Chrome resolves DNS at the proxy, so private hostnames resolve on the
//! requester's side where they're valid. HTTP CONNECT would resolve locally.
//!
//! ## Wire protocol
//! On upgrade the server sends one **text** frame `{"tunnel_id":"…"}` so the
//! agent learns the id to pass to `/shot?...&tunnel=<id>`. Everything after is
//! **binary**: one WS multiplexes many TCP streams via a 1-byte opcode +
//! 4-byte big-endian stream id:
//!
//! - `0x01` Open  — `[0x01][id:u32][host_len:u16][host][port:u16]` (server→agent)
//! - `0x02` Data  — `[0x02][id:u32][bytes…]`                        (both ways)
//! - `0x03` Close — `[0x03][id:u32]`                                (both ways)
//!
//! The agent (TRI-6, separate ticket) dials `host:port` locally on Open, pipes
//! bytes both ways as Data, and emits Close on EOF/error.
//!
//! ## Security
//! - `/tunnel` requires the same API key as `/shot` (TRI-4); an open tunnel is
//!   itself an SSRF/relay primitive.
//! - The SOCKS5 listener binds loopback only, so it is never externally
//!   reachable, and its lifetime is tied to the WebSocket: when the WS drops
//!   (or idles out) the listener and all streams are torn down and the port is
//!   freed.
//! - The direct-path private-IP block (TRI-4) is intentionally *skipped* for
//!   tunneled shots: reachability is delegated to the requester's own network.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, mpsc};

// Wire opcodes.
const OP_OPEN: u8 = 0x01;
const OP_DATA: u8 = 0x02;
const OP_CLOSE: u8 = 0x03;

/// A live tunnel: the loopback SOCKS5 endpoint Chrome should proxy through,
/// plus the identity of the key that opened it (for attribution).
pub struct Tunnel {
    /// `127.0.0.1:<port>` the per-tunnel SOCKS5 proxy listens on.
    pub socks_addr: SocketAddr,
    /// Key id that opened the tunnel.
    pub key_id: String,
}

impl Tunnel {
    /// The `proxyServer` string to hand a Chrome browser context.
    pub fn proxy_server(&self) -> String {
        format!("socks5://{}", self.socks_addr)
    }
}

/// Process-wide registry of open tunnels, keyed by `tunnel_id`.
#[derive(Default)]
pub struct TunnelRegistry {
    inner: RwLock<HashMap<String, Arc<Tunnel>>>,
}

impl TunnelRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn count(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn get(&self, id: &str) -> Option<Arc<Tunnel>> {
        self.inner.read().await.get(id).cloned()
    }

    async fn insert(&self, id: String, tunnel: Arc<Tunnel>) {
        self.inner.write().await.insert(id, tunnel);
    }

    async fn remove(&self, id: &str) {
        self.inner.write().await.remove(id);
    }
}

/// Mint an unguessable tunnel id (128 bits, url-safe base64).
fn mint_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Per-stream sink: bytes the SOCKS side wants delivered to the proxy peer
/// (i.e. forwarded to Chrome). Each accepted SOCKS connection registers one.
type StreamTx = mpsc::UnboundedSender<Vec<u8>>;

/// Shared state for one open tunnel's WebSocket: routes inbound Data/Close
/// frames to the right SOCKS-side stream, and lets SOCKS-side tasks send
/// frames out over the single WS.
struct TunnelConn {
    /// Writer half of the WS, shared by every stream (frames are independent).
    ws_tx: Mutex<SplitSink<WebSocket, Message>>,
    /// stream_id → channel feeding bytes back to the local SOCKS connection.
    streams: Mutex<HashMap<u32, StreamTx>>,
    next_id: AtomicU32,
}

impl TunnelConn {
    async fn send(&self, frame: Vec<u8>) -> bool {
        self.ws_tx.lock().await.send(Message::Binary(frame.into())).await.is_ok()
    }

    fn open_frame(id: u32, host: &str, port: u16) -> Vec<u8> {
        let host = host.as_bytes();
        let mut f = Vec::with_capacity(1 + 4 + 2 + host.len() + 2);
        f.push(OP_OPEN);
        f.extend_from_slice(&id.to_be_bytes());
        f.extend_from_slice(&(host.len() as u16).to_be_bytes());
        f.extend_from_slice(host);
        f.extend_from_slice(&port.to_be_bytes());
        f
    }

    fn data_frame(id: u32, data: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(1 + 4 + data.len());
        f.push(OP_DATA);
        f.extend_from_slice(&id.to_be_bytes());
        f.extend_from_slice(data);
        f
    }

    fn close_frame(id: u32) -> Vec<u8> {
        let mut f = Vec::with_capacity(5);
        f.push(OP_CLOSE);
        f.extend_from_slice(&id.to_be_bytes());
        f
    }
}

/// Configuration for tunnel lifecycle limits.
#[derive(Debug, Clone, Copy)]
pub struct TunnelConfig {
    /// Maximum concurrent open tunnels; further upgrades are rejected.
    pub max_tunnels: usize,
    /// Drop a tunnel after this long without any WS traffic.
    pub idle_timeout: Duration,
}

/// Drive a single tunnel: bind its loopback SOCKS5 listener, register it, then
/// pump the WebSocket until it closes or idles out. Always deregisters and
/// frees the port on exit.
pub async fn run(
    socket: WebSocket,
    registry: Arc<TunnelRegistry>,
    cfg: TunnelConfig,
    key_id: String,
) {
    let mut socket = socket;
    if !admit(&registry, cfg.max_tunnels).await {
        let _ = socket.send(Message::Close(None)).await;
        return;
    }

    let Some((listener, socks_addr)) = bind_socks().await else {
        return;
    };

    let id = mint_id();
    let tunnel = Arc::new(Tunnel { socks_addr, key_id: key_id.clone() });
    registry.insert(id.clone(), tunnel).await;
    tracing::info!(tunnel_id = %id, socks = %socks_addr, key_id = %key_id, "tunnel open");

    // Hand the freshly minted id to the agent as the first frame: a single text
    // message `{"tunnel_id":"…"}`. The agent reads it, then issues its shot with
    // `&tunnel=<id>`. Every binary frame after this is the stream multiplex.
    let hello = format!("{{\"tunnel_id\":\"{id}\"}}");
    if socket.send(Message::Text(hello.into())).await.is_err() {
        registry.remove(&id).await;
        return;
    }

    let conn = session(socket, listener, cfg.idle_timeout, &id).await;

    // Teardown: deregister and drop all stream channels (which closes the local
    // SOCKS connections). The accept task and listener were owned by `session`
    // and are gone now, freeing the port.
    registry.remove(&id).await;
    conn.streams.lock().await.clear();
    tracing::info!(tunnel_id = %id, "tunnel closed");
}

/// Run the active phase of a tunnel: spawn the SOCKS accept loop and pump the
/// WebSocket until it closes or idles out. Returns the shared [`TunnelConn`] so
/// the caller can drain its streams during teardown.
async fn session(
    socket: WebSocket,
    listener: TcpListener,
    idle_timeout: Duration,
    id: &str,
) -> Arc<TunnelConn> {
    let (ws_tx, ws_rx) = socket.split();
    let conn = Arc::new(TunnelConn {
        ws_tx: Mutex::new(ws_tx),
        streams: Mutex::new(HashMap::new()),
        next_id: AtomicU32::new(1),
    });

    let accept = tokio::spawn(accept_loop(listener, conn.clone()));
    if let Err(reason) = ws_pump(ws_rx, conn.clone(), idle_timeout).await {
        tracing::info!(tunnel_id = %id, reason, "tunnel closing");
    }
    accept.abort();
    conn
}

/// Capacity gate. Best-effort: `count` then register; a tiny race can admit one
/// over the cap, which is acceptable for a soft limit.
async fn admit(registry: &TunnelRegistry, max_tunnels: usize) -> bool {
    if registry.count().await >= max_tunnels {
        tracing::warn!(max = max_tunnels, "tunnel rejected: at capacity");
        return false;
    }
    true
}

/// Bind the per-tunnel SOCKS5 listener on an ephemeral loopback port. Returns
/// `None` (after logging) if binding or reading the address fails.
async fn bind_socks() -> Option<(TcpListener, SocketAddr)> {
    let listener = match TcpListener::bind(("127.0.0.1", 0)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "tunnel: cannot bind loopback SOCKS5 listener");
            return None;
        }
    };
    match listener.local_addr() {
        Ok(addr) => Some((listener, addr)),
        Err(e) => {
            tracing::warn!(error = %e, "tunnel: cannot read SOCKS5 listener addr");
            None
        }
    }
}

/// Pump inbound WebSocket frames until the socket closes or `idle_timeout`
/// elapses with no traffic. Returns `Err(reason)` describing why it ended.
async fn ws_pump(
    mut ws_rx: SplitStream<WebSocket>,
    conn: Arc<TunnelConn>,
    idle_timeout: Duration,
) -> Result<(), &'static str> {
    loop {
        let msg = match tokio::time::timeout(idle_timeout, ws_rx.next()).await {
            Err(_) => return Err("idle timeout"),
            Ok(None) => return Err("websocket closed"),
            Ok(Some(Err(_))) => return Err("websocket error"),
            Ok(Some(Ok(m))) => m,
        };
        match msg {
            Message::Binary(b) => handle_frame(&conn, &b).await,
            Message::Close(_) => return Err("client closed"),
            // Text/Ping/Pong: ignored (axum auto-replies to Ping); they still
            // count as traffic and reset the idle timer.
            _ => {}
        }
    }
}

/// Route one inbound agent→server frame to its SOCKS-side stream.
async fn handle_frame(conn: &TunnelConn, frame: &[u8]) {
    if frame.is_empty() {
        return;
    }
    let op = frame[0];
    if frame.len() < 5 {
        return; // need at least op + stream id
    }
    let id = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
    match op {
        OP_DATA => {
            let payload = frame[5..].to_vec();
            if let Some(tx) = conn.streams.lock().await.get(&id) {
                let _ = tx.send(payload);
            }
        }
        OP_CLOSE => {
            // Drop the sender → the per-stream forwarder sees channel close and
            // shuts down its half of the local SOCKS connection.
            conn.streams.lock().await.remove(&id);
        }
        _ => {}
    }
}

/// Accept SOCKS5 connections from Chrome for the lifetime of the tunnel.
async fn accept_loop(listener: TcpListener, conn: Arc<TunnelConn>) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let conn = conn.clone();
                tokio::spawn(async move {
                    // Box the (large) per-stream future to keep the task small.
                    if let Err(e) = Box::pin(serve_socks(stream, conn)).await {
                        tracing::debug!(error = %e, "tunnel socks stream ended");
                    }
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "tunnel socks accept error");
                return;
            }
        }
    }
}

/// Handle one SOCKS5 client (Chrome): negotiate, read the CONNECT target, open
/// a tunnel stream for it, then pipe bytes both ways over the WebSocket.
async fn serve_socks(mut stream: TcpStream, conn: Arc<TunnelConn>) -> std::io::Result<()> {
    // --- SOCKS5 greeting: VER, NMETHODS, METHODS… ---
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(std::io::Error::other("not socks5"));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    // Reply: no authentication required (0x00). The proxy is loopback-only.
    stream.write_all(&[0x05, 0x00]).await?;

    // --- CONNECT request: VER, CMD, RSV, ATYP, ADDR, PORT ---
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        // Only CONNECT is supported; reply "command not supported".
        let _ = reply_socks(&mut stream, 0x07).await;
        return Err(std::io::Error::other("unsupported socks command"));
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            let _ = reply_socks(&mut stream, 0x08).await; // addr type not supported
            return Err(std::io::Error::other("unsupported socks atyp"));
        }
    };
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    // Allocate a stream id and a channel for agent→Chrome bytes.
    let stream_id = conn.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    conn.streams.lock().await.insert(stream_id, tx);

    // Ask the agent to open the connection on its network.
    if !conn.send(TunnelConn::open_frame(stream_id, &host, port)).await {
        conn.streams.lock().await.remove(&stream_id);
        let _ = reply_socks(&mut stream, 0x01).await; // general failure
        return Err(std::io::Error::other("tunnel websocket gone"));
    }

    // We optimistically report success: bytes flow once the agent dials. (A v1
    // tradeoff — there is no per-stream Open-ack in the wire protocol.)
    reply_socks(&mut stream, 0x00).await?;

    let (mut read_half, mut write_half) = stream.into_split();

    // Chrome → agent: read from the socket, frame as Data over the WS.
    let conn_up = conn.clone();
    let up = async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if !conn_up.send(TunnelConn::data_frame(stream_id, &buf[..n])).await {
                        break;
                    }
                }
            }
        }
        // Tell the agent this stream is done.
        conn_up.send(TunnelConn::close_frame(stream_id)).await;
    };

    // agent → Chrome: drain the per-stream channel into the socket.
    let down = async move {
        while let Some(bytes) = rx.recv().await {
            if write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = write_half.shutdown().await;
    };

    tokio::join!(up, down);
    conn.streams.lock().await.remove(&stream_id);
    Ok(())
}

/// Write a minimal SOCKS5 reply with the given status and a `0.0.0.0:0` BND
/// address (clients ignore the bound address for CONNECT).
async fn reply_socks(stream: &mut TcpStream, status: u8) -> std::io::Result<()> {
    stream.write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_frame_layout() {
        let f = TunnelConn::open_frame(258, "host.internal", 8080);
        assert_eq!(f[0], OP_OPEN);
        assert_eq!(u32::from_be_bytes([f[1], f[2], f[3], f[4]]), 258);
        let host_len = u16::from_be_bytes([f[5], f[6]]) as usize;
        assert_eq!(host_len, "host.internal".len());
        let host = &f[7..7 + host_len];
        assert_eq!(host, b"host.internal");
        let port = u16::from_be_bytes([f[7 + host_len], f[8 + host_len]]);
        assert_eq!(port, 8080);
    }

    #[test]
    fn data_and_close_frame_layout() {
        let d = TunnelConn::data_frame(7, b"hello");
        assert_eq!(d[0], OP_DATA);
        assert_eq!(u32::from_be_bytes([d[1], d[2], d[3], d[4]]), 7);
        assert_eq!(&d[5..], b"hello");

        let c = TunnelConn::close_frame(7);
        assert_eq!(c, vec![OP_CLOSE, 0, 0, 0, 7]);
    }

    #[test]
    fn proxy_server_string() {
        let t = Tunnel { socks_addr: "127.0.0.1:5000".parse().unwrap(), key_id: "k1".into() };
        assert_eq!(t.proxy_server(), "socks5://127.0.0.1:5000");
    }

    #[test]
    fn mint_id_is_unguessable_and_unique() {
        let a = mint_id();
        let b = mint_id();
        assert_ne!(a, b);
        // 16 bytes url-safe-base64 (no pad) = 22 chars.
        assert_eq!(a.len(), 22);
    }
}
