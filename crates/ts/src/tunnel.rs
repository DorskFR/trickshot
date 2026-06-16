//! Reverse-tunnel agent (TRI-6 client side, pairs with TRI-5 server).
//!
//! Opens a WebSocket to `GET /tunnel`, reads the first text frame
//! `{"tunnel_id":"…"}`, then multiplexes TCP streams over the single WS using
//! the server's binary framing (see `trickshot-server/src/tunnel.rs`):
//!
//! * `0x01` Open  — `[0x01][id:u32][host_len:u16][host][port:u16]` (server→agent)
//! * `0x02` Data  — `[0x02][id:u32][bytes…]`                       (both ways)
//! * `0x03` Close — `[0x03][id:u32]`                               (both ways)
//!
//! On Open the agent dials `host:port` *locally* (DNS resolves on the caller's
//! network, so private/VPN names work), then pipes bytes both ways as Data and
//! emits Close on EOF/error. The shot is issued with `&tunnel=<id>` while the
//! agent runs; when the shot finishes the WS is dropped and the server tears the
//! tunnel down. Single foreground command — the agent lives only for the shot.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use url::Url;

use crate::Args;

const OP_OPEN: u8 = 0x01;
const OP_DATA: u8 = 0x02;
const OP_CLOSE: u8 = 0x03;

/// Frames the agent sends back to the server over the single shared WS.
type WsTx = mpsc::UnboundedSender<Message>;
/// Per-stream channel feeding server→target bytes to the local dialer task.
type StreamTx = mpsc::UnboundedSender<Vec<u8>>;

fn data_frame(id: u32, data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(5 + data.len());
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

/// Derive the `ws(s)://${server}/tunnel` URL from the http(s) base.
fn tunnel_url(server: &str) -> Result<Url> {
    let base = server.trim_end_matches('/');
    let mut u = Url::parse(&format!("{base}/tunnel")).context("invalid --server url")?;
    let scheme = match u.scheme() {
        "https" | "wss" => "wss",
        "http" | "ws" => "ws",
        other => bail!("unsupported server scheme: {other}"),
    };
    u.set_scheme(scheme).ok();
    Ok(u)
}

/// Open the tunnel, run the agent loop alongside the shot, then tear down.
pub async fn run(args: &Args, parsed: &Url) -> Result<()> {
    let ws_url = tunnel_url(&args.server)?;
    let mut request =
        ws_url.as_str().into_client_request().context("building tunnel websocket request")?;
    request
        .headers_mut()
        .insert("X-API-Key", args.api_key.parse().context("invalid api key header")?);

    let (ws, _resp) =
        tokio_tungstenite::connect_async(request).await.context("connecting /tunnel websocket")?;
    let (mut ws_sink, mut ws_stream) = ws.split();

    // First frame is the tunnel id.
    let tunnel_id = read_tunnel_id(&mut ws_stream).await?;
    eprintln!("ts: tunnel open ({tunnel_id})");

    // Single writer task owns the sink; everything else sends frames to it.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Agent loop: route inbound frames to per-stream dialer tasks.
    let streams: Arc<Mutex<HashMap<u32, StreamTx>>> = Arc::new(Mutex::new(HashMap::new()));
    let agent_tx = out_tx.clone();
    let agent = tokio::spawn(async move {
        while let Some(msg) = ws_stream.next().await {
            match msg {
                Ok(Message::Binary(b)) => handle_frame(&b, &streams, &agent_tx).await,
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
    });

    // Take the shot through the tunnel while the agent serves connections.
    let shot = crate::fetch_shot(args, Some(&tunnel_id)).await;

    // Tear down: dropping the writer's sender ends it, which drops the WS and
    // lets the server free the tunnel; abort the agent loop.
    drop(out_tx);
    agent.abort();
    let _ = writer.await;

    let png = shot.context("taking shot through tunnel")?;
    crate::write_output(args, parsed, &png).await
}

/// Read frames until the first text frame, parse its `tunnel_id`.
async fn read_tunnel_id<S>(ws_stream: &mut S) -> Result<String>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    while let Some(msg) = ws_stream.next().await {
        match msg.context("reading tunnel hello")? {
            Message::Text(t) => {
                let v: serde_json::Value =
                    serde_json::from_str(&t).context("parsing tunnel hello")?;
                return v
                    .get("tunnel_id")
                    .and_then(|x| x.as_str())
                    .map(str::to_owned)
                    .context("tunnel hello missing tunnel_id");
            }
            Message::Close(_) => bail!("tunnel closed before sending id"),
            _ => {}
        }
    }
    bail!("tunnel websocket ended before sending id")
}

/// Route one inbound server→agent frame.
async fn handle_frame(frame: &[u8], streams: &Arc<Mutex<HashMap<u32, StreamTx>>>, ws_tx: &WsTx) {
    if frame.len() < 5 {
        return;
    }
    let op = frame[0];
    let id = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
    match op {
        OP_OPEN => {
            // `[host_len:u16][host][port:u16]`
            let rest = &frame[5..];
            if rest.len() < 2 {
                return;
            }
            let host_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if rest.len() < 2 + host_len + 2 {
                return;
            }
            let host = String::from_utf8_lossy(&rest[2..2 + host_len]).into_owned();
            let port = u16::from_be_bytes([rest[2 + host_len], rest[3 + host_len]]);

            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
            streams.lock().await.insert(id, tx);
            let ws_tx = ws_tx.clone();
            let streams = streams.clone();
            tokio::spawn(async move {
                Box::pin(serve_stream(id, host, port, rx, ws_tx.clone())).await;
                streams.lock().await.remove(&id);
                // EOF/error → tell the server the stream is done.
                let _ = ws_tx.send(Message::Binary(close_frame(id)));
            });
        }
        OP_DATA => {
            let payload = frame[5..].to_vec();
            if let Some(tx) = streams.lock().await.get(&id) {
                let _ = tx.send(payload);
            }
        }
        OP_CLOSE => {
            // Drop the sender → the dialer task sees its channel close and ends.
            streams.lock().await.remove(&id);
        }
        _ => {}
    }
}

/// Dial `host:port` locally and pipe bytes both ways for one stream.
async fn serve_stream(
    id: u32,
    host: String,
    port: u16,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ws_tx: WsTx,
) {
    let stream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ts: tunnel dial {host}:{port} failed: {e}");
            return;
        }
    };
    let (mut read_half, mut write_half) = stream.into_split();

    // target → server: read from the socket, frame as Data.
    let up = async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx.send(Message::Binary(data_frame(id, &buf[..n]))).is_err() {
                        break;
                    }
                }
            }
        }
    };

    // server → target: drain the per-stream channel into the socket.
    let down = async move {
        while let Some(bytes) = rx.recv().await {
            if write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = write_half.shutdown().await;
    };

    tokio::join!(up, down);
}
