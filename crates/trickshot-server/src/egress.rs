//! Loopback SOCKS5 proxy that every direct-egress Chrome connection goes
//! through. Chrome hands it hostnames unresolved (SOCKS5 remote DNS); the guard
//! resolves them, refuses the connection if any resolved address is blocked,
//! and dials the exact address it vetted. Redirect hops, subresources, iframes,
//! workers and WebSockets all hit this path, and there is no second lookup a
//! rebinding DNS server could answer differently.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::{socks, ssrf};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Returns `true` when connecting to the address must be refused.
pub type Policy = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

pub fn policy(allow_private: bool) -> Policy {
    if allow_private { Arc::new(|_| false) } else { Arc::new(ssrf::is_blocked) }
}

pub struct EgressGuard {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for EgressGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl EgressGuard {
    pub async fn start(policy: Policy) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(accept_loop(listener, policy));
        tracing::info!(%addr, "egress guard listening");
        Ok(Self { addr, task })
    }

    pub fn proxy_server(&self) -> String {
        format!("socks5://{}", self.addr)
    }
}

async fn accept_loop(listener: TcpListener, policy: Policy) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let policy = policy.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, &policy).await {
                        tracing::debug!(error = %e, "egress stream ended");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "egress accept error"),
        }
    }
}

async fn serve(mut stream: TcpStream, policy: &Policy) -> io::Result<()> {
    let (host, port) = socks::accept(&mut stream).await?;
    let addrs = match vet(&host, port, policy).await {
        Ok(addrs) => addrs,
        Err(status) => {
            if status == socks::NOT_ALLOWED {
                tracing::warn!(%host, port, "egress blocked: private or reserved address");
            }
            return socks::reply(&mut stream, status).await;
        }
    };
    let Some(mut upstream) = connect_any(&addrs).await else {
        return socks::reply(&mut stream, socks::CONNECTION_REFUSED).await;
    };
    socks::reply(&mut stream, socks::SUCCEEDED).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
    Ok(())
}

/// Resolve `host` and return its addresses, or the SOCKS5 status to refuse
/// with. A single blocked address refuses the whole name.
pub async fn vet(host: &str, port: u16, policy: &Policy) -> Result<Vec<SocketAddr>, u8> {
    let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => lookup_host((host, port)).await.map_err(|_| socks::HOST_UNREACHABLE)?.collect(),
    };
    if addrs.is_empty() {
        return Err(socks::HOST_UNREACHABLE);
    }
    if addrs.iter().any(|a| policy(a.ip())) {
        return Err(socks::NOT_ALLOWED);
    }
    Ok(addrs)
}

async fn connect_any(addrs: &[SocketAddr]) -> Option<TcpStream> {
    for addr in addrs {
        if let Ok(Ok(s)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            return Some(s);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn socks_connect(proxy: &EgressGuard, host: &str, port: u16) -> (TcpStream, u8) {
        let mut s = TcpStream::connect(proxy.addr).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await.unwrap();
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        (s, rep[1])
    }

    async fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = s.read(&mut buf).await {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn refuses_private_ip_and_names_resolving_to_it() {
        let target = echo_server().await;
        let guard = EgressGuard::start(policy(false)).await.unwrap();
        for host in ["127.0.0.1", "localhost"] {
            let (_, status) = socks_connect(&guard, host, target.port()).await;
            assert_eq!(status, socks::NOT_ALLOWED, "{host}");
        }
    }

    #[tokio::test]
    async fn relays_allowed_targets() {
        let target = echo_server().await;
        let guard = EgressGuard::start(policy(true)).await.unwrap();
        let (mut s, status) = socks_connect(&guard, "localhost", target.port()).await;
        assert_eq!(status, socks::SUCCEEDED);
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn vet_rejects_if_any_resolved_address_is_blocked() {
        let block_v4_loopback: Policy = Arc::new(|ip| ip == IpAddr::from([127, 0, 0, 1]));
        assert_eq!(vet("localhost", 80, &block_v4_loopback).await, Err(socks::NOT_ALLOWED));
        assert!(vet("::1", 80, &block_v4_loopback).await.is_ok());
    }
}
