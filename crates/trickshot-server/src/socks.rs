//! Minimal SOCKS5 server side (no auth, CONNECT only), shared by the reverse
//! tunnel and the egress guard.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SUCCEEDED: u8 = 0x00;
pub const GENERAL_FAILURE: u8 = 0x01;
pub const NOT_ALLOWED: u8 = 0x02;
pub const HOST_UNREACHABLE: u8 = 0x04;
pub const CONNECTION_REFUSED: u8 = 0x05;
const COMMAND_NOT_SUPPORTED: u8 = 0x07;
const ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Negotiate "no auth" and read the CONNECT target. IP targets are returned
/// in their textual form (IPv6 without brackets).
pub async fn accept<S>(stream: &mut S) -> io::Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::other("not socks5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        let _ = reply(stream, COMMAND_NOT_SUPPORTED).await;
        return Err(io::Error::other("unsupported socks command"));
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
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
            Ipv6Addr::from(a).to_string()
        }
        _ => {
            let _ = reply(stream, ATYP_NOT_SUPPORTED).await;
            return Err(io::Error::other("unsupported socks atyp"));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

/// Write a SOCKS5 reply with a `0.0.0.0:0` bound address (ignored by clients
/// for CONNECT).
pub async fn reply<S>(stream: &mut S, status: u8) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await
}
