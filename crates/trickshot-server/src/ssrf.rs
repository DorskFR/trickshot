//! SSRF (Server-Side Request Forgery) target filtering. The submitted URL is
//! checked up front for a clean 400; [`crate::egress`] enforces the same
//! [`is_blocked`] policy on every connection Chrome actually makes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::net::lookup_host;
use url::{Host, Url};

use crate::error::ApiError;

/// Reject a URL whose host resolves to a private/reserved address, unless
/// `allow_private` is set.
pub async fn check(url: &Url, allow_private: bool) -> Result<(), ApiError> {
    if allow_private {
        return Ok(());
    }

    let host = url.host().ok_or_else(|| ApiError::BadRequest("url has no host".into()))?;

    match host {
        Host::Ipv4(ip) => guard(IpAddr::V4(ip))?,
        Host::Ipv6(ip) => guard(IpAddr::V6(ip))?,
        Host::Domain(name) => {
            let addrs: Vec<_> = lookup_host((name, 0u16))
                .await
                .map_err(|e| ApiError::BadRequest(format!("cannot resolve host: {e}")))?
                .collect();
            if addrs.is_empty() {
                return Err(ApiError::BadRequest("host did not resolve".into()));
            }
            for addr in addrs {
                guard(addr.ip())?;
            }
        }
    }
    Ok(())
}

fn guard(ip: IpAddr) -> Result<(), ApiError> {
    if is_blocked(ip) {
        return Err(ApiError::BadRequest(format!("target ip {ip} is in a blocked range")));
    }
    Ok(())
}

/// Whether `ip` is outside globally routable unicast space: RFC1918, loopback,
/// link-local (incl. cloud metadata), CGNAT, multicast, reserved, ULA, and v6
/// forms embedding such a v4 address.
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10
                || embedded_v4(v6).is_some_and(is_blocked_v4)
        }
    }
}

const fn is_blocked_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_multicast()
        || o[0] == 0 // 0.0.0.0/8
        || o[0] >= 240 // 240.0.0.0/4
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15
}

/// The v4 address carried by IPv4-mapped/-compatible, NAT64 (64:ff9b::/96) or
/// 6to4 (2002::/16) addresses.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let tail = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    match s {
        [0, 0, 0, 0, 0, 0 | 0xffff, hi, lo]
        | [0x64, 0xff9b, 0, 0, 0, 0, hi, lo]
        | [0x2002, hi, lo, ..] => Some(tail(hi, lo)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[tokio::test]
    async fn blocks_metadata_and_private() {
        for t in [
            "http://169.254.169.254/",
            "http://127.0.0.1/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://[::1]/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://2130706433/",
        ] {
            assert!(check(&u(t), false).await.is_err(), "{t}");
        }
    }

    #[tokio::test]
    async fn allows_public() {
        assert!(check(&u("http://1.1.1.1/"), false).await.is_ok());
        assert!(check(&u("http://8.8.8.8/"), false).await.is_ok());
    }

    #[tokio::test]
    async fn allow_flag_bypasses() {
        assert!(check(&u("http://127.0.0.1/"), true).await.is_ok());
    }

    #[test]
    fn blocks_reserved_and_embedded_v4() {
        for ip in [
            "0.1.2.3",
            "100.64.0.1",
            "192.0.0.8",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:c0a8:0101::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(is_blocked(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8", "2002:0808:0808::1"] {
            assert!(!is_blocked(ip.parse().unwrap()), "{ip}");
        }
    }
}
