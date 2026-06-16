//! SSRF (Server-Side Request Forgery) target filtering. After a URL is parsed,
//! its host is resolved and every resolved IP is checked against private /
//! reserved ranges; by default those are rejected so a caller cannot pivot the
//! renderer at internal services or cloud-metadata endpoints.
//!
//! Note: this resolves-then-the-browser-connects, leaving a TOCTOU /
//! DNS-rebinding gap (a name could resolve to a public IP here and a private
//! one when Chrome connects). Full connect-time IP pinning is out of scope for
//! v1; we block on the *resolved* IP, not just the literal host string, which
//! closes the common case.

use std::net::{IpAddr, ToSocketAddrs};

use url::{Host, Url};

use crate::error::ApiError;

/// Reject a URL whose host resolves to a private/reserved address, unless
/// `allow_private` is set. Returns `Ok(())` when the target is permitted.
pub fn check(url: &Url, allow_private: bool) -> Result<(), ApiError> {
    if allow_private {
        return Ok(());
    }

    let host = url.host().ok_or_else(|| ApiError::BadRequest("url has no host".into()))?;

    match host {
        Host::Ipv4(ip) => guard(IpAddr::V4(ip))?,
        Host::Ipv6(ip) => guard(IpAddr::V6(ip))?,
        Host::Domain(name) => {
            // Resolve the name and reject if *any* resolved address is blocked.
            // Port is irrelevant to the IP check; use a placeholder.
            let addrs = (name, 0u16)
                .to_socket_addrs()
                .map_err(|e| ApiError::BadRequest(format!("cannot resolve host: {e}")))?;
            let mut saw_any = false;
            for addr in addrs {
                saw_any = true;
                guard(addr.ip())?;
            }
            if !saw_any {
                return Err(ApiError::BadRequest("host did not resolve".into()));
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

/// Whether `ip` falls in a private/reserved range we refuse to render by
/// default: RFC1918, loopback, link-local (incl. cloud metadata 169.254.169.254),
/// unspecified, ULA, and other non-globally-routable space.
fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()         // 10/8, 172.16/12, 192.168/16
                || v4.is_loopback()  // 127/8
                || v4.is_link_local() // 169.254/16 — cloud metadata
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast()
                || v4.is_documentation()
                || is_shared_v4(v4) // 100.64/10 CGNAT
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()        // ::1
                || v6.is_unspecified() // ::
                || is_unique_local_v6(v6) // fc00::/7
                || is_unicast_link_local_v6(v6) // fe80::/10
                // IPv4-mapped (::ffff:a.b.c.d) — re-check the embedded v4.
                || v6.to_ipv4_mapped().is_some_and(|m| is_blocked(IpAddr::V4(m)))
        }
    }
}

const fn is_shared_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000 // 100.64.0.0/10
}

const fn is_unique_local_v6(ip: std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7
}

const fn is_unicast_link_local_v6(ip: std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn blocks_metadata_and_private() {
        assert!(check(&u("http://169.254.169.254/"), false).is_err());
        assert!(check(&u("http://127.0.0.1/"), false).is_err());
        assert!(check(&u("http://10.0.0.5/"), false).is_err());
        assert!(check(&u("http://192.168.1.1/"), false).is_err());
        assert!(check(&u("http://172.16.0.1/"), false).is_err());
        assert!(check(&u("http://[::1]/"), false).is_err());
    }

    #[test]
    fn allows_public() {
        assert!(check(&u("http://1.1.1.1/"), false).is_ok());
        assert!(check(&u("http://8.8.8.8/"), false).is_ok());
    }

    #[test]
    fn allow_flag_bypasses() {
        assert!(check(&u("http://127.0.0.1/"), true).is_ok());
    }
}
