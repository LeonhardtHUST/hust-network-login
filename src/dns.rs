//! Minimal DNS A resolver.
//!
//! `ToSocketAddrs` / `getaddrinfo` waits for both A and AAAA records. On a
//! captive-portal Wi-Fi the AAAA path is often advertised but not routable,
//! so a single lookup can stall for a minute. This module issues a plain UDP
//! A query with a hard timeout instead, which keeps the login probe bounded.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

fn encode_name(name: &str, out: &mut Vec<u8>) -> io::Result<()> {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DNS label: {label}"),
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Skip a possibly compressed DNS name and return the offset just after it.
fn skip_name(buf: &[u8], mut pos: usize) -> io::Result<usize> {
    loop {
        if pos >= buf.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let len = buf[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 2 > buf.len() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            return Ok(pos + 2);
        }
        if len == 0 {
            return Ok(pos + 1);
        }
        pos += 1 + len as usize;
        if pos > buf.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
}

fn parse_a_answer(buf: &[u8], expected_id: u16) -> io::Result<Ipv4Addr> {
    if buf.len() < 12 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response id mismatch",
        ));
    }
    let questions = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let answers = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(buf, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > buf.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }

    for _ in 0..answers {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let rr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rr_class = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let rd_len = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rd_len > buf.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        // TYPE A = 1, CLASS IN = 1, RDLENGTH = 4. CNAMEs are skipped.
        if rr_type == 1 && rr_class == 1 && rd_len == 4 {
            return Ok(Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]));
        }
        pos += rd_len;
    }

    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no A record in DNS response",
    ))
}

/// True when the local stack has no usable route at all: IPv4 unconfigured,
/// adapter down, still associating, or a tunnel/firewall filter swallowing the
/// packets. No other nameserver can work around this, and `getaddrinfo` will
/// stall instead of failing fast, so callers can skip their fallbacks.
pub fn is_link_down(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown
    )
}

/// Resolve the first A record for `host`. `servers` are tried in order.
/// Every attempt is bounded by `timeout`, so the caller never waits a minute
/// on a half-broken resolver.
pub fn resolve_a(host: &str, servers: &[&str], timeout: Duration) -> io::Result<Ipv4Addr> {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16;

    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    encode_name(host, &mut query)?;
    query.extend_from_slice(&[0x00, 0x01]); // TYPE A
    query.extend_from_slice(&[0x00, 0x01]); // CLASS IN

    // A reachability failure names the real cause, but it must not abort the
    // loop: a split route or tunnel can blackhole one destination while another
    // nameserver still answers. It is only reported when nothing more specific
    // happened, so the caller keeps its fallbacks in a mixed state.
    let mut specific_error: Option<io::Error> = None;
    let mut reachability_error: Option<io::Error> = None;
    for server in servers {
        let addr: SocketAddr = match format!("{server}:53").parse() {
            Ok(addr) => addr,
            Err(_) => continue,
        };
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => socket,
            Err(e) => {
                specific_error = Some(e);
                continue;
            }
        };
        if let Err(e) = socket.set_read_timeout(Some(timeout)) {
            specific_error = Some(e);
            continue;
        }
        if let Err(e) = socket.set_write_timeout(Some(timeout)) {
            specific_error = Some(e);
            continue;
        }

        let result = (|| -> io::Result<Ipv4Addr> {
            socket.send_to(&query, addr)?;
            let mut buf = [0u8; 2048];
            let (len, _) = socket.recv_from(&mut buf)?;
            parse_a_answer(&buf[..len], id)
        })();

        match result {
            Ok(ip) => return Ok(ip),
            Err(e) if is_link_down(&e) => reachability_error = Some(e),
            Err(e) => specific_error = Some(e),
        }
    }

    Err(no_answer(specific_error, reachability_error))
}

/// The error to report after every server failed: a specific failure (timeout,
/// malformed answer) wins over the generic reachability one, and only a run
/// where every server was unroutable may claim the link is down. Both are kept
/// in the message when both happened, because "one destination unroutable while
/// another merely times out" is exactly the split-route case worth seeing.
fn no_answer(specific: Option<io::Error>, reachability: Option<io::Error>) -> io::Error {
    match (specific, reachability) {
        (Some(specific), Some(reachability)) => io::Error::new(
            specific.kind(),
            format!("{specific}; another nameserver was unreachable: {reachability}"),
        ),
        (Some(specific), None) => specific,
        (None, Some(reachability)) => reachability,
        (None, None) => io::Error::new(io::ErrorKind::NotFound, "no DNS server configured"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_compressed_names() {
        // pointer to offset 12
        assert_eq!(skip_name(&[0xC0, 0x0C, 0, 0], 0).unwrap(), 2);
        // two labels then root
        assert_eq!(skip_name(&[3, b'w', b'w', b'w', 1, b'a', 0], 0).unwrap(), 7);
    }

    /// `10051` is what Windows reports when a UDP send has no route; it must be
    /// classified as a link failure, not as a resolver timeout.
    #[cfg(windows)]
    #[test]
    fn classifies_windows_unreachable() {
        assert!(is_link_down(&io::Error::from_raw_os_error(10051)));
        assert!(!is_link_down(&io::Error::from_raw_os_error(
            10060 // WSAETIMEDOUT
        )));
    }

    #[test]
    fn only_claims_link_down_when_nothing_else_failed() {
        let timeout = || io::Error::new(io::ErrorKind::TimedOut, "no answer");
        let unreachable = || io::Error::new(io::ErrorKind::NetworkUnreachable, "no route");

        // A mixed run keeps the specific failure, so the caller still tries
        // its fallback resolver, but the reachability clue is not thrown away.
        let mixed = no_answer(Some(timeout()), Some(unreachable()));
        assert_eq!(mixed.kind(), io::ErrorKind::TimedOut);
        assert!(mixed
            .to_string()
            .contains("another nameserver was unreachable"));
        // Nothing but unroutable servers: that is the actionable answer.
        assert_eq!(
            no_answer(None, Some(unreachable())).kind(),
            io::ErrorKind::NetworkUnreachable
        );
        assert_eq!(no_answer(None, None).kind(), io::ErrorKind::NotFound);
    }

    #[test]
    #[ignore = "requires network access to the campus DNS"]
    fn resolves_baidu_v4() {
        let ip = resolve_a(
            "www.baidu.com",
            &["202.114.0.131", "202.114.0.242", "223.5.5.5"],
            Duration::from_secs(2),
        )
        .unwrap();
        println!("resolved www.baidu.com -> {ip}");
    }
}
