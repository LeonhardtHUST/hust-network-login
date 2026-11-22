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

    let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no DNS server configured");
    for server in servers {
        let addr: SocketAddr = match format!("{server}:53").parse() {
            Ok(addr) => addr,
            Err(_) => continue,
        };
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => socket,
            Err(e) => {
                last_error = e;
                continue;
            }
        };
        if let Err(e) = socket.set_read_timeout(Some(timeout)) {
            last_error = e;
            continue;
        }
        if let Err(e) = socket.set_write_timeout(Some(timeout)) {
            last_error = e;
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
            Err(e) => last_error = e,
        }
    }

    Err(last_error)
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
