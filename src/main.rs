mod dns;
mod encrypt;
mod service;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

// Campus DNS first; public resolvers are only fallbacks. Keep every attempt
// short: no single server is allowed to stall the whole probe.
const DNS_SERVERS: [&str; 4] = ["202.114.0.131", "202.114.0.242", "223.5.5.5", "119.29.29.29"];
const DNS_TIMEOUT: Duration = Duration::from_millis(1500);
const IP_TTL: Duration = Duration::from_secs(60);
static CACHED_IP: Mutex<Option<(Ipv4Addr, Instant)>> = Mutex::new(None);

/// `getaddrinfo` blocks for seconds when the network is half-up, so the
/// blocking fallback is attempted at most once per interval. Without this a
/// dead resolver costs two seconds on every retry, forever.
const SYSTEM_RESOLVER_INTERVAL: Duration = Duration::from_secs(60);
const SYSTEM_RESOLVER_TIMEOUT: Duration = Duration::from_secs(2);
static SYSTEM_RESOLVER_AT: Mutex<Option<Instant>> = Mutex::new(None);

/// Retry pacing: grow on consecutive failures so a link that is still coming
/// up is picked up within a couple of seconds, while a link that is really
/// gone stops flooding the log (and the service log file) every second.
const RETRY_DELAY_MIN: Duration = Duration::from_secs(1);
const RETRY_DELAY_MAX: Duration = Duration::from_secs(15);
/// How long to wait between two connectivity checks while logged in.
const AWAIT_INTERVAL: Duration = Duration::from_secs(15);

/// minreq is built without the `proxy` feature, but clear the usual variables
/// anyway so a different build cannot silently route portal traffic through
/// a local proxy (Clash, etc.) that may not be up after sleep/resume.
fn clear_proxy_env() {
    for key in [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ] {
        std::env::remove_var(key);
    }
}

fn err(kind: io::ErrorKind, message: impl Into<String>) -> io::Error {
    io::Error::new(kind, message.into())
}

/// Last-resort system resolver, executed on a detached thread because
/// `getaddrinfo` itself has no timeout on Windows.
fn resolve_v4_slow(host: &str) -> io::Result<Ipv4Addr> {
    let host = host.to_owned();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = (host.as_str(), 80)
            .to_socket_addrs()
            .map_err(|e| e.to_string())
            .and_then(|mut addrs| {
                addrs
                    .find(|a| a.is_ipv4())
                    .map(|a| a.ip())
                    .ok_or_else(|| "no IPv4 for host".to_owned())
            });
        let _ = tx.send(result);
    });

    match rx.recv_timeout(SYSTEM_RESOLVER_TIMEOUT) {
        Ok(Ok(IpAddr::V4(ip))) => Ok(ip),
        Ok(Ok(_)) => Err(err(io::ErrorKind::AddrNotAvailable, "unexpected IPv6 result")),
        Ok(Err(e)) => Err(err(io::ErrorKind::AddrNotAvailable, e)),
        Err(_) => Err(err(
            io::ErrorKind::TimedOut,
            format!(
                "system resolver gave no answer within {}s",
                SYSTEM_RESOLVER_TIMEOUT.as_secs()
            ),
        )),
    }
}

/// Rate limiter for the blocking fallback above: returns true at most once per
/// `SYSTEM_RESOLVER_INTERVAL`, so a retry loop cannot pay two seconds per pass.
fn system_resolver_allowed() -> bool {
    let Ok(mut last) = SYSTEM_RESOLVER_AT.lock() else {
        // A poisoned lock must not disable the fallback permanently.
        return true;
    };
    let now = Instant::now();
    if let Some(previous) = *last {
        if now.duration_since(previous) < SYSTEM_RESOLVER_INTERVAL {
            return false;
        }
    }
    *last = Some(now);
    true
}

/// Exponential retry pacing, capped at `RETRY_DELAY_MAX`.
fn next_retry_delay(current: Duration) -> Duration {
    match current.checked_mul(2) {
        Some(next) if next <= RETRY_DELAY_MAX => next,
        _ => RETRY_DELAY_MAX,
    }
}

fn invalidate_ip_cache() {
    if let Ok(mut cache) = CACHED_IP.lock() {
        *cache = None;
    }
}

fn cached_v4() -> Option<Ipv4Addr> {
    let cache = CACHED_IP.lock().ok()?;
    let (ip, at) = (*cache)?;
    (at.elapsed() < IP_TTL).then_some(ip)
}

fn remember_v4(ip: Ipv4Addr) -> Ipv4Addr {
    if let Ok(mut cache) = CACHED_IP.lock() {
        *cache = Some((ip, Instant::now()));
    }
    ip
}

/// A-query first, system resolver as a bounded and throttled fallback.
fn baidu_v4() -> io::Result<Ipv4Addr> {
    if let Some(ip) = cached_v4() {
        return Ok(ip);
    }

    let ip = match dns::resolve_a("www.baidu.com", &DNS_SERVERS, DNS_TIMEOUT) {
        Ok(ip) => ip,
        // `10051` / ENETUNREACH is not a resolver problem: no nameserver is
        // reachable, and `getaddrinfo` would only add two seconds of silence.
        Err(e) if dns::is_link_down(&e) => {
            return Err(err(
                io::ErrorKind::NetworkUnreachable,
                format!(
                    "no reachable DNS server ({e}); IPv4 unconfigured, adapter down, \
                     still associating, or a route/VPN filter blackholing DNS"
                ),
            ));
        }
        Err(e) => {
            if !system_resolver_allowed() {
                return Err(err(
                    io::ErrorKind::TimedOut,
                    format!(
                        "A query failed ({e}); system resolver fallback skipped, \
                         throttled to one attempt per {}s",
                        SYSTEM_RESOLVER_INTERVAL.as_secs()
                    ),
                ));
            }
            println!("A query failed ({e}), falling back to system resolver");
            resolve_v4_slow("www.baidu.com")?
        }
    };

    Ok(remember_v4(ip))
}

fn extract<'a>(text: &'a str, prefix: &'a str, suffix: &'a str) -> io::Result<&'a str> {
    let left = text.find(prefix);
    let right = text.find(suffix);
    if let (Some(l), Some(r)) = (left, right) {
        if l + prefix.len() < r {
            return Ok(&text[l + prefix.len()..r]);
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}

/// The portal answers the connectivity probe with a redirect script instead of
/// the page that was asked for; anything else means the link is already open.
fn is_portal_redirect(resp: &str) -> bool {
    resp.contains("/eportal/index.jsp") || resp.contains("<script>top.self.location.href='http://")
}

fn login(username: &str, password: &str) -> io::Result<()> {
    let baidu_ip = baidu_v4()?;
    let resp = minreq::get(format!("http://{}/", baidu_ip))
        .with_header("Host", "www.baidu.com")
        .with_header("Connection", "close")
        .with_timeout(5)
        .send()
        .map_err(|e| {
            println!("baidu probe failed: {}", e);
            err(io::ErrorKind::TimedOut, format!("baidu probe: {e}"))
        })?;
    let resp = resp.as_str().map_err(|e| {
        println!("invalid probe response format: {}", e);
        err(io::ErrorKind::InvalidData, format!("probe response: {e}"))
    })?;

    if !is_portal_redirect(resp) {
        return Ok(());
    }

    let portal_ip = extract(
        resp,
        "<script>top.self.location.href='http://",
        "/eportal/index.jsp",
    )?;
    println!("portal ip: {}", portal_ip);

    let mac = extract(resp, "mac=", "&t=")?;
    println!("mac: {}", mac);

    let encrypt_pass = encrypt::encrypt_pass(format!("{}>{}", password, mac));

    let query_string = extract(resp, "/eportal/index.jsp?", "'</script>\r\n")?;
    println!("query_string: {}", query_string);

    let query_string = urlencoding::encode(query_string);

    let body = format!(
        "userId={}&password={}&service=&queryString={}&passwordEncrypt=true",
        username, encrypt_pass, query_string
    );

    let login_url = format!("http://{}/eportal/InterFace.do?method=login", portal_ip);

    let resp = minreq::post(login_url)
        .with_body(body)
        .with_header(
            "Content-Type",
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        .with_header("Accept", "*/*")
        .with_header("User-Agent", "hust-network-login")
        .with_header("Connection", "close")
        .with_timeout(8)
        .send()
        .map_err(|e| {
            println!("portal request failed: {}", e);
            err(io::ErrorKind::TimedOut, format!("portal request: {e}"))
        })?;

    let resp = resp.as_str().map_err(|e| {
        println!("invalid login response format: {}", e);
        err(io::ErrorKind::InvalidData, format!("login response: {e}"))
    })?;

    println!("login resp: {}", resp);

    // Authentication changes what the campus DNS returns, so don't keep the
    // pre-login address (often the portal itself) in the cache.
    invalidate_ip_cache();

    if resp.contains("success") {
        Ok(())
    } else {
        Err(err(
            io::ErrorKind::PermissionDenied,
            "portal rejected the credentials",
        ))
    }
}

#[test]
#[ignore = "performs a real network login"]
fn login_test() {
    let _ = login("username", "password");
}

struct Config {
    username: String,
    password: String,
}

impl Config {
    fn validate_and_assemble(
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self, &'static str> {
        match (username, password) {
            (Some(_), None) => Err("missing password"),
            (None, Some(_)) => Err("missing username"),
            (None, None) => Err("missing username and password"),
            (Some(username), Some(password)) => Ok(Self {
                username: username.to_owned(),
                password: password.to_owned(),
            }),
        }
    }

    pub fn from_env() -> Option<Self> {
        println!("reading configuration from environment variables");
        let username = std::env::var("HUST_NETWORK_LOGIN_USERNAME")
            .inspect_err(|err| println!("failed to read environment variable: {err}"))
            .ok();
        let password = std::env::var("HUST_NETWORK_LOGIN_PASSWORD")
            .inspect_err(|err| println!("failed to read environment variable: {err}"))
            .ok();

        let result = Self::validate_and_assemble(
            username.as_ref().map(String::as_str),
            password.as_ref().map(String::as_str),
        )
        .inspect_err(|err| println!("invalid configuration: {err}"))
        .ok()?;

        Some(result)
    }

    pub fn from_file(path: &str) -> Option<Self> {
        println!("reading configuration from file: {path}");

        let raw = fs::read(&path)
            .inspect_err(|err| println!("failed to read from {path}: {err}"))
            .ok()?;

        let configuration = String::from_utf8(raw)
            .inspect_err(|err| println!("failed to parse content of {path}: {err}"))
            .ok()?;

        let mut lines = configuration.lines();
        let username = lines.next();
        let password = lines.next();
        let result = Self::validate_and_assemble(username, password)
            .inspect_err(|err| println!("invalid configuration: {err}"))
            .ok()?;

        Some(result)
    }

    pub fn from_args(args: &[String]) -> Option<Self> {
        println!("reading configuration from arguments");

        let path = args
            .last()
            .ok_or("at least 1 argument is required")
            .inspect_err(|err| println!("no configuration file specified: {err}"))
            .ok()?;

        Self::from_file(path)
    }
}

fn main() {
    clear_proxy_env();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("service") {
        if let Err(e) = service::handle(&args[1..]) {
            eprintln!("service error: {e}");
            std::process::exit(1);
        }
        return;
    }

    let config = Config::from_args(&args)
        .or_else(Config::from_env)
        .or_else(|| Config::from_file("/etc/hust-network-login.conf"))
        .or_else(|| Config::from_file("/etc/hust-network-login/config"))
        .expect("no available configuration found");

    let mut retry_delay = RETRY_DELAY_MIN;
    loop {
        match login(&config.username, &config.password) {
            Ok(_) => {
                println!("login ok. awaiting...");
                retry_delay = RETRY_DELAY_MIN;
                thread::sleep(AWAIT_INTERVAL);
            }
            Err(e) => {
                println!("error! {}", e);
                thread::sleep(retry_delay);
                retry_delay = next_retry_delay(retry_delay);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A captured `top.self.location.href` body, in the shape the portal
    /// actually serves (note the CRLF after the closing script tag).
    const PORTAL_BODY: &str = "<script>top.self.location.href='http://10.50.2.1/eportal/index.jsp?\
wlanuserip=10.10.223.131&wlanacname=HUST-WLAN&nasip=10.50.255.1&mac=aa-bb-cc-dd-ee-ff&t=wireless-v2&\
url=http%3A%2F%2Fwww.baidu.com'</script>\r\n";

    #[test]
    fn retry_delay_doubles_then_caps() {
        let mut delay = RETRY_DELAY_MIN;
        let mut seen = vec![delay];
        for _ in 0..6 {
            delay = next_retry_delay(delay);
            seen.push(delay);
        }
        assert_eq!(
            seen,
            [1u64, 2, 4, 8, 15, 15, 15]
                .into_iter()
                .map(Duration::from_secs)
                .collect::<Vec<_>>()
        );
        // A cap that is already reached must stay put, not overflow.
        assert_eq!(next_retry_delay(RETRY_DELAY_MAX), RETRY_DELAY_MAX);
        assert_eq!(next_retry_delay(Duration::from_secs(3600)), RETRY_DELAY_MAX);
    }

    #[test]
    fn link_failures_are_recognised() {
        assert!(dns::is_link_down(&io::Error::from(
            io::ErrorKind::NetworkUnreachable
        )));
        assert!(dns::is_link_down(&io::Error::from(
            io::ErrorKind::HostUnreachable
        )));
        assert!(!dns::is_link_down(&io::Error::from(
            io::ErrorKind::TimedOut
        )));
        assert!(!dns::is_link_down(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
    }

    #[test]
    fn detects_portal_redirect() {
        assert!(is_portal_redirect(PORTAL_BODY));
        assert!(is_portal_redirect(
            "<html><body><a href=\"/eportal/index.jsp?x=1\">login</a></body></html>"
        ));
        // A real, unauthenticated page means the link is already open.
        assert!(!is_portal_redirect(
            "<!DOCTYPE html><html><head><title>百度一下</title></head></html>"
        ));
        assert!(!is_portal_redirect(""));
    }

    #[test]
    fn extracts_portal_fields() {
        assert_eq!(
            extract(
                PORTAL_BODY,
                "<script>top.self.location.href='http://",
                "/eportal/index.jsp"
            )
            .unwrap(),
            "10.50.2.1"
        );
        assert_eq!(
            extract(PORTAL_BODY, "mac=", "&t=").unwrap(),
            "aa-bb-cc-dd-ee-ff"
        );
        let query = extract(PORTAL_BODY, "/eportal/index.jsp?", "'</script>\r\n").unwrap();
        assert_eq!(
            query,
            "wlanuserip=10.10.223.131&wlanacname=HUST-WLAN&nasip=10.50.255.1&\
             mac=aa-bb-cc-dd-ee-ff&t=wireless-v2&url=http%3A%2F%2Fwww.baidu.com"
        );
        // A body without the fields must fail instead of yielding garbage.
        assert!(extract("", "mac=", "&t=").is_err());
        assert!(extract("mac=&t=", "mac=", "&t=").is_err());
    }
}
