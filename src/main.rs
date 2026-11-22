mod dns;
mod encrypt;
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

    match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(IpAddr::V4(ip))) => Ok(ip),
        Ok(Ok(_)) => Err(err(io::ErrorKind::AddrNotAvailable, "unexpected IPv6 result")),
        Ok(Err(e)) => Err(err(io::ErrorKind::AddrNotAvailable, e)),
        Err(_) => Err(err(
            io::ErrorKind::TimedOut,
            "system resolver timed out (IPv6 path stalled?)",
        )),
    }
}

fn invalidate_ip_cache() {
    if let Ok(mut cache) = CACHED_IP.lock() {
        *cache = None;
    }
}

/// A-query first, system resolver as a bounded fallback.
fn baidu_v4() -> io::Result<Ipv4Addr> {
    if let Ok(cache) = CACHED_IP.lock() {
        if let Some((ip, at)) = *cache {
            if at.elapsed() < IP_TTL {
                return Ok(ip);
            }
        }
    }

    let ip = match dns::resolve_a("www.baidu.com", &DNS_SERVERS, DNS_TIMEOUT) {
        Ok(ip) => ip,
        Err(e) => {
            println!("A query failed ({}), falling back to system resolver", e);
            resolve_v4_slow("www.baidu.com")?
        }
    };

    if let Ok(mut cache) = CACHED_IP.lock() {
        *cache = Some((ip, Instant::now()));
    }
    Ok(ip)
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

    if !resp.contains("/eportal/index.jsp")
        && !resp.contains("<script>top.self.location.href='http://")
    {
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

    pub fn from_args() -> Option<Self> {
        println!("reading configuration from arguments");

        let args = std::env::args();

        let path = args
            .skip(1) // skip executable path
            .last()
            .ok_or("at least 1 argument is required")
            .inspect_err(|err| println!("no configuration file specified: {err}"))
            .ok()?;

        Self::from_file(&path)
    }
}

fn main() {
    clear_proxy_env();

    let config = Config::from_args()
        .or_else(Config::from_env)
        .or_else(|| Config::from_file("/etc/hust-network-login.conf"))
        .or_else(|| Config::from_file("/etc/hust-network-login/config"))
        .expect("no available configuration found");

    loop {
        match login(&config.username, &config.password) {
            Ok(_) => {
                println!("login ok. awaiting...");
                thread::sleep(Duration::from_secs(15));
            }
            Err(e) => {
                println!("error! {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}
