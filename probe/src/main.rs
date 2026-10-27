// Measures WebSocket request/response RTT to every resolved IP of every target exchange endpoint,
// concurrently, for a fixed duration. Prints one JSON array of per-(target, ip) stats to stdout.
//
// targets.json: [{"name", "url", "request", "match", "interval_ms"?, "ips"?}]
//   request: text frame to send, "{id}" is replaced by a unique numeric id
//   match:   substring that identifies the response, "{id}" is replaced the same way
// A feed target replaces request/match with {"subscribe", "ts_key"}: it subscribes to a real market-data stream and
// records (local wall clock - exchange timestamp in ms under ts_key) for every push.
//
// A tcp target ({"name", "url", "kind": "tcp", "interval_ms"?}) only samples the TCP handshake (connect() -> return, then
// close) at that interval for the whole run: min/p50/p95/p99 of the pure network round trip.
//
// Every result also carries phases_us: TCP handshake (min/p50 of 5 connects), TLS handshake and WebSocket upgrade of
// the first connection, each timed with the monotonic clock.
use futures_util::{SinkExt, StreamExt, future::join_all};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::env;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio_tungstenite::tungstenite::{Message, http::Uri};
use tokio_tungstenite::{WebSocketStream, client_async};

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Ws = WebSocketStream<Box<dyn Io>>;

const WARMUP: u64 = 5;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_SAMPLES: usize = 5;
const TCP_TIMEOUT: Duration = Duration::from_secs(2);
const FEED_WARMUP: u64 = 20; // pushes skipped before recording lag

struct Probe {
    name: String,
    url: String,
    host: String,
    ip: IpAddr,
    port: u16,
    request: String,
    matcher: String,
    interval: Duration,
    secure: bool,
    tls: TlsConnector,
    subscribe: Option<String>,
    ts_key: Option<String>,
    tcp_only: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    rustls::crypto::ring::default_provider().install_default().expect("install TLS crypto provider");
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <targets.json> <duration_secs>", args[0]);
        std::process::exit(2);
    }
    let targets: Value = serde_json::from_str(&std::fs::read_to_string(&args[1]).expect("read targets file"))
        .expect("targets file is not valid JSON");
    let duration = Duration::from_secs(args[2].parse().expect("duration_secs must be an integer"));

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = TlsConnector::from(Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()));

    let mut probes = Vec::new();
    let mut results = Vec::new();
    for t in targets.as_array().expect("targets must be a JSON array") {
        let field = |k: &str| t[k].as_str().unwrap_or_else(|| panic!("target missing \"{k}\": {t}")).to_string();
        let opt = |k: &str| t[k].as_str().map(String::from);
        let feed = opt("ts_key").is_some();
        let tcp_only = opt("kind").as_deref() == Some("tcp");
        let url: Uri = field("url").parse().expect("invalid url");
        let host = url.host().expect("url has no host").to_string();
        let port = url.port_u16().unwrap_or(if url.scheme_str() == Some("ws") { 80 } else { 443 });
        let ips: BTreeSet<IpAddr> = match t["ips"].as_array() {
            Some(list) => list.iter().map(|v| v.as_str().and_then(|s| s.parse().ok()).expect("bad ip")).collect(),
            // No IPv6 route on the hunting subnet, so only IPv4 endpoints are probed.
            None => match tokio::net::lookup_host((host.as_str(), port)).await {
                Ok(addrs) => addrs.map(|a| a.ip()).filter(IpAddr::is_ipv4).collect(),
                Err(e) => {
                    // One bad target must not sink the whole run; report it and move on.
                    eprintln!("[{}] {} resolve {host} failed: {e}", ts(), field("name"));
                    results.push(json!({"name": field("name"), "host": host, "ip": null, "samples": 0,
                                        "lost": 0, "errors": 1, "stats_us": null}));
                    continue;
                }
            },
        };
        eprintln!("[{}] {} {} -> {:?}", ts(), field("name"), host, ips);
        for ip in ips {
            probes.push(Probe {
                name: field("name"),
                url: field("url"),
                host: host.clone(),
                ip,
                port,
                request: if feed || tcp_only { String::new() } else { field("request") },
                matcher: if feed || tcp_only { String::new() } else { field("match") },
                interval: Duration::from_millis(t["interval_ms"].as_u64().unwrap_or(1000)),
                secure: url.scheme_str() != Some("ws"),
                tls: tls.clone(),
                subscribe: opt("subscribe"),
                ts_key: opt("ts_key"),
                tcp_only,
            });
        }
    }

    // Give every connection time to handshake, then stagger send times so that
    // responses from different probes don't contend for this single thread.
    // Handshakes are also staggered (100 ms apart) so they don't queue behind each other on this single thread.
    let count = probes.len();
    let n = count as f64;
    let start = Instant::now() + Duration::from_secs(5) + Duration::from_millis(100 * count as u64);
    let deadline = start + duration;
    let tasks = probes.into_iter().enumerate().map(|(k, p)| {
        let offset = p.interval.mul_f64(k as f64 / n);
        tokio::spawn(async move {
            sleep(Duration::from_millis(100 * k as u64)).await;
            if p.tcp_only {
                return run_tcp(p, start + offset, deadline).await;
            }
            let tcp = tcp_rtt(&p).await;
            if p.ts_key.is_some() { run_feed(p, deadline, tcp).await } else { run_probe(p, start + offset, deadline, tcp).await }
        })
    });
    results.extend(join_all(tasks).await.into_iter().map(|r| r.expect("probe task panicked")));
    println!("{}", Value::Array(results));
}

/// Samples the TCP handshake (SYN -> SYN/ACK, one network round trip) at the probe's interval until the deadline.
async fn run_tcp(p: Probe, first_tick: Instant, deadline: Instant) -> Value {
    let mut tick = interval_at(first_tick, p.interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let (mut lat, mut lost, mut n) = (Vec::<i64>::new(), 0u64, 0u64);
    loop {
        tick.tick().await;
        if Instant::now() >= deadline {
            break;
        }
        let t0 = Instant::now();
        match timeout(TCP_TIMEOUT, TcpStream::connect((p.ip, p.port))).await {
            Ok(Ok(_)) => {
                n += 1;
                if n > WARMUP {
                    lat.push(t0.elapsed().as_micros() as i64);
                }
            }
            _ => lost += 1,
        }
    }
    let stats = summarize(&mut lat);
    eprintln!("[{}] {} {} tcp done: {stats}", ts(), p.name, p.ip);
    json!({"name": p.name, "kind": "tcp", "host": p.host, "ip": p.ip.to_string(), "samples": lat.len(),
           "lost": lost, "errors": 0, "stats_us": stats})
}

/// TCP handshake time to the exchange IP: SYN -> SYN/ACK, i.e. one network round trip.
async fn tcp_rtt(p: &Probe) -> Vec<i64> {
    let mut v = Vec::new();
    for _ in 0..TCP_SAMPLES {
        let t0 = Instant::now();
        if let Ok(Ok(_)) = timeout(CONNECT_TIMEOUT, TcpStream::connect((p.ip, p.port))).await {
            v.push(t0.elapsed().as_micros() as i64);
        }
        sleep(Duration::from_millis(50)).await;
    }
    v
}

/// (TLS handshake us, WebSocket upgrade us, negotiated TLS version and cipher suite) of a connection.
type ConnInfo = (u64, u64, Option<String>);

fn phases_json(mut tcp: Vec<i64>, first: Option<ConnInfo>) -> Value {
    let s = summarize(&mut tcp);
    json!({"tcp_min": s["min"], "tcp_p50": s["p50"], "tls": first.as_ref().map(|f| f.0), "ws": first.as_ref().map(|f| f.1),
           "tls_info": first.and_then(|f| f.2)})
}

async fn run_probe(p: Probe, first_tick: Instant, deadline: Instant, tcp: Vec<i64>) -> Value {
    let mut tick = interval_at(first_tick, p.interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut lat_us: Vec<i64> = Vec::new();
    let mut first = None;
    let (mut answered, mut lost, mut errors) = (0u64, 0u64, 0u64);
    // Fixed-width ids so "id":1000001 can never be a prefix match of another id.
    let mut seq = 1_000_000u64;

    'conn: while Instant::now() < deadline {
        let mut ws = match connect(&p).await {
            Ok((ws, ph)) => {
                first.get_or_insert(ph);
                ws
            }
            Err(e) => {
                errors += 1;
                eprintln!("[{}] {} {} connect failed: {e}", ts(), p.name, p.ip);
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        loop {
            tick.tick().await;
            if Instant::now() >= deadline {
                break 'conn;
            }
            seq += 1;
            let id = seq.to_string();
            let want = p.matcher.replace("{id}", &id);
            // Build the frame before stamping, so string formatting stays out of the RTT.
            let msg = Message::Text(p.request.replace("{id}", &id).into());
            let t0 = Instant::now();
            if let Err(e) = ws.send(msg).await {
                errors += 1;
                eprintln!("[{}] {} {} send failed: {e}", ts(), p.name, p.ip);
                continue 'conn;
            }
            match timeout(RESPONSE_TIMEOUT, wait_for(&mut ws, &want)).await {
                Ok(Ok(t1)) => {
                    let rtt = (t1 - t0).as_micros() as i64;
                    answered += 1;
                    if answered > WARMUP {
                        lat_us.push(rtt);
                    }
                }
                Ok(Err(e)) => {
                    errors += 1;
                    eprintln!("[{}] {} {} read failed: {e}", ts(), p.name, p.ip);
                    continue 'conn;
                }
                Err(_) => lost += 1,
            }
        }
    }

    let stats = summarize(&mut lat_us);
    eprintln!("[{}] {} {} done: {stats}", ts(), p.name, p.ip);
    json!({
        "name": p.name,
        "host": p.host,
        "ip": p.ip.to_string(),
        "samples": lat_us.len(),
        "lost": lost,
        "errors": errors,
        "stats_us": stats,
        "phases_us": phases_json(tcp, first),
    })
}

/// Subscribes to a real market-data stream and records how far behind the exchange's own timestamp (ms resolution)
/// every push arrives. The result includes the clock offset between exchange and instance, so compare instances
/// with each other rather than reading it as an absolute latency.
async fn run_feed(p: Probe, deadline: Instant, tcp: Vec<i64>) -> Value {
    let key = p.ts_key.clone().unwrap();
    let (mut lag, mut pushes, mut errors) = (Vec::<i64>::new(), 0u64, 0u64);
    let mut first = None;
    let began = Instant::now();
    match connect(&p).await {
        Ok((mut ws, ph)) => {
            first = Some(ph);
            if let Some(sub) = &p.subscribe {
                if let Err(e) = ws.send(Message::Text(sub.clone().into())).await {
                    errors += 1;
                    eprintln!("[{}] {} {} subscribe failed: {e}", ts(), p.name, p.ip);
                }
            }
            while errors == 0 {
                let Ok(msg) = timeout(deadline.saturating_duration_since(Instant::now()), ws.next()).await else { break };
                let recv_us = ts() as i64; // stamped before the payload is parsed
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let Some(ms) = serde_json::from_str::<Value>(&text).ok().and_then(|v| v[key.as_str()].as_i64()) else {
                            continue; // subscription ack or other control reply
                        };
                        pushes += 1;
                        if pushes > FEED_WARMUP {
                            lag.push(recv_us - ms * 1000);
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => errors += 1,
                }
            }
        }
        Err(e) => {
            errors += 1;
            eprintln!("[{}] {} {} connect failed: {e}", ts(), p.name, p.ip);
        }
    }
    let stats = summarize(&mut lag);
    eprintln!("[{}] {} {} feed done: {stats}", ts(), p.name, p.ip);
    json!({
        "name": p.name,
        "kind": "feed",
        "host": p.host,
        "ip": p.ip.to_string(),
        "samples": lag.len(),
        "pushes_per_s": pushes as f64 / began.elapsed().as_secs_f64(),
        "lost": 0,
        "errors": errors,
        "stats_us": stats,
        "phases_us": phases_json(tcp, first),
    })
}

/// Returns the socket and (TLS handshake, WebSocket upgrade) times in us; TCP is timed by tcp_rtt.
async fn connect(p: &Probe) -> Result<(Ws, ConnInfo), Box<dyn std::error::Error + Send + Sync>> {
    // Connect to the chosen IP ourselves; TLS SNI and Host header still come from the URL.
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect((p.ip, p.port))).await??;
    tcp.set_nodelay(true)?;
    let t0 = Instant::now();
    let mut tls_info = None;
    let io: Box<dyn Io> = if p.secure {
        let stream = timeout(CONNECT_TIMEOUT, p.tls.connect(ServerName::try_from(p.host.clone())?, tcp)).await??;
        let conn = stream.get_ref().1;
        tls_info = conn.protocol_version().zip(conn.negotiated_cipher_suite()).map(|(v, c)| format!("{v:?} {:?}", c.suite()));
        Box::new(stream)
    } else {
        Box::new(tcp)
    };
    let t1 = Instant::now();
    let (ws, _) = timeout(CONNECT_TIMEOUT, client_async(p.url.as_str(), io)).await??;
    let (tls, upgrade) = ((t1 - t0).as_micros() as u64, t1.elapsed().as_micros() as u64);
    eprintln!("[{}] {} {} tls {tls}µs, ws upgrade {upgrade}µs", ts(), p.name, p.ip);
    Ok((ws, (tls, upgrade, tls_info)))
}

/// Returns the arrival time of the matching frame, stamped before its payload is inspected.
async fn wait_for(ws: &mut Ws, want: &str) -> Result<Instant, String> {
    while let Some(msg) = ws.next().await {
        let received = Instant::now();
        match msg.map_err(|e| e.to_string())? {
            Message::Text(text) if text.contains(want) => return Ok(received),
            Message::Close(frame) => return Err(format!("closed by server: {frame:?}")),
            _ => {} // unsolicited pushes; pings are answered by tungstenite
        }
    }
    Err("stream ended".into())
}

fn summarize(lat: &mut [i64]) -> Value {
    if lat.is_empty() {
        return Value::Null;
    }
    lat.sort_unstable();
    let pct = |p: f64| lat[(p * (lat.len() - 1) as f64).round() as usize];
    json!({
        "min": lat[0],
        "p50": pct(0.50),
        "p95": pct(0.95),
        "p99": pct(0.99),
        "max": lat[lat.len() - 1],
        "mean": lat.iter().sum::<i64>() / lat.len() as i64,
    })
}

fn ts() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros()
}

#[cfg(test)]
mod tests {
    #[test]
    fn percentiles() {
        let mut v: Vec<i64> = (1..=100).rev().collect();
        let s = super::summarize(&mut v);
        assert_eq!((s["min"].as_u64(), s["p50"].as_u64(), s["p99"].as_u64()), (Some(1), Some(51), Some(99)));
        assert!(super::summarize(&mut []).is_null());
    }
}
