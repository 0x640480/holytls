// wreq (0x676e67) benchmark harness. Implements the shared bench/HARNESS.md
// contract. H1/H2 only — H3 exits with an honest error (wreq has no QUIC). wreq
// uses BoringSSL; we accept the origin's self-signed cert via cert_verification
// (false) — the full handshake still happens, only the (microsecond) chain check
// is skipped, so handshake cost stays comparable. Closed loop, --concurrency tokio tasks.
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use http::Version;
use wreq::Client;
use wreq_util::Emulation;

struct Cfg {
    url: String,
    protocol: String,
    mode: String,
    requests: i64,
    concurrency: usize,
    warmup: i64,
    single_thread: bool,
    out: String,
}

fn parse_args() -> Cfg {
    let mut c = Cfg {
        url: String::new(), protocol: "h2".into(), mode: "keepalive".into(),
        requests: 1000, concurrency: 1, warmup: 200, single_thread: true, out: String::new(),
    };
    let a: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i + 1 < a.len() {
        let (k, v) = (a[i].as_str(), a[i + 1].clone());
        match k {
            "--url" => { c.url = v; i += 2; }
            "--protocol" => { c.protocol = v; i += 2; }
            "--mode" => { c.mode = v; i += 2; }
            "--requests" => { c.requests = v.parse().unwrap_or(1000); i += 2; }
            "--concurrency" => { c.concurrency = v.parse().unwrap_or(1); i += 2; }
            "--warmup" => { c.warmup = v.parse().unwrap_or(200); i += 2; }
            "--single-thread" => { c.single_thread = v != "0"; i += 2; }
            "--out" => { c.out = v; i += 2; }
            "--ca" | "--max-conns" => { i += 2; } // ca: wreq skip-verifies; max-conns: derived from mode
            _ => { i += 1; }
        }
    }
    if c.concurrency == 0 { c.concurrency = 1; }
    c
}

fn pctl(sorted: &[f64], p: f64) -> f64 {
    let n = sorted.len();
    if n == 0 { return 0.0; }
    let mut rank = (p / 100.0 * n as f64 + 0.999999) as usize;
    if rank < 1 { rank = 1; }
    if rank > n { rank = n; }
    sorted[rank - 1]
}

fn norm_proto(v: Version) -> &'static str {
    match v {
        Version::HTTP_3 => "h3",
        Version::HTTP_2 => "h2",
        Version::HTTP_11 | Version::HTTP_10 => "h1",
        _ => "?",
    }
}

fn req_version(proto: &str) -> Version {
    match proto {
        "h1" => Version::HTTP_11,
        _ => Version::HTTP_2,
    }
}

fn rusage() -> libc::rusage {
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
        ru
    }
}
fn tv_ms(a: libc::timeval, b: libc::timeval) -> f64 {
    (a.tv_sec - b.tv_sec) as f64 * 1000.0 + (a.tv_usec - b.tv_usec) as f64 / 1000.0
}

fn emit(cfg: &Cfg, body: String) {
    if cfg.out.is_empty() { println!("{}", body); }
    else { let _ = std::fs::write(&cfg.out, body + "\n"); }
}

fn main() {
    let cfg = parse_args();

    if cfg.protocol == "h3" {
        emit(&cfg, format!(
            "{{\n  \"client\": \"wreq\",\n  \"client_version\": \"wreq@5.3.0\",\n  \"protocol_requested\": \"h3\",\n  \"protocol_negotiated\": \"\",\n  \"mode\": \"{}\",\n  \"concurrency\": {},\n  \"single_thread\": {},\n  \"requests\": 0,\n  \"warmup\": {},\n  \"throughput_rps\": 0.0,\n  \"latency_ms\": {{\"p50\": 0, \"p90\": 0, \"p99\": 0, \"p999\": 0, \"max\": 0}},\n  \"handshake_ms\": {{\"p50\": 0}},\n  \"connections_created\": 0,\n  \"pool_reuses\": 0,\n  \"bytes_received\": 0,\n  \"status\": 0,\n  \"errors\": {},\n  \"error_sample\": \"wreq does not support HTTP/3\",\n  \"peak_rss_kb\": 0,\n  \"cpu_user_ms\": 0.0,\n  \"cpu_sys_ms\": 0.0,\n  \"wall_ms\": 0.0,\n  \"alloc\": {{\"arenas_created\": 0, \"bytes_reserved\": 0}}\n}}",
            cfg.mode, cfg.concurrency, if cfg.single_thread {1} else {0}, cfg.warmup, cfg.requests));
        std::process::exit(3);
    }

    let rt = if cfg.single_thread {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    } else {
        tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap()
    };
    rt.block_on(run(cfg));
}

async fn run(cfg: Cfg) {
    let cold = cfg.mode == "cold";
    let client = Client::builder()
        .emulation(Emulation::Chrome137)
        .cert_verification(false) // accept the local self-signed origin (full handshake still runs)
        .redirect(wreq::redirect::Policy::none())
        .pool_max_idle_per_host(if cold { 0 } else { usize::MAX })
        .build()
        .expect("build client");
    let client = Arc::new(client);
    let ver = req_version(&cfg.protocol);

    let status = Arc::new(Mutex::new((0u16, "?".to_string())));
    let errsample = Arc::new(Mutex::new(String::new()));

    let phase = |total: i64, measuring: bool| {
        let client = client.clone();
        let url = cfg.url.clone();
        let conc = cfg.concurrency;
        let status = status.clone();
        let errsample = errsample.clone();
        async move {
            let remaining = Arc::new(AtomicI64::new(total));
            let t0 = Instant::now();
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..conc {
                let client = client.clone();
                let url = url.clone();
                let remaining = remaining.clone();
                let status = status.clone();
                let errsample = errsample.clone();
                set.spawn(async move {
                    let mut lat: Vec<f64> = Vec::new();
                    let mut bytes: i64 = 0;
                    let mut errors: i64 = 0;
                    loop {
                        if remaining.fetch_sub(1, Ordering::Relaxed) <= 0 { break; }
                        let t = Instant::now();
                        match client.get(&url).version(ver).send().await {
                            Ok(resp) => {
                                let st = resp.status().as_u16();
                                let pv = norm_proto(resp.version()).to_string();
                                match resp.bytes().await {
                                    Ok(b) => {
                                        if measuring {
                                            lat.push(t.elapsed().as_nanos() as f64 / 1e6);
                                            bytes += b.len() as i64;
                                            let mut s = status.lock().unwrap();
                                            if s.0 == 0 { *s = (st, pv); }
                                        }
                                    }
                                    Err(e) => { errors += 1; *errsample.lock().unwrap() = e.to_string(); }
                                }
                            }
                            Err(e) => { errors += 1; *errsample.lock().unwrap() = e.to_string(); }
                        }
                    }
                    (lat, bytes, errors)
                });
            }
            let mut all: Vec<f64> = Vec::new();
            let mut bytes = 0i64;
            let mut errors = 0i64;
            while let Some(r) = set.join_next().await {
                if let Ok((l, b, e)) = r { all.extend(l); bytes += b; errors += e; }
            }
            (all, bytes, errors, t0.elapsed().as_secs_f64())
        }
    };

    if cfg.warmup > 0 { phase(cfg.warmup, false).await; }
    let ru0 = rusage();
    let (mut samples, bytes, errors, wall) = phase(cfg.requests, true).await;
    let ru1 = rusage();

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let measured = samples.len();
    let rps = if wall > 0.0 { measured as f64 / wall } else { 0.0 };
    let (st, pv) = status.lock().unwrap().clone();
    let conns: i64 = if cold { measured as i64 } else { 0 };
    let esc = errsample.lock().unwrap().replace('\\', "\\\\").replace('"', "\\\"");

    emit(&cfg, format!(
        "{{\n  \"client\": \"wreq\",\n  \"client_version\": \"wreq@5.3.0\",\n  \"protocol_requested\": \"{}\",\n  \"protocol_negotiated\": \"{}\",\n  \"mode\": \"{}\",\n  \"concurrency\": {},\n  \"single_thread\": {},\n  \"requests\": {},\n  \"warmup\": {},\n  \"throughput_rps\": {:.2},\n  \"latency_ms\": {{\"p50\": {:.3}, \"p90\": {:.3}, \"p99\": {:.3}, \"p999\": {:.3}, \"max\": {:.3}}},\n  \"handshake_ms\": {{\"p50\": 0}},\n  \"connections_created\": {},\n  \"pool_reuses\": {},\n  \"bytes_received\": {},\n  \"status\": {},\n  \"errors\": {},\n  \"error_sample\": \"{}\",\n  \"peak_rss_kb\": {},\n  \"cpu_user_ms\": {:.1},\n  \"cpu_sys_ms\": {:.1},\n  \"wall_ms\": {:.1},\n  \"alloc\": {{\"arenas_created\": 0, \"bytes_reserved\": 0}}\n}}",
        cfg.protocol, pv, cfg.mode, cfg.concurrency, if cfg.single_thread {1} else {0},
        measured, cfg.warmup, rps,
        pctl(&samples, 50.0), pctl(&samples, 90.0), pctl(&samples, 99.0), pctl(&samples, 99.9), pctl(&samples, 100.0),
        conns, measured as i64 - conns, bytes, st, errors, esc,
        ru1.ru_maxrss, tv_ms(ru1.ru_utime, ru0.ru_utime), tv_ms(ru1.ru_stime, ru0.ru_stime), wall * 1000.0));

    if measured == 0 { std::process::exit(1); }
}
