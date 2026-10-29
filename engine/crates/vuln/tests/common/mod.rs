#![allow(dead_code)]
use std::io::{Cursor, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
pub struct Req {
    /// Path dan query, mis. `/Packagist/all.zip` atau `/nvd?startIndex=0`.
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Resp {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn ok(body: Vec<u8>) -> Resp {
        Resp { status: 200, body }
    }
    pub fn status(status: u16) -> Resp {
        Resp {
            status,
            body: b"galat".to_vec(),
        }
    }
}

pub struct Server {
    pub base: String,
    pub log: Arc<Mutex<Vec<Req>>>,
}

impl Server {
    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }
}

fn handle(
    mut stream: impl Read + Write,
    handler: &(dyn Fn(&Req) -> Resp + Send + Sync),
    log: &Mutex<Vec<Req>>,
) {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while !data.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    }
    let text = String::from_utf8_lossy(&data).into_owned();
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("");
    let target = first.split_whitespace().nth(1).unwrap_or("/").to_string();
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let req = Req { target, headers };
    log.lock().unwrap().push(req.clone());
    let resp = handler(&req);
    let head = format!(
        "HTTP/1.1 {} X\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        resp.body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&resp.body);
    let _ = stream.flush();
}

/// Server HTTP di loopback; satu thread per koneksi.
pub fn serve(handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let handler: Arc<dyn Fn(&Req) -> Resp + Send + Sync> = Arc::new(handler);
    let log2 = log.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let (h, l) = (handler.clone(), log2.clone());
            thread::spawn(move || handle(stream, &*h, &l));
        }
    });
    Server {
        base: format!("http://{addr}"),
        log,
    }
}

pub fn make_zip(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, body) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// Advisory OSV minimal.
pub fn osv_json(
    id: &str,
    eco: &str,
    pkg: &str,
    introduced: &str,
    fixed: &str,
    cve: Option<&str>,
) -> Vec<u8> {
    let aliases = cve.map(|c| format!("\"{c}\"")).unwrap_or_default();
    format!(
        r#"{{"schema_version":"1.6.0","id":"{id}","modified":"2026-10-01T00:00:00Z","aliases":[{aliases}],
"summary":"Ringkasan {id}",
"severity":[{{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
"affected":[{{"package":{{"ecosystem":"{eco}","name":"{pkg}"}},
"ranges":[{{"type":"SEMVER","events":[{{"introduced":"{introduced}"}},{{"fixed":"{fixed}"}}]}}]}}],
"references":[{{"type":"ADVISORY","url":"https://example.test/{id}"}}]}}"#
    )
    .into_bytes()
}

pub fn ecosystem_zip(eco: &str, pkg: &str, n: usize) -> Vec<u8> {
    let mut entries: Vec<(String, Vec<u8>)> = (0..n)
        .map(|i| {
            (
                format!("GHSA-{eco}-{i:04}.json"),
                osv_json(
                    &format!("GHSA-{eco}-{i:04}"),
                    eco,
                    pkg,
                    "0",
                    "1.0.0",
                    Some(&format!("CVE-2099-{i:04}")),
                ),
            )
        })
        .collect();
    entries.push((
        "MAL-2099-1.json".into(),
        osv_json("MAL-2099-1", eco, "evil", "0", "9.9.9", None),
    ));
    entries.push(("README.txt".into(), b"bukan json".to_vec()));
    entries.push(("rusak.json".into(), b"{ tidak valid".to_vec()));
    let refs: Vec<(&str, Vec<u8>)> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    make_zip(&refs)
}

pub fn dir_listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}
