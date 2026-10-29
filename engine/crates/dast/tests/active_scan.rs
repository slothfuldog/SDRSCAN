//! Uji pemeriksaan aktif (`--active`) `sdrscan-dast`: SELURUH tes memakai server HTTP loopback
//! buatan sendiri yang ditulis di berkas ini (tidak pernah memindai target nyata/eksternal).
//!
//! Server mencatat setiap permintaan (method, jalur, query mentah) sehingga tes dapat memastikan:
//! tanpa `--active` tidak ada payload terkirim; payload tidak pernah mengenai jalur yang dikecualikan;
//! DELETE tidak pernah dipanggil; dan setiap kelas temuan terdeteksi pada endpoint rentan tetapi NOL
//! false positive pada endpoint aman.

#![allow(dead_code)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::Command;

fn cmd() -> Command {
    Command::cargo_bin("sdrscan-dast").unwrap()
}

/// Loopback dipakai server uji; default produksi menolaknya, jadi pengecualian uji wajib dipasang.
const ALLOW: &str = "--allow-private-networks-for-tests";
const FAST: &str = "100";

#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
    at: Instant,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn path_only(&self) -> &str {
        self.path.split('?').next().unwrap_or("")
    }

    fn query(&self) -> &str {
        self.path.split_once('?').map(|(_, q)| q).unwrap_or("")
    }

    fn query_decoded(&self) -> String {
        percent_decode(self.query())
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct Resp {
    status: u16,
    reason: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Octets bruto tambahan ditulis APA ADANYA tepat sebelum akhir blok header (dipakai untuk
    /// mensimulasikan CRLF/header injection yang sungguhan: server "rentan" menyisipkan nilai
    /// parameter yang sudah di-decode langsung ke area header tanpa membuang CR/LF).
    raw_header_tail: Vec<u8>,
}

fn ok_html(body: String) -> Resp {
    Resp {
        status: 200,
        reason: "OK",
        headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
        body: body.into_bytes(),
        raw_header_tail: Vec::new(),
    }
}

fn ok_text(body: String) -> Resp {
    Resp {
        status: 200,
        reason: "OK",
        headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
        body: body.into_bytes(),
        raw_header_tail: Vec::new(),
    }
}

fn not_found() -> Resp {
    Resp {
        status: 404,
        reason: "Not Found",
        headers: vec![("Content-Type".into(), "text/plain".into())],
        body: b"not found".to_vec(),
        raw_header_tail: Vec::new(),
    }
}

fn redirect(location: &str) -> Resp {
    Resp {
        status: 302,
        reason: "Found",
        headers: vec![("Location".into(), location.to_string())],
        body: Vec::new(),
        raw_header_tail: Vec::new(),
    }
}

// --------------------------------------------------------------------------------------------
// Evaluasi "basis data" tiruan: dipakai bersama oleh endpoint GET, formulir POST, dan operasi API,
// supaya perilaku rentan/aman konsisten di semua jalur.
// --------------------------------------------------------------------------------------------

enum Outcome {
    One,
    Many,
    None,
    Error,
}

/// Simulasi `SELECT ... WHERE id = '<raw>'` tanpa escaping: nilai dasar `"1"` cocok satu baris,
/// payload `' OR '1'='1` membuat kondisi selalu benar (semua baris), `' AND '1'='2` selalu salah
/// (kosong), dan kutip tunggal lainnya memicu galat sintaks SQL.
fn vulnerable_outcome(raw: &str) -> Outcome {
    if raw == "1" || raw == "test" {
        Outcome::One
    } else if raw.contains("OR '1'='1") {
        Outcome::Many
    } else if raw.contains("AND '1'='2") {
        Outcome::None
    } else if raw.contains('\'') {
        Outcome::Error
    } else {
        Outcome::None
    }
}

/// Simulasi versi aman: nilai diperlakukan sebagai literal (diparameterisasi), jadi hanya nilai dasar
/// persis yang cocok; tidak pernah galat, tidak pernah dipengaruhi OR/AND.
fn safe_outcome(raw: &str) -> Outcome {
    if raw == "1" || raw == "test" {
        Outcome::One
    } else {
        Outcome::None
    }
}

fn render(outcome: Outcome) -> String {
    match outcome {
        Outcome::One => "Hasil: 1 produk ditemukan: Produk-A".to_string(),
        Outcome::Many => {
            "Hasil: 5 produk ditemukan: Produk-A, Produk-B, Produk-C, Produk-D, Produk-E"
                .to_string()
        }
        Outcome::None => "Tidak ditemukan".to_string(),
        Outcome::Error => {
            "Galat basis data: You have an error in your SQL syntax near '''".to_string()
        }
    }
}

// --------------------------------------------------------------------------------------------
// Server
// --------------------------------------------------------------------------------------------

struct State {
    log: Mutex<Vec<Req>>,
    /// Basis origin server "lain" dipakai utk formulir lintas-origin (tidak pernah boleh dihubungi).
    /// Default sentinel (bukan string kosong) agar formulir lintas-origin tetap "asing" di tes yang
    /// tidak secara eksplisit mengatur server kedua.
    other_origin: Mutex<String>,
    /// Hanya tes yang secara eksplisit mengaktifkannya yang menyajikan `/openapi.json` (200 + spek);
    /// bila tidak, 404 seperti jalur tak dikenal lain, supaya probe jalur-umum tidak mencemari tes
    /// kelas kerentanan lain dengan temuan dari endpoint API.
    openapi_enabled: Mutex<bool>,
}

impl Default for State {
    fn default() -> State {
        State {
            log: Mutex::new(Vec::new()),
            other_origin: Mutex::new("http://127.0.0.1:1".to_string()),
            openapi_enabled: Mutex::new(false),
        }
    }
}

struct App {
    base: String,
    state: Arc<State>,
}

impl App {
    fn start() -> App {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(State::default());
        let st = state.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let st = st.clone();
                thread::spawn(move || {
                    let Some(req) = read_request(&mut stream) else {
                        return;
                    };
                    st.log.lock().unwrap().push(req.clone());
                    let other = st.other_origin.lock().unwrap().clone();
                    let openapi_on = *st.openapi_enabled.lock().unwrap();
                    let r = route(&req, &other, openapi_on);
                    write_response(&mut stream, &r);
                });
            }
        });
        App {
            base: format!("http://{addr}"),
            state,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn log(&self) -> Vec<Req> {
        self.state.log.lock().unwrap().clone()
    }

    fn set_other_origin(&self, base: &str) {
        *self.state.other_origin.lock().unwrap() = base.to_string();
    }

    fn enable_openapi(&self) {
        *self.state.openapi_enabled.lock().unwrap() = true;
    }

    /// Nilai query mentah (sudah di-decode persen) yang pernah diterima `path`.
    fn raw_values_seen(&self, path: &str) -> Vec<String> {
        self.log()
            .iter()
            .filter(|r| r.path_only() == path)
            .map(|r| r.query_decoded())
            .collect()
    }

    fn was_requested(&self, path: &str) -> bool {
        self.log().iter().any(|r| r.path_only() == path)
    }

    fn count(&self, path: &str) -> usize {
        self.log().iter().filter(|r| r.path_only() == path).count()
    }

    fn methods_used(&self) -> HashSet<String> {
        self.log().iter().map(|r| r.method.clone()).collect()
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Req> {
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    let head_end = loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(p) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if data.len() > 1_500_000 {
            break data.len();
        }
    };
    let head = String::from_utf8_lossy(&data[..head_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = data.get(head_end + 4..).unwrap_or_default().to_vec();
    while body.len() < len {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    Some(Req {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
        at: Instant::now(),
    })
}

fn write_response(stream: &mut std::net::TcpStream, r: &Resp) {
    let mut out = format!("HTTP/1.1 {} {}\r\n", r.status, r.reason);
    for (k, v) in &r.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n", r.body.len()));
    out.push_str("Connection: close\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&r.raw_header_tail);
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&r.body);
    let _ = stream.write_all(&bytes);
}

const OPENAPI_JSON: &str = r#"{
  "openapi": "3.0.0",
  "paths": {
    "/items/{id}": {
      "get": {
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}]
      },
      "put": {
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
        "requestBody": {"content": {"application/json": {"schema": {
          "type": "object",
          "properties": {"name": {"type": "string"}, "qty": {"type": "integer"}}
        }}}}
      },
      "patch": {
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
        "requestBody": {"content": {"application/json": {"schema": {
          "type": "object",
          "properties": {"name": {"type": "string"}}
        }}}}
      },
      "delete": {
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}]
      }
    },
    "/weird": {
      "post": {
        "requestBody": {"content": {"application/json": {"schema": {"oneOf": []}}}}
      }
    }
  }
}"#;

fn route(req: &Req, other_origin: &str, openapi_enabled: bool) -> Resp {
    let path = req.path_only();
    let q: Vec<(String, String)> = req
        .query()
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .map(|(k, v)| (percent_decode(&k), percent_decode(&v)))
        .collect();
    let get = |name: &str| q.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());

    match (req.method.as_str(), path) {
        ("GET", "/") => ok_html(format!(
            r#"<html><body>
                <a href="/sqli-error?id=1">a</a>
                <a href="/sqli-error-safe?id=1">a</a>
                <a href="/sqli-blind?id=1">a</a>
                <a href="/sqli-blind-safe?id=1">a</a>
                <a href="/xss?q=hello">a</a>
                <a href="/xss-safe?q=hello">a</a>
                <a href="/redirect?next=%2Fwelcome">a</a>
                <a href="/redirect-safe?next=%2Fwelcome">a</a>
                <a href="/header?x=hello">a</a>
                <a href="/header-safe?x=hello">a</a>
                <a href="/delete-item?id=1">a</a>
                <a href="/app.js">a</a>
                <script src="/app.js"></script>
                <form method="get" action="/sqli-blind"><input name="id" value="1"></form>
                <form method="post" action="/post-sqli">
                  <input type="hidden" name="csrf_token" value="FIXEDCSRF123">
                  <input type="text" name="username" value="1">
                  <input type="checkbox" name="agree" value="yes" checked>
                </form>
                <form method="post" action="/post-sqli-safe">
                  <input type="hidden" name="csrf_token" value="FIXEDCSRF123">
                  <input type="text" name="username" value="1">
                </form>
                <form method="post" action="{other_origin}/cross-origin-post">
                  <input type="text" name="username" value="1">
                </form>
              </body></html>"#
        )),
        ("GET", "/app.js") => ok_text(
            "fetch('/api/widgets?wid=1').then(r=>r.json()); axios.get('/api/widgets?wid=1');"
                .to_string(),
        ),
        ("GET", "/api/widgets") => {
            let id = get("wid").unwrap_or_default();
            ok_text(render(vulnerable_outcome(&id)))
        }
        ("GET", "/sqli-error") => {
            let id = get("id").unwrap_or_default();
            ok_html(render(vulnerable_outcome(&id)))
        }
        ("GET", "/sqli-error-safe") => {
            let id = get("id").unwrap_or_default();
            ok_html(render(safe_outcome(&id)))
        }
        ("GET", "/sqli-blind") | ("GET", "/delete-item") => {
            let id = get("id").unwrap_or_default();
            ok_html(render(vulnerable_outcome(&id)))
        }
        ("GET", "/sqli-blind-safe") => {
            let id = get("id").unwrap_or_default();
            ok_html(render(safe_outcome(&id)))
        }
        ("GET", "/xss") => {
            let qv = get("q").unwrap_or_default();
            ok_html(format!("<html><body>Search: {qv}</body></html>"))
        }
        ("GET", "/xss-safe") => {
            let qv = get("q").unwrap_or_default();
            let esc = qv
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;");
            ok_html(format!("<html><body>Search: {esc}</body></html>"))
        }
        ("GET", "/redirect") => {
            let next = get("next").unwrap_or_default();
            redirect(&next)
        }
        ("GET", "/redirect-safe") => {
            let next = get("next").unwrap_or_default();
            if next.starts_with('/') && !next.starts_with("//") {
                redirect(&next)
            } else {
                redirect("/")
            }
        }
        ("GET", "/header") => {
            let x = get("x").unwrap_or_default();
            let mut r = ok_html("<html><body>ok</body></html>".to_string());
            // RENTAN: nilai sudah di-decode (`x` berasal dari `get()` yang memanggil percent_decode)
            // disisipkan apa adanya ke area header; bila memuat CRLF literal, ini membelah baris
            // header sungguhan (mensimulasikan response splitting pada aplikasi yang salah desain).
            r.raw_header_tail = format!("X-Echo: {x}\r\n").into_bytes();
            r
        }
        ("GET", "/header-safe") => {
            let x = get("x").unwrap_or_default();
            let sanitized = x.replace(['\r', '\n'], "");
            let mut r = ok_html("<html><body>ok</body></html>".to_string());
            r.raw_header_tail = format!("X-Echo: {sanitized}\r\n").into_bytes();
            r
        }
        ("GET", "/sleep") => {
            let id = get("id").unwrap_or_default();
            if id.to_ascii_lowercase().contains("sleep(3)") {
                thread::sleep(Duration::from_secs(3));
            }
            ok_html(render(vulnerable_outcome("1")))
        }
        ("GET", "/openapi.json") if openapi_enabled => Resp {
            status: 200,
            reason: "OK",
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: OPENAPI_JSON.as_bytes().to_vec(),
            raw_header_tail: Vec::new(),
        },
        ("GET", p) if p.starts_with("/items/") => {
            let id = percent_decode(p.trim_start_matches("/items/"));
            ok_text(render(vulnerable_outcome(&id)))
        }
        ("PUT", p) | ("PATCH", p) if p.starts_with("/items/") => {
            let id = percent_decode(p.trim_start_matches("/items/"));
            let v: serde_json::Value = serde_json::from_str(&req.body).unwrap_or_default();
            let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("");
            // id dan name sama-sama bisa memicu galat/boolean; gabungkan (id valid dasarnya "1").
            let outcome = if id != "1" {
                vulnerable_outcome(&id)
            } else {
                vulnerable_outcome(name)
            };
            ok_text(render(outcome))
        }
        ("DELETE", p) if p.starts_with("/items/") => {
            // TIDAK PERNAH seharusnya dipanggil oleh pemindai; tetap dilayani agar tes bisa
            // membuktikan nol permintaan sampai di sini (lihat assert di tes).
            ok_text("deleted".to_string())
        }
        ("POST", "/post-sqli") | ("POST", "/post-sqli-safe") => {
            let form: Vec<(String, String)> = url::form_urlencoded::parse(req.body.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            let field = |k: &str| form.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
            if field("csrf_token").as_deref() != Some("FIXEDCSRF123") {
                return Resp {
                    status: 403,
                    reason: "Forbidden",
                    headers: vec![],
                    body: b"bad csrf".to_vec(),
                    raw_header_tail: Vec::new(),
                };
            }
            let username = field("username").unwrap_or_default();
            let outcome = if path == "/post-sqli" {
                vulnerable_outcome(&username)
            } else {
                safe_outcome(&username)
            };
            ok_text(render(outcome))
        }
        ("POST", "/login") => {
            let mut r = redirect("/");
            r.headers
                .push(("Set-Cookie".into(), "session=ABC; Path=/".into()));
            r
        }
        _ => not_found(),
    }
}

// --------------------------------------------------------------------------------------------
// Tes
// --------------------------------------------------------------------------------------------

fn active_args<'a>(extra: &'a [&'a str]) -> Vec<&'a str> {
    let mut v = vec![
        "scan",
        ALLOW,
        "--active",
        "--max-rps",
        FAST,
        "--fail-on",
        "info",
    ];
    v.extend_from_slice(extra);
    v
}

#[test]
fn without_active_flag_no_payload_is_ever_sent() {
    let app = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            &app.url("/"),
            "--crawl",
            "--max-rps",
            FAST,
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    for r in app.log() {
        assert!(
            !r.query().contains('\''),
            "payload ditemukan tanpa --active: {}",
            r.path
        );
        assert!(!r.query_decoded().contains("sdrscanxss"), "{}", r.path);
    }
    assert!(!app.was_requested("/openapi.json"));
}

#[test]
fn active_timing_without_active_is_a_usage_error() {
    let app = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            &app.url("/sqli-error?id=1"),
            "--active-timing",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn sqli_error_based_detected_on_vulnerable_not_on_safe() {
    let app = App::start();
    let o = cmd()
        .args(active_args(&[&app.url("/sqli-error?id=1")]))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(stdout.contains("dast-active-sqli-error-based"), "{stdout}");

    let o = cmd()
        .args(active_args(&[&app.url("/sqli-error-safe?id=1")]))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(!stdout.contains("dast-active-sqli-error-based"), "{stdout}");
}

#[test]
fn sqli_boolean_blind_detected_on_vulnerable_not_on_safe() {
    let app = App::start();
    let o = cmd()
        .args(active_args(&[&app.url("/sqli-blind?id=1")]))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        stdout.contains("dast-active-sqli-boolean-blind"),
        "{stdout}"
    );

    let o = cmd()
        .args(active_args(&[&app.url("/sqli-blind-safe?id=1")]))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        !stdout.contains("dast-active-sqli-boolean-blind"),
        "{stdout}"
    );
}

#[test]
fn xss_reflected_detected_on_vulnerable_not_on_safe() {
    let app = App::start();
    let o = cmd()
        .args(active_args(&[&app.url("/xss?q=hello")]))
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("dast-active-xss-reflected"));

    let o = cmd()
        .args(active_args(&[&app.url("/xss-safe?q=hello")]))
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&o.stdout).contains("dast-active-xss-reflected"));
}

#[test]
fn open_redirect_confirmed_on_vulnerable_not_on_safe() {
    let app = App::start();
    let o = cmd()
        .args(active_args(&[&app.url("/redirect?next=%2Fwelcome")]))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        stdout.contains("dast-active-open-redirect-confirmed"),
        "{stdout}"
    );

    let o = cmd()
        .args(active_args(&[&app.url("/redirect-safe?next=%2Fwelcome")]))
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&o.stdout).contains("dast-active-open-redirect-confirmed"));
}

#[test]
fn header_injection_detected_on_vulnerable_not_on_safe() {
    let app = App::start();
    let o = cmd()
        .args(active_args(&[&app.url("/header?x=hello")]))
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("dast-active-header-injection"));

    let o = cmd()
        .args(active_args(&[&app.url("/header-safe?x=hello")]))
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&o.stdout).contains("dast-active-header-injection"));
}

#[test]
fn excluded_path_never_receives_any_active_payload_even_as_crawl_target() {
    let app = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--crawl",
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            &app.url("/"),
        ])
        .output()
        .unwrap();
    assert_ne!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // /delete-item cocok pengecualian bawaan ("delete"): tidak boleh pernah diminta sama sekali,
    // baik oleh crawl pasif maupun pemeriksaan aktif.
    assert!(!app.was_requested("/delete-item"), "{:?}", app.log());
}

#[test]
fn only_get_and_known_post_targets_are_used_delete_is_never_called() {
    let app = App::start();
    app.enable_openapi();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--crawl",
            "--openapi-spec",
            &app.url("/openapi.json"),
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            &app.url("/"),
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let methods = app.methods_used();
    assert!(!methods.contains("DELETE"), "{methods:?}");
    for r in app.log() {
        let allowed_post = matches!(r.path_only(), "/login" | "/post-sqli" | "/post-sqli-safe");
        assert!(
            r.method == "GET"
                || r.method == "PUT"
                || r.method == "PATCH"
                || (r.method == "POST" && allowed_post),
            "permintaan tidak diharapkan: {} {}",
            r.method,
            r.path
        );
    }
}

#[test]
fn openapi_discovery_tests_put_patch_and_skips_unparseable_schema() {
    let app = App::start();
    app.enable_openapi();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--openapi-spec",
            &app.url("/openapi.json"),
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            &app.url("/items/1"),
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        stdout.contains("dast-active-sqli-error-based")
            || stdout.contains("dast-active-sqli-boolean-blind"),
        "{stdout}"
    );
    assert!(app.was_requested("/items/1"));
    assert!(app.methods_used().contains("PUT") || app.methods_used().contains("PATCH"));
    assert!(!app.methods_used().contains("DELETE"));
    // Skema requestBody /weird (POST) tidak bisa diurai (oneOf) dan operasi itu tidak punya
    // path/query param: tidak ada kandidat untuk diuji, jadi tidak pernah diminta sama sekali
    // (tidak gagal total, tetapi juga tidak pernah mengirim POST tanpa memahami badannya).
    assert!(!app.was_requested("/weird"));
}

#[test]
fn explicit_openapi_spec_cross_origin_url_is_rejected_but_scan_continues() {
    let app = App::start();
    let other = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--openapi-spec",
            &other.url("/openapi.json"),
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            &app.url("/sqli-error?id=1"),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("satu origin"), "{stderr}");
    assert_eq!(o.status.code(), Some(1), "{stderr}"); // sqli-error tetap terdeteksi di target
    assert!(!other.was_requested("/openapi.json"));
}

#[test]
fn js_static_scanning_finds_additional_get_candidate_from_fetch_call() {
    let app = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--crawl",
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            &app.url("/"),
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(app.was_requested("/api/widgets"));
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(stdout.contains("/api/widgets"), "{stdout}");
}

#[test]
fn post_form_sqli_detected_vulnerable_safe_has_no_false_positive_and_csrf_never_tampered() {
    let app = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--crawl",
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            &app.url("/"),
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        stdout.contains("POST")
            && stdout.contains("/post-sqli")
            && stdout.contains("dast-active-sqli"),
        "{stdout}"
    );
    // endpoint aman tidak boleh menghasilkan temuan SQLi apa pun yang menunjuk ke /post-sqli-safe.
    let doc: serde_json::Value = {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("out.sarif");
        let o2 = cmd()
            .args([
                "scan",
                ALLOW,
                "--active",
                "--crawl",
                "--max-rps",
                FAST,
                "--fail-on",
                "info",
                "--format",
                "sarif",
                "--output",
            ])
            .arg(&file)
            .args([&app.url("/")])
            .output()
            .unwrap();
        assert_eq!(
            o2.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&o2.stderr)
        );
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap()
    };
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert!(!results.iter().any(|r| {
        r["ruleId"]
            .as_str()
            .unwrap_or("")
            .starts_with("dast-active-sqli")
            && r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap_or("")
                .contains("post-sqli-safe")
    }));
    for r in app
        .log()
        .iter()
        .filter(|r| r.path_only() == "/post-sqli" || r.path_only() == "/post-sqli-safe")
    {
        let form: Vec<(String, String)> = url::form_urlencoded::parse(r.body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let csrf = form
            .iter()
            .find(|(k, _)| k == "csrf_token")
            .map(|(_, v)| v.clone());
        assert_eq!(
            csrf.as_deref(),
            Some("FIXEDCSRF123"),
            "field CSRF-like tidak boleh pernah diinjeksi"
        );
    }
}

#[test]
fn login_form_itself_is_never_fuzzed_beyond_the_single_login_post() {
    let app = App::start();
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    std::fs::write(
        &auth_path,
        format!(
            r#"{{"version":1,"login":{{"type":"form","url":"{}/login","body_format":"form","username_field":"user","password_field":"password","username":"alice","password":"pw"}}}}"#,
            app.base
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--crawl",
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            "--auth-file",
        ])
        .arg(&auth_path)
        .args([&app.url("/")])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let login_posts = app
        .log()
        .iter()
        .filter(|r| r.path_only() == "/login" && r.method == "POST")
        .count();
    assert_eq!(
        login_posts,
        1,
        "login form tidak boleh pernah difuzz: {:?}",
        app.log()
    );
}

#[test]
fn cross_origin_form_action_is_never_contacted() {
    let app = App::start();
    let other = App::start();
    app.set_other_origin(&other.base);
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--crawl",
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            &app.url("/"),
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code().unwrap_or(-1),
        1,
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(other.log().is_empty(), "{:?}", other.log());
}

#[test]
fn dedupe_reports_one_finding_per_rule_url_and_param() {
    let app = App::start();
    let o = cmd()
        .args(active_args(&[&app.url("/sqli-error?id=1")]))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert_eq!(
        stdout.matches("dast-active-sqli-error-based").count(),
        1,
        "{stdout}"
    );
}

#[test]
fn active_max_params_limits_tested_parameters_and_warns() {
    let app = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            "--active-max-params",
            "1",
            &app.url("/sqli-error?id=1&q=2&x=3"),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("active-max-params"), "{stderr}");
    let tested: HashSet<String> = app
        .log()
        .iter()
        .filter(|r| r.path_only() == "/sqli-error")
        .filter_map(|r| {
            r.query()
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|p| p.split('=').next().unwrap_or("").to_string())
                .find(|_| true)
        })
        .collect();
    assert!(tested.len() <= 1, "{tested:?}");
}

#[test]
fn active_max_requests_limits_total_requests_and_warns() {
    let app = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            "--active-max-requests",
            "2",
            &app.url("/sqli-error?id=1"),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("active-max-requests"), "{stderr}");
    // +1 untuk satu pengambilan halaman pasif normal (di luar anggaran aktif).
    assert!(
        app.count("/sqli-error") <= 3,
        "{}",
        app.count("/sqli-error")
    );
}

#[test]
fn active_timeout_stops_early_and_warns() {
    let app = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--max-rps",
            "2", // 500ms antar permintaan: cukup lambat agar batas waktu tercapai lebih dulu
            "--fail-on",
            "info",
            "--active-timeout",
            "1",
            &app.url("/sqli-error?id=1&q=2&x=3&y=4&z=5"),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("active-timeout"), "{stderr}");
}

#[test]
fn time_based_sqli_off_by_default_and_detected_with_opt_in() {
    let app = App::start();
    // Tanpa --active-timing: baseline/error/boolean boleh terkirim, tetapi TIDAK PERNAH payload SLEEP.
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--max-rps",
            FAST,
            "--fail-on",
            "critical",
            &app.url("/sleep?id=1"),
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        !app.raw_values_seen("/sleep")
            .iter()
            .any(|v| v.to_ascii_lowercase().contains("sleep(3)")),
        "{:?}",
        app.raw_values_seen("/sleep")
    );

    let app2 = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--active-timing",
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            &app2.url("/sleep?id=1"),
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stdout).contains("dast-active-sqli-time-based"));
}

#[test]
fn rate_limit_is_respected_for_active_requests() {
    let app = App::start();
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--max-rps",
            "4",
            "--fail-on",
            "info",
            &app.url("/sqli-error?id=1"),
        ])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let log = app.log();
    assert!(log.len() >= 3, "{}", log.len());
    for w in log.windows(2) {
        let gap = w[1].at.duration_since(w[0].at).as_millis();
        assert!(gap >= 200, "jeda {gap}ms antara permintaan");
    }
}

#[test]
fn metadata_and_private_network_rules_still_apply_with_active() {
    let o = cmd()
        .args([
            "scan",
            "--active",
            "--block-private-networks",
            "http://169.254.169.254/latest/meta-data/",
            "--timeout",
            "3",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn sarif_output_for_active_findings_validates_against_official_schema() {
    let app = App::start();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("out.sarif");
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--max-rps",
            FAST,
            "--fail-on",
            "critical",
            "--format",
            "sarif",
            "--output",
        ])
        .arg(&file)
        .args([&app.url("/sqli-error?id=1")])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("tests/schemas/sarif-schema-2.1.0.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::draft4::new(&schema).unwrap();
    let errors: Vec<String> = validator.iter_errors(&doc).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{errors:?}");
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert!(results
        .iter()
        .any(|r| r["ruleId"] == "dast-active-sqli-error-based"));
    assert!(results
        .iter()
        .all(|r| r["properties"]["vulnerability"].is_null()));
}

#[test]
fn active_payloads_use_authenticated_session_and_never_leak_the_token() {
    let app = App::start();
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    std::fs::write(
        &auth_path,
        r#"{"version":1,"headers":{"Authorization":"Bearer SUPERSECRETVALUE"}}"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            "--active",
            "--max-rps",
            FAST,
            "--fail-on",
            "info",
            "--auth-file",
        ])
        .arg(&auth_path)
        .args([&app.url("/sqli-error?id=1")])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let (stdout, stderr) = (
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr),
    );
    assert!(!stdout.contains("SUPERSECRETVALUE") && !stderr.contains("SUPERSECRETVALUE"));
    for r in app.log() {
        assert_eq!(r.header("authorization"), Some("Bearer SUPERSECRETVALUE"));
    }
}

#[test]
fn final_summary_line_reports_active_requests_and_findings() {
    let app = App::start();
    let o = cmd()
        .args(active_args(&[&app.url("/sqli-error?id=1")]))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("permintaan aktif dikirim"), "{stderr}");
    assert!(stderr.contains("temuan aktif"), "{stderr}");
}
