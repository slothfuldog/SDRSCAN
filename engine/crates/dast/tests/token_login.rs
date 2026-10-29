//! Login berbasis token dari respons (JSON atau header) terhadap server loopback buatan sendiri:
//! API login mengembalikan token tanpa Set-Cookie, halaman terproteksi menuntut token tersebut.
mod common;

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use common::{cmd, read_request, text, write_auth, Req, PASS, USER};

const FAST: &str = "100";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// `{"status":"ok","data":{"access_token":T}}`
    JsonToken,
    /// `{"items":[{"token":T}]}`
    ItemsToken,
    /// Token di header respons `X-Auth-Token`, isi `{"status":"ok"}`.
    HeaderToken,
    /// Isi `{"status":"ok","data":{"id":1}}` tanpa token dan tanpa cookie.
    NoToken,
    /// Halaman HTML 200 (endpoint salah: halaman login).
    Html,
    /// Token lebih dari 8 KiB.
    BigToken,
    /// Token berupa objek.
    ObjectToken,
    /// `{"status":"denied","data":{"access_token":T}}`
    DeniedStatus,
}

struct State {
    log: Mutex<Vec<Req>>,
    valid: Mutex<Vec<String>>,
    logins: AtomicUsize,
    hits: AtomicUsize,
    mode: Mode,
    /// Setelah sekian akses halaman terproteksi, semua token dibatalkan sekali.
    expire_after: Option<usize>,
    /// Halaman terproteksi menerima token lewat cookie `jwt`, bukan header.
    cookie_auth: bool,
    /// Header yang dipakai untuk token (huruf kecil).
    token_header: &'static str,
    other: String,
}

struct Srv {
    base: String,
    st: Arc<State>,
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn ctype(ct: &str, status: u16, body: &str) -> Resp {
    Resp {
        status,
        headers: vec![("Content-Type".into(), ct.into())],
        body: body.as_bytes().to_vec(),
    }
}

fn html(body: &str) -> Resp {
    ctype("text/html; charset=utf-8", 200, body)
}

fn page(links: &[String]) -> Resp {
    let l: String = links
        .iter()
        .map(|h| format!("<a href=\"{h}\">l</a> "))
        .collect();
    html(&format!("<html><body>{l}</body></html>"))
}

impl State {
    fn token_for(&self, n: usize) -> String {
        format!("TKN.{n}.zzSECRETzz")
    }

    fn authed(&self, req: &Req) -> bool {
        let presented = if self.cookie_auth {
            req.header("cookie").and_then(|c| {
                c.split(';').find_map(|p| {
                    let (k, v) = p.trim().split_once('=')?;
                    (k == "jwt").then(|| v.to_string())
                })
            })
        } else {
            req.header(self.token_header).map(|v| {
                v.strip_prefix("Bearer ")
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string())
            })
        };
        let Some(t) = presented else { return false };
        if !self.valid.lock().unwrap().contains(&t) {
            return false;
        }
        let n = self.hits.fetch_add(1, Ordering::SeqCst) + 1;
        if self.expire_after == Some(n) {
            self.valid.lock().unwrap().clear();
            return false;
        }
        true
    }

    fn guarded(&self, req: &Req, links: &[String]) -> Resp {
        if self.authed(req) {
            page(links)
        } else {
            ctype("text/plain", 401, "unauthorized")
        }
    }

    fn login(&self, req: &Req) -> Resp {
        let v: serde_json::Value = serde_json::from_str(&req.body).unwrap_or_default();
        if v["username"] != USER || v["password"] != PASS {
            return ctype("application/json", 401, "{\"message\":\"bad credentials\"}");
        }
        let n = self.logins.fetch_add(1, Ordering::SeqCst) + 1;
        let tok = self.token_for(n);
        self.valid.lock().unwrap().push(tok.clone());
        let j = |s: String| ctype("application/json", 200, &s);
        match self.mode {
            Mode::JsonToken => j(format!(
                "{{\"status\":\"ok\",\"data\":{{\"access_token\":\"{tok}\"}}}}"
            )),
            Mode::DeniedStatus => j(format!(
                "{{\"status\":\"denied\",\"data\":{{\"access_token\":\"{tok}\"}}}}"
            )),
            Mode::ItemsToken => j(format!("{{\"items\":[{{\"token\":\"{tok}\"}}]}}")),
            Mode::HeaderToken => {
                let mut r = j("{\"status\":\"ok\"}".to_string());
                r.headers.push(("X-Auth-Token".into(), tok));
                r
            }
            Mode::NoToken => j("{\"status\":\"ok\",\"data\":{\"id\":1}}".to_string()),
            Mode::Html => html("<html><body>LOGINPAGE-SECRETBODY</body></html>"),
            Mode::BigToken => {
                let big = "B".repeat(9000);
                j(format!("{{\"data\":{{\"access_token\":\"{big}\"}}}}"))
            }
            Mode::ObjectToken => {
                j("{\"data\":{\"access_token\":{\"x\":\"OBJSECRET\"}}}".to_string())
            }
        }
    }

    fn route(&self, req: &Req) -> Resp {
        let other = &self.other;
        match (req.method.as_str(), req.path_only()) {
            ("POST", "/api/auth/login") => self.login(req),
            ("GET", "/login") => html("<html><body>login page (js)</body></html>"),
            ("GET", "/dashboard") => self.guarded(
                req,
                &[
                    "/p1".into(),
                    "/p2".into(),
                    "/logout".into(),
                    format!("{other}/ext"),
                    "/redir-out".into(),
                ],
            ),
            ("GET", "/p1") => self.guarded(req, &["/deep".into(), "/dashboard".into()]),
            ("GET", "/p2") => self.guarded(req, &["/p3".into()]),
            ("GET", "/p3") | ("GET", "/deep") => self.guarded(req, &[]),
            ("GET", "/redir-out") => {
                if self.authed(req) {
                    Resp {
                        status: 302,
                        headers: vec![("Location".into(), format!("{other}/landed"))],
                        body: Vec::new(),
                    }
                } else {
                    ctype("text/plain", 401, "unauthorized")
                }
            }
            _ => ctype("text/plain", 404, "nf"),
        }
    }
}

impl Srv {
    fn start(
        mode: Mode,
        expire_after: Option<usize>,
        cookie_auth: bool,
        token_header: &'static str,
        other: String,
    ) -> Srv {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let st = Arc::new(State {
            log: Mutex::new(Vec::new()),
            valid: Mutex::new(Vec::new()),
            logins: AtomicUsize::new(0),
            hits: AtomicUsize::new(0),
            mode,
            expire_after,
            cookie_auth,
            token_header,
            other,
        });
        let s2 = st.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let st = s2.clone();
                thread::spawn(move || {
                    let Some(req) = read_request(&mut stream) else {
                        return;
                    };
                    st.log.lock().unwrap().push(req.clone());
                    let r = st.route(&req);
                    let reason = match r.status {
                        200 => "OK",
                        302 => "Found",
                        401 => "Unauthorized",
                        _ => "Other",
                    };
                    let mut out = format!("HTTP/1.1 {} {reason}\r\n", r.status);
                    for (k, v) in &r.headers {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                    out.push_str(&format!(
                        "Content-Length: {}\r\nConnection: close\r\n\r\n",
                        r.body.len()
                    ));
                    let _ = stream.write_all(out.as_bytes());
                    let _ = stream.write_all(&r.body);
                });
            }
        });
        Srv {
            base: format!("http://{addr}"),
            st,
        }
    }

    fn simple(mode: Mode) -> Srv {
        Srv::start(mode, None, false, "authorization", String::new())
    }

    fn url(&self, p: &str) -> String {
        format!("{}{p}", self.base)
    }

    fn log(&self) -> Vec<Req> {
        self.st.log.lock().unwrap().clone()
    }

    fn logins(&self) -> usize {
        self.st.logins.load(Ordering::SeqCst)
    }

    fn gets(&self) -> Vec<Req> {
        self.log()
            .into_iter()
            .filter(|r| r.method == "GET")
            .collect()
    }

    /// Tidak ada permintaan ke halaman di balik login (crawl).
    fn never_crawled(&self) -> bool {
        self.gets()
            .iter()
            .all(|r| matches!(r.path_only(), "/login" | "/api/auth/login"))
    }
}

fn auth_json(base: &str, token: &str, success: &str) -> String {
    format!(
        r#"{{"version":1,"login":{{"type":"form","url":"{base}/api/auth/login","body_format":"json",
        "username_field":"username","password_field":"password","username":"{USER}","password":"{PASS}"
        {token}{success}}}}}"#
    )
}

const TOK_JSON: &str = r#","token":{"from":"json","path":"data.access_token"}"#;

fn run(
    dir: &Path,
    srv: &Srv,
    start: &str,
    auth: &PathBuf,
    extra: &[&str],
) -> (std::process::Output, serde_json::Value) {
    let out = dir.join("out.sarif");
    let o = cmd()
        .args(["scan", &srv.url(start), "--auth-file"])
        .arg(auth)
        .args(["--crawl", "--max-rps", FAST, "--fail-on", "critical"])
        .args(["--format", "sarif", "--output"])
        .arg(&out)
        .args(extra)
        .output()
        .unwrap();
    let doc = std::fs::read_to_string(&out)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    (o, doc)
}

fn login_check(srv: &Srv, auth: &PathBuf) -> (Option<i32>, String, String) {
    let o = cmd()
        .args([
            "scan",
            &srv.url("/dashboard"),
            "--login-check",
            "--auth-file",
        ])
        .arg(auth)
        .args(["--max-rps", FAST])
        .output()
        .unwrap();
    let (stdout, stderr) = text(&o);
    (o.status.code(), stdout, stderr)
}

fn no_leak(texts: &[&str], secrets: &[&str]) {
    for t in texts {
        for s in secrets {
            assert!(!t.contains(s), "rahasia '{s}' bocor: {t}");
        }
    }
}

#[test]
fn json_token_without_cookies_is_sent_as_bearer_on_every_request() {
    let other = Srv::simple(Mode::JsonToken);
    let srv = Srv::start(
        Mode::JsonToken,
        None,
        false,
        "authorization",
        other.base.clone(),
    );
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, TOK_JSON, ""));
    let (o, doc) = run(dir.path(), &srv, "/dashboard", &auth, &["-vv"]);
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert_eq!(srv.logins(), 1);

    let tok = "TKN.1.zzSECRETzz";
    let gets = srv.gets();
    for p in ["/dashboard", "/p1", "/p2", "/p3", "/deep"] {
        let r = gets
            .iter()
            .find(|r| r.path_only() == p)
            .unwrap_or_else(|| panic!("{p} tidak diambil"));
        assert_eq!(
            r.header("authorization"),
            Some(format!("Bearer {tok}").as_str()),
            "{p}"
        );
    }
    // Kredensial login tidak membawa token; origin lain tidak disentuh sama sekali.
    let post = srv.log().into_iter().find(|r| r.method == "POST").unwrap();
    assert_eq!(post.header("authorization"), None);
    assert!(other.log().is_empty(), "origin lain tidak boleh diakses");
    assert!(srv.log().iter().all(|r| r.path_only() != "/logout"));
    no_leak(
        &[&stdout, &stderr, &doc.to_string()],
        &[tok, "zzSECRETzz", PASS, USER],
    );
    assert!(stderr.contains("GET http"), "{stderr}");
}

#[test]
fn token_is_found_through_array_index_path() {
    let srv = Srv::simple(Mode::ItemsToken);
    let dir = tempfile::tempdir().unwrap();
    let tok = r#","token":{"path":"items[0].token"}"#;
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, tok, ""));
    let (o, _) = run(dir.path(), &srv, "/dashboard", &auth, &[]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o).1);
    let r = srv
        .gets()
        .into_iter()
        .find(|r| r.path_only() == "/p1")
        .unwrap();
    assert_eq!(r.header("authorization"), Some("Bearer TKN.1.zzSECRETzz"));
}

#[test]
fn token_from_response_header_with_custom_header_and_prefix() {
    let srv = Srv::start(Mode::HeaderToken, None, false, "x-api-token", String::new());
    let dir = tempfile::tempdir().unwrap();
    let tok = r#","token":{"from":"header","path":"X-Auth-Token","header_name":"X-Api-Token","prefix":""}"#;
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, tok, ""));
    let (o, doc) = run(dir.path(), &srv, "/dashboard", &auth, &["-vv"]);
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    let r = srv
        .gets()
        .into_iter()
        .find(|r| r.path_only() == "/p1")
        .unwrap();
    assert_eq!(r.header("x-api-token"), Some("TKN.1.zzSECRETzz"));
    assert_eq!(r.header("authorization"), None);
    no_leak(&[&stdout, &stderr, &doc.to_string()], &["zzSECRETzz"]);
}

#[test]
fn token_sent_as_cookie() {
    let srv = Srv::start(Mode::JsonToken, None, true, "", String::new());
    let dir = tempfile::tempdir().unwrap();
    let tok = r#","token":{"path":"data.access_token","send_as":"cookie","cookie_name":"jwt"}"#;
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, tok, ""));
    let (o, doc) = run(dir.path(), &srv, "/dashboard", &auth, &["-vv"]);
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    let r = srv
        .gets()
        .into_iter()
        .find(|r| r.path_only() == "/p2")
        .unwrap();
    assert_eq!(r.header("cookie"), Some("jwt=TKN.1.zzSECRETzz"));
    assert_eq!(r.header("authorization"), None);
    no_leak(&[&stdout, &stderr, &doc.to_string()], &["zzSECRETzz"]);
}

#[test]
fn wrong_path_fails_with_path_but_never_the_body() {
    let srv = Srv::simple(Mode::JsonToken);
    let dir = tempfile::tempdir().unwrap();
    let tok = r#","token":{"path":"data.salah"}"#;
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, tok, ""));
    let (code, stdout, stderr) = login_check(&srv, &auth);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("data.salah"), "{stderr}");
    assert!(stderr.contains("tidak ditemukan"), "{stderr}");
    no_leak(
        &[&stdout, &stderr],
        &["TKN.", "zzSECRETzz", "access_token", PASS],
    );
    assert!(srv.never_crawled());
}

#[test]
fn non_scalar_empty_and_huge_tokens_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    for (mode, expect) in [
        (Mode::ObjectToken, "bukan string atau angka"),
        (Mode::BigToken, "8 KiB"),
        (Mode::NoToken, "tidak ditemukan"),
    ] {
        let srv = Srv::simple(mode);
        let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, TOK_JSON, ""));
        let (code, stdout, stderr) = login_check(&srv, &auth);
        assert_eq!(code, Some(2), "{mode:?}: {stderr}");
        assert!(stderr.contains(expect), "{mode:?}: {stderr}");
        no_leak(
            &[&stdout, &stderr],
            &["BBBBBBBBBB", "OBJSECRET", "zzSECRETzz", PASS],
        );
    }
}

#[test]
fn html_response_to_json_login_gives_hint_without_body() {
    let dir = tempfile::tempdir().unwrap();
    for token in ["", TOK_JSON] {
        let srv = Srv::simple(Mode::Html);
        let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, token, ""));
        let (code, stdout, stderr) = login_check(&srv, &auth);
        assert_eq!(code, Some(2), "{stderr}");
        assert!(
            stderr.contains(
                "respons login berupa HTML; kemungkinan URL login adalah halaman, bukan endpoint API"
            ),
            "{stderr}"
        );
        no_leak(&[&stdout, &stderr], &["LOGINPAGE-SECRETBODY", PASS]);
    }
}

#[test]
fn no_cookie_and_no_token_configured_suggests_login_token() {
    let srv = Srv::simple(Mode::JsonToken);
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, "", ""));
    let (code, stdout, stderr) = login_check(&srv, &auth);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("login gagal: tidak ada cookie sesi baru diterima dari server"),
        "{stderr}"
    );
    assert!(stderr.contains("konfigurasikan login.token"), "{stderr}");
    assert!(stderr.contains("data.access_token"), "{stderr}");
    assert!(stderr.contains("lihat tab Network"), "{stderr}");
    no_leak(&[&stdout, &stderr], &["TKN.", "zzSECRETzz"]);
}

#[test]
fn bad_credentials_with_token_configured_fail_on_status() {
    let srv = Srv::simple(Mode::JsonToken);
    let dir = tempfile::tempdir().unwrap();
    let bad = auth_json(&srv.base, TOK_JSON, "").replace(PASS, "salah");
    let auth = write_auth(dir.path(), "a.json", &bad);
    let (code, stdout, stderr) = login_check(&srv, &auth);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("status HTTP 401"), "{stderr}");
    no_leak(&[&stdout, &stderr], &["salah", "bad credentials"]);
}

#[test]
fn success_json_path_checks() {
    let dir = tempfile::tempdir().unwrap();
    let cases: &[(Mode, &str, bool, &str)] = &[
        (
            Mode::JsonToken,
            r#","success":{"json_path_equals":{"path":"status","value":"ok"},"json_path_exists":"data.access_token"}"#,
            true,
            "",
        ),
        (
            Mode::DeniedStatus,
            r#","success":{"json_path_equals":{"path":"status","value":"ok"}}"#,
            false,
            "tidak sama dengan yang diharapkan",
        ),
        (
            Mode::JsonToken,
            r#","success":{"json_path_exists":"data.refresh"}"#,
            false,
            "data.refresh",
        ),
        (
            Mode::JsonToken,
            r#","success":{"json_path_equals":{"path":"data.nope","value":1}}"#,
            false,
            "data.nope",
        ),
        (
            Mode::Html,
            r#","success":{"json_path_exists":"a"}"#,
            false,
            "berupa HTML",
        ),
    ];
    for (mode, success, ok, expect) in cases {
        let srv = Srv::simple(*mode);
        let tok = if *mode == Mode::Html { "" } else { TOK_JSON };
        let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, tok, success));
        let (code, stdout, stderr) = login_check(&srv, &auth);
        if *ok {
            assert_eq!(code, Some(0), "{success}: {stderr}");
        } else {
            assert_eq!(code, Some(2), "{success}: {stderr}");
            assert!(stderr.contains(expect), "{success}: {stderr}");
        }
        no_leak(&[&stdout, &stderr], &["zzSECRETzz", "TKN.", "LOGINPAGE"]);
    }
}

#[test]
fn json_path_exists_alone_does_not_replace_the_session_requirement() {
    // Tanpa token dan tanpa cookie, login tetap gagal walau json_path_exists terpenuhi.
    let srv = Srv::simple(Mode::NoToken);
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(
        dir.path(),
        "a.json",
        &auth_json(
            &srv.base,
            "",
            r#","success":{"json_path_exists":"data.id"}"#,
        ),
    );
    let (code, _, stderr) = login_check(&srv, &auth);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("tidak ada cookie sesi baru"), "{stderr}");
}

#[test]
fn login_check_reports_token_received_without_value() {
    let srv = Srv::simple(Mode::JsonToken);
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, TOK_JSON, ""));
    let (code, stdout, stderr) = login_check(&srv, &auth);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stdout.starts_with("login berhasil: token diterima (header Authorization)"),
        "{stdout}"
    );
    no_leak(&[&stdout, &stderr], &["TKN.", "zzSECRETzz", PASS]);
    // Login-check tidak crawl.
    assert!(srv.never_crawled());

    let tok = r#","token":{"path":"data.access_token","send_as":"cookie","cookie_name":"jwt"}"#;
    let auth = write_auth(dir.path(), "b.json", &auth_json(&srv.base, tok, ""));
    let (code, stdout, _) = login_check(&srv, &auth);
    assert_eq!(code, Some(0));
    assert!(stdout.contains("token diterima (cookie jwt)"), "{stdout}");
}

#[test]
fn relogin_after_401_replaces_the_token() {
    let srv = Srv::start(
        Mode::JsonToken,
        Some(3),
        false,
        "authorization",
        String::new(),
    );
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, TOK_JSON, ""));
    let (o, doc) = run(dir.path(), &srv, "/dashboard", &auth, &["-vv"]);
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert_eq!(srv.logins(), 2, "{stderr}");
    assert!(stderr.contains("sesi kedaluwarsa"), "{stderr}");
    // Permintaan setelah login ulang memakai token baru, bukan yang lama.
    let log = srv.log();
    let second_login = log
        .iter()
        .rposition(|r| r.method == "POST")
        .expect("login kedua");
    let after: Vec<&Req> = log[second_login..]
        .iter()
        .filter(|r| r.method == "GET" && r.path_only() != "/login")
        .collect();
    assert!(!after.is_empty());
    for r in after {
        assert_eq!(
            r.header("authorization"),
            Some("Bearer TKN.2.zzSECRETzz"),
            "{}",
            r.path
        );
    }
    no_leak(&[&stdout, &stderr, &doc.to_string()], &["zzSECRETzz"]);
}

#[test]
fn token_is_not_sent_to_other_origins_even_via_redirects_and_links() {
    let other = Srv::simple(Mode::JsonToken);
    let srv = Srv::start(
        Mode::JsonToken,
        None,
        false,
        "authorization",
        other.base.clone(),
    );
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, TOK_JSON, ""));
    let (o, _) = run(dir.path(), &srv, "/dashboard", &auth, &[]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o).1);
    // /redir-out sudah diambil (dengan token) tetapi tujuan di origin lain tidak diikuti.
    assert!(srv.log().iter().any(|r| r.path_only() == "/redir-out"));
    assert!(other.log().is_empty());

    // URL login di origin lain ditolak sebelum apa pun dikirim.
    let bad = auth_json(&other.base, TOK_JSON, "");
    let auth2 = write_auth(dir.path(), "b.json", &bad);
    let (code, _, stderr) = login_check(&srv, &auth2);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(other.log().is_empty());
}

#[test]
fn failed_token_extraction_stops_before_crawling() {
    let srv = Srv::simple(Mode::JsonToken);
    let dir = tempfile::tempdir().unwrap();
    let tok = r#","token":{"path":"data.salah"}"#;
    let auth = write_auth(dir.path(), "a.json", &auth_json(&srv.base, tok, ""));
    let (o, _) = run(dir.path(), &srv, "/dashboard", &auth, &[]);
    assert_eq!(o.status.code(), Some(2));
    assert!(srv.never_crawled());
}
