//! Aplikasi web tiruan di loopback untuk menguji login, crawl, dan pemeriksaan pasif `sdrscan-dast`.
//! Server mencatat setiap permintaan (metode, jalur, header, waktu) agar tes dapat memastikan apa
//! yang BOLEH dan TIDAK BOLEH diakses.
#![allow(dead_code)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use assert_cmd::Command;

pub const USER: &str = "alice-the-tester";
pub const PASS: &str = "S3cretPass!Zq";
pub const CSRF_FIELD: &str = "CSRF-FIELD-VALUE-77";
pub const CSRF_COOKIE: &str = "CSRF-COOKIE-VALUE-88";
pub const BEARER: &str = "GOODTOKEN-5566";
pub const API_KEY: &str = "APIKEY-VALUE-9911";
pub const PASTED_SESSION: &str = "SESS-PASTED-4242";
pub const URL_SECRET: &str = "URLSECRET-31337";

#[derive(Clone, Debug)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub at: Instant,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn path_only(&self) -> &str {
        self.path.split('?').next().unwrap_or("")
    }
}

#[derive(Clone, Default)]
pub struct Cfg {
    /// Sesi dibatalkan setelah sekian akses halaman terautentikasi.
    pub expire_after: Option<usize>,
    /// Bila true, sesi dibatalkan lagi setiap `expire_after` akses.
    pub repeat_expiry: bool,
    /// Atribut cookie sesi (default: Path=/; HttpOnly; SameSite=Lax).
    pub cookie_attrs: Option<&'static str>,
    /// URL server lain (tautan keluar origin dan redirect keluar).
    pub other: String,
    /// Cookie sesi tempelan dianggap sah.
    pub accept_pasted: bool,
}

pub struct State {
    pub log: Mutex<Vec<Req>>,
    valid: Mutex<HashSet<String>>,
    logins: AtomicUsize,
    hits: AtomicUsize,
    cfg: Cfg,
}

pub struct App {
    pub base: String,
    pub state: Arc<State>,
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn html(body: &str) -> Resp {
    Resp {
        status: 200,
        headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
        body: body.as_bytes().to_vec(),
    }
}

fn redirect(to: &str) -> Resp {
    Resp {
        status: 302,
        headers: vec![("Location".into(), to.into())],
        body: Vec::new(),
    }
}

fn status(code: u16, body: &str) -> Resp {
    Resp {
        status: code,
        headers: vec![("Content-Type".into(), "text/plain".into())],
        body: body.as_bytes().to_vec(),
    }
}

fn cookie_of(req: &Req, name: &str) -> Option<String> {
    req.header("cookie")?.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

impl State {
    fn authed(&self, req: &Req) -> bool {
        let Some(sess) = cookie_of(req, "session") else {
            return false;
        };
        if !self.valid.lock().unwrap().contains(&sess) {
            return false;
        }
        let n = self.hits.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(k) = self.cfg.expire_after {
            if (self.cfg.repeat_expiry && n.is_multiple_of(k))
                || (!self.cfg.repeat_expiry && n == k)
            {
                self.valid.lock().unwrap().clear();
                if self.cfg.accept_pasted {
                    self.valid.lock().unwrap().insert(PASTED_SESSION.into());
                }
                return false;
            }
        }
        true
    }

    fn login_ok(&self, fail_to: Option<&str>) -> Resp {
        let n = self.logins.fetch_add(1, Ordering::SeqCst) + 1;
        let val = format!("SESS-VALUE-{n}");
        self.valid.lock().unwrap().insert(val.clone());
        let attrs = self
            .cfg
            .cookie_attrs
            .unwrap_or("; Path=/; HttpOnly; SameSite=Lax");
        let _ = fail_to;
        let mut r = redirect("/welcome");
        r.headers
            .push(("Set-Cookie".into(), format!("session={val}{attrs}")));
        r
    }

    fn login_fail(&self, fail_to: Option<&str>) -> Resp {
        match fail_to {
            Some(to) => redirect(to),
            None => status(401, "invalid credentials"),
        }
    }

    fn route(&self, req: &Req) -> Resp {
        let path = req.path_only();
        let base = &self.cfg.other;
        let page = |title: &str, links: &[String]| {
            let l: String = links
                .iter()
                .map(|h| format!("<a href=\"{h}\">l</a> "))
                .collect();
            html(&format!(
                "<html><head><title>{title}</title></head><body>{l}</body></html>"
            ))
        };
        match (req.method.as_str(), path) {
            ("GET", "/login") | ("GET", "/login2") => {
                let mut r = html(&format!(
                    "<html><body><form method=\"post\" action=\"{path}\">\
                     <input type=\"hidden\" name=\"csrf_token\" value=\"{CSRF_FIELD}\">\
                     <input name=\"user\"><input type=\"password\" name=\"password\">\
                     </form></body></html>"
                ));
                r.headers
                    .push(("Set-Cookie".into(), "init=INITCOOKIE; Path=/".into()));
                r
            }
            ("POST", "/login") | ("POST", "/login2") => {
                let form: Vec<(String, String)> = url::form_urlencoded::parse(req.body.as_bytes())
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                let get = |k: &str| form.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
                let fail_to = (path == "/login2").then_some("/login2?error=1");
                let ct_ok = req
                    .header("content-type")
                    .is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
                if ct_ok
                    && get("csrf_token") == Some(CSRF_FIELD)
                    && get("user") == Some(USER)
                    && get("password") == Some(PASS)
                    && cookie_of(req, "init").as_deref() == Some("INITCOOKIE")
                {
                    self.login_ok(fail_to)
                } else {
                    self.login_fail(fail_to)
                }
            }
            ("GET", "/login-cookie") => {
                let mut r = html("<html><body>login via cookie csrf</body></html>");
                r.headers
                    .push(("Set-Cookie".into(), format!("csrf={CSRF_COOKIE}; Path=/")));
                r
            }
            ("POST", "/login-cookie") | ("POST", "/api/login") => {
                let v: serde_json::Value = serde_json::from_str(&req.body).unwrap_or_default();
                let csrf_ok =
                    path == "/api/login" || req.header("x-csrf-token") == Some(CSRF_COOKIE);
                let extra_ok = v["remember"] == "true";
                if csrf_ok && extra_ok && v["user"] == USER && v["password"] == PASS {
                    let mut r = self.login_ok(None);
                    r.status = 200;
                    r.headers.retain(|(k, _)| k != "Location");
                    r.body = b"{\"ok\":true}".to_vec();
                    r
                } else {
                    status(401, "{\"ok\":false}")
                }
            }
            ("GET", "/welcome") => {
                if self.authed(req) {
                    page("welcome", &["/dashboard".into()])
                } else {
                    redirect("/login")
                }
            }
            ("GET", "/dashboard") => {
                if !self.authed(req) {
                    return redirect("/login");
                }
                let mut r = page(
                    "dashboard",
                    &[
                        "/page1".into(),
                        "/page2".into(),
                        "/logout".into(),
                        "/delete?id=1".into(),
                        "/style.css".into(),
                        "/logo.png".into(),
                        format!("{base}/ext"),
                        "/links".into(),
                        "/go-out".into(),
                        "/many".into(),
                        "/nonhtml".into(),
                        "/big".into(),
                        "#frag".into(),
                        "mailto:a@b.test".into(),
                        "/login".into(),
                    ],
                );
                r.headers
                    .push(("Server".into(), "Apache/2.4.41 (Unix)".into()));
                r
            }
            ("GET", "/page1") => {
                self.guarded(req, || page("p1", &["/deep/1".into(), "/dashboard".into()]))
            }
            ("GET", "/page2") => {
                self.guarded(req, || page("p2", &["/page2".into(), "/dashboard".into()]))
            }
            ("GET", p) if p.starts_with("/deep/") => {
                let n: u32 = p[6..].parse().unwrap_or(0);
                self.guarded(req, || page("deep", &[format!("/deep/{}", n + 1)]))
            }
            ("GET", "/many") => {
                let links: Vec<String> = (1..=20).map(|i| format!("/many/{i}")).collect();
                self.guarded(req, || page("many", &links))
            }
            ("GET", p) if p.starts_with("/many/") => self.guarded(req, || page("m", &[])),
            ("GET", "/links") => self.guarded(req, || {
                page(
                    "links",
                    &[
                        format!("/share?token={URL_SECRET}&view=1"),
                        format!("/s?api_key={URL_SECRET}"),
                        "/list?page=1".into(),
                        "/list?page=2".into(),
                        "/list?page=3".into(),
                        "/list?page=4".into(),
                        "/list?page=5".into(),
                    ],
                )
            }),
            ("GET", "/share") | ("GET", "/s") | ("GET", "/list") => {
                self.guarded(req, || page("x", &[]))
            }
            ("GET", "/go-out") => self.guarded(req, || redirect("/logout")),
            ("GET", "/redir-out") => redirect(&format!("{base}/landed")),
            ("GET", "/nonhtml") => self.guarded(req, || Resp {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: b"{\"a\":\"<a href=\\\"/hidden-json\\\">x</a>\"}".to_vec(),
            }),
            ("GET", "/big") => self.guarded(req, || {
                let mut r = html("<html><body><a href=\"/after-big\">x</a>");
                r.body.extend(std::iter::repeat_n(b' ', 3 * 1024 * 1024));
                r
            }),
            ("GET", "/api/home") => {
                if req.header("authorization") == Some(&format!("Bearer {BEARER}"))
                    && req.header("x-api-key") == Some(API_KEY)
                {
                    page(
                        "home",
                        &["/public".into(), format!("{base}/ext"), "/redir-out".into()],
                    )
                } else {
                    status(401, "unauthorized")
                }
            }
            ("GET", "/public") => page("public", &[]),
            ("GET", "/cookie-home") => {
                if cookie_of(req, "session").as_deref() == Some(PASTED_SESSION) {
                    page("cookie-home", &["/public".into()])
                } else {
                    status(401, "no")
                }
            }
            ("GET", "/") => page("root", &["/public".into()]),
            _ => status(404, "not found"),
        }
    }

    fn guarded(&self, req: &Req, f: impl FnOnce() -> Resp) -> Resp {
        if self.authed(req) {
            f()
        } else {
            redirect("/login")
        }
    }
}

pub fn read_request(stream: &mut std::net::TcpStream) -> Option<Req> {
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
    let mut body = data[head_end + 4..].to_vec();
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

impl App {
    pub fn start(cfg: Cfg) -> App {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut valid = HashSet::new();
        if cfg.accept_pasted {
            valid.insert(PASTED_SESSION.to_string());
        }
        let state = Arc::new(State {
            log: Mutex::new(Vec::new()),
            valid: Mutex::new(valid),
            logins: AtomicUsize::new(0),
            hits: AtomicUsize::new(0),
            cfg,
        });
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
                    let r = st.route(&req);
                    let reason = match r.status {
                        200 => "OK",
                        302 => "Found",
                        401 => "Unauthorized",
                        _ => "Other",
                    };
                    let mut out = format!("HTTP/1.1 {} {reason}\r\n", r.status);
                    if !r.headers.iter().any(|(k, _)| k == "Server") {
                        out.push_str("Server: Apache/2.4.41 (Unix)\r\n");
                    }
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
        App {
            base: format!("http://{addr}"),
            state,
        }
    }

    /// Dua server: yang pertama dengan tautan ke yang kedua ("origin lain").
    pub fn pair(mut cfg: Cfg) -> (App, App) {
        let other = App::start(Cfg::default());
        cfg.other = other.base.clone();
        (App::start(cfg), other)
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub fn log(&self) -> Vec<Req> {
        self.state.log.lock().unwrap().clone()
    }

    pub fn logins(&self) -> usize {
        self.state.logins.load(Ordering::SeqCst)
    }

    /// Permintaan GET selain halaman login/welcome (yaitu yang berasal dari crawl).
    pub fn crawl_gets(&self) -> Vec<String> {
        self.log()
            .iter()
            .filter(|r| r.method == "GET")
            .map(|r| r.path_only().to_string())
            .filter(|p| !p.starts_with("/login") && p != "/welcome")
            .collect()
    }

    pub fn was_requested(&self, path: &str) -> bool {
        self.log().iter().any(|r| r.path_only() == path)
    }

    /// Semua metode selain GET harus POST ke endpoint login.
    pub fn assert_only_get_except_login(&self) {
        for r in self.log() {
            assert!(
                r.method == "GET"
                    || (r.method == "POST"
                        && matches!(
                            r.path_only(),
                            "/login" | "/login2" | "/login-cookie" | "/api/login"
                        )),
                "permintaan tidak diizinkan: {} {}",
                r.method,
                r.path
            );
        }
    }
}

pub fn cmd() -> Command {
    Command::cargo_bin("sdrscan-dast").unwrap()
}

/// Menulis berkas auth dengan izin 0600.
pub fn write_auth(dir: &Path, name: &str, json: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, json).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    p
}

pub fn form_login_json(base: &str, path: &str) -> String {
    format!(
        r#"{{"version":1,"login":{{"type":"form","url":"{base}{path}","method":"POST","body_format":"form",
        "username_field":"user","password_field":"password","username":"{USER}","password":"{PASS}",
        "csrf":{{"source":"html_input","name":"csrf_token","send_as":"field"}}}}}}"#
    )
}

pub fn text(o: &std::process::Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).to_string(),
        String::from_utf8_lossy(&o.stderr).to_string(),
    )
}
