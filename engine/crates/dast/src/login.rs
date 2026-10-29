//! Alur login formulir: ambil halaman login (cookie awal, token CSRF), kirim kredensial (JSON atau
//! form), tampung cookie ke jar, lalu evaluasi kriteria sukses. Pesan galat tidak pernah memuat
//! kredensial, nilai cookie, atau token.

use serde_json::{json, Map, Value};
use url::Url;

use crate::auth::{
    BodyFormat, CsrfSendAs, CsrfSource, LoginConfig, Secret, TokenConfig, TokenFrom, TokenSendAs,
};
use crate::session::{BodyMode, Fetched, Hop, PostBody, Session};
use crate::{html, jsonpath, urlutil, DastError};

pub struct LoginOutcome {
    /// Cookie yang diterima dari server selama alur login.
    pub cookies_received: usize,
    /// URL halaman awal setelah login (tanpa query).
    pub landing: String,
    /// Halaman login (untuk pemeriksaan pasif).
    pub login_page: Fetched,
    /// Seluruh `Set-Cookie` dari respons pengiriman kredensial dan redirect-nya.
    pub post_set_cookies: Vec<String>,
    /// Deskripsi tempat token dikirim (mis. `header Authorization`) bila login menerima token;
    /// nilai token tidak pernah disimpan di sini.
    pub token: Option<String>,
}

/// Token terbesar yang diterima dari respons login.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

const HINT_NO_SESSION: &str = "Jika aplikasi mengembalikan token di isi JSON, konfigurasikan login.token (mis. path \"data.access_token\"); jika halaman login memakai JavaScript, isi URL login dengan endpoint API yang dipanggil browser (lihat tab Network), bukan halaman /login.";
const HINT_HTML: &str =
    "respons login berupa HTML; kemungkinan URL login adalah halaman, bukan endpoint API";

/// Salinan bagian respons POST login yang dibutuhkan untuk membaca token dan memeriksa JSON.
struct Snapshot {
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    oversized: bool,
    is_html: bool,
}

impl Snapshot {
    fn of(hop: &Hop, with_body: bool) -> Snapshot {
        Snapshot {
            headers: hop.headers.clone(),
            body: if with_body { hop.body.clone() } else { None },
            oversized: hop.oversized,
            is_html: hop.is_html(),
        }
    }

    fn json(&self) -> Result<Value, &'static str> {
        if self.oversized {
            return Err("respons login terlalu besar untuk dibaca");
        }
        let Some(body) = &self.body else {
            return Err("respons login tidak memiliki isi");
        };
        serde_json::from_slice(body).map_err(|_| "respons login bukan JSON yang valid")
    }
}

/// Galat login; bila respons berupa HTML padahal body_format json, tambahkan petunjuk.
fn fail_for(cfg: &LoginConfig, snap: &Snapshot, reason: &str) -> DastError {
    if cfg.body_format == BodyFormat::Json && snap.is_html {
        fail(&format!("{reason}. {HINT_HTML}"))
    } else {
        fail(reason)
    }
}

/// Membaca token dari respons login. Pesan galat menyebut jalur, tidak pernah nilai atau isi respons.
fn extract_token(t: &TokenConfig, snap: &Snapshot) -> Result<String, String> {
    let (raw, label): (String, String) = match t.from {
        TokenFrom::Json => {
            let doc = snap.json().map_err(str::to_string)?;
            let segs = jsonpath::parse(&t.path)
                .ok_or_else(|| format!("jalur token '{}' tidak valid", t.path))?;
            let label = format!("jalur '{}'", t.path);
            match jsonpath::get(&doc, &segs) {
                None => {
                    return Err(format!(
                        "jalur token '{}' tidak ditemukan di respons login",
                        t.path
                    ))
                }
                Some(Value::String(s)) => (s.clone(), label),
                Some(Value::Number(n)) => (n.to_string(), label),
                Some(_) => {
                    return Err(format!(
                        "nilai di jalur token '{}' bukan string atau angka",
                        t.path
                    ))
                }
            }
        }
        TokenFrom::Header => {
            let name = t.path.to_ascii_lowercase();
            let v = snap
                .headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .ok_or_else(|| format!("header respons '{}' (token) tidak ditemukan", t.path))?;
            (v, format!("header respons '{}'", t.path))
        }
    };
    let raw = raw.trim().to_string();
    if raw.is_empty() {
        return Err(format!("nilai token di {label} kosong"));
    }
    if raw.len() > MAX_TOKEN_BYTES {
        return Err(format!(
            "nilai token di {label} lebih dari {} KiB",
            MAX_TOKEN_BYTES / 1024
        ));
    }
    if !raw.is_ascii()
        || raw.chars().any(|c| c.is_control())
        || (t.send_as == TokenSendAs::Cookie && raw.contains(';'))
    {
        return Err(format!(
            "nilai token di {label} memuat karakter tidak valid"
        ));
    }
    Ok(raw)
}

fn same_scalar(got: &Value, want: &Value) -> bool {
    fn scalar(v: &Value) -> Option<String> {
        match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }
    got == want || scalar(got).zip(scalar(want)).is_some_and(|(a, b)| a == b)
}

fn fail(reason: &str) -> DastError {
    DastError::Auth(format!("login gagal: {reason}"))
}

const MAX_LOGIN_HOPS: usize = 5;

fn build_body(cfg: &LoginConfig, csrf_field: Option<(&str, &str)>) -> (&'static str, Vec<u8>) {
    match cfg.body_format {
        BodyFormat::Form => {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in &cfg.extra_fields {
                let val = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                ser.append_pair(k, &val);
            }
            if let Some((k, v)) = csrf_field {
                ser.append_pair(k, v);
            }
            ser.append_pair(&cfg.username_field, cfg.username.expose());
            ser.append_pair(&cfg.password_field, cfg.password.expose());
            (
                "application/x-www-form-urlencoded",
                ser.finish().into_bytes(),
            )
        }
        BodyFormat::Json => {
            let mut m = Map::new();
            for (k, v) in &cfg.extra_fields {
                m.insert(k.clone(), v.clone());
            }
            if let Some((k, v)) = csrf_field {
                m.insert(k.to_string(), json!(v));
            }
            m.insert(cfg.username_field.clone(), json!(cfg.username.expose()));
            m.insert(cfg.password_field.clone(), json!(cfg.password.expose()));
            (
                "application/json",
                serde_json::to_vec(&Value::Object(m)).unwrap_or_default(),
            )
        }
    }
}

fn body_text(hop: &Hop) -> String {
    hop.body
        .as_deref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

pub fn perform(session: &mut Session, cfg: &LoginConfig) -> Result<LoginOutcome, DastError> {
    if !urlutil::same_origin(&session.target, &cfg.url) {
        return Err(DastError::Auth(
            "URL login harus satu origin dengan target; kredensial tidak dikirim".to_string(),
        ));
    }
    session.jar.clear_server_cookies();
    session.clear_token();

    // 1. Halaman login: cookie awal dan token CSRF.
    let get = session.exec(&cfg.url, None, BodyMode::HtmlOnly)?;
    let login_html = get
        .body
        .as_deref()
        .filter(|_| get.is_html())
        .map(|b| String::from_utf8_lossy(b).into_owned());

    let mut csrf_field: Option<(String, String)> = None;
    let mut csrf_header: Option<(String, String)> = None;
    if let Some(c) = &cfg.csrf {
        let token = match c.source {
            CsrfSource::HtmlInput => login_html
                .as_deref()
                .and_then(|h| html::input_value(h, &c.name)),
            CsrfSource::Cookie => session.jar.get(&c.name).map(str::to_string),
            CsrfSource::Header => get.header(&c.name.to_ascii_lowercase()).map(str::to_string),
        };
        let Some(token) = token.filter(|t| !t.is_empty()) else {
            let where_ = match c.source {
                CsrfSource::HtmlInput => "input HTML di halaman login",
                CsrfSource::Cookie => "cookie",
                CsrfSource::Header => "header respons halaman login",
            };
            return Err(fail(&format!(
                "token CSRF '{}' tidak ditemukan ({where_}, status halaman login {})",
                c.name, get.status
            )));
        };
        match c.send_as {
            CsrfSendAs::Field => csrf_field = Some((c.name.clone(), token)),
            CsrfSendAs::Header => csrf_header = Some((c.header_name.clone(), token)),
        }
    }
    let login_page = Fetched {
        status: get.status,
        response: crate::checks::Response {
            url: urlutil::redact_url(&get.url),
            https: get.url.scheme() == "https",
            status: get.status,
            headers: get.headers.clone(),
            set_cookies: get.set_cookies.clone(),
        },
        url: get.url.clone(),
        html: login_html,
        oversized: get.oversized,
        is_html: get.is_html(),
    };

    // 2. Kirim kredensial.
    let (content_type, body) = build_body(
        cfg,
        csrf_field.as_ref().map(|(k, v)| (k.as_str(), v.as_str())),
    );
    let extra: Vec<(String, String)> = csrf_header.into_iter().collect();
    let mut cookies_chain: Vec<String> = Vec::new();
    let first = session.exec(
        &cfg.url,
        Some(PostBody {
            content_type,
            body,
            extra_headers: extra,
        }),
        BodyMode::Always,
    )?;
    cookies_chain.extend(first.set_cookies.iter().cloned());
    let first_status = first.status;
    let needs_json = cfg
        .token
        .as_ref()
        .is_some_and(|t| t.from == TokenFrom::Json)
        || cfg.success.json_path_exists.is_some()
        || cfg.success.json_path_equals.is_some();
    let snap = Snapshot::of(&first, needs_json);

    // 3. Status HTTP (401/403 dan semua di luar 2xx/3xx = gagal) dan token respons.
    let s = &cfg.success;
    let status_ok = match &s.statuses {
        Some(list) => list.contains(&first_status),
        None => (200..400).contains(&first_status),
    };
    if !status_ok {
        return Err(fail_for(
            cfg,
            &snap,
            &format!("status HTTP {first_status} tidak memenuhi kriteria sukses"),
        ));
    }
    let mut token_label = None;
    if let Some(t) = &cfg.token {
        let value = extract_token(t, &snap).map_err(|m| fail_for(cfg, &snap, &m))?;
        match t.send_as {
            TokenSendAs::Header => session
                .set_token_header(&t.header_name, Secret::new(format!("{}{value}", t.prefix))),
            TokenSendAs::Cookie => session.set_token_cookie(&t.cookie_name, Secret::new(value)),
        }
        token_label = Some(t.describe());
    }

    // 4. Ikuti redirect satu origin dengan GET (307/308 pun tidak mengulang POST kredensial).
    let mut locations: Vec<String> = Vec::new();
    let mut last = first;
    for _ in 0..MAX_LOGIN_HOPS {
        if !(300..400).contains(&last.status) {
            break;
        }
        let Some(loc) = last.location.clone() else {
            break;
        };
        locations.push(loc.clone());
        let Some(next) = last
            .url
            .join(&loc)
            .ok()
            .filter(|n| urlutil::same_origin(&session.target, n))
        else {
            break;
        };
        if session.is_login_url(&next) || session.exclude.is_excluded(&next) {
            break;
        }
        let hop = session.exec(&next, None, BodyMode::Always)?;
        cookies_chain.extend(hop.set_cookies.iter().cloned());
        last = hop;
    }
    // Lokasi terakhir yang belum diikuti (mis. ke login) tetap dicatat untuk evaluasi.
    if (300..400).contains(&last.status) {
        if let Some(loc) = &last.location {
            if !locations.contains(loc) {
                locations.push(loc.clone());
            }
        }
    }

    // 5. Kriteria sukses.
    let redirected_to_login = locations.iter().any(|l| {
        let resolved = first_url_join(&cfg.url, l);
        match &s.redirect_not_to {
            Some(pat) => {
                l.contains(pat.as_str())
                    || resolved.is_some_and(|u| u.path().contains(pat.as_str()))
            }
            None => resolved
                .is_some_and(|u| urlutil::same_origin(&u, &cfg.url) && u.path() == cfg.url.path()),
        }
    });
    if redirected_to_login {
        return Err(fail("diarahkan kembali ke halaman login"));
    }
    let accepted = cookies_chain.len();
    match &s.cookie_set {
        Some(name) => {
            if !cookies_chain.iter().any(|c| {
                c.split(';')
                    .next()
                    .and_then(|p| p.split_once('='))
                    .is_some_and(|(n, v)| n.trim() == name && !v.trim().is_empty())
            }) {
                return Err(fail(&format!("cookie '{name}' tidak diterima dari server")));
            }
        }
        None => {
            if accepted == 0 && cfg.token.is_none() {
                return Err(if cfg.body_format == BodyFormat::Json && snap.is_html {
                    fail_for(
                        cfg,
                        &snap,
                        "tidak ada cookie sesi baru diterima dari server",
                    )
                } else {
                    fail(&format!(
                        "tidak ada cookie sesi baru diterima dari server. {HINT_NO_SESSION}"
                    ))
                });
            }
        }
    }
    if s.json_path_exists.is_some() || s.json_path_equals.is_some() {
        let doc = snap.json().map_err(|m| fail_for(cfg, &snap, m))?;
        if let Some(p) = &s.json_path_exists {
            let found = jsonpath::parse(p).and_then(|segs| jsonpath::get(&doc, &segs));
            if found.is_none() {
                return Err(fail(&format!(
                    "jalur '{p}' tidak ditemukan di respons login (success.json_path_exists)"
                )));
            }
        }
        if let Some(e) = &s.json_path_equals {
            let found = jsonpath::parse(&e.path).and_then(|segs| jsonpath::get(&doc, &segs));
            match found {
                None => {
                    return Err(fail(&format!(
                        "jalur '{}' tidak ditemukan di respons login (success.json_path_equals)",
                        e.path
                    )))
                }
                Some(v) if !same_scalar(v, &e.value) => {
                    return Err(fail(&format!(
                        "nilai di jalur '{}' tidak sama dengan yang diharapkan (success.json_path_equals)",
                        e.path
                    )))
                }
                Some(_) => {}
            }
        }
    }
    let text = body_text(&last);
    if let Some(needle) = &s.body_contains {
        if !text.contains(needle.as_str()) {
            return Err(fail("isi respons tidak memuat teks yang diharapkan"));
        }
    }
    if let Some(needle) = &s.body_not_contains {
        if text.contains(needle.as_str()) {
            return Err(fail("isi respons memuat teks penanda kegagalan"));
        }
    }

    Ok(LoginOutcome {
        cookies_received: session.jar.server_count(),
        landing: urlutil::no_query(&last.url),
        login_page,
        post_set_cookies: cookies_chain,
        token: token_label,
    })
}

fn first_url_join(base: &Url, loc: &str) -> Option<Url> {
    base.join(loc).ok()
}
