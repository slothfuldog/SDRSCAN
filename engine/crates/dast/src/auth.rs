//! Konfigurasi autentikasi DAST dari berkas JSON (`--auth-file`).
//!
//! Berkas dibaca sekali dan isinya TIDAK pernah dicetak: semua nilai rahasia dibungkus `Secret`
//! (Debug tersamarkan) dan galat hanya menyebut nama bidang, tidak pernah nilainya.

use std::fmt;
use std::io::Read;
use std::path::Path;

use sdrscan_core::{Warning, WarningKind};
use serde_json::{Map, Value};
use url::Url;

use crate::DastError;

/// Ukuran maksimum berkas auth.
pub const MAX_AUTH_FILE_BYTES: u64 = 64 * 1024;
const MAX_ENTRIES: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<disamarkan>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFormat {
    Json,
    Form,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrfSource {
    HtmlInput,
    Cookie,
    Header,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrfSendAs {
    Field,
    Header,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfConfig {
    pub source: CsrfSource,
    pub name: String,
    pub send_as: CsrfSendAs,
    pub header_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFrom {
    Json,
    Header,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSendAs {
    Header,
    Cookie,
}

/// Token yang dikembalikan respons login (isi JSON atau header respons) dan dikirim di setiap
/// permintaan berikutnya ke origin target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenConfig {
    pub from: TokenFrom,
    /// Jalur titik ke nilai di JSON (`from=json`) atau nama header respons (`from=header`).
    pub path: String,
    pub send_as: TokenSendAs,
    /// Nama header permintaan (`send_as=header`).
    pub header_name: String,
    pub prefix: String,
    /// Nama cookie (`send_as=cookie`).
    pub cookie_name: String,
}

impl TokenConfig {
    /// Deskripsi tanpa nilai token, mis. `header Authorization` atau `cookie token`.
    pub fn describe(&self) -> String {
        match self.send_as {
            TokenSendAs::Header => format!("header {}", self.header_name),
            TokenSendAs::Cookie => format!("cookie {}", self.cookie_name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonEquals {
    pub path: String,
    /// Skalar JSON (string, angka, atau boolean).
    pub value: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuccessConfig {
    pub statuses: Option<Vec<u16>>,
    pub cookie_set: Option<String>,
    pub body_contains: Option<String>,
    pub body_not_contains: Option<String>,
    pub redirect_not_to: Option<String>,
    /// Jalur JSON yang harus ada di isi respons login.
    pub json_path_exists: Option<String>,
    /// Jalur JSON yang nilainya harus sama.
    pub json_path_equals: Option<JsonEquals>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LoginConfig {
    pub url: Url,
    pub body_format: BodyFormat,
    pub username_field: String,
    pub password_field: String,
    pub username: Secret,
    pub password: Secret,
    /// Nilai konstan tambahan (skalar JSON), urut menurut nama.
    pub extra_fields: Vec<(String, Value)>,
    pub csrf: Option<CsrfConfig>,
    pub token: Option<TokenConfig>,
    pub success: SuccessConfig,
}

impl fmt::Debug for LoginConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginConfig")
            .field("url", &crate::urlutil::redact_url(&self.url))
            .field("body_format", &self.body_format)
            .field("username", &self.username)
            .field("password", &self.password)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct AuthConfig {
    pub login: Option<LoginConfig>,
    /// Header tetap (nama, nilai); hanya dikirim ke origin target.
    pub headers: Vec<(String, Secret)>,
    /// Cookie tempel (nama, nilai); hanya dikirim ke origin target.
    pub cookies: Vec<(String, Secret)>,
    /// Peringatan saat memuat berkas (mis. izin terlalu longgar); dipindahkan ke hasil pemindaian.
    pub load_warnings: Vec<Warning>,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("login", &self.login)
            .field(
                "headers",
                &self.headers.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .field(
                "cookies",
                &self.cookies.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .finish()
    }
}

fn err(msg: impl Into<String>) -> DastError {
    DastError::Config(msg.into())
}

fn field<'a>(obj: &'a Map<String, Value>, ctx: &str, key: &str) -> Result<&'a Value, DastError> {
    obj.get(key)
        .ok_or_else(|| err(format!("berkas auth: bidang '{ctx}{key}' wajib ada")))
}

fn as_str<'a>(v: &'a Value, path: &str) -> Result<&'a str, DastError> {
    v.as_str()
        .ok_or_else(|| err(format!("berkas auth: bidang '{path}' harus berupa string")))
}

fn str_field(obj: &Map<String, Value>, ctx: &str, key: &str) -> Result<String, DastError> {
    Ok(as_str(field(obj, ctx, key)?, &format!("{ctx}{key}"))?.to_string())
}

fn opt_str(obj: &Map<String, Value>, ctx: &str, key: &str) -> Result<Option<String>, DastError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => Ok(Some(as_str(v, &format!("{ctx}{key}"))?.to_string())),
    }
}

fn object<'a>(v: &'a Value, path: &str) -> Result<&'a Map<String, Value>, DastError> {
    v.as_object()
        .ok_or_else(|| err(format!("berkas auth: bidang '{path}' harus berupa objek")))
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "cookie",
    "upgrade",
    "te",
    "expect",
];

fn parse_pairs(
    obj: &Map<String, Value>,
    path: &str,
    kind: &str,
) -> Result<Vec<(String, Secret)>, DastError> {
    if obj.len() > MAX_ENTRIES {
        return Err(err(format!(
            "berkas auth: '{path}' memuat lebih dari {MAX_ENTRIES} entri"
        )));
    }
    let mut out = Vec::new();
    for (k, v) in obj {
        let value = as_str(v, &format!("{path}.{k}"))?;
        if k.is_empty() || !k.chars().all(is_token_char) {
            return Err(err(format!("berkas auth: nama {kind} '{k}' tidak valid")));
        }
        if value.chars().any(|c| c.is_control() && c != '\t') {
            return Err(err(format!(
                "berkas auth: nilai {kind} '{k}' memuat karakter kontrol"
            )));
        }
        if kind == "header" {
            if FORBIDDEN_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
                return Err(err(format!(
                    "berkas auth: header '{k}' tidak diizinkan (gunakan 'cookies' untuk cookie)"
                )));
            }
        } else if value.contains(';') {
            return Err(err(format!(
                "berkas auth: nilai cookie '{k}' memuat karakter terlarang (;)"
            )));
        }
        out.push((k.clone(), Secret::new(value)));
    }
    Ok(out)
}

fn parse_login(v: &Value) -> Result<LoginConfig, DastError> {
    let o = object(v, "login")?;
    let ty = str_field(o, "login.", "type")?;
    if ty != "form" {
        return Err(err("berkas auth: login.type tidak didukung (hanya 'form')"));
    }
    let url_s = str_field(o, "login.", "url")?;
    let url = Url::parse(&url_s).map_err(|_| err("berkas auth: login.url bukan URL yang valid"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(err("berkas auth: login.url harus http atau https"));
    }
    if let Some(m) = opt_str(o, "login.", "method")? {
        if !m.eq_ignore_ascii_case("POST") {
            return Err(err("berkas auth: login.method hanya mendukung POST"));
        }
    }
    let body_format = match opt_str(o, "login.", "body_format")?.as_deref() {
        None | Some("form") => BodyFormat::Form,
        Some("json") => BodyFormat::Json,
        Some(_) => {
            return Err(err(
                "berkas auth: login.body_format harus 'json' atau 'form'",
            ))
        }
    };
    let username_field = str_field(o, "login.", "username_field")?;
    let password_field = str_field(o, "login.", "password_field")?;
    if username_field.is_empty() || password_field.is_empty() || username_field == password_field {
        return Err(err(
            "berkas auth: login.username_field dan login.password_field harus berbeda dan tidak kosong",
        ));
    }
    let username = Secret::new(str_field(o, "login.", "username")?);
    let password = Secret::new(str_field(o, "login.", "password")?);

    let mut extra_fields = Vec::new();
    if let Some(e) = o.get("extra_fields").filter(|e| !e.is_null()) {
        let e = object(e, "login.extra_fields")?;
        if e.len() > MAX_ENTRIES {
            return Err(err("berkas auth: login.extra_fields terlalu banyak entri"));
        }
        for (k, val) in e {
            if !matches!(val, Value::String(_) | Value::Bool(_) | Value::Number(_)) {
                return Err(err(format!(
                    "berkas auth: login.extra_fields.{k} harus string, angka, atau boolean"
                )));
            }
            extra_fields.push((k.clone(), val.clone()));
        }
        extra_fields.sort_by(|a, b| a.0.cmp(&b.0));
    }

    let csrf = match o.get("csrf").filter(|c| !c.is_null()) {
        None => None,
        Some(c) => {
            let c = object(c, "login.csrf")?;
            let source = match str_field(c, "login.csrf.", "source")?.as_str() {
                "html_input" => CsrfSource::HtmlInput,
                "cookie" => CsrfSource::Cookie,
                "header" => CsrfSource::Header,
                _ => {
                    return Err(err(
                        "berkas auth: login.csrf.source harus html_input, cookie, atau header",
                    ))
                }
            };
            let name = str_field(c, "login.csrf.", "name")?;
            if name.is_empty() {
                return Err(err("berkas auth: login.csrf.name tidak boleh kosong"));
            }
            let send_as = match opt_str(c, "login.csrf.", "send_as")?.as_deref() {
                None => match source {
                    CsrfSource::HtmlInput => CsrfSendAs::Field,
                    _ => CsrfSendAs::Header,
                },
                Some("field") => CsrfSendAs::Field,
                Some("header") => CsrfSendAs::Header,
                Some(_) => {
                    return Err(err(
                        "berkas auth: login.csrf.send_as harus 'field' atau 'header'",
                    ))
                }
            };
            let header_name = opt_str(c, "login.csrf.", "header_name")?
                .unwrap_or_else(|| "X-CSRF-Token".to_string());
            if header_name.is_empty()
                || !header_name.chars().all(is_token_char)
                || FORBIDDEN_HEADERS.contains(&header_name.to_ascii_lowercase().as_str())
            {
                return Err(err("berkas auth: login.csrf.header_name tidak valid"));
            }
            Some(CsrfConfig {
                source,
                name,
                send_as,
                header_name,
            })
        }
    };

    let mut success = SuccessConfig::default();
    if let Some(s) = o.get("success").filter(|s| !s.is_null()) {
        let s = object(s, "login.success")?;
        if let Some(st) = s.get("statuses").filter(|v| !v.is_null()) {
            let arr = st
                .as_array()
                .ok_or_else(|| err("berkas auth: login.success.statuses harus berupa larik"))?;
            let mut list = Vec::new();
            for n in arr {
                let code = n
                    .as_u64()
                    .filter(|c| (100..=599).contains(c))
                    .ok_or_else(|| {
                        err("berkas auth: login.success.statuses harus berisi kode HTTP 100-599")
                    })?;
                list.push(code as u16);
            }
            if list.is_empty() {
                return Err(err(
                    "berkas auth: login.success.statuses tidak boleh kosong",
                ));
            }
            success.statuses = Some(list);
        }
        success.cookie_set = opt_str(s, "login.success.", "cookie_set")?;
        success.body_contains = opt_str(s, "login.success.", "body_contains")?;
        success.body_not_contains = opt_str(s, "login.success.", "body_not_contains")?;
        success.redirect_not_to = opt_str(s, "login.success.", "redirect_not_to")?;
        if let Some(p) = opt_str(s, "login.success.", "json_path_exists")? {
            check_json_path(&p, "login.success.json_path_exists")?;
            success.json_path_exists = Some(p);
        }
        if let Some(e) = s.get("json_path_equals").filter(|v| !v.is_null()) {
            let e = object(e, "login.success.json_path_equals")?;
            let path = str_field(e, "login.success.json_path_equals.", "path")?;
            check_json_path(&path, "login.success.json_path_equals.path")?;
            let value = field(e, "login.success.json_path_equals.", "value")?.clone();
            if !matches!(value, Value::String(_) | Value::Bool(_) | Value::Number(_)) {
                return Err(err(
                    "berkas auth: login.success.json_path_equals.value harus string, angka, atau boolean",
                ));
            }
            success.json_path_equals = Some(JsonEquals { path, value });
        }
    }

    let token = match o.get("token").filter(|t| !t.is_null()) {
        None => None,
        Some(t) => Some(parse_token(object(t, "login.token")?)?),
    };

    Ok(LoginConfig {
        url,
        body_format,
        username_field,
        password_field,
        username,
        password,
        extra_fields,
        csrf,
        token,
        success,
    })
}

fn check_json_path(p: &str, field: &str) -> Result<(), DastError> {
    if crate::jsonpath::parse(p).is_none() {
        return Err(err(format!(
            "berkas auth: {field} bukan jalur JSON yang valid (contoh: data.access_token atau items[0].token)"
        )));
    }
    Ok(())
}

fn parse_token(t: &Map<String, Value>) -> Result<TokenConfig, DastError> {
    let from = match opt_str(t, "login.token.", "from")?.as_deref() {
        None | Some("json") => TokenFrom::Json,
        Some("header") => TokenFrom::Header,
        Some(_) => {
            return Err(err(
                "berkas auth: login.token.from harus 'json' atau 'header'",
            ));
        }
    };
    let path = str_field(t, "login.token.", "path")?;
    match from {
        TokenFrom::Json => check_json_path(&path, "login.token.path")?,
        TokenFrom::Header => {
            if path.is_empty() || path.len() > 100 || !path.chars().all(is_token_char) {
                return Err(err(
                    "berkas auth: login.token.path harus nama header respons yang valid bila from=header",
                ));
            }
        }
    }
    let send_as = match opt_str(t, "login.token.", "send_as")?.as_deref() {
        None | Some("header") => TokenSendAs::Header,
        Some("cookie") => TokenSendAs::Cookie,
        Some(_) => {
            return Err(err(
                "berkas auth: login.token.send_as harus 'header' atau 'cookie'",
            ));
        }
    };
    let header_name =
        opt_str(t, "login.token.", "header_name")?.unwrap_or_else(|| "Authorization".to_string());
    if header_name.is_empty()
        || header_name.len() > 100
        || !header_name.chars().all(is_token_char)
        || FORBIDDEN_HEADERS.contains(&header_name.to_ascii_lowercase().as_str())
    {
        return Err(err("berkas auth: login.token.header_name tidak valid"));
    }
    let prefix = match opt_str(t, "login.token.", "prefix")? {
        Some(p) => p,
        None if header_name.eq_ignore_ascii_case("authorization") => "Bearer ".to_string(),
        None => String::new(),
    };
    if prefix.chars().count() > 32 || !prefix.is_ascii() || prefix.chars().any(|c| c.is_control()) {
        return Err(err(
            "berkas auth: login.token.prefix terlalu panjang (maksimum 32) atau memuat karakter non-ASCII/kontrol",
        ));
    }
    let cookie_name = opt_str(t, "login.token.", "cookie_name")?.unwrap_or_default();
    if send_as == TokenSendAs::Cookie
        && (cookie_name.is_empty()
            || cookie_name.len() > 100
            || !cookie_name.chars().all(is_token_char))
    {
        return Err(err(
            "berkas auth: login.token.cookie_name wajib dan harus nama cookie yang valid bila send_as=cookie",
        ));
    }
    Ok(TokenConfig {
        from,
        path,
        send_as,
        header_name,
        prefix,
        cookie_name,
    })
}

impl AuthConfig {
    /// Mengurai JSON berkas auth. Galat tidak pernah memuat isi berkas (hanya nama bidang).
    pub fn parse(bytes: &[u8]) -> Result<AuthConfig, DastError> {
        let v: Value = serde_json::from_slice(bytes).map_err(|e| {
            err(format!(
                "berkas auth bukan JSON yang valid (baris {}, kolom {})",
                e.line(),
                e.column()
            ))
        })?;
        let o = v
            .as_object()
            .ok_or_else(|| err("berkas auth harus berupa objek JSON"))?;
        match o.get("version") {
            Some(Value::Number(n)) if n.as_u64() == Some(1) => {}
            _ => return Err(err("berkas auth: 'version' harus 1")),
        }
        let login = match o.get("login").filter(|l| !l.is_null()) {
            Some(l) => Some(parse_login(l)?),
            None => None,
        };
        let headers = match o.get("headers").filter(|h| !h.is_null()) {
            Some(h) => parse_pairs(object(h, "headers")?, "headers", "header")?,
            None => Vec::new(),
        };
        let cookies = match o.get("cookies").filter(|h| !h.is_null()) {
            Some(h) => parse_pairs(object(h, "cookies")?, "cookies", "cookie")?,
            None => Vec::new(),
        };
        if login.is_none() && headers.is_empty() && cookies.is_empty() {
            return Err(err(
                "berkas auth tidak memuat 'login', 'headers', maupun 'cookies'",
            ));
        }
        Ok(AuthConfig {
            login,
            headers,
            cookies,
            load_warnings: Vec::new(),
        })
    }

    /// Membaca berkas auth: harus berkas biasa, maksimum 64 KiB; izin lebih longgar dari 0600
    /// (Unix) hanya diberi peringatan.
    pub fn from_file(path: &Path) -> Result<AuthConfig, DastError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| err(format!("berkas auth tidak dapat dibaca: {}", e.kind())))?;
        if !meta.is_file() {
            return Err(err("berkas auth harus berupa berkas biasa"));
        }
        if meta.len() > MAX_AUTH_FILE_BYTES {
            return Err(err(format!(
                "berkas auth terlalu besar (maksimum {} KiB)",
                MAX_AUTH_FILE_BYTES / 1024
            )));
        }
        let mut buf = Vec::new();
        std::fs::File::open(path)
            .and_then(|f| f.take(MAX_AUTH_FILE_BYTES + 1).read_to_end(&mut buf))
            .map_err(|e| err(format!("berkas auth tidak dapat dibaca: {}", e.kind())))?;
        if buf.len() as u64 > MAX_AUTH_FILE_BYTES {
            return Err(err("berkas auth terlalu besar"));
        }
        let mut cfg = AuthConfig::parse(&buf)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                cfg.load_warnings.push(Warning {
                    kind: WarningKind::Auth,
                    message: format!(
                        "izin berkas auth terlalu longgar ({mode:04o}); gunakan 0600 agar kredensial tidak terbaca pengguna lain"
                    ),
                    path: None,
                    rule_id: None,
                    location: None,
                    snippet: None,
                });
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<AuthConfig, String> {
        AuthConfig::parse(s.as_bytes()).map_err(|e| e.to_string())
    }

    #[test]
    fn full_login_config() {
        let c = parse(
            r#"{"version":1,"login":{"type":"form","url":"http://h:3000/login","method":"POST",
            "body_format":"json","username_field":"user","password_field":"password",
            "username":"alice","password":"pw","extra_fields":{"remember":"true","n":1},
            "csrf":{"source":"cookie","name":"csrf"},
            "success":{"statuses":[200,302],"cookie_set":"session"}},
            "headers":{"Authorization":"Bearer abc"},"cookies":{"c":"v"}}"#,
        )
        .unwrap();
        let l = c.login.unwrap();
        assert_eq!(l.body_format, BodyFormat::Json);
        assert_eq!(l.csrf.as_ref().unwrap().send_as, CsrfSendAs::Header);
        assert_eq!(l.csrf.as_ref().unwrap().header_name, "X-CSRF-Token");
        assert_eq!(l.success.statuses, Some(vec![200, 302]));
        assert_eq!(l.extra_fields.len(), 2);
        assert_eq!(c.headers.len(), 1);
        assert_eq!(c.cookies.len(), 1);
    }

    fn login_with(extra: &str) -> String {
        format!(
            r#"{{"version":1,"login":{{"type":"form","url":"http://h/api/login","body_format":"json",
            "username_field":"u","password_field":"p","username":"alice","password":"pw",{extra}}}}}"#
        )
    }

    #[test]
    fn token_defaults_and_explicit_fields() {
        let c = parse(&login_with(
            r#""token":{"from":"json","path":"data.access_token"}"#,
        ))
        .unwrap();
        let t = c.login.unwrap().token.unwrap();
        assert_eq!(t.from, TokenFrom::Json);
        assert_eq!(t.send_as, TokenSendAs::Header);
        assert_eq!(t.header_name, "Authorization");
        assert_eq!(t.prefix, "Bearer ");
        assert_eq!(t.describe(), "header Authorization");

        let c = parse(&login_with(
            r#""token":{"from":"header","path":"X-Auth","header_name":"X-Token"}"#,
        ))
        .unwrap();
        let t = c.login.unwrap().token.unwrap();
        assert_eq!(t.prefix, "");
        assert_eq!(t.header_name, "X-Token");

        let c = parse(&login_with(
            r#""token":{"path":"a[0].t","header_name":"Authorization","prefix":""}"#,
        ))
        .unwrap();
        assert_eq!(c.login.unwrap().token.unwrap().prefix, "");

        let c = parse(&login_with(
            r#""token":{"path":"t","send_as":"cookie","cookie_name":"jwt"},
            "success":{"json_path_exists":"data.id","json_path_equals":{"path":"status","value":"ok"}}"#,
        ))
        .unwrap();
        let l = c.login.unwrap();
        assert_eq!(l.token.unwrap().describe(), "cookie jwt");
        assert_eq!(l.success.json_path_exists.as_deref(), Some("data.id"));
        assert_eq!(l.success.json_path_equals.unwrap().path, "status");
    }

    #[test]
    fn invalid_token_and_json_checks_are_rejected() {
        for extra in [
            r#""token":{"path":"a..b"}"#,
            r#""token":{"path":""}"#,
            r#""token":{"from":"cookie","path":"a"}"#,
            r#""token":{"path":"a","send_as":"body"}"#,
            r#""token":{"path":"a","header_name":"Host"}"#,
            r#""token":{"path":"a","header_name":"Cookie"}"#,
            r#""token":{"path":"a","header_name":"X Bad"}"#,
            r#""token":{"path":"a","send_as":"cookie"}"#,
            r#""token":{"path":"a","send_as":"cookie","cookie_name":"a b"}"#,
            r#""token":{"from":"header","path":"bad header"}"#,
            r#""token":{"path":"a","prefix":"x\ny"}"#,
            r#""token":{"path":"a","prefix":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            r#""token":"SECRETTOKEN""#,
            r#""success":{"json_path_exists":"a["}"#,
            r#""success":{"json_path_equals":{"path":"a"}}"#,
            r#""success":{"json_path_equals":{"path":"a","value":[1]}}"#,
            r#""success":{"json_path_equals":{"path":"a..b","value":1}}"#,
        ] {
            let e = parse(&login_with(extra)).unwrap_err();
            assert!(e.contains("login."), "{extra}: {e}");
            assert!(!e.contains("SECRET"), "{e}");
        }
    }

    #[test]
    fn errors_never_echo_values() {
        for bad in [
            r#"{"version":1,"login":{"type":"form","url":"http://h/l","username_field":"u","password_field":"p","username":"SECRETUSER","password":7}}"#,
            r#"{"version":"SECRETVER","headers":{"A":"b"}}"#,
            r#"{"version":1,"headers":{"Host":"SECRETHOST"}}"#,
            r#"{"version":1,"headers":{"A":"SECRET\u0001"}}"#,
            r#"{"version":1,"login":"SECRETLOGIN"}"#,
            r#"{"version":1,"login":{"type":"SECRETTYPE"}}"#,
            r#"{"version":1,"cookies":{"c":"SECRET;x"}}"#,
            r#"{ "SECRET": "#,
            r#"SECRETGARBAGE"#,
        ] {
            let e = parse(bad).unwrap_err();
            assert!(!e.contains("SECRET"), "{e}");
        }
    }

    #[test]
    fn requires_some_auth_and_version() {
        assert!(parse(r#"{"version":1}"#).is_err());
        assert!(parse(r#"{"headers":{"A":"b"}}"#).is_err());
        assert!(parse(r#"{"version":1,"headers":{"A":"b"}}"#).is_ok());
    }

    #[test]
    fn debug_output_is_redacted() {
        let c = parse(
            r#"{"version":1,"login":{"type":"form","url":"http://h/l","username_field":"u",
            "password_field":"p","username":"alice-user","password":"PWSECRET"},
            "headers":{"X-Api-Key":"KEYSECRET"},"cookies":{"c":"COOKIESECRET"}}"#,
        )
        .unwrap();
        let d = format!("{c:?}");
        for s in ["alice-user", "PWSECRET", "KEYSECRET", "COOKIESECRET"] {
            assert!(!d.contains(s), "{d}");
        }
    }

    #[test]
    fn file_rules() {
        let dir = tempfile::tempdir().unwrap();
        assert!(AuthConfig::from_file(dir.path()).is_err());
        let big = dir.path().join("big.json");
        std::fs::write(&big, vec![b' '; 70 * 1024]).unwrap();
        assert!(AuthConfig::from_file(&big)
            .unwrap_err()
            .to_string()
            .contains("terlalu besar"));
        let ok = dir.path().join("ok.json");
        std::fs::write(&ok, r#"{"version":1,"headers":{"A":"b"}}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(AuthConfig::from_file(&ok).unwrap().load_warnings.len(), 1);
            std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(AuthConfig::from_file(&ok).unwrap().load_warnings.is_empty());
        }
    }
}
