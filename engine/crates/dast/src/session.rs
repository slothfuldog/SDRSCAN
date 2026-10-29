//! Sesi HTTP DAST: satu agen berpagar jaringan, cookie jar sederhana, header tetap, pembatas laju,
//! dan pengikutan redirect satu origin. Seluruh permintaan (login, crawl, redirect) lewat `Session::exec`,
//! yang menolak URL di luar origin target, sehingga header dan cookie tidak pernah bocor ke host lain.

use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};
use sdrscan_core::{Warning, WarningKind};
use url::Url;

use crate::auth::{AuthConfig, Secret};
use crate::checks::Response;
use crate::{urlutil, DastError, Options};

/// Batas ukuran badan per respons.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Batas total badan yang dibaca dalam satu pemindaian.
pub const MAX_TOTAL_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Pola jalur yang tidak pernah diambil (tidak peka huruf besar-kecil): aksi yang dapat mengubah
/// keadaan aplikasi atau mengakhiri sesi.
pub const DEFAULT_EXCLUDE: &str = "logout|log-out|signout|sign-out|keluar|delete|remove|destroy|hapus|unsubscribe|reset|revoke|terminate|disable|deactivate|purge|drop|wipe|/api/.*/delete";

pub struct ExcludeSet {
    patterns: Vec<Regex>,
}

impl ExcludeSet {
    pub fn new(user: &[String]) -> Result<ExcludeSet, DastError> {
        let mut patterns = Vec::new();
        for p in std::iter::once(DEFAULT_EXCLUDE).chain(user.iter().map(String::as_str)) {
            let re = RegexBuilder::new(p)
                .case_insensitive(true)
                .size_limit(1 << 20)
                .build()
                .map_err(|_| {
                    DastError::Config("--exclude-path bukan regex yang valid".to_string())
                })?;
            patterns.push(re);
        }
        Ok(ExcludeSet { patterns })
    }

    /// Dicocokkan dengan jalur dan query yang sudah didekode persen.
    pub fn is_excluded(&self, url: &Url) -> bool {
        let mut target = url.path().to_string();
        if let Some(q) = url.query() {
            target.push('?');
            target.push_str(q);
        }
        let decoded = percent_encoding::percent_decode_str(&target)
            .decode_utf8_lossy()
            .into_owned();
        self.patterns
            .iter()
            .any(|re| re.is_match(&target) || re.is_match(&decoded))
    }
}

#[derive(Debug, Clone)]
struct Cookie {
    name: String,
    value: String,
    path: String,
    secure: bool,
    fixed: bool,
}

/// Cookie jar sederhana untuk satu host: menghormati Path, Domain (harus mencakup host), dan Secure.
#[derive(Debug, Default)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
}

fn default_path(url: &Url) -> String {
    let p = url.path();
    match p.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => p[..i].to_string(),
    }
}

impl CookieJar {
    fn put(&mut self, c: Cookie) {
        self.cookies
            .retain(|x| !(x.name == c.name && x.path == c.path));
        self.cookies.push(c);
    }

    pub fn add_fixed(&mut self, name: &str, value: &str) {
        self.put(Cookie {
            name: name.to_string(),
            value: value.to_string(),
            path: "/".to_string(),
            secure: false,
            fixed: true,
        });
    }

    /// Memproses satu header `Set-Cookie`; true bila cookie diterima (bukan penghapusan).
    pub fn set_from_header(&mut self, url: &Url, raw: &str) -> bool {
        let mut parts = raw.split(';');
        let Some((name, value)) = parts.next().and_then(|p| p.split_once('=')) else {
            return false;
        };
        let name = name.trim();
        if name.is_empty() {
            return false;
        }
        let mut path = None;
        let mut secure = false;
        let mut delete = false;
        for attr in parts {
            let attr = attr.trim();
            let (k, v) = attr.split_once('=').unwrap_or((attr, ""));
            let v = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "path" if v.starts_with('/') => path = Some(v.to_string()),
                "secure" => secure = true,
                "max-age" => {
                    if v.parse::<i64>().is_ok_and(|n| n <= 0) {
                        delete = true;
                    }
                }
                "expires" => {
                    if v.contains("1970") {
                        delete = true;
                    }
                }
                "domain" => {
                    let d = v.trim_start_matches('.').to_ascii_lowercase();
                    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
                    if !(host == d || host.ends_with(&format!(".{d}"))) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        let path = path.unwrap_or_else(|| default_path(url));
        if delete {
            self.cookies.retain(|c| !(c.name == name && c.path == path));
            return false;
        }
        self.put(Cookie {
            name: name.to_string(),
            value: value.trim().to_string(),
            path,
            secure,
            fixed: false,
        });
        true
    }

    /// Nilai header `Cookie` untuk `url`, atau None.
    pub fn header_for(&self, url: &Url) -> Option<String> {
        let req_path = url.path();
        let https = url.scheme() == "https";
        let mut matching: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                (https || !c.secure)
                    && (req_path == c.path
                        || (req_path.starts_with(&c.path)
                            && (c.path.ends_with('/')
                                || req_path.as_bytes().get(c.path.len()) == Some(&b'/'))))
            })
            .collect();
        if matching.is_empty() {
            return None;
        }
        matching.sort_by_key(|c| std::cmp::Reverse(c.path.len()));
        Some(
            matching
                .iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .rev()
            .find(|c| c.name == name)
            .map(|c| c.value.as_str())
    }

    /// Jumlah cookie yang diterima dari server (bukan cookie tempel).
    pub fn server_count(&self) -> usize {
        self.cookies.iter().filter(|c| !c.fixed).count()
    }

    pub fn clear_server_cookies(&mut self) {
        self.cookies.retain(|c| c.fixed);
    }
}

/// Pembatas laju: jeda minimum antar awal permintaan.
struct RateLimiter {
    interval: Duration,
    last: Option<Instant>,
}

impl RateLimiter {
    fn wait(&mut self) {
        if let Some(last) = self.last {
            let elapsed = last.elapsed();
            if elapsed < self.interval {
                std::thread::sleep(self.interval - elapsed);
            }
        }
        self.last = Some(Instant::now());
    }
}

/// Respons mentah satu hop.
pub struct Hop {
    pub url: Url,
    pub status: u16,
    /// Nama huruf kecil, tanpa `set-cookie`.
    pub headers: Vec<(String, String)>,
    pub set_cookies: Vec<String>,
    pub location: Option<String>,
    pub body: Option<Vec<u8>>,
    pub oversized: bool,
}

impl Hop {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn is_html(&self) -> bool {
        self.header("content-type").is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("text/html") || v.contains("application/xhtml")
        })
    }
}

/// Badan permintaan (login, atau pemeriksaan aktif).
pub struct PostBody {
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub extra_headers: Vec<(String, String)>,
}

/// Method HTTP yang didukung `Session::exec_method` (dipakai pemeriksaan aktif untuk endpoint API).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BodyMode {
    /// Badan tidak dibaca.
    Skip,
    /// Hanya bila Content-Type HTML.
    HtmlOnly,
    /// Selalu (dibatasi `MAX_BODY_BYTES`).
    Always,
}

/// Hasil pengambilan satu halaman setelah redirect.
pub struct Fetched {
    /// URL akhir (asli, belum disamarkan).
    pub url: Url,
    pub status: u16,
    pub response: Response,
    pub html: Option<String>,
    pub oversized: bool,
    pub is_html: bool,
}

pub enum Landing {
    Page(Box<Fetched>),
    /// Respons mengarah ke halaman login (redirect) atau 401 saat login dikonfigurasi.
    LoginRequired(Box<Fetched>),
    /// Redirect menuju URL yang dikecualikan: URL tujuan tidak diambil; respons redirect itu
    /// sendiri tetap dikembalikan untuk diperiksa.
    Excluded(Box<Fetched>, Url),
    TooManyRedirects,
}

pub struct Session {
    agent: ureq::Agent,
    pub target: Url,
    pub jar: CookieJar,
    fixed_headers: Vec<(String, String)>,
    /// Token hasil login (header: nama, nilai lengkap dengan prefiks). Rahasia: tidak pernah dicatat.
    token_header: Option<(String, Secret)>,
    /// Token hasil login yang dikirim sebagai cookie (nama, nilai).
    token_cookie: Option<(String, Secret)>,
    limiter: RateLimiter,
    pub exclude: ExcludeSet,
    pub login_url: Option<Url>,
    max_redirects: usize,
    total_body: usize,
    pub warnings: Vec<Warning>,
}

fn map_error(e: ureq::Error) -> DastError {
    let msg = e.to_string();
    fn is_cert(msg: &str) -> bool {
        let m = msg.to_ascii_lowercase();
        m.contains("invalid peer certificate")
            || m.contains("certificate")
            || m.contains("unknownissuer")
    }
    match msg.split_once("alamat jaringan privat tidak diizinkan: ") {
        Some((_, addr)) => DastError::AddressNotAllowed(addr.to_string()),
        None if is_cert(&msg) => DastError::Request(format!(
            "{msg}. Sertifikat HTTPS target tidak dipercaya. Untuk CA internal, berikan \
             berkas CA dengan --ca-cert <berkas.pem> atau pasang CA di penyimpanan \
             sertifikat sistem; --insecure melewati verifikasi (tidak aman, hanya untuk percobaan)"
        )),
        None => DastError::Request(msg),
    }
}

impl Session {
    pub fn new(
        target: &Url,
        opts: &Options,
        auth: Option<&AuthConfig>,
        exclude: ExcludeSet,
    ) -> Result<Session, DastError> {
        let agent = crate::build_agent(opts, 0, false)?;
        let mut jar = CookieJar::default();
        let mut fixed_headers = Vec::new();
        if let Some(a) = auth {
            for (k, v) in &a.headers {
                fixed_headers.push((k.clone(), v.expose().to_string()));
            }
            for (k, v) in &a.cookies {
                jar.add_fixed(k, v.expose());
            }
        }
        let rps = opts.max_rps.clamp(1, 1000) as u64;
        Ok(Session {
            agent,
            target: target.clone(),
            jar,
            fixed_headers,
            token_header: None,
            token_cookie: None,
            limiter: RateLimiter {
                interval: Duration::from_millis(1000 / rps),
                last: None,
            },
            exclude,
            login_url: auth.and_then(|a| a.login.as_ref().map(|l| l.url.clone())),
            max_redirects: opts.max_redirects,
            total_body: 0,
            warnings: Vec::new(),
        })
    }

    /// Menghapus token login (dipanggil sebelum login ulang agar token lama tidak ikut terkirim).
    pub fn clear_token(&mut self) {
        self.token_header = None;
        self.token_cookie = None;
    }

    /// Menyimpan token yang dikirim di setiap permintaan berikutnya (hanya ke origin target,
    /// karena semua permintaan lewat `exec`).
    pub fn set_token_header(&mut self, name: &str, value: Secret) {
        self.token_header = Some((name.to_string(), value));
        self.token_cookie = None;
    }

    pub fn set_token_cookie(&mut self, name: &str, value: Secret) {
        self.token_cookie = Some((name.to_string(), value));
        self.token_header = None;
    }

    /// Header permintaan: header tetap (kecuali yang ditimpa token), token, lalu `extra`.
    fn request_headers(&self, extra: &[(String, String)]) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .fixed_headers
            .iter()
            .filter(|(k, _)| {
                !self
                    .token_header
                    .as_ref()
                    .is_some_and(|(n, _)| n.eq_ignore_ascii_case(k))
            })
            .cloned()
            .collect();
        if let Some((n, v)) = &self.token_header {
            out.push((n.clone(), v.expose().to_string()));
        }
        out.extend(extra.iter().cloned());
        out
    }

    fn cookie_header(&self, url: &Url) -> Option<String> {
        let jar = self.jar.header_for(url);
        match (&self.token_cookie, jar) {
            (Some((n, v)), Some(j)) => Some(format!("{j}; {n}={}", v.expose())),
            (Some((n, v)), None) => Some(format!("{n}={}", v.expose())),
            (None, j) => j,
        }
    }

    pub fn is_login_url(&self, u: &Url) -> bool {
        self.login_url
            .as_ref()
            .is_some_and(|l| urlutil::same_origin(l, u) && l.path() == u.path())
    }

    fn warn(&mut self, message: String, path: Option<String>) {
        self.warnings.push(Warning {
            kind: WarningKind::Crawl,
            message,
            path,
            rule_id: None,
            location: None,
            snippet: None,
        });
    }

    /// Satu permintaan GET atau POST. `post`: (Content-Type, badan, header tambahan); dipakai alur login
    /// dan pemeriksaan aktif. Setara `exec_method(Post bila `post` ada else Get, ...)`.
    pub fn exec(
        &mut self,
        url: &Url,
        post: Option<PostBody>,
        mode: BodyMode,
    ) -> Result<Hop, DastError> {
        let method = if post.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        };
        self.exec_method(method, url, post, mode)
    }

    /// Satu permintaan dengan method eksplisit (GET/POST/PUT/PATCH); dipakai pemeriksaan aktif untuk
    /// endpoint API (OpenAPI/Swagger). DELETE sengaja tidak didukung (tidak pernah dipanggil).
    pub fn exec_method(
        &mut self,
        method: HttpMethod,
        url: &Url,
        post: Option<PostBody>,
        mode: BodyMode,
    ) -> Result<Hop, DastError> {
        if !urlutil::same_origin(&self.target, url) {
            return Err(DastError::Request(
                "permintaan ke luar origin target ditolak".to_string(),
            ));
        }
        self.limiter.wait();
        tracing::debug!("{} {}", method.as_str(), urlutil::no_query(url));
        let cookie = self.cookie_header(url);
        let result = match (method, post) {
            (HttpMethod::Get, _) => {
                let mut req = self.agent.get(url.as_str());
                for (k, v) in &self.request_headers(&[]) {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(c) = &cookie {
                    req = req.header("cookie", c.as_str());
                }
                req.call()
            }
            (
                m,
                Some(PostBody {
                    content_type,
                    body,
                    extra_headers: extra,
                }),
            ) => {
                let mut req = match m {
                    HttpMethod::Post => self.agent.post(url.as_str()),
                    HttpMethod::Put => self.agent.put(url.as_str()),
                    HttpMethod::Patch => self.agent.patch(url.as_str()),
                    HttpMethod::Get => unreachable!("ditangani di lengan pertama"),
                }
                .content_type(content_type);
                for (k, v) in &self.request_headers(&extra) {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(c) = &cookie {
                    req = req.header("cookie", c.as_str());
                }
                req.send(body)
            }
            (m, None) => {
                let mut req = match m {
                    HttpMethod::Post => self.agent.post(url.as_str()),
                    HttpMethod::Put => self.agent.put(url.as_str()),
                    HttpMethod::Patch => self.agent.patch(url.as_str()),
                    HttpMethod::Get => unreachable!("ditangani di lengan pertama"),
                };
                for (k, v) in &self.request_headers(&[]) {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(c) = &cookie {
                    req = req.header("cookie", c.as_str());
                }
                req.send(&[] as &[u8])
            }
        };
        let mut resp = result.map_err(map_error)?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter(|(k, _)| k.as_str() != "set-cookie")
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        let set_cookies: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        for sc in &set_cookies {
            self.jar.set_from_header(url, sc);
        }
        let mut hop = Hop {
            url: url.clone(),
            status,
            headers,
            set_cookies,
            location,
            body: None,
            oversized: false,
        };
        let want = match mode {
            BodyMode::Skip => false,
            BodyMode::HtmlOnly => hop.is_html(),
            BodyMode::Always => true,
        };
        if want {
            let declared = hop
                .header("content-length")
                .and_then(|v| v.trim().parse::<usize>().ok());
            if declared.is_some_and(|n| n > MAX_BODY_BYTES)
                || self.total_body >= MAX_TOTAL_BODY_BYTES
            {
                hop.oversized = true;
            } else {
                use std::io::Read;
                let mut buf = Vec::new();
                let read = resp
                    .body_mut()
                    .as_reader()
                    .take(MAX_BODY_BYTES as u64 + 1)
                    .read_to_end(&mut buf);
                match read {
                    Ok(_) if buf.len() <= MAX_BODY_BYTES => {
                        self.total_body += buf.len();
                        hop.body = Some(buf);
                    }
                    Ok(_) => hop.oversized = true,
                    Err(e) => {
                        return Err(DastError::Request(format!("membaca badan respons: {e}")));
                    }
                }
            }
        }
        Ok(hop)
    }

    /// Mengambil `start` dan mengikuti redirect satu origin (hanya GET). `detect_login`: respons
    /// yang mengarah ke URL login atau berstatus 401 dilaporkan sebagai `LoginRequired`.
    pub fn fetch(
        &mut self,
        start: &Url,
        detect_login: bool,
        mode: BodyMode,
    ) -> Result<Landing, DastError> {
        let detect = detect_login && self.login_url.is_some() && !self.is_login_url(start);
        let mut current = start.clone();
        let mut cookies: Vec<String> = Vec::new();
        for _ in 0..=self.max_redirects {
            let hop = self.exec(&current, None, mode)?;
            cookies.extend(hop.set_cookies.iter().cloned());
            if (300..400).contains(&hop.status) {
                let next = hop
                    .location
                    .as_deref()
                    .and_then(|loc| current.join(loc).ok())
                    .filter(|n| urlutil::same_origin(&self.target, n));
                if let Some(next) = next {
                    if detect && self.is_login_url(&next) {
                        return Ok(Landing::LoginRequired(Box::new(self.build(hop, cookies))));
                    }
                    if self.exclude.is_excluded(&next) {
                        return Ok(Landing::Excluded(Box::new(self.build(hop, cookies)), next));
                    }
                    current = next;
                    continue;
                }
            }
            let login_required = detect && hop.status == 401;
            let fetched = Box::new(self.build(hop, cookies));
            return Ok(if login_required {
                Landing::LoginRequired(fetched)
            } else {
                Landing::Page(fetched)
            });
        }
        Ok(Landing::TooManyRedirects)
    }

    fn build(&mut self, hop: Hop, cookies: Vec<String>) -> Fetched {
        let is_html = hop.is_html();
        let shown = urlutil::redact_url(&hop.url);
        if hop.oversized {
            self.warn(
                format!(
                    "respons terlalu besar (lebih dari {} MiB); badan tidak dianalisis",
                    MAX_BODY_BYTES / (1024 * 1024)
                ),
                Some(shown.clone()),
            );
        }
        let html = hop
            .body
            .as_deref()
            .filter(|_| is_html)
            .map(|b| String::from_utf8_lossy(b).into_owned());
        Fetched {
            status: hop.status,
            response: Response {
                url: shown,
                https: hop.url.scheme() == "https",
                status: hop.status,
                headers: hop.headers,
                set_cookies: cookies,
            },
            url: hop.url,
            html,
            oversized: hop.oversized,
            is_html,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn cookie_jar_path_secure_domain_and_delete() {
        let mut jar = CookieJar::default();
        let base = u("http://h/app/login");
        assert!(jar.set_from_header(&base, "a=1"));
        assert!(jar.set_from_header(&base, "b=2; Path=/; Secure"));
        assert!(jar.set_from_header(&base, "c=3; Path=/admin"));
        assert!(!jar.set_from_header(&base, "d=4; Domain=other.test"));
        assert!(jar.set_from_header(&base, "e=5; Domain=h"));
        assert_eq!(jar.header_for(&u("http://h/app/x")).unwrap(), "a=1; e=5");
        assert_eq!(jar.header_for(&u("https://h/admin/y")).unwrap(), "c=3; b=2");
        // /admin tidak boleh cocok dengan /administrator
        assert!(!jar
            .header_for(&u("http://h/administrator"))
            .unwrap_or_default()
            .contains("c=3"));
        assert!(!jar.set_from_header(&base, "a=; Max-Age=0"));
        assert!(jar.get("a").is_none());
        assert_eq!(jar.server_count(), 3);
    }

    #[test]
    fn fixed_cookies_survive_clear() {
        let mut jar = CookieJar::default();
        jar.add_fixed("f", "v");
        jar.set_from_header(&u("http://h/"), "s=1");
        jar.clear_server_cookies();
        assert_eq!(jar.header_for(&u("http://h/")).unwrap(), "f=v");
    }

    #[test]
    fn default_exclusions() {
        let ex = ExcludeSet::new(&["^/private".to_string()]).unwrap();
        for p in [
            "/logout",
            "/Account/LogOut",
            "/delete?id=1",
            "/x?action=remove",
            "/api/users/5/delete",
            "/de%6cete",
            "/private/x",
            "/keluar",
            "/reset-password",
        ] {
            assert!(ex.is_excluded(&u(&format!("http://h{p}"))), "{p}");
        }
        for p in ["/", "/dashboard", "/page1?x=1", "/deep/1"] {
            assert!(!ex.is_excluded(&u(&format!("http://h{p}"))), "{p}");
        }
        assert!(ExcludeSet::new(&["(".to_string()]).is_err());
    }
}
