//! Orkestrasi pemindaian: login (opsional), satu halaman atau crawl pasif, pemeriksaan pasif per
//! halaman, dan dedupe hasil.

use std::collections::HashSet;

use sdrscan_core::{ScanOutput, Warning, WarningKind};
use url::Url;

use crate::active;
use crate::auth::LoginConfig;
use crate::checks::{self, Response};
use crate::collect::Collector;
use crate::crawl::{Frontier, MAX_DEPTH_LIMIT, MAX_PAGES_LIMIT};
use crate::html::FormInfo;
use crate::login::{self, LoginOutcome};
use crate::openapi;
use crate::session::{BodyMode, ExcludeSet, Fetched, Landing, Session};
use crate::{banner, urlutil, DastError, Options};

/// Jumlah berkas JS statis maksimum yang dipindai untuk menemukan jalur `/api/...` tambahan (lihat
/// `active::extract_js_paths`); batas tetap, bukan opsi (sengaja kecil, hanya best-effort).
const MAX_JS_FILES_SCANNED: usize = 20;

enum Step {
    Page(Box<Fetched>),
    Skip,
    Stop,
}

pub struct LoginSummary {
    pub cookies_received: usize,
    pub landing: String,
    /// Tempat token dikirim (mis. `header Authorization`) bila login menerima token; tanpa nilai.
    pub token: Option<String>,
}

pub struct ScanRun<'a> {
    opts: &'a Options,
    target: Url,
    login: Option<LoginConfig>,
    session: Session,
    collector: Collector,
    relogin_used: bool,
    seen_banners: HashSet<String>,
    banners_checked: bool,
    excluded: std::collections::BTreeSet<String>,
    first_https: Option<String>,
    /// Kandidat pemeriksaan aktif terkumpul (dedup via `active_seen`); dikosongkan saat dijalankan.
    active_candidates: Vec<active::Candidate>,
    active_seen: HashSet<(&'static str, String, String)>,
    /// URL `<script src>` satu origin yang sudah dipindai (hindari memindai berkas JS yang sama berkali-kali).
    js_scanned: HashSet<String>,
    /// Tautan hasil regex JS statis menunggu ditawarkan ke frontier crawl (lihat `offer_active_page`).
    pending_js_links: Vec<Url>,
}

fn warning(kind: WarningKind, message: String, path: Option<String>) -> Warning {
    Warning {
        kind,
        message,
        path,
        rule_id: None,
        location: None,
        snippet: None,
    }
}

impl<'a> ScanRun<'a> {
    pub fn new(target: &Url, opts: &'a Options) -> Result<ScanRun<'a>, DastError> {
        let exclude = ExcludeSet::new(&opts.exclude_paths)?;
        let login = opts.auth.as_ref().and_then(|a| a.login.clone());
        if let Some(l) = &login {
            if !urlutil::same_origin(target, &l.url) {
                return Err(DastError::Auth(
                    "URL login harus satu origin dengan target; kredensial tidak dikirim"
                        .to_string(),
                ));
            }
        }
        let session = Session::new(target, opts, opts.auth.as_ref(), exclude)?;
        let mut collector = Collector::default();
        if let Some(a) = &opts.auth {
            for w in &a.load_warnings {
                collector.add_warning(w.clone());
            }
        }
        Ok(ScanRun {
            opts,
            target: target.clone(),
            login,
            session,
            collector,
            relogin_used: false,
            seen_banners: HashSet::new(),
            banners_checked: false,
            excluded: Default::default(),
            first_https: None,
            active_candidates: Vec::new(),
            active_seen: HashSet::new(),
            js_scanned: HashSet::new(),
            pending_js_links: Vec::new(),
        })
    }

    fn offer_active(&mut self, c: active::Candidate) {
        if self.active_seen.insert(c.dedupe_key()) {
            self.active_candidates.push(c);
        }
    }

    /// Parameter query dan formulir GET/POST ditemukan pada halaman `f` (dipanggil hanya saat crawl,
    /// karena sumber (b) butuh crawler; parameter query URL target sendiri sudah ditambahkan di `run`).
    fn offer_active_page(&mut self, target: &Url, f: &Fetched) {
        for c in active::candidates_from_query(&f.url) {
            self.offer_active(c);
        }
        let Some(html) = f.html.as_deref() else {
            return;
        };
        let info = crate::html::analyze(html);
        for form in &info.forms {
            if form.has_password {
                continue; // termasuk kemungkinan form login: tidak pernah difuzz di luar alur auth
            }
            let Some(action) = resolve_form_action(target, &f.url, form) else {
                continue;
            };
            if self.session.is_login_url(&action) || self.session.exclude.is_excluded(&action) {
                continue;
            }
            if form.get {
                for c in active::candidates_from_get_form(&action, &form.fields) {
                    self.offer_active(c);
                }
            } else {
                for c in active::candidates_from_post_form(&action, &form.fields) {
                    self.offer_active(c);
                }
            }
        }
        for tag in crate::html::parse_tags(html) {
            if tag.name != "script" || tag.closing {
                continue;
            }
            let Some(src) = tag.attr("src") else { continue };
            let Some(js_url) = resolve_same_origin(target, &f.url, src) else {
                continue;
            };
            if js_url.path().to_ascii_lowercase().ends_with(".js")
                && !self.session.exclude.is_excluded(&js_url)
            {
                self.fetch_and_scan_js(target, &js_url);
            }
        }
    }

    fn fetch_and_scan_js(&mut self, target: &Url, js_url: &Url) {
        let key = js_url.as_str().to_string();
        if self.js_scanned.contains(&key) || self.js_scanned.len() >= MAX_JS_FILES_SCANNED {
            return;
        }
        self.js_scanned.insert(key);
        let Ok(hop) = self.session.exec(js_url, None, BodyMode::Always) else {
            return;
        };
        self.drain_session_warnings();
        let Some(body) = hop.body else { return };
        let text = String::from_utf8_lossy(&body);
        for raw in active::extract_js_paths(&text) {
            if let Some(u) = resolve_same_origin(target, js_url, &raw) {
                self.pending_js_links.push(u);
            }
        }
    }

    /// Spesifikasi OpenAPI/Swagger eksplisit (`--openapi-spec`) atau ditemukan lewat jalur umum
    /// (hanya pada origin target); operasinya (GET/POST/PUT/PATCH, tidak pernah DELETE) ditambahkan
    /// sebagai kandidat pemeriksaan aktif.
    fn discover_openapi(&mut self, target: &Url) {
        let mut specs = Vec::new();
        if let Some(loc) = self.opts.openapi_spec.clone() {
            match load_openapi_spec(&mut self.session, &loc, target) {
                Ok(doc) => specs.push(doc),
                Err(e) => self.collector.add_warning(warning(
                    WarningKind::Crawl,
                    format!("--openapi-spec: {e}"),
                    Some(loc),
                )),
            }
        } else {
            for path in openapi::WELL_KNOWN_PATHS {
                let Ok(url) = target.join(path) else { continue };
                if self.session.exclude.is_excluded(&url) {
                    continue;
                }
                if let Ok(hop) = self.session.exec(&url, None, BodyMode::Always) {
                    if hop.status == 200 {
                        if let Some(doc) = hop
                            .body
                            .as_deref()
                            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
                        {
                            if openapi::looks_like_spec(&doc) {
                                specs.push(doc);
                            }
                        }
                    }
                }
            }
            self.drain_session_warnings();
        }
        for doc in specs {
            for op in openapi::parse(&doc) {
                for c in active::candidates_from_operation(&self.session.target.clone(), &op) {
                    self.offer_active(c);
                }
            }
        }
    }

    fn drain_session_warnings(&mut self) {
        for w in std::mem::take(&mut self.session.warnings) {
            self.collector.add_warning(w);
        }
    }

    /// Hanya login (`--login-check`): tidak ada crawl dan tidak ada temuan.
    pub fn login_only(mut self) -> Result<LoginSummary, DastError> {
        let Some(cfg) = self.login.clone() else {
            return Err(DastError::Config(
                "--login-check memerlukan bagian 'login' pada berkas auth".to_string(),
            ));
        };
        let o = login::perform(&mut self.session, &cfg)?;
        Ok(LoginSummary {
            cookies_received: o.cookies_received,
            landing: o.landing,
            token: o.token,
        })
    }

    fn scan_fetched(&mut self, f: &Fetched) {
        let mut findings = checks::run(&f.response);
        if let Some(html) = &f.html {
            findings.extend(checks::run_html(&f.response, &f.url, html));
        }
        let banners = banner::parse_banners(&f.response);
        let keys: Vec<String> = banners
            .iter()
            .map(|b| format!("{}|{}|{}", b.header, b.product.key, b.version))
            .collect();
        if !self.banners_checked || keys.iter().any(|k| !self.seen_banners.contains(k)) {
            self.banners_checked = true;
            self.seen_banners.extend(keys);
            let (cve, warns) = banner::check(&f.response, self.opts.vuln_db.as_deref());
            findings.extend(cve);
            for w in warns {
                self.collector.add_warning(w);
            }
        }
        if f.response.https && self.first_https.is_none() {
            self.first_https = Some(f.response.url.clone());
        }
        self.collector.add_findings(findings);
        self.collector.add_page(&f.response.url);
        self.drain_session_warnings();
    }

    fn after_first_login(&mut self, o: LoginOutcome) {
        if o.login_page.status < 400 {
            self.scan_fetched(&o.login_page);
        }
        let resp = Response {
            url: o.login_page.response.url.clone(),
            https: o.login_page.response.https,
            status: 0,
            headers: Vec::new(),
            set_cookies: o.post_set_cookies,
        };
        self.collector.add_findings(checks::run_cookies(&resp));
    }

    /// Mengambil satu halaman dengan penanganan sesi kedaluwarsa (login ulang satu kali per pemindaian).
    fn get_page(&mut self, url: &Url, is_start: bool) -> Result<Step, DastError> {
        loop {
            let shown = urlutil::no_query(url);
            let landing = match self.session.fetch(url, true, BodyMode::HtmlOnly) {
                Ok(l) => l,
                Err(e) if is_start => return Err(e),
                Err(e) => {
                    self.collector.add_warning(warning(
                        WarningKind::Crawl,
                        format!("gagal mengambil halaman: {e}"),
                        Some(shown),
                    ));
                    return Ok(Step::Skip);
                }
            };
            self.drain_session_warnings();
            match landing {
                Landing::Page(f) => {
                    if f.status == 401 && self.login.is_none() {
                        self.collector.add_warning(warning(
                            WarningKind::Auth,
                            "respons 401: kredensial (header/cookie) mungkin ditolak".to_string(),
                            Some(f.response.url.clone()),
                        ));
                    }
                    return Ok(Step::Page(f));
                }
                Landing::Excluded(f, next) => {
                    self.excluded.insert(urlutil::no_query(&next));
                    return Ok(Step::Page(f));
                }
                Landing::TooManyRedirects => {
                    if is_start {
                        return Err(DastError::Request("terlalu banyak redirect".to_string()));
                    }
                    self.collector.add_warning(warning(
                        WarningKind::Crawl,
                        "terlalu banyak redirect; halaman dilewati".to_string(),
                        Some(shown),
                    ));
                    return Ok(Step::Skip);
                }
                Landing::LoginRequired(_) => {
                    let Some(cfg) = self.login.clone() else {
                        return Ok(Step::Skip);
                    };
                    if self.relogin_used {
                        self.collector.add_warning(warning(
                            WarningKind::Auth,
                            "sesi berakhir lagi setelah login ulang; pemindaian dihentikan"
                                .to_string(),
                            Some(shown),
                        ));
                        return Ok(Step::Stop);
                    }
                    self.relogin_used = true;
                    self.collector.add_warning(warning(
                        WarningKind::Auth,
                        "sesi kedaluwarsa (diarahkan ke halaman login atau 401); login ulang satu kali"
                            .to_string(),
                        Some(shown),
                    ));
                    if let Err(e) = login::perform(&mut self.session, &cfg) {
                        self.collector.add_warning(warning(
                            WarningKind::Auth,
                            format!("login ulang gagal, pemindaian dihentikan: {e}"),
                            None,
                        ));
                        return Ok(Step::Stop);
                    }
                }
            }
        }
    }

    /// Mengembalikan hasil pemindaian dan jumlah permintaan pemeriksaan aktif yang terkirim (0 bila
    /// `--active` tidak dipakai; bukan bagian dari `ScanOutput` karena hanya dipakai ringkasan teks CLI).
    pub fn run(mut self) -> Result<(ScanOutput, usize), DastError> {
        if let Some(cfg) = self.login.clone() {
            let outcome = login::perform(&mut self.session, &cfg)?;
            self.after_first_login(outcome);
        }
        let target = self.target.clone();
        if self.opts.active.enabled {
            for c in active::candidates_from_query(&target) {
                self.offer_active(c);
            }
            self.discover_openapi(&target);
        }
        if self.opts.crawl {
            self.crawl(&target)?;
        } else if let Step::Page(f) = self.get_page(&target, true)? {
            self.scan_fetched(&f);
        }
        let requests_sent = if self.opts.active.enabled {
            self.run_active_phase()
        } else {
            0
        };
        Ok((self.finish(), requests_sent))
    }

    fn run_active_phase(&mut self) -> usize {
        let candidates = std::mem::take(&mut self.active_candidates);
        let result = active::run(&mut self.session, candidates, &self.opts.active);
        self.collector.add_findings(result.findings);
        for w in result.warnings {
            self.collector.add_warning(w);
        }
        self.drain_session_warnings();
        result.requests_sent
    }

    fn crawl(&mut self, target: &Url) -> Result<(), DastError> {
        let max_depth = self.opts.max_depth.min(MAX_DEPTH_LIMIT);
        let max_pages = self.opts.max_pages.clamp(1, MAX_PAGES_LIMIT);
        let mut frontier = Frontier::new(target, max_depth);
        let mut requested = 0usize;
        let mut page_limited = 0usize;
        while let Some((url, depth)) = frontier.pop() {
            if requested >= max_pages {
                page_limited = frontier.pending() + 1;
                break;
            }
            requested += 1;
            let f = match self.get_page(&url, depth == 0)? {
                Step::Page(f) => f,
                Step::Skip => continue,
                Step::Stop => break,
            };
            if depth > 0 && matches!(f.status, 404 | 410) {
                continue;
            }
            self.scan_fetched(&f);
            if self.opts.active.enabled {
                self.offer_active_page(target, &f);
                for link in std::mem::take(&mut self.pending_js_links) {
                    frontier.offer(target, &f.url, link.as_str(), depth, &self.session.exclude);
                }
            }
            if let (true, Some(html)) = (f.is_html, f.html.as_deref()) {
                let info = crate::html::analyze(html);
                for raw in &info.links {
                    frontier.offer(target, &f.url, raw, depth, &self.session.exclude);
                }
                for form in info.forms.iter().filter(|x| x.get && !x.has_password) {
                    if let Some(a) = form.action.as_deref().filter(|a| !a.is_empty()) {
                        frontier.offer(target, &f.url, a, depth, &self.session.exclude);
                    }
                }
            }
        }
        self.excluded.extend(frontier.excluded.iter().cloned());
        if page_limited > 0 {
            self.collector.add_warning(warning(
                WarningKind::Crawl,
                format!(
                    "batas jumlah halaman ({max_pages}) tercapai; {page_limited} URL belum diambil (naikkan --max-pages, maksimum {MAX_PAGES_LIMIT})"
                ),
                None,
            ));
        }
        if frontier.depth_limited {
            self.collector.add_warning(warning(
                WarningKind::Crawl,
                format!(
                    "batas kedalaman ({max_depth}) tercapai; tautan yang lebih dalam tidak diikuti (naikkan --max-depth, maksimum {MAX_DEPTH_LIMIT})"
                ),
                None,
            ));
        }
        if frontier.variant_limited > 0 {
            self.collector.add_warning(warning(
                WarningKind::Crawl,
                format!(
                    "{} tautan dilewati karena variasi query per jalur melebihi {}",
                    frontier.variant_limited,
                    crate::crawl::MAX_QUERY_VARIANTS
                ),
                None,
            ));
        }
        Ok(())
    }

    fn finish(mut self) -> ScanOutput {
        self.drain_session_warnings();
        if !self.excluded.is_empty() {
            let sample: Vec<String> = self.excluded.iter().take(5).cloned().collect();
            self.collector.add_warning(warning(
                WarningKind::Crawl,
                format!(
                    "{} halaman dilewati karena pengecualian jalur (mis. logout, delete): {}",
                    self.excluded.len(),
                    sample.join(", ")
                ),
                None,
            ));
        }
        if let (true, Some(first)) = (self.opts.insecure_tls, self.first_https.clone()) {
            self.collector.add_warning(Warning {
                kind: WarningKind::InsecureTls,
                message: "verifikasi sertifikat TLS dimatikan (--insecure); identitas target tidak terverifikasi"
                    .to_string(),
                path: Some(first),
                rule_id: None,
                location: None,
                snippet: None,
            });
        }
        let (findings, warnings, pages) = self.collector.finish();
        ScanOutput {
            findings,
            warnings,
            files_scanned: pages,
        }
    }
}

/// URL aksi formulir (default: halaman itu sendiri bila `action` kosong/tidak ada), hanya bila
/// http/https dan satu origin dengan `target`.
fn resolve_form_action(target: &Url, base: &Url, form: &FormInfo) -> Option<Url> {
    let raw = form.action.as_deref().filter(|a| !a.is_empty());
    let u = match raw {
        Some(a) => base.join(a).ok()?,
        None => base.clone(),
    };
    (matches!(u.scheme(), "http" | "https") && urlutil::same_origin(target, &u)).then_some(u)
}

fn resolve_same_origin(target: &Url, base: &Url, raw: &str) -> Option<Url> {
    let u = base.join(raw).ok()?;
    (matches!(u.scheme(), "http" | "https") && urlutil::same_origin(target, &u)).then_some(u)
}

/// Memuat spesifikasi OpenAPI/Swagger dari berkas lokal atau URL satu origin dengan `target` (JSON saja).
fn load_openapi_spec(
    session: &mut Session,
    loc: &str,
    target: &Url,
) -> Result<serde_json::Value, String> {
    let path = std::path::Path::new(loc);
    if path.is_file() {
        let bytes =
            std::fs::read(path).map_err(|e| format!("tidak dapat membaca berkas: {}", e.kind()))?;
        return serde_json::from_slice(&bytes).map_err(|e| format!("bukan JSON valid: {e}"));
    }
    let url = Url::parse(loc).map_err(|_| {
        "bukan path berkas lokal maupun URL yang valid (hanya JSON yang didukung)".to_string()
    })?;
    if !urlutil::same_origin(target, &url) {
        return Err("URL --openapi-spec harus satu origin dengan target".to_string());
    }
    let hop = session
        .exec(&url, None, BodyMode::Always)
        .map_err(|e| e.to_string())?;
    let body = hop
        .body
        .ok_or_else(|| "respons tidak memuat isi (terlalu besar atau kosong)".to_string())?;
    serde_json::from_slice(&body).map_err(|e| format!("bukan JSON valid: {e}"))
}
