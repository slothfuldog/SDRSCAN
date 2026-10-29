//! Pemeriksaan aktif opsional (`--active`, MATI secara default): mengirim payload uji ke parameter
//! yang ditemukan (query GET, formulir GET/POST hasil crawl, dan endpoint API dari OpenAPI/Swagger)
//! untuk mendeteksi SQL injection (error-based, boolean-blind, time-based opsional), XSS reflected,
//! open redirect, dan CRLF/header injection. Lingkup, batas, dan payload sengaja dibatasi kecil (lihat
//! README bagian "Active scanning"). Tidak ada command injection/SSTI/XXE/payload destruktif, dan
//! method DELETE tidak pernah dipanggil.

use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS, NON_ALPHANUMERIC};
use regex::Regex;
use sdrscan_core::{Finding, Location, Severity, Template, TemplateType, Warning, WarningKind};
use serde_json::Value;
use url::Url;

use crate::html;
use crate::openapi;
use crate::session::{Hop, HttpMethod, PostBody, Session};
use crate::urlutil;

/// Batas keras (tidak dapat dilewati opsi pengguna).
pub const MAX_PARAMS_LIMIT: usize = 100;
pub const MAX_REQUESTS_LIMIT: usize = 2000;
pub const MAX_TIMEOUT_SECS: u64 = 3600;
/// Jumlah parameter maksimum yang diuji time-based blind SQLi per pemindaian (bukan per parameter).
const MAX_TIMING_PARAMS: usize = 3;

#[derive(Debug, Clone)]
pub struct ActiveOptions {
    pub enabled: bool,
    /// Opt-in ganda: time-based blind SQLi (payload SLEEP), hanya berlaku bila `enabled` juga true.
    pub timing: bool,
    pub max_params: usize,
    pub max_requests: usize,
    pub timeout: Duration,
}

impl Default for ActiveOptions {
    fn default() -> Self {
        ActiveOptions {
            enabled: false,
            timing: false,
            max_params: 30,
            max_requests: 300,
            timeout: Duration::from_secs(600),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Kandidat uji
// ---------------------------------------------------------------------------------------------

/// Basis permintaan satu operasi API (OpenAPI/Swagger): method, jalur bertemplat, dan nilai dasar
/// seluruh parameter path/query (termasuk yang sedang diuji; diganti saat membangun permintaan).
#[derive(Debug, Clone)]
pub struct ApiBase {
    pub method: openapi::ApiMethod,
    pub path_template: String,
    pub origin: Url,
    pub path_values: Vec<(String, String)>,
    pub query_values: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub enum Candidate {
    /// Parameter query GET (URL target awal, atau URL halaman/formulir GET hasil crawl).
    Query { url: Url, param: String },
    /// Field formulir HTML `method="post"` hasil crawl (hanya field yang ada di `fields` boleh diuji;
    /// `injectable` false untuk field CSRF-like atau checkbox/radio: tetap terkirim apa adanya).
    FormPost {
        action: Url,
        fields: Vec<(String, String)>,
        param: String,
        injectable: bool,
    },
    /// Parameter path atau query pada operasi API (method GET/POST/PUT/PATCH; DELETE tidak pernah dibuat).
    ApiParam {
        base: ApiBase,
        body: Option<Vec<(String, Value)>>,
        param: String,
        in_path: bool,
    },
    /// Properti string pada badan JSON operasi API.
    ApiBodyProp {
        base: ApiBase,
        base_fields: Vec<(String, Value)>,
        param: String,
    },
}

impl Candidate {
    pub fn param_name(&self) -> &str {
        match self {
            Candidate::Query { param, .. }
            | Candidate::FormPost { param, .. }
            | Candidate::ApiParam { param, .. }
            | Candidate::ApiBodyProp { param, .. } => param,
        }
    }

    /// Kunci dedupe lintas-sumber: (jenis, url/jalur tanpa query, nama parameter).
    pub fn dedupe_key(&self) -> (&'static str, String, String) {
        match self {
            Candidate::Query { url, param } => ("query", urlutil::no_query(url), param.clone()),
            Candidate::FormPost { action, param, .. } => {
                ("form-post", urlutil::no_query(action), param.clone())
            }
            Candidate::ApiParam {
                base,
                param,
                in_path,
                ..
            } => (
                if *in_path { "api-path" } else { "api-query" },
                format!("{} {}", base.method.as_str(), base.path_template),
                param.clone(),
            ),
            Candidate::ApiBodyProp { base, param, .. } => (
                "api-body",
                format!("{} {}", base.method.as_str(), base.path_template),
                param.clone(),
            ),
        }
    }
}

fn http_method(c: &Candidate) -> HttpMethod {
    match c {
        Candidate::Query { .. } => HttpMethod::Get,
        Candidate::FormPost { .. } => HttpMethod::Post,
        Candidate::ApiParam { base, .. } | Candidate::ApiBodyProp { base, .. } => {
            match base.method {
                openapi::ApiMethod::Get => HttpMethod::Get,
                openapi::ApiMethod::Post => HttpMethod::Post,
                openapi::ApiMethod::Put => HttpMethod::Put,
                openapi::ApiMethod::Patch => HttpMethod::Patch,
            }
        }
    }
}

/// Jenis kandidat yang juga mendapat XSS reflected, open redirect, dan CRLF/header injection
/// (selain SQLi, yang berlaku untuk semua jenis kandidat): URL GET biasa dan parameter path/query
/// endpoint API. Field formulir POST dan properti badan JSON TIDAK mendapat ketiga pemeriksaan ini.
fn gets_extra_checks(c: &Candidate) -> bool {
    matches!(c, Candidate::Query { .. } | Candidate::ApiParam { .. })
}

fn is_csrf_like(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["csrf", "token", "_token", "authenticity", "nonce"]
        .iter()
        .any(|p| n.contains(p))
}

fn default_form_value(f: &html::FormField) -> String {
    if !f.value.is_empty() {
        return f.value.clone();
    }
    match f.ty.as_str() {
        "email" => "test@example.com".to_string(),
        "number" | "range" => "1".to_string(),
        "url" => "https://example.test".to_string(),
        _ => "test".to_string(),
    }
}

/// Parameter query pada `url` (target awal, atau halaman hasil crawl).
pub fn candidates_from_query(url: &Url) -> Vec<Candidate> {
    let mut seen = HashSet::new();
    url.query_pairs()
        .filter_map(|(k, _)| {
            let name = k.into_owned();
            seen.insert(name.clone()).then(|| Candidate::Query {
                url: url.clone(),
                param: name,
            })
        })
        .collect()
}

/// Formulir GET hasil crawl: query dibangun dari seluruh field (nilai bawaan/placeholder/generik).
pub fn candidates_from_get_form(action: &Url, fields: &[html::FormField]) -> Vec<Candidate> {
    let pairs: Vec<(String, String)> = fields
        .iter()
        .map(|f| (f.name.clone(), default_form_value(f)))
        .collect();
    let base_url = build_url(action, &pairs);
    let mut seen = HashSet::new();
    pairs
        .into_iter()
        .filter_map(|(k, _)| {
            seen.insert(k.clone()).then(|| Candidate::Query {
                url: base_url.clone(),
                param: k,
            })
        })
        .collect()
}

/// Formulir POST hasil crawl. Field CSRF-like dan checkbox/radio tidak pernah diinjeksi, tetapi tetap
/// menjadi kandidat (dihitung ke `--active-max-params`) agar anggaran konsisten.
pub fn candidates_from_post_form(action: &Url, fields: &[html::FormField]) -> Vec<Candidate> {
    let base: Vec<(String, String)> = fields
        .iter()
        .map(|f| (f.name.clone(), default_form_value(f)))
        .collect();
    let mut seen = HashSet::new();
    fields
        .iter()
        .filter(|f| seen.insert(f.name.clone()))
        .map(|f| Candidate::FormPost {
            action: action.clone(),
            fields: base.clone(),
            param: f.name.clone(),
            injectable: !f.fixed && !is_csrf_like(&f.name),
        })
        .collect()
}

fn json_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => "1".to_string(),
    }
}

/// Kandidat dari satu operasi API (OpenAPI/Swagger): parameter path/query, dan properti string badan JSON.
pub fn candidates_from_operation(origin: &Url, op: &openapi::Operation) -> Vec<Candidate> {
    let path_values: Vec<(String, String)> = op
        .path_params
        .iter()
        .map(|p| (p.name.clone(), json_to_string(&p.value())))
        .collect();
    let query_values: Vec<(String, String)> = op
        .query_params
        .iter()
        .map(|p| (p.name.clone(), json_to_string(&p.value())))
        .collect();
    let body: Option<Vec<(String, Value)>> = op
        .body
        .as_ref()
        .map(|props| props.iter().map(|p| (p.name.clone(), p.value())).collect());
    let base = ApiBase {
        method: op.method,
        path_template: op.path.clone(),
        origin: origin.clone(),
        path_values,
        query_values,
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for p in &op.path_params {
        if seen.insert(("p", p.name.clone())) {
            out.push(Candidate::ApiParam {
                base: base.clone(),
                body: body.clone(),
                param: p.name.clone(),
                in_path: true,
            });
        }
    }
    for p in &op.query_params {
        if seen.insert(("q", p.name.clone())) {
            out.push(Candidate::ApiParam {
                base: base.clone(),
                body: body.clone(),
                param: p.name.clone(),
                in_path: false,
            });
        }
    }
    if let (Some(fields), Some(props)) = (&body, &op.body) {
        for prop in props {
            if prop.ty == openapi::PropType::String {
                out.push(Candidate::ApiBodyProp {
                    base: base.clone(),
                    base_fields: fields.clone(),
                    param: prop.name.clone(),
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Konstruksi permintaan (query/body) dengan payload; '%' sengaja tidak di-escape ulang agar payload
// CRLF (`%0d%0a`) yang sudah berupa escape tidak di-escape ganda.
// ---------------------------------------------------------------------------------------------

const QUERY_VALUE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'&')
    .add(b'=')
    .add(b'<')
    .add(b'>');

fn enc(v: &str) -> String {
    utf8_percent_encode(v, QUERY_VALUE).to_string()
}

fn enc_path_segment(v: &str) -> String {
    utf8_percent_encode(v, NON_ALPHANUMERIC).to_string()
}

fn base_pairs(url: &Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn build_url(base: &Url, pairs: &[(String, String)]) -> Url {
    let mut u = base.clone();
    if pairs.is_empty() {
        u.set_query(None);
        return u;
    }
    let qs: String = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    u.set_query(Some(&qs));
    u
}

fn with_value(base: &Url, param: &str, new_value: &str) -> Url {
    let pairs: Vec<(String, String)> = base_pairs(base)
        .into_iter()
        .map(|(k, v)| {
            if k == param {
                (k, new_value.to_string())
            } else {
                (k, v)
            }
        })
        .collect();
    build_url(base, &pairs)
}

fn build_api_url(
    base: &ApiBase,
    override_param: Option<&str>,
    override_value: Option<&str>,
    in_path: bool,
) -> Option<Url> {
    let mut path = base.path_template.clone();
    for (k, v) in &base.path_values {
        let val: &str = if in_path && override_param == Some(k.as_str()) {
            override_value.unwrap_or(v.as_str())
        } else {
            v.as_str()
        };
        path = path.replace(&format!("{{{k}}}"), &enc_path_segment(val));
    }
    let path = if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    };
    let mut url = base.origin.join(&path).ok()?;
    if !base.query_values.is_empty() {
        let pairs: Vec<(String, String)> = base
            .query_values
            .iter()
            .map(|(k, v)| {
                if !in_path && override_param == Some(k.as_str()) {
                    (k.clone(), override_value.unwrap_or(v.as_str()).to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();
        let qs: String = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&");
        url.set_query(Some(&qs));
    }
    Some(url)
}

fn location_url(c: &Candidate) -> Url {
    match c {
        Candidate::Query { url, .. } => url.clone(),
        Candidate::FormPost { action, .. } => action.clone(),
        Candidate::ApiParam { base, .. } | Candidate::ApiBodyProp { base, .. } => {
            build_api_url(base, None, None, false).unwrap_or_else(|| base.origin.clone())
        }
    }
}

fn base_value(c: &Candidate) -> String {
    match c {
        Candidate::Query { url, param } => url
            .query_pairs()
            .find(|(k, _)| k == param)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default(),
        Candidate::FormPost { fields, param, .. } => fields
            .iter()
            .find(|(k, _)| k == param)
            .map(|(_, v)| v.clone())
            .unwrap_or_default(),
        Candidate::ApiParam {
            base,
            param,
            in_path,
            ..
        } => {
            let values = if *in_path {
                &base.path_values
            } else {
                &base.query_values
            };
            values
                .iter()
                .find(|(k, _)| k == param)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        }
        Candidate::ApiBodyProp {
            base_fields, param, ..
        } => base_fields
            .iter()
            .find(|(k, _)| k == param)
            .and_then(|(_, v)| v.as_str())
            .unwrap_or_default()
            .to_string(),
    }
}

/// Membangun (url, badan) untuk `c` dengan nilai parameter diganti `override_value` (`None` = nilai dasar).
fn build_request(c: &Candidate, override_value: Option<&str>) -> (Url, Option<PostBody>) {
    match c {
        Candidate::Query { url, param } => {
            let u = match override_value {
                Some(v) => with_value(url, param, v),
                None => url.clone(),
            };
            (u, None)
        }
        Candidate::FormPost {
            action,
            fields,
            param,
            ..
        } => {
            let pairs: Vec<(String, String)> = fields
                .iter()
                .map(|(k, v)| {
                    if k == param {
                        (k.clone(), override_value.unwrap_or(v).to_string())
                    } else {
                        (k.clone(), v.clone())
                    }
                })
                .collect();
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish()
                .into_bytes();
            (
                action.clone(),
                Some(PostBody {
                    content_type: "application/x-www-form-urlencoded",
                    body,
                    extra_headers: Vec::new(),
                }),
            )
        }
        Candidate::ApiParam {
            base,
            body,
            param,
            in_path,
        } => {
            let url = build_api_url(base, Some(param), override_value, *in_path)
                .unwrap_or_else(|| base.origin.clone());
            let post = body.as_ref().map(|fields| {
                let map: serde_json::Map<String, Value> = fields.iter().cloned().collect();
                PostBody {
                    content_type: "application/json",
                    body: serde_json::to_vec(&Value::Object(map)).unwrap_or_default(),
                    extra_headers: Vec::new(),
                }
            });
            (url, post)
        }
        Candidate::ApiBodyProp {
            base,
            base_fields,
            param,
        } => {
            let url = build_api_url(base, None, None, false).unwrap_or_else(|| base.origin.clone());
            let mut map = serde_json::Map::new();
            for (k, v) in base_fields {
                let val = if k == param {
                    match override_value {
                        Some(ov) => Value::String(ov.to_string()),
                        None => v.clone(),
                    }
                } else {
                    v.clone()
                };
                map.insert(k.clone(), val);
            }
            let body = serde_json::to_vec(&Value::Object(map)).unwrap_or_default();
            (
                url,
                Some(PostBody {
                    content_type: "application/json",
                    body,
                    extra_headers: Vec::new(),
                }),
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

fn short(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

// ---------------------------------------------------------------------------------------------
// Deteksi: SQLi error-based (tanda galat basis data), boolean-blind (perbandingan panjang body),
// XSS reflected (marker unik tidak ter-escape), open redirect (Location persis ke domain uji
// `.invalid`), CRLF/header injection (header respons tambahan).
// ---------------------------------------------------------------------------------------------

fn sql_error_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let raw = [
            r"(?i)you have an error in your sql syntax",
            r"(?i)warning:\s*mysqli?_",
            r"(?i)unknown column '",
            r"(?i)sqlstate\[",
            r"(?i)unterminated quoted string",
            r"(?i)invalid input syntax for",
            r"(?i)ora-\d{5}",
            r"(?i)quoted string not properly terminated",
            r"(?i)unclosed quotation mark after the character string",
            r#"(?i)near "[^"]*": syntax error"#,
            r"(?i)sqlite(?:3)?\.(?:operationalerror|error)",
            r"(?i)microsoft ole db provider for sql server",
            r"(?i)pg_query\(\)\s*:",
        ];
        raw.iter()
            .map(|p| Regex::new(p).expect("regex galat SQL valid"))
            .collect()
    })
}

/// Kutipan singkat tanda galat basis data pada `body`, atau `None` bila tidak ada pola yang cocok.
fn sql_error_match(body: &str) -> Option<String> {
    sql_error_patterns()
        .iter()
        .find_map(|re| re.find(body).map(|m| short(m.as_str(), 120)))
}

/// Heuristik SQLi boolean-blind: body(true) sepanjang/semirip body dasar, body(false) jauh lebih
/// pendek dari KEDUANYA (meniru pola umum: kondisi salah -> halaman "tidak ditemukan" yang jauh lebih
/// pendek daripada halaman dengan isi, baik satu baris (dasar) maupun banyak baris (true)).
fn boolean_blind_signal(base_len: usize, true_len: usize, false_len: usize) -> bool {
    if base_len == 0 {
        return false;
    }
    let base = base_len as f64;
    let similar_to_base = true_len as f64 >= base * 0.8;
    let false_is_much_smaller =
        (false_len as f64) < base * 0.5 && (false_len as f64) < (true_len as f64 * 0.5);
    similar_to_base && false_is_much_smaller
}

const XSS_PREFIX: &str = "sdrscanxss";

fn random_token() -> String {
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    format!("{:?}", std::thread::current().id()).hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn xss_reflected_unescaped(body: &str, marker: &str) -> bool {
    body.contains(&format!("<{marker}"))
}

const REDIRECT_TEST_HOST: &str = "sdrscan-redirect-check.invalid";

fn looks_like_redirect_param(name: &str, value: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let name_hit = [
        "redirect", "return", "next", "continue", "url", "target", "dest", "callback",
    ]
    .iter()
    .any(|p| n.contains(p));
    let value_hit = value.starts_with('/')
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("//");
    name_hit || value_hit
}

fn redirect_confirmed(location: &str) -> bool {
    Url::parse(location)
        .ok()
        .is_some_and(|u| u.scheme() == "https" && u.host_str() == Some(REDIRECT_TEST_HOST))
}

fn header_injection_payload(orig: &str) -> String {
    format!("{orig}x%0d%0aX-Sdrscan-Test:%201")
}

// ---------------------------------------------------------------------------------------------
// Aturan dan temuan
// ---------------------------------------------------------------------------------------------

struct Rule {
    id: &'static str,
    severity: Severity,
    cwe: &'static str,
    tags: &'static [&'static str],
    message: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        id: "dast-active-sqli-error-based",
        severity: Severity::Critical,
        cwe: "CWE-89",
        tags: &["dast", "active", "sqli", "owasp-a03"],
        message: "Payload SQL menimbulkan pesan galat basis data pada respons (SQL injection berbasis galat).",
    },
    Rule {
        id: "dast-active-sqli-boolean-blind",
        severity: Severity::High,
        cwe: "CWE-89",
        tags: &["dast", "active", "sqli", "owasp-a03"],
        message: "Perbedaan respons antara kondisi SQL benar dan salah mengindikasikan SQL injection buta berbasis boolean.",
    },
    Rule {
        id: "dast-active-sqli-time-based",
        severity: Severity::High,
        cwe: "CWE-89",
        tags: &["dast", "active", "sqli", "timing", "owasp-a03"],
        message: "Payload SQL dengan jeda waktu menunda respons secara konsisten (indikasi SQL injection buta berbasis waktu; keyakinan rendah).",
    },
    Rule {
        id: "dast-active-xss-reflected",
        severity: Severity::High,
        cwe: "CWE-79",
        tags: &["dast", "active", "xss", "owasp-a03"],
        message: "Payload uji dipantulkan tanpa escaping pada respons HTML (indikasi XSS reflected).",
    },
    Rule {
        id: "dast-active-open-redirect-confirmed",
        severity: Severity::Medium,
        cwe: "CWE-601",
        tags: &["dast", "active", "redirect"],
        message: "Parameter mengarahkan redirect persis ke domain uji eksternal (open redirect dikonfirmasi aktif).",
    },
    Rule {
        id: "dast-active-header-injection",
        severity: Severity::Medium,
        cwe: "CWE-113",
        tags: &["dast", "active", "header-injection", "owasp-a03"],
        message: "Payload CRLF pada nilai parameter menghasilkan header respons tambahan (CRLF/header injection).",
    },
];

/// Aturan bawaan aktif, digabung dengan `checks::builtin_rules()` untuk SARIF.
pub fn builtin_rules() -> Vec<Template> {
    RULES
        .iter()
        .map(|r| Template {
            id: r.id.to_string(),
            kind: TemplateType::Http,
            languages: Vec::new(),
            severity: r.severity,
            cwe: vec![r.cwe.to_string()],
            tags: r.tags.iter().map(|t| t.to_string()).collect(),
            message: r.message.to_string(),
            query: None,
            taint: None,
            source: Default::default(),
        })
        .collect()
}

fn finding(id: &str, url: &Url, evidence: String) -> Finding {
    let rule = RULES
        .iter()
        .find(|r| r.id == id)
        .expect("id aturan harus terdaftar");
    Finding {
        rule_id: rule.id.to_string(),
        severity: rule.severity,
        message: rule.message.to_string(),
        location: Location::url(&urlutil::no_query(url)),
        snippet: evidence,
        vulnerability: None,
    }
}

fn warn(message: String) -> Warning {
    Warning {
        kind: WarningKind::Crawl,
        message,
        path: None,
        rule_id: None,
        location: None,
        snippet: None,
    }
}

// ---------------------------------------------------------------------------------------------
// Anggaran dan eksekusi
// ---------------------------------------------------------------------------------------------

struct Budget {
    max_requests: usize,
    sent: usize,
    deadline: Instant,
    exhausted: bool,
    timed_out: bool,
}

impl Budget {
    fn allow(&mut self) -> bool {
        if self.sent >= self.max_requests {
            self.exhausted = true;
            return false;
        }
        if Instant::now() >= self.deadline {
            self.timed_out = true;
            return false;
        }
        true
    }

    fn record(&mut self) {
        self.sent += 1;
    }
}

enum Probe {
    Resp(Box<Hop>, Duration),
    OutOfBudget,
    Failed,
}

fn probe(
    session: &mut Session,
    method: HttpMethod,
    url: &Url,
    post: Option<PostBody>,
    budget: &mut Budget,
) -> Probe {
    if !budget.allow() {
        return Probe::OutOfBudget;
    }
    let start = Instant::now();
    let r = session.exec_method(method, url, post, crate::session::BodyMode::Always);
    budget.record();
    match r {
        Ok(hop) => Probe::Resp(Box::new(hop), start.elapsed()),
        Err(_) => Probe::Failed,
    }
}

pub struct ActiveResult {
    pub findings: Vec<Finding>,
    pub requests_sent: usize,
    pub warnings: Vec<Warning>,
}

fn test_candidate(
    session: &mut Session,
    budget: &mut Budget,
    marker: &str,
    timing_remaining: &mut usize,
    opts: &ActiveOptions,
    c: &Candidate,
) -> Result<Vec<Finding>, ()> {
    let mut out = Vec::new();
    if let Candidate::FormPost {
        injectable: false, ..
    } = c
    {
        return Ok(out);
    }
    let method = http_method(c);
    let method_label = method.as_str();
    let loc_url = location_url(c);
    let loc_shown = urlutil::no_query(&loc_url);
    let param = c.param_name().to_string();

    let (base_url, base_post) = build_request(c, None);
    let (base_hop, base_elapsed) = match probe(session, method, &base_url, base_post, budget) {
        Probe::Resp(h, d) => (h, d),
        Probe::OutOfBudget => return Err(()),
        Probe::Failed => return Ok(out),
    };
    let base_body = body_text(&base_hop);
    let orig = base_value(c);

    // 1. SQLi error-based (semua jenis kandidat).
    {
        let (u, post) = build_request(c, Some(&format!("{orig}'")));
        match probe(session, method, &u, post, budget) {
            Probe::Resp(hop, _) => {
                if sql_error_match(&base_body).is_none() {
                    if let Some(ev) = sql_error_match(&body_text(&hop)) {
                        out.push(finding(
                            "dast-active-sqli-error-based",
                            &loc_url,
                            format!("{method_label} {loc_shown}: parameter '{param}' payload ' memicu galat: {ev}"),
                        ));
                    }
                }
            }
            Probe::OutOfBudget => return Err(()),
            Probe::Failed => {}
        }
    }

    // 2. SQLi boolean-based blind.
    {
        let (tu, tp) = build_request(c, Some(&format!("{orig}' OR '1'='1")));
        let true_hop = match probe(session, method, &tu, tp, budget) {
            Probe::Resp(h, _) => Some(h),
            Probe::OutOfBudget => return Err(()),
            Probe::Failed => None,
        };
        let (fu, fp) = build_request(c, Some(&format!("{orig}' AND '1'='2")));
        let false_hop = match probe(session, method, &fu, fp, budget) {
            Probe::Resp(h, _) => Some(h),
            Probe::OutOfBudget => return Err(()),
            Probe::Failed => None,
        };
        if let (Some(th), Some(fh)) = (true_hop, false_hop) {
            let tb = body_text(&th);
            let fb = body_text(&fh);
            let (bl, tl, fl) = (
                base_body.chars().count(),
                tb.chars().count(),
                fb.chars().count(),
            );
            if boolean_blind_signal(bl, tl, fl) {
                out.push(finding(
                    "dast-active-sqli-boolean-blind",
                    &loc_url,
                    format!(
                        "{method_label} {loc_shown}: parameter '{param}' panjang body dasar={bl} true={tl} false={fl}"
                    ),
                ));
            }
        }
    }

    // 3. SQLi time-based blind (opt-in ganda, maksimum MAX_TIMING_PARAMS parameter per pemindaian).
    if opts.timing && *timing_remaining > 0 {
        *timing_remaining -= 1;
        for payload in ["' OR SLEEP(3)-- -", "' OR pg_sleep(3)-- -"] {
            let (u, p) = build_request(c, Some(&format!("{orig}{payload}")));
            match probe(session, method, &u, p, budget) {
                Probe::Resp(_, elapsed) => {
                    if elapsed >= base_elapsed + Duration::from_millis(2500) {
                        out.push(finding(
                            "dast-active-sqli-time-based",
                            &loc_url,
                            format!(
                                "{method_label} {loc_shown}: parameter '{param}' payload {payload:?} menunda respons {:.1}s (dasar {:.1}s); keyakinan rendah (time-based)",
                                elapsed.as_secs_f64(),
                                base_elapsed.as_secs_f64()
                            ),
                        ));
                        break;
                    }
                }
                Probe::OutOfBudget => return Err(()),
                Probe::Failed => {}
            }
        }
    }

    // 4-6. XSS reflected, open redirect, CRLF/header injection: hanya untuk Query dan ApiParam.
    if gets_extra_checks(c) {
        for variant in [marker.to_string(), format!("\"><{marker}>")] {
            let (u, p) = build_request(c, Some(&format!("{orig}{variant}")));
            match probe(session, method, &u, p, budget) {
                Probe::Resp(hop, _) => {
                    if hop.is_html() && xss_reflected_unescaped(&body_text(&hop), marker) {
                        out.push(finding(
                            "dast-active-xss-reflected",
                            &loc_url,
                            format!(
                                "{method_label} {loc_shown}: parameter '{param}' payload {variant:?} dipantulkan tanpa escaping"
                            ),
                        ));
                        break;
                    }
                }
                Probe::OutOfBudget => return Err(()),
                Probe::Failed => {}
            }
        }

        if looks_like_redirect_param(&param, &orig) {
            let (u, p) = build_request(c, Some(&format!("https://{REDIRECT_TEST_HOST}/x")));
            match probe(session, method, &u, p, budget) {
                Probe::Resp(hop, _) => {
                    if hop.header("location").is_some_and(redirect_confirmed) {
                        out.push(finding(
                            "dast-active-open-redirect-confirmed",
                            &loc_url,
                            format!(
                                "{method_label} {loc_shown}: parameter '{param}' redirect Location mengarah persis ke https://{REDIRECT_TEST_HOST}/x"
                            ),
                        ));
                    }
                }
                Probe::OutOfBudget => return Err(()),
                Probe::Failed => {}
            }
        }

        let (u, p) = build_request(c, Some(&header_injection_payload(&orig)));
        match probe(session, method, &u, p, budget) {
            Probe::Resp(hop, _) => {
                if hop.header("x-sdrscan-test").is_some() {
                    out.push(finding(
                        "dast-active-header-injection",
                        &loc_url,
                        format!(
                            "{method_label} {loc_shown}: parameter '{param}' payload CRLF menghasilkan header respons X-Sdrscan-Test"
                        ),
                    ));
                }
            }
            Probe::OutOfBudget => return Err(()),
            Probe::Failed => {}
        }
    }

    Ok(out)
}

/// Menjalankan pemeriksaan aktif atas `candidates` (sudah dideduplikasi oleh pemanggil menurut
/// `Candidate::dedupe_key`, urutan penemuan dipertahankan untuk determinisme).
pub fn run(
    session: &mut Session,
    mut candidates: Vec<Candidate>,
    opts: &ActiveOptions,
) -> ActiveResult {
    let mut warnings = Vec::new();
    if candidates.len() > opts.max_params {
        let skipped = candidates.len() - opts.max_params;
        candidates.truncate(opts.max_params);
        warnings.push(warn(format!(
            "--active-max-params ({}) tercapai; {skipped} parameter dilewati (urutan ditemukan)",
            opts.max_params
        )));
    }
    let mut budget = Budget {
        max_requests: opts.max_requests,
        sent: 0,
        deadline: Instant::now() + opts.timeout,
        exhausted: false,
        timed_out: false,
    };
    let marker = format!("{XSS_PREFIX}{}", random_token());
    let mut timing_remaining = if opts.timing { MAX_TIMING_PARAMS } else { 0 };
    let mut findings = Vec::new();
    for c in &candidates {
        if session.exclude.is_excluded(&location_url(c)) {
            continue;
        }
        match test_candidate(
            session,
            &mut budget,
            &marker,
            &mut timing_remaining,
            opts,
            c,
        ) {
            Ok(fs) => findings.extend(fs),
            Err(()) => break,
        }
    }
    if budget.exhausted {
        warnings.push(warn(format!(
            "--active-max-requests ({}) tercapai; sebagian parameter tidak sempat diuji",
            opts.max_requests
        )));
    }
    if budget.timed_out {
        warnings.push(warn(
            "--active-timeout tercapai; pemeriksaan aktif dihentikan lebih awal".to_string(),
        ));
    }
    findings.sort_by(|a, b| (&a.rule_id, &a.snippet).cmp(&(&b.rule_id, &b.snippet)));
    findings.dedup();
    ActiveResult {
        findings,
        requests_sent: budget.sent,
        warnings,
    }
}

// ---------------------------------------------------------------------------------------------
// Penemuan endpoint tambahan dari JS statis (best-effort, tidak dieksekusi, hanya regex).
// ---------------------------------------------------------------------------------------------

const MAX_JS_PATHS: usize = 200;

/// Jalur mirip `/api/...` ditemukan secara tekstual pada `text` (sumber JS statis, tidak dieksekusi):
/// literal yang diawali `/api/`, atau argumen pertama pemanggilan `fetch(...)`, `axios.<method>(...)`,
/// atau `.get/post/put/patch(...)`. Method HTTP tidak dapat dipastikan dari teks, sehingga hasil ini
/// HANYA dipakai sebagai kandidat GET (untuk ditambahkan ke frontier crawl).
pub fn extract_js_paths(text: &str) -> Vec<String> {
    static PATTERNS: OnceLock<(Regex, Regex)> = OnceLock::new();
    let (re_api, re_call) = PATTERNS.get_or_init(|| {
        (
            Regex::new(r#"["'](/api/[^"']*)["']"#).unwrap(),
            Regex::new(
                r#"(?:\bfetch|axios\.\w+|\.(?:get|post|put|patch))\s*\(\s*["'](/[^"']*)["']"#,
            )
            .unwrap(),
        )
    });
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for re in [re_api, re_call] {
        for cap in re.captures_iter(text) {
            if out.len() >= MAX_JS_PATHS {
                break;
            }
            if let Some(m) = cap.get(1) {
                if seen.insert(m.as_str().to_string()) {
                    out.push(m.as_str().to_string());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_error_detection_covers_common_engines() {
        for (body, want) in [
            ("blah You have an error in your SQL syntax; check", true),
            ("ERROR: unterminated quoted string at or near", true),
            (r#"SQLite3::query(): near "'": syntax error"#, true),
            ("ORA-00933: SQL command not properly ended", true),
            ("SQLSTATE[42000]: Syntax error", true),
            ("hello world, nothing wrong here", false),
        ] {
            assert_eq!(sql_error_match(body).is_some(), want, "{body}");
        }
    }

    #[test]
    fn boolean_blind_heuristic() {
        // satu item (dasar) vs daftar penuh (true) vs kosong (false): rentan.
        assert!(boolean_blind_signal(40, 90, 8));
        // escaped: ketiganya identik panjang -> aman.
        assert!(!boolean_blind_signal(40, 40, 40));
        // param tidak berpengaruh sama sekali.
        assert!(!boolean_blind_signal(0, 0, 0));
        // false tidak cukup berbeda.
        assert!(!boolean_blind_signal(40, 42, 35));
    }

    #[test]
    fn xss_detects_only_unescaped_marker() {
        let marker = "sdrscanxssABC123";
        assert!(xss_reflected_unescaped(
            &format!("x \"><{marker}> y"),
            marker
        ));
        assert!(!xss_reflected_unescaped(
            &format!("x &lt;{marker}&gt; y"),
            marker
        ));
        assert!(!xss_reflected_unescaped(
            &format!("just {marker} alone"),
            marker
        ));
    }

    #[test]
    fn redirect_param_heuristic_and_confirmation() {
        assert!(looks_like_redirect_param("redirect_to", "ok"));
        assert!(looks_like_redirect_param("next", "ok"));
        assert!(looks_like_redirect_param("q", "/path"));
        assert!(!looks_like_redirect_param("q", "hello"));
        assert!(redirect_confirmed(&format!(
            "https://{REDIRECT_TEST_HOST}/x"
        )));
        assert!(!redirect_confirmed("https://evil.example/x"));
        assert!(!redirect_confirmed("/local/path"));
    }

    #[test]
    fn header_injection_payload_keeps_percent_escapes_literal() {
        let url = Url::parse("http://h/x?next=a").unwrap();
        let payload = header_injection_payload("a");
        let u = with_value(&url, "next", &payload);
        assert!(
            u.query().unwrap().contains("%0d%0aX-Sdrscan-Test:%201"),
            "{u}"
        );
    }

    #[test]
    fn query_value_builder_round_trips_sqli_payload() {
        let url = Url::parse("http://h/x?id=1").unwrap();
        let u = with_value(&url, "id", "1' OR '1'='1");
        let got: String = u
            .query_pairs()
            .find(|(k, _)| k == "id")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        assert_eq!(got, "1' OR '1'='1");
    }

    #[test]
    fn dedupe_keys_distinguish_method_and_location() {
        let a = Candidate::Query {
            url: Url::parse("http://h/x?id=1").unwrap(),
            param: "id".to_string(),
        };
        let b = Candidate::FormPost {
            action: Url::parse("http://h/x").unwrap(),
            fields: vec![("id".to_string(), "1".to_string())],
            param: "id".to_string(),
            injectable: true,
        };
        assert_ne!(a.dedupe_key(), b.dedupe_key());
    }

    #[test]
    fn js_path_extraction_finds_api_and_call_literals() {
        let js = r#"
            fetch('/api/items/search').then(r => r.json());
            axios.post('/users/42/update', data);
        "#;
        let found = extract_js_paths(js);
        assert!(
            found.contains(&"/api/items/search".to_string()),
            "{found:?}"
        );
        assert!(found.contains(&"/users/42/update".to_string()), "{found:?}");
    }

    #[test]
    fn candidates_from_operation_skip_delete_and_build_path_and_body() {
        let doc = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/items/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
                    "put": {
                        "requestBody": {"content": {"application/json": {"schema": {
                            "type": "object",
                            "properties": {"name": {"type": "string"}, "qty": {"type": "integer"}}
                        }}}}
                    }
                }
            }
        });
        let ops = openapi::parse(&doc);
        assert_eq!(ops.len(), 1);
        let origin = Url::parse("http://h/").unwrap();
        let cands = candidates_from_operation(&origin, &ops[0]);
        // id (path) + name (body string); qty (integer) tidak diinjeksi.
        assert!(cands
            .iter()
            .any(|c| matches!(c, Candidate::ApiParam { in_path: true, .. })
                && c.param_name() == "id"));
        assert!(cands
            .iter()
            .any(|c| matches!(c, Candidate::ApiBodyProp { .. }) && c.param_name() == "name"));
        assert!(!cands.iter().any(|c| c.param_name() == "qty"));
        let (url, post) = build_request(&cands[0], Some("1' OR '1'='1"));
        assert!(url.path().starts_with("/items/1%27"), "{url}");
        assert!(post.is_some());
    }
}
