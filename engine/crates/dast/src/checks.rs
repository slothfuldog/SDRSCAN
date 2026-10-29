//! Pemeriksaan pasif DAST: hanya membaca satu respons HTTP, tanpa mengirim payload.
//! Setiap pemeriksaan adalah fungsi murni atas `Response` sehingga dapat diuji tanpa jaringan.

use sdrscan_core::{Finding, Location, Severity, Template, TemplateType};
use url::Url;

use crate::html;
use crate::urlutil;

/// Respons yang sudah dinormalisasi; nama header huruf kecil.
#[derive(Debug, Clone)]
pub struct Response {
    pub url: String,
    pub https: bool,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub set_cookies: Vec<String>,
}

impl Response {
    /// Semua nilai header bernama `name` (proksi atau aplikasi dapat mengirim `Server` ganda).
    pub(crate) fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Rule {
    id: &'static str,
    severity: Severity,
    cwe: &'static str,
    tags: &'static [&'static str],
    message: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        id: "dast-insecure-transport",
        severity: Severity::Medium,
        cwe: "CWE-319",
        tags: &["dast", "passive", "transport", "owasp-a02"],
        message: "Target dilayani lewat HTTP tanpa TLS.",
    },
    Rule {
        id: "dast-missing-hsts",
        severity: Severity::Medium,
        cwe: "CWE-319",
        tags: &["dast", "passive", "headers", "owasp-a05"],
        message: "Header Strict-Transport-Security tidak ada pada respons HTTPS.",
    },
    Rule {
        id: "dast-missing-csp",
        severity: Severity::Low,
        cwe: "CWE-693",
        tags: &["dast", "passive", "headers", "owasp-a05"],
        message: "Header Content-Security-Policy tidak ada.",
    },
    Rule {
        id: "dast-missing-frame-protection",
        severity: Severity::Low,
        cwe: "CWE-1021",
        tags: &["dast", "passive", "headers", "owasp-a05"],
        message: "Tidak ada X-Frame-Options maupun CSP frame-ancestors (risiko clickjacking).",
    },
    Rule {
        id: "dast-missing-content-type-options",
        severity: Severity::Low,
        cwe: "CWE-693",
        tags: &["dast", "passive", "headers", "owasp-a05"],
        message: "Header X-Content-Type-Options: nosniff tidak ada.",
    },
    Rule {
        id: "dast-missing-referrer-policy",
        severity: Severity::Info,
        cwe: "CWE-200",
        tags: &["dast", "passive", "headers", "owasp-a05"],
        message: "Header Referrer-Policy tidak ada.",
    },
    Rule {
        id: "dast-cookie-missing-secure",
        severity: Severity::Medium,
        cwe: "CWE-614",
        tags: &["dast", "passive", "cookies", "owasp-a05"],
        message: "Cookie tanpa atribut Secure.",
    },
    Rule {
        id: "dast-cookie-missing-httponly",
        severity: Severity::Medium,
        cwe: "CWE-1004",
        tags: &["dast", "passive", "cookies", "owasp-a05"],
        message: "Cookie tanpa atribut HttpOnly.",
    },
    Rule {
        id: "dast-cookie-missing-samesite",
        severity: Severity::Low,
        cwe: "CWE-1275",
        tags: &["dast", "passive", "cookies", "owasp-a01"],
        message: "Cookie tanpa atribut SameSite.",
    },
    Rule {
        id: "dast-server-version-disclosure",
        severity: Severity::Info,
        cwe: "CWE-200",
        tags: &["dast", "passive", "disclosure", "owasp-a05"],
        message: "Header Server atau X-Powered-By membuka nama dan versi perangkat lunak.",
    },
    Rule {
        id: "dast-form-password-over-http",
        severity: Severity::Medium,
        cwe: "CWE-319",
        tags: &["dast", "passive", "forms", "owasp-a02"],
        message: "Input kata sandi berada di halaman atau dikirim ke URL HTTP tanpa TLS.",
    },
    Rule {
        id: "dast-autocomplete-password",
        severity: Severity::Info,
        cwe: "CWE-522",
        tags: &["dast", "passive", "forms", "owasp-a05"],
        message: "Input kata sandi tanpa autocomplete=off atau new-password; peramban dapat menyimpan kata sandi.",
    },
    Rule {
        id: "dast-sensitive-info-in-url",
        severity: Severity::Low,
        cwe: "CWE-598",
        tags: &["dast", "passive", "disclosure", "owasp-a02"],
        message: "Parameter query bernama token, kunci, kata sandi, rahasia, atau sesi tercantum di URL (bocor lewat log, riwayat, dan header Referer).",
    },
];

/// Aturan bawaan sebagai `Template` (type: http) agar SARIF dari `core` dapat dipakai apa adanya.
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

fn finding(id: &str, resp: &Response, evidence: String) -> Finding {
    let rule = RULES
        .iter()
        .find(|r| r.id == id)
        .expect("id aturan harus terdaftar");
    Finding {
        rule_id: rule.id.to_string(),
        severity: rule.severity,
        message: rule.message.to_string(),
        location: Location::url(&resp.url),
        snippet: evidence,
        vulnerability: None,
    }
}

/// Atribut cookie (huruf kecil, tanpa nilai) dan nama cookie.
fn parse_cookie(raw: &str) -> (String, Vec<String>) {
    let mut parts = raw.split(';');
    let name = parts
        .next()
        .and_then(|p| p.split('=').next())
        .unwrap_or("")
        .trim()
        .to_string();
    let attrs = parts
        .map(|a| a.trim().to_ascii_lowercase())
        .filter(|a| !a.is_empty())
        .collect();
    (name, attrs)
}

fn has_version(value: &str) -> bool {
    value.contains('/') && value.chars().any(|c| c.is_ascii_digit())
}

fn cookie_findings(resp: &Response, out: &mut Vec<Finding>) {
    for raw in &resp.set_cookies {
        let (name, attrs) = parse_cookie(raw);
        let has = |a: &str| attrs.iter().any(|x| x == a);
        let has_prefix = |p: &str| attrs.iter().any(|x| x.starts_with(p));
        if resp.https && !has("secure") {
            out.push(finding(
                "dast-cookie-missing-secure",
                resp,
                format!("Set-Cookie: {name}=<disamarkan>"),
            ));
        }
        if !has("httponly") {
            out.push(finding(
                "dast-cookie-missing-httponly",
                resp,
                format!("Set-Cookie: {name}=<disamarkan>"),
            ));
        }
        if !has_prefix("samesite") {
            out.push(finding(
                "dast-cookie-missing-samesite",
                resp,
                format!("Set-Cookie: {name}=<disamarkan>"),
            ));
        }
    }
}

/// Hanya pemeriksaan flag cookie (Secure, HttpOnly, SameSite) atas `Set-Cookie` pada `resp`.
pub fn run_cookies(resp: &Response) -> Vec<Finding> {
    let mut out = Vec::new();
    cookie_findings(resp, &mut out);
    out.sort_by(|a, b| (&a.rule_id, &a.snippet).cmp(&(&b.rule_id, &b.snippet)));
    out.dedup();
    out
}

fn short(s: &str) -> String {
    s.chars().take(60).collect()
}

/// Pemeriksaan pasif atas badan HTML: input kata sandi (HTTP, autocomplete) dan parameter rahasia di tautan.
/// `base` adalah URL halaman (untuk menyelesaikan tautan relatif). Bukti tidak pernah memuat nilai parameter.
pub fn run_html(resp: &Response, base: &Url, html_text: &str) -> Vec<Finding> {
    let info = html::analyze(html_text);
    let mut out = Vec::new();
    let resolve = |raw: &str| -> Option<Url> {
        let u = base.join(raw).ok()?;
        matches!(u.scheme(), "http" | "https").then_some(u)
    };

    for pw in &info.passwords {
        let action = pw
            .form
            .and_then(|f| info.forms[f].action.as_deref())
            .filter(|a| !a.is_empty())
            .and_then(resolve)
            .unwrap_or_else(|| base.clone());
        if base.scheme() == "http" {
            out.push(finding(
                "dast-form-password-over-http",
                resp,
                format!(
                    "Input password pada halaman HTTP: {}",
                    urlutil::no_query(base)
                ),
            ));
        } else if action.scheme() == "http" {
            out.push(finding(
                "dast-form-password-over-http",
                resp,
                format!(
                    "Formulir password dikirim ke URL HTTP: {}",
                    urlutil::no_query(&action)
                ),
            ));
        }
        let ok = |v: &Option<String>| matches!(v.as_deref(), Some("off") | Some("new-password"));
        if !ok(&pw.autocomplete) && !ok(&pw.form_autocomplete) {
            let name = if pw.name.is_empty() {
                "(tanpa nama)".to_string()
            } else {
                short(&pw.name)
            };
            out.push(finding(
                "dast-autocomplete-password",
                resp,
                format!(
                    "<input type=password name={name}> tanpa autocomplete=off atau new-password"
                ),
            ));
        }
    }

    let mut sensitive = |u: &Url, what: &str| {
        for p in urlutil::sensitive_params(u) {
            out.push(finding(
                "dast-sensitive-info-in-url",
                resp,
                format!(
                    "Parameter '{}' pada {what} {}",
                    short(&p),
                    urlutil::no_query(u)
                ),
            ));
        }
    };
    sensitive(base, "URL halaman");
    for raw in &info.links {
        if let Some(u) = resolve(raw) {
            sensitive(&u, "tautan");
        }
    }
    for f in &info.forms {
        if let Some(u) = f
            .action
            .as_deref()
            .filter(|a| !a.is_empty())
            .and_then(resolve)
        {
            sensitive(&u, "tautan");
        }
    }

    out.sort_by(|a, b| (&a.rule_id, &a.snippet).cmp(&(&b.rule_id, &b.snippet)));
    out.dedup();
    out
}

pub fn run(resp: &Response) -> Vec<Finding> {
    let mut out = Vec::new();

    if !resp.https {
        out.push(finding(
            "dast-insecure-transport",
            resp,
            format!("URL: {}", resp.url),
        ));
    } else if resp.header("strict-transport-security").is_none() {
        out.push(finding(
            "dast-missing-hsts",
            resp,
            "Strict-Transport-Security: (tidak ada)".to_string(),
        ));
    }

    let csp = resp.header("content-security-policy");
    if csp.is_none() {
        out.push(finding(
            "dast-missing-csp",
            resp,
            "Content-Security-Policy: (tidak ada)".to_string(),
        ));
    }
    let frame_ancestors = csp.is_some_and(|v| v.to_ascii_lowercase().contains("frame-ancestors"));
    if resp.header("x-frame-options").is_none() && !frame_ancestors {
        out.push(finding(
            "dast-missing-frame-protection",
            resp,
            "X-Frame-Options: (tidak ada)".to_string(),
        ));
    }
    if !resp
        .header("x-content-type-options")
        .is_some_and(|v| v.eq_ignore_ascii_case("nosniff"))
    {
        out.push(finding(
            "dast-missing-content-type-options",
            resp,
            format!(
                "X-Content-Type-Options: {}",
                resp.header("x-content-type-options")
                    .unwrap_or("(tidak ada)")
            ),
        ));
    }
    if resp.header("referrer-policy").is_none() {
        out.push(finding(
            "dast-missing-referrer-policy",
            resp,
            "Referrer-Policy: (tidak ada)".to_string(),
        ));
    }

    cookie_findings(resp, &mut out);

    for header in ["server", "x-powered-by"] {
        for v in resp.header_all(header) {
            if has_version(v) {
                out.push(finding(
                    "dast-server-version-disclosure",
                    resp,
                    format!("{header}: {v}"),
                ));
            }
        }
    }

    out.sort_by(|a, b| (&a.rule_id, &a.snippet).cmp(&(&b.rule_id, &b.snippet)));
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(https: bool, headers: &[(&str, &str)], cookies: &[&str]) -> Response {
        Response {
            url: if https {
                "https://t.example/"
            } else {
                "http://t.example/"
            }
            .to_string(),
            https,
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            set_cookies: cookies.iter().map(|c| c.to_string()).collect(),
        }
    }

    fn ids(r: &Response) -> Vec<String> {
        run(r).into_iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn hardened_response_has_no_findings() {
        let r = resp(
            true,
            &[
                ("strict-transport-security", "max-age=31536000"),
                (
                    "content-security-policy",
                    "default-src 'self'; frame-ancestors 'none'",
                ),
                ("x-content-type-options", "nosniff"),
                ("referrer-policy", "no-referrer"),
                ("server", "nginx"),
            ],
            &["sid=abc; Secure; HttpOnly; SameSite=Lax"],
        );
        assert!(ids(&r).is_empty(), "{:?}", run(&r));
    }

    #[test]
    fn bare_http_response_reports_headers_and_transport() {
        let got = ids(&resp(false, &[], &[]));
        for want in [
            "dast-insecure-transport",
            "dast-missing-csp",
            "dast-missing-frame-protection",
            "dast-missing-content-type-options",
            "dast-missing-referrer-policy",
        ] {
            assert!(
                got.contains(&want.to_string()),
                "{want} tidak ada di {got:?}"
            );
        }
        assert!(!got.contains(&"dast-missing-hsts".to_string()));
    }

    #[test]
    fn hsts_only_matters_on_https() {
        assert!(ids(&resp(true, &[], &[])).contains(&"dast-missing-hsts".to_string()));
    }

    #[test]
    fn cookie_flags_are_checked_and_value_is_masked() {
        let r = resp(true, &[], &["sid=SECRETVALUE; Path=/"]);
        let findings = run(&r);
        let cookie: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.starts_with("dast-cookie"))
            .collect();
        assert_eq!(cookie.len(), 3);
        assert!(cookie.iter().all(|f| !f.snippet.contains("SECRETVALUE")));
    }

    #[test]
    fn plain_http_cookie_is_not_flagged_for_secure() {
        let got = ids(&resp(false, &[], &["sid=1; HttpOnly; SameSite=Strict"]));
        assert!(!got.contains(&"dast-cookie-missing-secure".to_string()));
    }

    #[test]
    fn version_disclosure_needs_a_version() {
        assert!(!ids(&resp(true, &[("server", "nginx")], &[]))
            .contains(&"dast-server-version-disclosure".to_string()));
        assert!(ids(&resp(true, &[("server", "Apache/2.4.41")], &[]))
            .contains(&"dast-server-version-disclosure".to_string()));
        assert!(ids(&resp(true, &[("x-powered-by", "PHP/8.1.2")], &[]))
            .contains(&"dast-server-version-disclosure".to_string()));
    }

    #[test]
    fn duplicate_server_headers_are_all_inspected() {
        let r = resp(
            true,
            &[("server", "gws"), ("server", "Apache/2.4.41 (Ubuntu)")],
            &[],
        );
        let f = run(&r);
        assert!(f
            .iter()
            .any(|f| f.rule_id == "dast-server-version-disclosure"
                && f.snippet.contains("Apache/2.4.41")));
    }

    fn html_ids(r: &Response, page: &str, body: &str) -> Vec<String> {
        run_html(r, &Url::parse(page).unwrap(), body)
            .into_iter()
            .map(|f| f.rule_id)
            .collect()
    }

    #[test]
    fn password_input_over_http_is_flagged_but_not_over_https() {
        let body =
            r#"<form action="/login"><input type="password" name="p" autocomplete="off"></form>"#;
        let http = resp(false, &[], &[]);
        assert!(html_ids(&http, "http://t.example/login", body)
            .contains(&"dast-form-password-over-http".to_string()));
        let https = resp(true, &[], &[]);
        assert!(html_ids(&https, "https://t.example/login", body).is_empty());
        // halaman https yang mengirim ke URL http tetap ditandai
        let leaky = r#"<form action="http://t.example/login"><input type="password" autocomplete="new-password"></form>"#;
        let f = run_html(&https, &Url::parse("https://t.example/").unwrap(), leaky);
        assert_eq!(f.len(), 1);
        assert!(f[0].snippet.contains("http://t.example/login"));
    }

    #[test]
    fn autocomplete_rule_is_info_and_respects_off_and_new_password() {
        let r = resp(true, &[], &[]);
        let f = run_html(
            &r,
            &Url::parse("https://t.example/").unwrap(),
            r#"<input type="password" name="pw">"#,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "dast-autocomplete-password");
        assert_eq!(f[0].severity, Severity::Info);
        for ok in [
            r#"<input type="password" autocomplete="off">"#,
            r#"<input type="password" autocomplete="new-password">"#,
            r#"<form autocomplete="off"><input type="password"></form>"#,
            r#"<input type="text">"#,
        ] {
            assert!(html_ids(&r, "https://t.example/", ok).is_empty(), "{ok}");
        }
    }

    #[test]
    fn sensitive_query_params_in_links_never_leak_values() {
        let r = resp(true, &[], &[]);
        let body = r#"<a href="/a?token=VALUE1&x=1">a</a><a href="https://other.test/b?password=VALUE2">b</a>
            <a href="/c?keyword=ok&page=2">c</a><form action="/f?api_key=VALUE3"></form>"#;
        let f = run_html(&r, &Url::parse("https://t.example/").unwrap(), body);
        assert_eq!(f.len(), 3, "{f:?}");
        assert!(f.iter().all(|x| x.rule_id == "dast-sensitive-info-in-url"
            && x.severity == Severity::Low
            && !x.snippet.contains("VALUE")));
        // URL halaman sendiri
        let f = run_html(
            &r,
            &Url::parse("https://t.example/p?session=V4").unwrap(),
            "<p>x</p>",
        );
        assert_eq!(f.len(), 1);
        assert!(!f[0].snippet.contains("V4"));
    }

    #[test]
    fn run_cookies_only_reports_cookie_rules() {
        let r = resp(true, &[], &["sid=abc; Path=/"]);
        let ids: Vec<String> = run_cookies(&r).into_iter().map(|f| f.rule_id).collect();
        assert_eq!(
            ids,
            vec![
                "dast-cookie-missing-httponly",
                "dast-cookie-missing-samesite",
                "dast-cookie-missing-secure"
            ]
        );
    }

    #[test]
    fn builtin_rules_cover_every_rule_id() {
        assert_eq!(builtin_rules().len(), RULES.len());
    }
}
