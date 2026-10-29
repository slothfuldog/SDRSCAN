//! Kerentanan dari versi perangkat lunak yang terbaca di header `Server`, `X-Powered-By`, dan
//! `X-AspNet-Version`, dicocokkan dengan basis data NVD lokal (offline). Karena nomor versi dapat
//! ditambal tanpa berubah (backport distribusi), semua temuan berkeyakinan rendah dan perlu verifikasi.

use std::cmp::Reverse;
use std::path::Path;

use sdrscan_core::{Cvss, Finding, Location, VulnTarget, Vulnerability, Warning, WarningKind};
use sdrscan_vulndb::products::{self, Product};
use sdrscan_vulndb::{resolve_db_dir, VulnDb};

use crate::checks::Response;

/// Batas temuan CVE per respons agar laporan tidak banjir.
pub const MAX_CVE_FINDINGS: usize = 25;
/// Basis data lebih tua dari ini memicu peringatan.
pub const STALE_AFTER_DAYS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Banner {
    /// Nama header kanonik: `Server`, `X-Powered-By`, `X-AspNet-Version`.
    pub header: &'static str,
    /// Potongan banner apa adanya, mis. `Apache/2.4.41`.
    pub token: String,
    pub product: &'static Product,
    /// Hanya bagian angka (dan satu huruf akhiran untuk OpenSSL), mis. `2.4.41`, `1.0.2k`.
    pub version: String,
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// `\d+(\.\d+)*` di awal `s`, ditambah satu huruf akhiran bila `allow_letter` dan huruf itu tidak
/// diikuti huruf/angka lain (`1.0.2k-fips` -> `1.0.2k`; `1.0.0rc1` -> `1.0.0`).
fn leading_version(s: &str, allow_letter: bool) -> Option<String> {
    let b = s.as_bytes();
    if b.first().is_none_or(|c| !c.is_ascii_digit()) {
        return None;
    }
    let mut i = 0;
    loop {
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i + 1 < b.len() && b[i] == b'.' && b[i + 1].is_ascii_digit() {
            i += 1;
            continue;
        }
        break;
    }
    let mut end = i;
    if allow_letter {
        // satu atau dua huruf kecil akhiran (OpenSSL `1.0.2k`, `1.0.2zd`) yang tidak diikuti huruf/angka lain
        let letters = b[i..].iter().take_while(|c| c.is_ascii_lowercase()).count();
        if (1..=2).contains(&letters)
            && b.get(i + letters)
                .is_none_or(|c| !c.is_ascii_alphanumeric())
        {
            end = i + letters;
        }
    }
    Some(s[..end].to_string())
}

fn scan_value(header: &'static str, value: &str, out: &mut Vec<Banner>) {
    let chars: Vec<(usize, char)> = value.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].1.is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_name_char(chars[i].1) {
            i += 1;
        }
        let name = &value[chars[start].0..chars.get(i).map_or(value.len(), |c| c.0)];
        let sep = chars.get(i).map(|c| c.1);
        if !matches!(sep, Some('/') | Some('(')) {
            continue;
        }
        let v_start = chars.get(i + 1).map_or(value.len(), |c| c.0);
        let rest = &value[v_start..];
        let token_end_rel = rest
            .find(|c: char| c.is_whitespace() || c == ')' || c == ';' || c == ',')
            .unwrap_or(rest.len());
        let Some(product) = products::by_alias(name) else {
            continue;
        };
        let allow_letter = product.key == "openssl";
        let Some(version) = leading_version(&rest[..token_end_rel], allow_letter) else {
            continue;
        };
        let token = match sep {
            Some('(') => format!("{name}({})", &rest[..token_end_rel]),
            _ => format!("{name}/{}", &rest[..token_end_rel]),
        };
        out.push(Banner {
            header,
            token,
            product,
            version,
        });
    }
}

/// Banner produk terkurasi yang bernomor versi, tanpa duplikat (produk, versi), urut menurut produk lalu versi.
pub fn parse_banners(resp: &Response) -> Vec<Banner> {
    let mut out = Vec::new();
    for (key, header) in [("server", "Server"), ("x-powered-by", "X-Powered-By")] {
        for v in resp.header_all(key) {
            scan_value(header, v, &mut out);
        }
    }
    for v in resp.header_all("x-aspnet-version") {
        if let (Some(product), Some(version)) = (
            products::by_alias("asp.net"),
            leading_version(v.trim(), false),
        ) {
            out.push(Banner {
                header: "X-AspNet-Version",
                token: v.trim().to_string(),
                product,
                version,
            });
        }
    }
    let mut seen: Vec<(&str, String)> = Vec::new();
    out.retain(|b| {
        let key = (b.product.key, b.version.clone());
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
    out.sort_by(|a, b| (a.product.key, &a.version).cmp(&(b.product.key, &b.version)));
    out
}

fn warn(message: String, path: &str) -> Warning {
    Warning {
        kind: WarningKind::VulnDb,
        message,
        path: Some(path.to_string()),
        rule_id: None,
        location: None,
        snippet: None,
    }
}

fn finding_for(resp: &Response, b: &Banner, hit: &sdrscan_vulndb::ProductHit) -> Finding {
    let e = &hit.entry;
    let fixed = if hit.fixed.is_empty() {
        String::new()
    } else {
        format!(" Versi perbaikan upstream: {}.", hit.fixed.join(", "))
    };
    let summary = if e.summary.is_empty() {
        e.id.clone()
    } else {
        e.summary.clone()
    };
    let message = format!(
        "{} {} (dari banner {}) mungkin rentan terhadap {}: {summary}. Keyakinan rendah: nomor versi dapat \
         ditambal oleh distribusi tanpa berubah; verifikasi versi dan status patch yang sebenarnya.{fixed}",
        b.product.display, b.version, b.header, e.id
    );
    Finding {
        rule_id: e.id.clone(),
        severity: e.severity(),
        message,
        location: Location::url(&resp.url),
        snippet: format!("{}: {}", b.header, b.token),
        vulnerability: Some(Vulnerability {
            ids: vec![e.id.clone()],
            package: VulnTarget::Product {
                product: b.product.cpe.to_string(),
                version: b.version.clone(),
            },
            fixed_versions: hit.fixed.clone(),
            source: "nvd".to_string(),
            references: e.references.iter().take(5).cloned().collect(),
            cvss: e.cvss.as_ref().map(|c| Cvss {
                score: c.score,
                vector: c.vector.clone(),
            }),
            confidence: "low".to_string(),
            scope: None,
            summary: e.summary.clone(),
            cwe: e.cwe.clone(),
        }),
    }
}

/// Memeriksa banner respons terhadap basis data lokal. Tanpa basis data yang dapat dipakai, hasilnya
/// peringatan (bukan galat). Temuan dibatasi `MAX_CVE_FINDINGS` (severity tertinggi dulu, lalu id).
pub fn check(resp: &Response, db_flag: Option<&Path>) -> (Vec<Finding>, Vec<Warning>) {
    let banners = parse_banners(resp);
    let configured = resolve_db_dir(db_flag);
    let mut warnings = Vec::new();
    let db = match &configured {
        Some(dir) => match VulnDb::open(dir) {
            Ok(db) if db.has_nvd() => Some(db),
            Ok(_) => {
                warnings.push(warn(
                    format!(
                        "basis data kerentanan {} tidak memuat data NVD; pemeriksaan CVE dari banner dilewati (jalankan: sdrscan-vuln update --nvd)",
                        dir.display()
                    ),
                    &resp.url,
                ));
                None
            }
            Err(e) => {
                warnings.push(warn(
                    format!("basis data kerentanan tidak dapat dipakai, pemeriksaan CVE dari banner dilewati: {e}"),
                    &resp.url,
                ));
                None
            }
        },
        None => {
            if !banners.is_empty() {
                warnings.push(warn(
                    "banner dengan nomor versi terbaca tetapi basis data kerentanan tidak diset (--vuln-db atau env SDRSCAN_VULN_DB); pemeriksaan CVE dari banner dilewati".to_string(),
                    &resp.url,
                ));
            }
            None
        }
    };
    let Some(db) = db else {
        return (Vec::new(), warnings);
    };
    if banners.is_empty() {
        return (Vec::new(), warnings);
    }
    if let Some(age) = db.age_days(sdrscan_vulndb::time::now_epoch()) {
        if age > STALE_AFTER_DAYS {
            warnings.push(warn(
                format!(
                    "basis data kerentanan berumur {age} hari (diperbarui {}); jalankan sdrscan-vuln update",
                    db.meta().updated_at
                ),
                &resp.url,
            ));
        }
    }
    let mut findings: Vec<Finding> = Vec::new();
    for b in &banners {
        match db.query_product(b.product.cpe, &b.version) {
            Ok(q) => {
                if q.corrupt_lines > 0 {
                    warnings.push(warn(
                        format!(
                            "basis data NVD: {} baris rusak dilewati; jalankan sdrscan-vuln update --nvd",
                            q.corrupt_lines
                        ),
                        &resp.url,
                    ));
                }
                findings.extend(q.hits.iter().map(|h| finding_for(resp, b, h)));
            }
            Err(e) => warnings.push(warn(
                format!("gagal membaca basis data NVD: {e}"),
                &resp.url,
            )),
        }
    }
    findings.sort_by(|a, b| {
        (Reverse(a.severity), &a.rule_id, &a.snippet).cmp(&(
            Reverse(b.severity),
            &b.rule_id,
            &b.snippet,
        ))
    });
    findings.dedup();
    if findings.len() > MAX_CVE_FINDINGS {
        let dropped = findings.len() - MAX_CVE_FINDINGS;
        findings.truncate(MAX_CVE_FINDINGS);
        warnings.push(Warning {
            kind: WarningKind::Truncated,
            message: format!(
                "{dropped} temuan CVE dari banner dipotong (batas {MAX_CVE_FINDINGS} per respons, severity tertinggi dulu)"
            ),
            path: Some(resp.url.clone()),
            rule_id: None,
            location: None,
            snippet: None,
        });
    }
    (findings, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(headers: &[(&str, &str)]) -> Response {
        Response {
            url: "http://t.example/".to_string(),
            https: false,
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            set_cookies: vec![],
        }
    }

    fn pairs(r: &Response) -> Vec<(String, String, String)> {
        parse_banners(r)
            .into_iter()
            .map(|b| (b.product.key.to_string(), b.version, b.token))
            .collect()
    }

    #[test]
    fn apache_with_modules_and_php() {
        let r = resp(&[
            (
                "server",
                "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f mod_wsgi/4.6.8",
            ),
            ("x-powered-by", "PHP/7.4.3-4ubuntu2.18"),
        ]);
        assert_eq!(
            pairs(&r),
            [
                (
                    "apache-httpd".to_string(),
                    "2.4.41".to_string(),
                    "Apache/2.4.41".to_string()
                ),
                (
                    "openssl".to_string(),
                    "1.1.1f".to_string(),
                    "OpenSSL/1.1.1f".to_string()
                ),
                (
                    "php".to_string(),
                    "7.4.3".to_string(),
                    "PHP/7.4.3-4ubuntu2.18".to_string()
                ),
            ]
        );
    }

    #[test]
    fn nginx_iis_lighttpd_jetty_tomcat() {
        assert_eq!(
            pairs(&resp(&[("server", "nginx/1.18.0 (Ubuntu)")]))[0].1,
            "1.18.0"
        );
        assert_eq!(
            pairs(&resp(&[("server", "Microsoft-IIS/10.0")]))[0].0,
            "iis"
        );
        assert_eq!(
            pairs(&resp(&[("server", "lighttpd/1.4.55")]))[0].1,
            "1.4.55"
        );
        assert_eq!(
            pairs(&resp(&[("server", "Jetty(9.4.12.v20180830)")])),
            [(
                "jetty".to_string(),
                "9.4.12".to_string(),
                "Jetty(9.4.12.v20180830)".to_string()
            )]
        );
        assert_eq!(
            pairs(&resp(&[("server", "Apache Tomcat/9.0.30")]))[0].0,
            "tomcat"
        );
        assert_eq!(
            pairs(&resp(&[("x-powered-by", "Express/4.17.1")]))[0].0,
            "express"
        );
    }

    #[test]
    fn aspnet_version_header() {
        let r = resp(&[
            ("x-aspnet-version", "4.0.30319"),
            ("x-powered-by", "ASP.NET"),
        ]);
        assert_eq!(
            pairs(&r),
            [(
                "aspnet".to_string(),
                "4.0.30319".to_string(),
                "4.0.30319".to_string()
            )]
        );
    }

    #[test]
    fn unclear_or_unknown_banners_are_ignored() {
        for h in [
            ("server", "nginx"),
            ("server", "Apache"),
            ("server", "Apache-Coyote/1.1"),
            ("server", "cloudflare"),
            ("x-powered-by", "Express"),
            ("x-powered-by", "PHP"),
            ("x-powered-by", "PHP/"),
            ("server", "gws"),
            ("server", ""),
        ] {
            assert!(parse_banners(&resp(&[h])).is_empty(), "{h:?}");
        }
    }

    #[test]
    fn repeated_server_headers_are_all_read() {
        // mis. http.server Python menambah "Server: BaseHTTP/..." sebelum header aplikasi; proksi juga dapat menggandakan
        let r = resp(&[
            ("server", "BaseHTTP/0.6 Python/3.9.6"),
            ("server", "Apache/2.4.41 (Ubuntu)"),
            ("x-powered-by", "Express/4.17.1"),
            ("x-powered-by", "PHP/7.4.3"),
        ]);
        let got: Vec<String> = pairs(&r).into_iter().map(|p| p.0).collect();
        assert_eq!(got, ["apache-httpd", "express", "php"]);
    }

    #[test]
    fn openssl_two_letter_suffix_in_banner() {
        let r = resp(&[("server", "Apache/2.4.41 OpenSSL/1.0.2zd")]);
        assert!(pairs(&r)
            .iter()
            .any(|p| p.0 == "openssl" && p.1 == "1.0.2zd"));
    }

    #[test]
    fn duplicate_product_version_across_headers_is_collapsed() {
        let r = resp(&[
            ("server", "Apache/2.4.41 PHP/7.4.3"),
            ("x-powered-by", "PHP/7.4.3"),
        ]);
        assert_eq!(
            parse_banners(&r)
                .iter()
                .filter(|b| b.product.key == "php")
                .count(),
            1
        );
    }

    #[test]
    fn openssl_letter_suffix_is_kept_only_for_openssl() {
        assert_eq!(
            leading_version("1.0.2k-fips", true).as_deref(),
            Some("1.0.2k")
        );
        assert_eq!(leading_version("1.0.2k", false).as_deref(), Some("1.0.2"));
        assert_eq!(leading_version("1.0.0rc1", true).as_deref(), Some("1.0.0"));
        assert_eq!(leading_version("1.0.2zd", true).as_deref(), Some("1.0.2zd"));
        assert_eq!(leading_version("1.0.2zde", true).as_deref(), Some("1.0.2"));
        assert_eq!(leading_version("x1", true), None);
    }
}
