//! Pengolah halaman respons NVD API 2.0 (`/rest/json/cves/2.0`) menjadi `NvdEntry` per (produk, CVE),
//! terbatas pada produk terkurasi. Hanya cpeMatch `vulnerable: true` yang dipakai.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::model::{CpeRange, Cvss, NvdEntry, MAX_REFERENCES};

const MAX_SUMMARY_CHARS: usize = 300;

#[derive(Debug, Default)]
pub struct NvdPage {
    pub total_results: u64,
    pub results_per_page: u64,
    pub start_index: u64,
    /// Jumlah CVE di halaman (termasuk yang tidak menyentuh produk terkurasi).
    pub cve_count: usize,
    pub entries: Vec<NvdEntry>,
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn metric(cve: &Value) -> (Option<Cvss>, Option<String>) {
    let metrics = match cve.get("metrics") {
        Some(m) => m,
        None => return (None, None),
    };
    for key in [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV40",
        "cvssMetricV2",
    ] {
        let Some(list) = metrics.get(key).and_then(Value::as_array) else {
            continue;
        };
        let pick = list
            .iter()
            .find(|m| str_of(m, "type") == Some("Primary"))
            .or_else(|| list.first());
        let Some(m) = pick else { continue };
        let Some(data) = m.get("cvssData") else {
            continue;
        };
        let Some(score) = data.get("baseScore").and_then(Value::as_f64) else {
            continue;
        };
        let label = str_of(data, "baseSeverity")
            .or_else(|| str_of(m, "baseSeverity"))
            .map(|s| s.to_ascii_lowercase());
        return (
            Some(Cvss {
                score: score as f32,
                vector: str_of(data, "vectorString").map(str::to_string),
            }),
            label,
        );
    }
    (None, None)
}

fn cpe_parts(criteria: &str) -> Option<(String, Vec<&str>)> {
    let parts: Vec<&str> = criteria.split(':').collect();
    if parts.len() < 7 || parts[0] != "cpe" || parts[1] != "2.3" || parts[2] != "a" {
        return None;
    }
    Some((parts[..5].join(":"), parts))
}

fn range_of(parts: &[&str], m: &Value) -> Option<CpeRange> {
    let version = parts[5];
    let update = parts[6];
    let bound = |k: &str| str_of(m, k).map(str::to_string);
    let mut r = CpeRange {
        version: None,
        start_including: bound("versionStartIncluding"),
        start_excluding: bound("versionStartExcluding"),
        end_including: bound("versionEndIncluding"),
        end_excluding: bound("versionEndExcluding"),
    };
    match version {
        "*" => {}
        "-" => return None, // "tidak berlaku": tanpa versi, tidak bisa dicocokkan dengan banner
        v => {
            // versi pra-rilis (rc1, beta) ditulis di kolom update; banner tidak membawanya
            if update != "*" && update != "-" {
                return None;
            }
            r.version = Some(v.to_string());
        }
    }
    Some(r)
}

/// Mengurai satu halaman respons NVD. `products` = awalan CPE terkurasi (`cpe:2.3:a:vendor:produk`).
pub fn parse_page(bytes: &[u8], products: &[&str]) -> Result<NvdPage, String> {
    let root: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let list = root
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| "respons NVD tidak memuat 'vulnerabilities'".to_string())?;
    let mut page = NvdPage {
        total_results: root
            .get("totalResults")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        results_per_page: root
            .get("resultsPerPage")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        start_index: root.get("startIndex").and_then(Value::as_u64).unwrap_or(0),
        cve_count: list.len(),
        entries: Vec::new(),
    };
    for item in list {
        let Some(cve) = item.get("cve") else { continue };
        let Some(id) = str_of(cve, "id") else {
            continue;
        };
        if str_of(cve, "vulnStatus").is_some_and(|s| s.eq_ignore_ascii_case("rejected")) {
            continue;
        }
        let summary: String = cve
            .get("descriptions")
            .and_then(Value::as_array)
            .and_then(|d| d.iter().find(|x| str_of(x, "lang") == Some("en")))
            .and_then(|d| str_of(d, "value"))
            .unwrap_or("")
            .trim()
            .chars()
            .take(MAX_SUMMARY_CHARS)
            .collect();
        let (cvss, severity) = metric(cve);
        let mut cwe: Vec<String> = cve
            .get("weaknesses")
            .and_then(Value::as_array)
            .map(|w| {
                w.iter()
                    .flat_map(|w| {
                        w.get("description")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default()
                    })
                    .filter_map(|d| str_of(&d, "value").map(str::to_string))
                    .filter(|v| v.starts_with("CWE-"))
                    .collect()
            })
            .unwrap_or_default();
        cwe.sort();
        cwe.dedup();
        let mut references: Vec<String> = Vec::new();
        for r in cve
            .get("references")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(u) = str_of(r, "url") {
                let ok = u.starts_with("https://") || u.starts_with("http://");
                if ok && !references.iter().any(|x| x == u) && references.len() < MAX_REFERENCES {
                    references.push(u.to_string());
                }
            }
        }
        let modified = str_of(cve, "lastModified").unwrap_or("").to_string();

        let mut by_product: BTreeMap<String, Vec<CpeRange>> = BTreeMap::new();
        let mut stack: Vec<&Value> = Vec::new();
        for conf in cve
            .get("configurations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            stack.extend(
                conf.get("nodes")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            );
        }
        while let Some(node) = stack.pop() {
            stack.extend(
                node.get("children")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            );
            for m in node
                .get("cpeMatch")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if m.get("vulnerable").and_then(Value::as_bool) != Some(true) {
                    continue;
                }
                let Some(criteria) = str_of(m, "criteria") else {
                    continue;
                };
                let Some((prefix, parts)) = cpe_parts(criteria) else {
                    continue;
                };
                if !products.contains(&prefix.as_str()) {
                    continue;
                }
                if let Some(r) = range_of(&parts, m) {
                    let list = by_product
                        .entry(crate::products::canonical_cpe(&prefix).to_string())
                        .or_default();
                    if !list.contains(&r) {
                        list.push(r);
                    }
                }
            }
        }
        for (product, mut matches) in by_product {
            matches.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
            page.entries.push(NvdEntry {
                product,
                id: id.to_string(),
                summary: summary.clone(),
                cvss: cvss.clone(),
                severity: severity.clone(),
                cwe: cwe.clone(),
                matches,
                references: references.clone(),
                modified: modified.clone(),
            });
        }
    }
    page.entries
        .sort_by(|a, b| (&a.product, &a.id).cmp(&(&b.product, &b.id)));
    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"{
      "resultsPerPage": 2, "startIndex": 0, "totalResults": 2,
      "vulnerabilities": [
        {"cve": {
          "id": "CVE-2021-41773",
          "vulnStatus": "Analyzed",
          "lastModified": "2023-11-07T03:38:00.000",
          "descriptions": [{"lang":"es","value":"hola"},{"lang":"en","value":"Path traversal in Apache HTTP Server 2.4.49"}],
          "metrics": {
            "cvssMetricV2": [{"baseSeverity":"HIGH","cvssData":{"baseScore":4.3,"vectorString":"AV:N/AC:M/Au:N/C:N/I:P/A:N"}}],
            "cvssMetricV31": [{"type":"Primary","cvssData":{"baseScore":7.5,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","baseSeverity":"HIGH"}}]
          },
          "weaknesses": [{"description":[{"lang":"en","value":"CWE-22"},{"lang":"en","value":"NVD-CWE-Other"}]}],
          "configurations": [{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
             {"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
             {"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"},
             {"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.51:rc1:*:*:*:*:*:*"},
             {"vulnerable":false,"criteria":"cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*"},
             {"vulnerable":true,"criteria":"cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*"}
          ]}]}],
          "references": [{"url":"https://httpd.apache.org/security/vulnerabilities_24.html"},{"url":"javascript:alert(1)"}]
        }},
        {"cve": {
          "id": "CVE-2022-0001",
          "descriptions": [{"lang":"en","value":"nginx heap bug"}],
          "metrics": {},
          "configurations": [{"nodes":[{"operator":"OR","cpeMatch":[
             {"vulnerable":true,"criteria":"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0.0","versionEndExcluding":"1.20.2"}
          ]}]}]
        }},
        {"cve": {"id":"CVE-2022-0002","vulnStatus":"Rejected","descriptions":[],"configurations":[]}}
      ]}"#;

    #[test]
    fn parses_curated_products_only() {
        let page = parse_page(
            PAGE.as_bytes(),
            &["cpe:2.3:a:apache:http_server", "cpe:2.3:a:nginx:nginx"],
        )
        .unwrap();
        assert_eq!(page.total_results, 2);
        assert_eq!(page.cve_count, 3);
        assert_eq!(page.entries.len(), 2);
        let a = &page.entries[0];
        assert_eq!(a.product, "cpe:2.3:a:apache:http_server");
        assert_eq!(a.id, "CVE-2021-41773");
        assert_eq!(a.summary, "Path traversal in Apache HTTP Server 2.4.49");
        assert_eq!(a.cvss.as_ref().unwrap().score, 7.5);
        assert!(a
            .cvss
            .as_ref()
            .unwrap()
            .vector
            .as_ref()
            .unwrap()
            .starts_with("CVSS:3.1/"));
        assert_eq!(a.severity.as_deref(), Some("high"));
        assert_eq!(a.cwe, ["CWE-22"]);
        assert_eq!(
            a.references,
            ["https://httpd.apache.org/security/vulnerabilities_24.html"]
        );
        // rc1 dan produk lain / cpe non-vulnerable dibuang
        assert_eq!(a.matches.len(), 2);
        assert!(a.affects("2.4.49"));
        assert!(a.affects("2.4.50"));
        assert!(!a.affects("2.4.51"));
        let n = &page.entries[1];
        assert_eq!(n.product, "cpe:2.3:a:nginx:nginx");
        assert!(n.cvss.is_none());
        assert!(n.affects("1.18.0"));
        assert!(!n.affects("1.20.2"));
        assert!(!n.affects("0.9.0"));
    }

    #[test]
    fn falls_back_to_v2_metric() {
        let src = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2010-1","descriptions":[],
          "metrics":{"cvssMetricV2":[{"baseSeverity":"MEDIUM","cvssData":{"baseScore":5.0,"vectorString":"AV:N/AC:L/Au:N/C:N/I:N/A:P"}}]},
          "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*","versionEndIncluding":"5.3.0"}]}]}]}}]}"#;
        let page = parse_page(src.as_bytes(), &["cpe:2.3:a:php:php"]).unwrap();
        assert_eq!(page.entries[0].cvss.as_ref().unwrap().score, 5.0);
        assert_eq!(page.entries[0].severity.as_deref(), Some("medium"));
        assert!(page.entries[0].affects("5.3.0"));
        assert!(!page.entries[0].affects("5.3.1"));
    }

    #[test]
    fn alternative_cpe_prefixes_are_normalised_and_merged() {
        // NVD mencatat nginx modern di bawah f5:nginx; satu CVE bisa memuat keduanya.
        let src = r#"{"vulnerabilities":[
          {"cve":{"id":"CVE-2021-23017","descriptions":[{"lang":"en","value":"nginx resolver"}],
            "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":7.7,"vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H","baseSeverity":"HIGH"}}]},
            "configurations":[{"nodes":[{"operator":"OR","cpeMatch":[
              {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:open_source:*:*:*","versionStartIncluding":"0.6.18","versionEndExcluding":"1.20.1"},
              {"vulnerable":true,"criteria":"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*","versionStartIncluding":"1.21.0","versionEndExcluding":"1.21.0"},
              {"vulnerable":true,"criteria":"cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"}]}]}]}}]}"#;
        let all = crate::products::cpe_prefixes();
        let page = parse_page(src.as_bytes(), &all).unwrap();
        assert_eq!(page.entries.len(), 1, "satu entri per (produk utama, CVE)");
        let e = &page.entries[0];
        assert_eq!(e.product, "cpe:2.3:a:nginx:nginx");
        assert_eq!(e.matches.len(), 3);
        assert!(e.affects("1.18.0"));
        assert!(!e.affects("1.20.1"));
        assert_eq!(e.fixed_for("1.18.0"), ["1.20.1"]);
    }

    #[test]
    fn invalid_pages_are_errors() {
        assert!(parse_page(b"nope", &[]).is_err());
        assert!(parse_page(b"{}", &[]).is_err());
    }
}
