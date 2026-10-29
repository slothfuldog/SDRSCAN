//! Pengolah satu berkas advisory OSV (JSON) menjadi `Advisory` per paket.
//! Hanya membaca data: tidak ada konten unduhan yang dijalankan.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::cvss::{score_v3, severity_from_label};
use crate::ecosystem::Ecosystem;
use crate::model::{Advisory, Cvss, Event, Range, RangeKind, MAX_REFERENCES};
use crate::version::{sort_versions, Version};

const MAX_SUMMARY_CHARS: usize = 300;
const MAX_VERSIONS: usize = 5000;

#[derive(Deserialize)]
struct OsvRecord {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    database_specific: Option<Value>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize)]
struct OsvReference {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    url: String,
}

#[derive(Deserialize)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<BTreeMap<String, String>>,
}

fn first_line_summary(summary: Option<&str>, details: Option<&str>) -> String {
    let text = summary
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            details
                .and_then(|d| d.lines().map(str::trim).find(|l| !l.is_empty()))
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("");
    text.chars().take(MAX_SUMMARY_CHARS).collect()
}

fn pick_references(refs: &[OsvReference]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |url: &str| {
        let ok = url.starts_with("https://") || url.starts_with("http://");
        if ok && !out.iter().any(|u| u == url) && out.len() < MAX_REFERENCES {
            out.push(url.to_string());
        }
    };
    for r in refs.iter().filter(|r| {
        r.kind
            .as_deref()
            .is_some_and(|k| k.eq_ignore_ascii_case("ADVISORY"))
    }) {
        push(&r.url);
    }
    for r in refs {
        push(&r.url);
    }
    out
}

fn qualitative(db: &Option<Value>) -> Option<String> {
    let label = db.as_ref()?.get("severity")?.as_str()?;
    severity_from_label(label).map(|s| s.as_str().to_string())
}

fn cwes(db: &Option<Value>) -> Vec<String> {
    let mut out: Vec<String> = db
        .as_ref()
        .and_then(|d| d.get("cwe_ids"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter(|s| s.to_ascii_uppercase().starts_with("CWE-"))
                .map(|s| s.to_ascii_uppercase())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

fn cvss_of(sev: &[OsvSeverity]) -> Option<Cvss> {
    sev.iter()
        .filter(|s| s.kind == "CVSS_V3" || s.score.starts_with("CVSS:3"))
        .find_map(|s| {
            score_v3(&s.score).map(|score| Cvss {
                score,
                vector: Some(s.score.trim().to_string()),
            })
        })
}

/// Mengurai satu advisory OSV dan mengembalikan satu `Advisory` per paket di ekosistem `eco`
/// (kosong bila tidak ada). Advisory malware (`MAL-`) dilewati. Galat bila JSON tidak valid.
pub fn parse_record(bytes: &[u8], eco: Ecosystem) -> Result<Vec<Advisory>, String> {
    let rec: OsvRecord = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if rec.id.trim().is_empty() {
        return Err("id kosong".to_string());
    }
    if rec.id.starts_with("MAL-") {
        return Ok(Vec::new());
    }
    let cvss = cvss_of(&rec.severity);
    let severity = qualitative(&rec.database_specific);
    let cwe = cwes(&rec.database_specific);
    let summary = first_line_summary(rec.summary.as_deref(), rec.details.as_deref());
    let references = pick_references(&rec.references);
    let mut aliases: Vec<String> = rec
        .aliases
        .iter()
        .filter(|a| !a.is_empty() && **a != rec.id)
        .cloned()
        .collect();
    aliases.sort();
    aliases.dedup();

    let mut by_pkg: BTreeMap<String, Advisory> = BTreeMap::new();
    for aff in &rec.affected {
        let Some(pkg) = &aff.package else { continue };
        if pkg.ecosystem != eco.as_str() {
            continue;
        }
        let name = eco.normalize_name(pkg.name.trim());
        if name.is_empty() {
            continue;
        }
        let adv = by_pkg.entry(name.clone()).or_insert_with(|| Advisory {
            package: name,
            ecosystem: eco,
            id: rec.id.clone(),
            aliases: aliases.clone(),
            summary: summary.clone(),
            cvss: cvss.clone(),
            severity: severity.clone(),
            ranges: Vec::new(),
            versions: Vec::new(),
            fixed: Vec::new(),
            references: references.clone(),
            cwe: cwe.clone(),
            modified: rec.modified.clone().unwrap_or_default(),
            withdrawn: rec.withdrawn.clone().filter(|w| !w.is_empty()),
        });
        for r in &aff.ranges {
            let kind = match r.kind.as_str() {
                "SEMVER" => RangeKind::Semver,
                "ECOSYSTEM" => RangeKind::Ecosystem,
                _ => continue, // GIT: rentang berbasis commit tidak dapat dicocokkan dengan versi paket
            };
            let mut events = Vec::new();
            for ev in &r.events {
                for (k, v) in ev {
                    let v = v.trim().to_string();
                    match k.as_str() {
                        "introduced" => events.push(Event::Introduced(v)),
                        "fixed" => {
                            adv.fixed.push(v.clone());
                            events.push(Event::Fixed(v));
                        }
                        "last_affected" => events.push(Event::LastAffected(v)),
                        "limit" => events.push(Event::Limit(v)),
                        _ => {}
                    }
                }
            }
            if !events.is_empty() {
                adv.ranges.push(Range { kind, events });
            }
        }
        adv.versions.extend(aff.versions.iter().cloned());
    }

    let mut out: Vec<Advisory> = by_pkg.into_values().collect();
    for a in &mut out {
        a.fixed.sort();
        a.fixed.dedup();
        sort_versions(eco.scheme(), &mut a.fixed);
        a.versions.sort();
        a.versions.dedup();
        // Daftar versi enumerasi yang sudah tercakup rentang hanya menggembungkan basis data.
        if !a.ranges.is_empty() {
            let scheme = eco.scheme();
            let ranges = a.ranges.clone();
            a.versions.retain(|v| {
                Version::parse(scheme, v)
                    .is_none_or(|pv| !ranges.iter().any(|r| r.affects(scheme, &pv)))
            });
        }
        a.versions.truncate(MAX_VERSIONS);
        a.ranges.dedup();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GHSA: &str = r#"{
      "schema_version": "1.6.0",
      "id": "GHSA-aaaa-bbbb-cccc",
      "modified": "2024-05-01T10:00:00Z",
      "published": "2024-04-01T10:00:00Z",
      "aliases": ["CVE-2024-0001", "CVE-2024-0001"],
      "summary": "Prototype pollution di lodash",
      "details": "Baris pertama\nBaris kedua",
      "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
      "affected": [
        {"package":{"ecosystem":"npm","name":"lodash"},
         "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}],
         "versions":["4.17.19","4.17.20", "9.9.9"]},
        {"package":{"ecosystem":"PyPI","name":"lodash"},"versions":["1.0"]}
      ],
      "references":[
        {"type":"WEB","url":"https://example.com/a"},
        {"type":"ADVISORY","url":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc"},
        {"type":"WEB","url":"ftp://bad.example/x"},
        {"type":"WEB","url":"https://example.com/b"}
      ],
      "database_specific": {"severity":"MODERATE","cwe_ids":["CWE-1321","cwe-79"]}
    }"#;

    #[test]
    fn parses_ghsa_for_matching_ecosystem_only() {
        let out = parse_record(GHSA.as_bytes(), Ecosystem::Npm).unwrap();
        assert_eq!(out.len(), 1);
        let a = &out[0];
        assert_eq!(a.package, "lodash");
        assert_eq!(a.id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(a.aliases, ["CVE-2024-0001"]);
        assert_eq!(a.summary, "Prototype pollution di lodash");
        assert_eq!(a.cvss.as_ref().unwrap().score, 9.8);
        assert_eq!(a.severity.as_deref(), Some("medium"));
        assert_eq!(a.fixed, ["4.17.21"]);
        assert_eq!(a.cwe, ["CWE-1321", "CWE-79"]);
        assert_eq!(a.modified, "2024-05-01T10:00:00Z");
        // advisory ADVISORY didahulukan, url non-http dibuang
        assert_eq!(
            a.references,
            [
                "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                "https://example.com/a",
                "https://example.com/b"
            ]
        );
        // versi enumerasi yang sudah tercakup rentang dibuang; yang di luar tetap
        assert_eq!(a.versions, ["9.9.9"]);
        assert!(a.affects("4.17.20"));
        assert!(!a.affects("4.17.21"));
        assert!(parse_record(GHSA.as_bytes(), Ecosystem::Go)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn packagist_names_are_lowercased_and_details_fill_summary() {
        let src = r#"{"id":"GHSA-x","modified":"2024-01-01T00:00:00Z","details":"\n\nRingkasan dari details",
          "affected":[{"package":{"ecosystem":"Packagist","name":"Vendor/Pkg"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"1.2"}]}]}]}"#;
        let out = parse_record(src.as_bytes(), Ecosystem::Packagist).unwrap();
        assert_eq!(out[0].package, "vendor/pkg");
        assert_eq!(out[0].summary, "Ringkasan dari details");
        assert!(out[0].cvss.is_none());
        assert!(out[0].affects("v1.1.0"));
    }

    #[test]
    fn multiple_affected_entries_for_one_package_are_merged() {
        let src = r#"{"id":"GHSA-m","modified":"2024-01-01T00:00:00Z","summary":"s",
          "affected":[
            {"package":{"ecosystem":"crates.io","name":"tokio"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.1.0"},{"fixed":"0.1.5"}]}]},
            {"package":{"ecosystem":"crates.io","name":"tokio"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.0.3"}]}]}]}"#;
        let out = parse_record(src.as_bytes(), Ecosystem::CratesIo).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ranges.len(), 2);
        assert_eq!(out[0].fixed, ["0.1.5", "1.0.3"]);
        assert!(out[0].affects("1.0.2"));
        assert!(!out[0].affects("0.5.0"));
    }

    #[test]
    fn git_ranges_and_malware_and_garbage_are_handled() {
        let git = r#"{"id":"X-1","affected":[{"package":{"ecosystem":"Go","name":"m"},
          "ranges":[{"type":"GIT","repo":"https://x","events":[{"introduced":"0"},{"fixed":"abcdef"}]}]}]}"#;
        let out = parse_record(git.as_bytes(), Ecosystem::Go).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].ranges.is_empty());
        assert!(!out[0].affects("1.0.0"));

        let mal = r#"{"id":"MAL-2024-1","affected":[{"package":{"ecosystem":"npm","name":"evil"},"versions":["1.0.0"]}]}"#;
        assert!(parse_record(mal.as_bytes(), Ecosystem::Npm)
            .unwrap()
            .is_empty());

        assert!(parse_record(b"{ not json", Ecosystem::Npm).is_err());
        assert!(parse_record(b"{\"id\":\"\"}", Ecosystem::Npm).is_err());
        assert!(parse_record(b"[]", Ecosystem::Npm).is_err());
    }

    #[test]
    fn withdrawn_is_kept_but_never_matches() {
        let src = r#"{"id":"GHSA-w","withdrawn":"2024-02-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"p"},
          "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}"#;
        let out = parse_record(src.as_bytes(), Ecosystem::Npm).unwrap();
        assert_eq!(out[0].withdrawn.as_deref(), Some("2024-02-02T00:00:00Z"));
        assert!(!out[0].affects("1.0.0"));
    }

    #[test]
    fn v4_only_severity_falls_back_to_label() {
        let src = r#"{"id":"GHSA-v4","severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
          "database_specific":{"severity":"HIGH"},
          "affected":[{"package":{"ecosystem":"npm","name":"p"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}"#;
        let out = parse_record(src.as_bytes(), Ecosystem::Npm).unwrap();
        assert!(out[0].cvss.is_none());
        assert_eq!(out[0].severity.as_deref(), Some("high"));
        assert_eq!(out[0].severity(), sdrscan_core::Severity::High);
    }
}
