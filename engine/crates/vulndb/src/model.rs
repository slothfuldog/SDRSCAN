//! Model advisory (OSV) dan entri produk (NVD) beserta pencocokan versi.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use sdrscan_core::Severity;
use serde::{Deserialize, Serialize};

pub use sdrscan_core::Cvss;

use crate::cvss::{severity_from_label, severity_from_score};
use crate::ecosystem::Ecosystem;
use crate::version::{sort_versions, Scheme, Version};

pub const MAX_REFERENCES: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RangeKind {
    #[serde(rename = "SEMVER")]
    Semver,
    #[serde(rename = "ECOSYSTEM")]
    Ecosystem,
}

/// Peristiwa rentang OSV; bentuk JSON persis OSV: `{"introduced":"0"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
}

impl Event {
    fn value(&self) -> &str {
        match self {
            Event::Introduced(v) | Event::Fixed(v) | Event::LastAffected(v) | Event::Limit(v) => v,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Event::Introduced(_) => 0,
            Event::LastAffected(_) => 1,
            Event::Fixed(_) => 2,
            Event::Limit(_) => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub kind: RangeKind,
    pub events: Vec<Event>,
}

impl Range {
    /// Algoritma OSV: peristiwa diurut menurut versi; `introduced` menyalakan, `fixed` dan
    /// `last_affected` mematikan. Peristiwa dengan versi tak terbaca dilewati; versi terpasang
    /// tak terbaca -> tidak terdampak.
    pub fn affects(&self, scheme: Scheme, installed: &Version) -> bool {
        let mut events: Vec<(Version, &Event)> = self
            .events
            .iter()
            .filter(|e| !matches!(e, Event::Limit(_)))
            .filter_map(|e| Version::parse(scheme, e.value()).map(|v| (v, e)))
            .collect();
        events.sort_by(|(va, ea), (vb, eb)| va.cmp(vb).then(ea.rank().cmp(&eb.rank())));
        let mut affected = false;
        for (v, e) in &events {
            match e {
                Event::Introduced(_) => {
                    if v.is_zero() || installed >= v {
                        affected = true;
                    }
                }
                Event::Fixed(_) => {
                    if installed >= v {
                        affected = false;
                    }
                }
                Event::LastAffected(_) => {
                    if installed > v {
                        affected = false;
                    }
                }
                Event::Limit(_) => {}
            }
        }
        affected
    }
}

fn skip_none<T>(o: &Option<T>) -> bool {
    o.is_none()
}

/// Satu advisory untuk satu paket (satu baris di `osv/<Ekosistem>.jsonl`). `package` harus
/// field pertama: pembaca memfilter baris dari awalan `{"package":"<nama>"` tanpa mengurai JSON penuh.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advisory {
    pub package: String,
    pub ecosystem: Ecosystem,
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default, skip_serializing_if = "skip_none")]
    pub cvss: Option<Cvss>,
    /// Severity kualitatif dari sumber: low, medium, high, critical.
    #[serde(default, skip_serializing_if = "skip_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<Range>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub modified: String,
    #[serde(default, skip_serializing_if = "skip_none")]
    pub withdrawn: Option<String>,
}

pub(crate) fn severity_of(cvss: &Option<Cvss>, label: &Option<String>) -> Severity {
    if let Some(c) = cvss {
        return severity_from_score(c.score);
    }
    label
        .as_deref()
        .and_then(severity_from_label)
        .unwrap_or(Severity::Medium)
}

impl Advisory {
    /// True bila `installed` ada di daftar `versions` atau di salah satu rentang; advisory yang ditarik tidak cocok.
    pub fn affects(&self, installed: &str) -> bool {
        if self.withdrawn.is_some() {
            return false;
        }
        let scheme = self.ecosystem.scheme();
        let Some(v) = Version::parse(scheme, installed) else {
            return false;
        };
        if self
            .versions
            .iter()
            .any(|x| Version::parse(scheme, x).is_some_and(|x| x == v))
        {
            return true;
        }
        self.ranges.iter().any(|r| r.affects(scheme, &v))
    }

    /// Versi perbaikan yang relevan bagi `installed`: tiap rentang yang memuatnya menyumbang versi
    /// `fixed` terkecil di atasnya. Bila tak ada, semua `fixed` yang lebih tinggi dari versi terpasang.
    pub fn fixed_for(&self, installed: &str) -> Vec<String> {
        let scheme = self.ecosystem.scheme();
        let Some(v) = Version::parse(scheme, installed) else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for r in self.ranges.iter().filter(|r| r.affects(scheme, &v)) {
            let next = r
                .events
                .iter()
                .filter_map(|e| match e {
                    Event::Fixed(f) => Version::parse(scheme, f).map(|pv| (pv, f)),
                    _ => None,
                })
                .filter(|(pv, _)| *pv > v)
                .min_by(|a, b| a.0.cmp(&b.0));
            if let Some((_, f)) = next {
                out.push(f.clone());
            }
        }
        if out.is_empty() {
            out = self
                .fixed
                .iter()
                .filter(|f| Version::parse(scheme, f).is_some_and(|pv| pv > v))
                .cloned()
                .collect();
        }
        out.sort();
        out.dedup();
        sort_versions(scheme, &mut out);
        out
    }

    pub fn severity(&self) -> Severity {
        severity_of(&self.cvss, &self.severity)
    }

    /// `id` lalu `aliases`, tanpa duplikat.
    pub fn all_ids(&self) -> Vec<&str> {
        let mut out: Vec<&str> = vec![self.id.as_str()];
        for a in &self.aliases {
            if !out.contains(&a.as_str()) {
                out.push(a);
            }
        }
        out
    }
}

/// Peringkat id untuk urutan tampilan: CVE, lalu GHSA, lalu lainnya.
fn id_rank(id: &str) -> u8 {
    let up = id.to_ascii_uppercase();
    if up.starts_with("CVE-") {
        0
    } else if up.starts_with("GHSA-") {
        1
    } else {
        2
    }
}

pub fn order_ids(ids: &mut [String]) {
    ids.sort_by(|a, b| id_rank(a).cmp(&id_rank(b)).then_with(|| a.cmp(b)));
}

/// Advisory yang sudah digabung: advisory berbeda sumber (GHSA, PKSA, CVE, ...) yang saling beralias menjadi satu.
#[derive(Debug, Clone, PartialEq)]
pub struct MergedAdvisory {
    /// CVE dulu, lalu GHSA, lalu id lain; tiap kelompok urut abjad.
    pub ids: Vec<String>,
    pub summary: String,
    pub cvss: Option<Cvss>,
    pub severity: Severity,
    pub fixed_versions: Vec<String>,
    pub references: Vec<String>,
    pub cwe: Vec<String>,
}

impl MergedAdvisory {
    /// ID CVE pertama bila ada, jika tidak id pertama.
    pub fn rule_id(&self) -> &str {
        &self.ids[0]
    }
}

/// Menggabungkan advisory yang beririsan id/aliasnya. Hasil urut menurut `rule_id` (deterministik).
pub fn merge_advisories(advisories: Vec<Advisory>, installed: &str) -> Vec<MergedAdvisory> {
    let n = advisories.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while p[r] != r {
            r = p[r];
        }
        let mut c = x;
        while p[c] != r {
            let next = p[c];
            p[c] = r;
            c = next;
        }
        r
    }
    let mut owner: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, a) in advisories.iter().enumerate() {
        for id in a.all_ids() {
            let key = id.to_ascii_uppercase();
            match owner.get(&key) {
                Some(&j) => {
                    let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                    if ri != rj {
                        parent[ri.max(rj)] = ri.min(rj);
                    }
                }
                None => {
                    owner.insert(key, i);
                }
            }
        }
    }
    let mut groups: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }

    let mut out: Vec<MergedAdvisory> = Vec::new();
    for members in groups.values() {
        let mut members: Vec<&Advisory> = members.iter().map(|&i| &advisories[i]).collect();
        // Sumber pilihan: GHSA dulu (ringkasan terawat), lalu id terkecil.
        members.sort_by(|a, b| {
            let pref = |x: &Advisory| u8::from(!x.id.starts_with("GHSA-"));
            pref(a).cmp(&pref(b)).then_with(|| a.id.cmp(&b.id))
        });
        let mut ids: Vec<String> = Vec::new();
        let mut refs: Vec<String> = Vec::new();
        let mut fixed: Vec<String> = Vec::new();
        let mut cwe: BTreeSet<String> = BTreeSet::new();
        let mut cvss: Option<Cvss> = None;
        let mut label: Option<(Severity, String)> = None;
        let mut summary = String::new();
        for a in &members {
            for id in a.all_ids() {
                if !ids.iter().any(|x| x.eq_ignore_ascii_case(id)) {
                    ids.push(id.to_string());
                }
            }
            if summary.is_empty() && !a.summary.trim().is_empty() {
                summary = a.summary.trim().to_string();
            }
            for r in &a.references {
                if !refs.contains(r) {
                    refs.push(r.clone());
                }
            }
            fixed.extend(a.fixed_for(installed));
            cwe.extend(a.cwe.iter().cloned());
            if let Some(c) = &a.cvss {
                if cvss.as_ref().is_none_or(|b| c.score > b.score) {
                    cvss = Some(c.clone());
                }
            }
            if let Some(l) = &a.severity {
                if let Some(s) = severity_from_label(l) {
                    if label.as_ref().is_none_or(|(b, _)| s > *b) {
                        label = Some((s, l.clone()));
                    }
                }
            }
        }
        order_ids(&mut ids);
        refs.truncate(MAX_REFERENCES);
        fixed.sort();
        fixed.dedup();
        sort_versions(members[0].ecosystem.scheme(), &mut fixed);
        let severity = match (&cvss, &label) {
            (Some(c), _) => severity_from_score(c.score),
            (None, Some((s, _))) => *s,
            _ => Severity::Medium,
        };
        out.push(MergedAdvisory {
            ids,
            summary,
            cvss,
            severity,
            fixed_versions: fixed,
            references: refs,
            cwe: cwe.into_iter().collect(),
        });
    }
    out.sort_by(|a, b| a.ids.cmp(&b.ids));
    out
}

/// Hasil pencarian paket: advisory yang mencakup `version` dari paket `name`.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageHit {
    pub name: String,
    pub version: String,
    pub advisory: Advisory,
}

/// Satu rentang versi CPE NVD. `version` = versi persis; selain itu batas rentang
/// (semua kosong = semua versi).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpeRange {
    #[serde(default, skip_serializing_if = "skip_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "skip_none")]
    pub start_including: Option<String>,
    #[serde(default, skip_serializing_if = "skip_none")]
    pub start_excluding: Option<String>,
    #[serde(default, skip_serializing_if = "skip_none")]
    pub end_including: Option<String>,
    #[serde(default, skip_serializing_if = "skip_none")]
    pub end_excluding: Option<String>,
}

impl CpeRange {
    pub fn affects(&self, installed: &Version) -> bool {
        let parse = |s: &String| Version::parse(Scheme::Loose, s);
        let check = |bound: &Option<String>, ok: &dyn Fn(Ordering) -> bool| -> bool {
            match bound {
                None => true,
                Some(b) => parse(b).is_some_and(|b| ok(installed.cmp(&b))),
            }
        };
        if let Some(v) = &self.version {
            return parse(v).is_some_and(|v| v == *installed);
        }
        check(&self.start_including, &|o| o != Ordering::Less)
            && check(&self.start_excluding, &|o| o == Ordering::Greater)
            && check(&self.end_including, &|o| o != Ordering::Greater)
            && check(&self.end_excluding, &|o| o == Ordering::Less)
    }
}

/// Satu CVE untuk satu produk CPE (satu baris di `nvd/products.jsonl`). `product` field pertama.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NvdEntry {
    /// Awalan CPE `cpe:2.3:a:<vendor>:<produk>`.
    pub product: String,
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default, skip_serializing_if = "skip_none")]
    pub cvss: Option<Cvss>,
    #[serde(default, skip_serializing_if = "skip_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    pub matches: Vec<CpeRange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default)]
    pub modified: String,
}

impl NvdEntry {
    pub fn affects(&self, installed: &str) -> bool {
        Version::parse(Scheme::Loose, installed)
            .is_some_and(|v| self.matches.iter().any(|m| m.affects(&v)))
    }

    /// `versionEndExcluding` dari rentang yang memuat versi terpasang (umumnya versi perbaikan).
    pub fn fixed_for(&self, installed: &str) -> Vec<String> {
        let Some(v) = Version::parse(Scheme::Loose, installed) else {
            return Vec::new();
        };
        let mut out: Vec<String> = self
            .matches
            .iter()
            .filter(|m| m.affects(&v))
            .filter_map(|m| m.end_excluding.clone())
            .collect();
        out.sort();
        out.dedup();
        sort_versions(Scheme::Loose, &mut out);
        out
    }

    pub fn severity(&self) -> Severity {
        severity_of(&self.cvss, &self.severity)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProductHit {
    pub entry: NvdEntry,
    pub fixed: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adv(eco: Ecosystem, events: &[Event], versions: &[&str]) -> Advisory {
        Advisory {
            package: "p".into(),
            ecosystem: eco,
            id: "GHSA-xxxx-yyyy-zzzz".into(),
            aliases: vec!["CVE-2024-0001".into()],
            summary: "uji".into(),
            cvss: None,
            severity: None,
            ranges: vec![Range {
                kind: RangeKind::Semver,
                events: events.to_vec(),
            }],
            versions: versions.iter().map(|s| s.to_string()).collect(),
            fixed: Vec::new(),
            references: Vec::new(),
            cwe: Vec::new(),
            modified: String::new(),
            withdrawn: None,
        }
    }

    fn i(s: &str) -> Event {
        Event::Introduced(s.into())
    }
    fn f(s: &str) -> Event {
        Event::Fixed(s.into())
    }
    fn la(s: &str) -> Event {
        Event::LastAffected(s.into())
    }

    #[test]
    fn introduced_fixed_boundaries() {
        let a = adv(Ecosystem::Npm, &[i("1.0.0"), f("1.5.0")], &[]);
        assert!(!a.affects("0.9.9"));
        assert!(a.affects("1.0.0"));
        assert!(a.affects("1.4.99"));
        assert!(!a.affects("1.5.0"));
        assert!(!a.affects("2.0.0"));
    }

    #[test]
    fn introduced_zero_covers_everything_below_fix() {
        let a = adv(Ecosystem::Npm, &[i("0"), f("2.1.0")], &[]);
        assert!(a.affects("0.0.1"));
        assert!(a.affects("2.0.9"));
        assert!(!a.affects("2.1.0"));
        assert!(a.affects("1.0.0-beta.1"));
    }

    #[test]
    fn last_affected_is_inclusive() {
        let a = adv(Ecosystem::CratesIo, &[i("0"), la("1.2.3")], &[]);
        assert!(a.affects("1.2.3"));
        assert!(!a.affects("1.2.4"));
    }

    #[test]
    fn open_ended_range_affects_all_later_versions() {
        let a = adv(Ecosystem::Go, &[i("1.2.0")], &[]);
        assert!(!a.affects("v1.1.9"));
        assert!(a.affects("v1.2.0"));
        assert!(a.affects("v9.9.9"));
    }

    #[test]
    fn multiple_intervals_in_one_range_and_unsorted_events() {
        let a = adv(
            Ecosystem::Npm,
            &[f("2.5.0"), i("2.0.0"), f("1.5.0"), i("0")],
            &[],
        );
        assert!(a.affects("1.4.0"));
        assert!(!a.affects("1.5.0"));
        assert!(!a.affects("1.9.9"));
        assert!(a.affects("2.0.0"));
        assert!(a.affects("2.4.9"));
        assert!(!a.affects("2.5.0"));
    }

    #[test]
    fn several_ranges_are_ored() {
        let mut a = adv(Ecosystem::Npm, &[i("0"), f("1.0.0")], &[]);
        a.ranges.push(Range {
            kind: RangeKind::Semver,
            events: vec![i("3.0.0"), f("3.1.0")],
        });
        assert!(a.affects("0.5.0"));
        assert!(!a.affects("2.0.0"));
        assert!(a.affects("3.0.5"));
        assert!(!a.affects("3.1.0"));
    }

    #[test]
    fn explicit_versions_list() {
        let mut a = adv(Ecosystem::Npm, &[], &["1.0.0", "1.0.1"]);
        a.ranges.clear();
        assert!(a.affects("1.0.1"));
        assert!(a.affects("v1.0.1"));
        assert!(!a.affects("1.0.2"));
    }

    #[test]
    fn no_ranges_and_no_versions_never_matches() {
        let mut a = adv(Ecosystem::Npm, &[], &[]);
        a.ranges.clear();
        assert!(!a.affects("1.0.0"));
    }

    #[test]
    fn withdrawn_never_matches() {
        let mut a = adv(Ecosystem::Npm, &[i("0")], &[]);
        a.withdrawn = Some("2024-01-01T00:00:00Z".into());
        assert!(!a.affects("1.0.0"));
    }

    #[test]
    fn unparsable_installed_version_is_not_affected() {
        let a = adv(Ecosystem::Npm, &[i("0")], &[]);
        assert!(!a.affects("latest"));
        assert!(!a.affects(""));
        let p = adv(Ecosystem::Packagist, &[i("0")], &[]);
        assert!(!p.affects("dev-main"));
    }

    #[test]
    fn unparsable_event_is_skipped_not_fatal() {
        let a = adv(
            Ecosystem::Npm,
            &[i("0"), f("not-a-version"), f("1.0.0")],
            &[],
        );
        assert!(a.affects("0.5.0"));
        assert!(!a.affects("1.0.0"));
    }

    #[test]
    fn composer_ranges_use_composer_ordering() {
        let a = adv(Ecosystem::Packagist, &[i("2.0.0-beta1"), f("2.3.0")], &[]);
        assert!(a.affects("v2.0.0-RC1"));
        assert!(a.affects("2.2.9"));
        assert!(!a.affects("2.3.0"));
        assert!(!a.affects("2.0.0-alpha3"));
    }

    #[test]
    fn go_v_prefix_vs_unprefixed_events() {
        let a = adv(Ecosystem::Go, &[i("0"), f("1.17.4")], &[]);
        assert!(a.affects("v1.17.3"));
        assert!(!a.affects("v1.17.4"));
        assert!(a.affects("v0.0.0-20190101000000-abcdef123456"));
    }

    #[test]
    fn fixed_for_picks_the_range_containing_the_install() {
        let mut a = adv(Ecosystem::Npm, &[i("0"), f("1.5.0")], &[]);
        a.ranges.push(Range {
            kind: RangeKind::Semver,
            events: vec![i("2.0.0"), f("2.0.3")],
        });
        assert_eq!(a.fixed_for("1.2.0"), ["1.5.0"]);
        assert_eq!(a.fixed_for("2.0.1"), ["2.0.3"]);
        assert!(a.fixed_for("3.0.0").is_empty());
    }

    #[test]
    fn fixed_for_falls_back_to_listed_fixed() {
        let mut a = adv(Ecosystem::Npm, &[], &["1.0.0"]);
        a.ranges.clear();
        a.fixed = vec!["1.0.1".into(), "0.9.0".into()];
        assert_eq!(a.fixed_for("1.0.0"), ["1.0.1"]);
    }

    #[test]
    fn merge_groups_aliases_and_orders_ids() {
        let mut ghsa = adv(Ecosystem::Packagist, &[i("0"), f("1.0.1")], &[]);
        ghsa.id = "GHSA-aaaa-bbbb-cccc".into();
        ghsa.aliases = vec!["CVE-2024-1111".into()];
        ghsa.summary = "Ringkasan GHSA".into();
        ghsa.cvss = Some(Cvss {
            score: 7.5,
            vector: None,
        });
        let mut pksa = adv(Ecosystem::Packagist, &[i("0"), f("1.0.1")], &[]);
        pksa.id = "PKSA-1234".into();
        pksa.aliases = vec!["CVE-2024-1111".into()];
        pksa.summary = "Ringkasan PKSA".into();
        let mut other = adv(Ecosystem::Packagist, &[i("0"), f("1.0.2")], &[]);
        other.id = "GHSA-dddd-eeee-ffff".into();
        other.aliases = vec![];
        let merged = merge_advisories(vec![pksa, other, ghsa], "1.0.0");
        assert_eq!(merged.len(), 2);
        assert_eq!(
            merged[0].ids,
            ["CVE-2024-1111", "GHSA-aaaa-bbbb-cccc", "PKSA-1234"]
        );
        assert_eq!(merged[0].summary, "Ringkasan GHSA");
        assert_eq!(merged[0].severity, Severity::High);
        assert_eq!(merged[0].fixed_versions, ["1.0.1"]);
        assert_eq!(merged[1].ids, ["GHSA-dddd-eeee-ffff"]);
        assert_eq!(merged[1].severity, Severity::Medium);
    }

    #[test]
    fn nvd_bounds() {
        let e = NvdEntry {
            product: "cpe:2.3:a:apache:http_server".into(),
            id: "CVE-2021-41773".into(),
            summary: String::new(),
            cvss: None,
            severity: None,
            cwe: vec![],
            matches: vec![
                CpeRange {
                    version: Some("2.4.49".into()),
                    ..Default::default()
                },
                CpeRange {
                    start_including: Some("2.4.0".into()),
                    end_excluding: Some("2.4.10".into()),
                    ..Default::default()
                },
                CpeRange {
                    start_excluding: Some("3.0.0".into()),
                    end_including: Some("3.0.5".into()),
                    ..Default::default()
                },
            ],
            references: vec![],
            modified: String::new(),
        };
        assert!(e.affects("2.4.49"));
        assert!(!e.affects("2.4.50"));
        assert!(e.affects("2.4.0"));
        assert!(e.affects("2.4.9"));
        assert!(!e.affects("2.4.10"));
        assert!(!e.affects("3.0.0"));
        assert!(e.affects("3.0.1"));
        assert!(e.affects("3.0.5"));
        assert!(!e.affects("3.0.6"));
        assert!(!e.affects("garbage"));
        assert_eq!(e.fixed_for("2.4.5"), ["2.4.10"]);
    }

    #[test]
    fn nvd_unbounded_range_means_all_versions() {
        let e = NvdEntry {
            product: "p".into(),
            id: "CVE-1".into(),
            summary: String::new(),
            cvss: None,
            severity: None,
            cwe: vec![],
            matches: vec![CpeRange::default()],
            references: vec![],
            modified: String::new(),
        };
        assert!(e.affects("1.0"));
    }

    #[test]
    fn advisory_json_roundtrip_has_package_first() {
        let a = adv(Ecosystem::Npm, &[i("0"), f("1.0.0")], &[]);
        let line = serde_json::to_string(&a).unwrap();
        assert!(
            line.starts_with(r#"{"package":"p","ecosystem":"npm","id":"#),
            "{line}"
        );
        assert!(
            line.contains(r#"{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}"#)
        );
        let back: Advisory = serde_json::from_str(&line).unwrap();
        assert_eq!(back, a);
    }
}
