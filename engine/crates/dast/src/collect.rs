//! Pengumpul hasil multi-halaman: dedupe temuan (satu per aturan dan bukti ternormalisasi), daftar
//! halaman yang dipindai, dan peringatan unik.

use std::collections::{HashMap, HashSet};

use sdrscan_core::finding::MULTI_PAGE_MARKER;
use sdrscan_core::{Finding, Warning};

/// Daftar URL "berlaku juga di" dibatasi sekian.
pub const MAX_LISTED_URLS: usize = 5;

struct Entry {
    finding: Finding,
    others: Vec<String>,
}

#[derive(Default)]
pub struct Collector {
    entries: Vec<Entry>,
    index: HashMap<(String, String), usize>,
    pages: Vec<String>,
    page_set: HashSet<String>,
    warnings: Vec<Warning>,
    warning_keys: HashSet<(String, String)>,
}

fn normalize_evidence(rule_id: &str, snippet: &str) -> String {
    let n = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    // Bukti transport memuat URL halaman; temuan yang sama untuk semua halaman http digabung.
    if rule_id == "dast-insecure-transport" && n.starts_with("URL: ") {
        return "URL: *".to_string();
    }
    n
}

impl Collector {
    pub fn add_page(&mut self, url: &str) {
        if self.page_set.insert(url.to_string()) {
            self.pages.push(url.to_string());
        }
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn first_page(&self) -> Option<&str> {
        self.pages.first().map(String::as_str)
    }

    pub fn add_findings(&mut self, findings: Vec<Finding>) {
        for f in findings {
            let key = (
                f.rule_id.clone(),
                normalize_evidence(&f.rule_id, &f.snippet),
            );
            match self.index.get(&key) {
                Some(&i) => {
                    let e = &mut self.entries[i];
                    let url = &f.location.path;
                    if *url != e.finding.location.path && !e.others.contains(url) {
                        e.others.push(url.clone());
                    }
                }
                None => {
                    self.index.insert(key, self.entries.len());
                    self.entries.push(Entry {
                        finding: f,
                        others: Vec::new(),
                    });
                }
            }
        }
    }

    pub fn add_warning(&mut self, w: Warning) {
        let key = (format!("{:?}", w.kind), w.message.clone());
        if self.warning_keys.insert(key) {
            self.warnings.push(w);
        }
    }

    /// Temuan urut (rule_id, bukti dasar, lokasi) dan peringatan menurut urutan kemunculan.
    pub fn finish(self) -> (Vec<Finding>, Vec<Warning>, usize) {
        let mut entries = self.entries;
        entries.sort_by(|a, b| {
            (
                &a.finding.rule_id,
                &a.finding.snippet,
                &a.finding.location.path,
            )
                .cmp(&(
                    &b.finding.rule_id,
                    &b.finding.snippet,
                    &b.finding.location.path,
                ))
        });
        let findings = entries
            .into_iter()
            .map(|mut e| {
                if !e.others.is_empty() {
                    let n = e.others.len();
                    let listed = e
                        .others
                        .iter()
                        .take(MAX_LISTED_URLS)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    let more = if n > MAX_LISTED_URLS { ", ..." } else { "" };
                    e.finding.snippet = format!(
                        "{}{MULTI_PAGE_MARKER}{n} halaman lain: {listed}{more})",
                        e.finding.snippet
                    );
                }
                e.finding
            })
            .collect();
        (findings, self.warnings, self.pages.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdrscan_core::{Location, Severity};

    fn f(rule: &str, url: &str, ev: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            severity: Severity::Low,
            message: "m".into(),
            location: Location::url(url),
            snippet: ev.into(),
            vulnerability: None,
        }
    }

    #[test]
    fn merges_same_rule_and_evidence_across_pages() {
        let mut c = Collector::default();
        for i in 0..8 {
            let u = format!("http://h/p{i}");
            c.add_findings(vec![
                f(
                    "dast-missing-csp",
                    &u,
                    "Content-Security-Policy: (tidak ada)",
                ),
                f("dast-insecure-transport", &u, &format!("URL: {u}")),
            ]);
        }
        let (fs, _, _) = c.finish();
        assert_eq!(fs.len(), 2);
        let csp = fs.iter().find(|x| x.rule_id == "dast-missing-csp").unwrap();
        assert_eq!(csp.location.path, "http://h/p0");
        assert!(csp
            .snippet
            .contains("(berlaku juga di 7 halaman lain: http://h/p1,"));
        assert!(csp.snippet.ends_with(", ...)"));
        assert_eq!(csp.snippet.matches("http://h/p").count(), 5);
    }

    #[test]
    fn different_evidence_stays_separate_and_single_page_has_no_suffix() {
        let mut c = Collector::default();
        c.add_findings(vec![f("r", "http://h/a", "e1"), f("r", "http://h/a", "e2")]);
        c.add_findings(vec![f("r", "http://h/b", "e1")]);
        let (fs, _, _) = c.finish();
        assert_eq!(fs.len(), 2);
        assert_eq!(
            fs[0].snippet,
            "e1 (berlaku juga di 1 halaman lain: http://h/b)"
        );
        assert_eq!(fs[1].snippet, "e2");
    }

    #[test]
    fn warnings_are_unique() {
        let mut c = Collector::default();
        let w = Warning {
            kind: sdrscan_core::WarningKind::Crawl,
            message: "x".into(),
            path: None,
            rule_id: None,
            location: None,
            snippet: None,
        };
        c.add_warning(w.clone());
        c.add_warning(w);
        assert_eq!(c.finish().1.len(), 1);
    }
}
