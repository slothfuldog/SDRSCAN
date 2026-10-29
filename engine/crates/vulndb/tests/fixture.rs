//! Basis data fixture yang ditulis tangan (tests/fixtures/vulndb) berfungsi sebagai contoh format di disk.

use std::path::{Path, PathBuf};

use sdrscan_vulndb::{Ecosystem, VulnDb, FORMAT_VERSION};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/vulndb")
}

#[test]
fn fixture_database_opens_and_counts_match_meta() {
    let db = VulnDb::open(&fixture()).unwrap();
    assert_eq!(db.meta().format_version, FORMAT_VERSION);
    assert!(db.has_data() && db.has_nvd());
    let lines = |rel: &str| {
        std::fs::read_to_string(fixture().join(rel))
            .unwrap()
            .lines()
            .count() as u64
    };
    for eco in Ecosystem::ALL {
        assert_eq!(
            db.meta().sources.osv.ecosystems[eco.as_str()].advisories,
            lines(&format!("osv/{}.jsonl", eco.as_str())),
            "{eco}"
        );
    }
    assert_eq!(
        db.meta().sources.nvd.as_ref().unwrap().entries,
        lines("nvd/products.jsonl")
    );
    let total: u64 = db
        .meta()
        .sources
        .osv
        .ecosystems
        .values()
        .map(|e| e.advisories)
        .sum::<u64>()
        + db.meta().sources.nvd.as_ref().unwrap().entries;
    assert_eq!(db.meta().advisory_count, total);
}

#[test]
fn fixture_files_are_sorted_and_lines_reparse() {
    for eco in Ecosystem::ALL {
        let text =
            std::fs::read_to_string(fixture().join(format!("osv/{}.jsonl", eco.as_str()))).unwrap();
        let mut keys = Vec::new();
        for l in text.lines() {
            let a: sdrscan_vulndb::Advisory = serde_json::from_str(l).unwrap();
            assert_eq!(a.ecosystem, eco);
            keys.push((a.package, a.id));
        }
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "{eco}: harus terurut menurut (paket, id)");
    }
}

#[test]
fn lookup_merges_aliases_and_applies_ranges() {
    let db = VulnDb::open(&fixture()).unwrap();
    let (m, corrupt) = db
        .lookup(Ecosystem::Packagist, "Acme/Web-Framework", "v2.4.0")
        .unwrap();
    assert_eq!(corrupt, 0);
    assert_eq!(m.len(), 1);
    assert_eq!(
        m[0].ids,
        [
            "CVE-2099-0001",
            "GHSA-2099-fram-0001",
            "PKSA-2099-fram-0001"
        ]
    );
    assert_eq!(m[0].severity, sdrscan_core::Severity::Critical);
    assert_eq!(m[0].fixed_versions, ["2.5.3"]);
    assert!(db
        .lookup(Ecosystem::Packagist, "acme/web-framework", "2.5.3")
        .unwrap()
        .0
        .is_empty());
    assert!(db
        .lookup(Ecosystem::Packagist, "acme/web-framework", "1.9.0")
        .unwrap()
        .0
        .is_empty());
    // go: introduced 0 mencakup pseudo-versi
    assert_eq!(
        db.lookup(
            Ecosystem::Go,
            "example.com/acme/lib",
            "v0.0.0-20190101000000-abcdef123456"
        )
        .unwrap()
        .0
        .len(),
        1
    );
    // crates: introduced "0.0.0-0"
    assert_eq!(
        db.lookup(Ecosystem::CratesIo, "acme-parser", "0.1.0-alpha.1")
            .unwrap()
            .0
            .len(),
        1
    );
}

#[test]
fn nvd_products_match_by_range_and_exact_version() {
    let db = VulnDb::open(&fixture()).unwrap();
    let ids = |v: &str| -> Vec<String> {
        db.query_product("cpe:2.3:a:apache:http_server", v)
            .unwrap()
            .hits
            .into_iter()
            .map(|h| h.entry.id)
            .collect()
    };
    assert_eq!(ids("2.4.41"), ["CVE-2099-1000", "CVE-2099-1001"]);
    assert_eq!(ids("2.4.42"), ["CVE-2099-1000"]);
    assert!(ids("2.4.50").is_empty());
}

/// Kutipan baris nyata dari NVD (tests/fixtures/vulndb-real): bentuk `matches` yang ada di data sungguhan.
mod real_excerpt {
    use super::*;

    fn db() -> VulnDb {
        VulnDb::open(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/vulndb-real"),
        )
        .unwrap()
    }

    fn ids(product: &str, version: &str) -> Vec<String> {
        db().query_product(&format!("cpe:2.3:a:{product}"), version)
            .unwrap()
            .hits
            .into_iter()
            .map(|h| h.entry.id)
            .collect()
    }

    #[test]
    fn apache_range_without_lower_bound_matches_old_versions() {
        // CVE-2021-44790: matches=[{end_excluding:"2.4.52"}] (tanpa batas awal)
        assert!(ids("apache:http_server", "2.4.41").contains(&"CVE-2021-44790".to_string()));
        assert!(ids("apache:http_server", "2.4.51").contains(&"CVE-2021-44790".to_string()));
        assert!(!ids("apache:http_server", "2.4.52").contains(&"CVE-2021-44790".to_string()));
        assert!(ids("apache:http_server", "1.3.0").contains(&"CVE-2021-44790".to_string()));
        let hits = db()
            .query_product("cpe:2.3:a:apache:http_server", "2.4.41")
            .unwrap()
            .hits;
        let h = hits
            .iter()
            .find(|h| h.entry.id == "CVE-2021-44790")
            .unwrap();
        assert_eq!(h.fixed, ["2.4.52"]);
        assert_eq!(h.entry.severity(), sdrscan_core::Severity::Critical);
    }

    #[test]
    fn apache_bounded_and_exact_entries() {
        assert_eq!(
            ids("apache:http_server", "2.4.41"),
            ["CVE-2020-11984", "CVE-2021-44790"]
        );
        assert!(!ids("apache:http_server", "2.4.44").contains(&"CVE-2020-11984".to_string()));
        // CVE-1999-0045 hanya mencantumkan versi persis kuno
        assert!(ids("apache:http_server", "1.0").contains(&"CVE-1999-0045".to_string()));
        assert!(!ids("apache:http_server", "2.4.41").contains(&"CVE-1999-0045".to_string()));
    }

    #[test]
    fn nginx_exact_version_entry() {
        assert_eq!(ids("nginx:nginx", "0.6.1516"), ["CVE-2009-3896"]);
        assert!(ids("nginx:nginx", "1.18.0").is_empty());
    }

    #[test]
    fn php_all_versions_and_mixed_bounds() {
        // CVE-2007-3205: satu entri tanpa batas apa pun = semua versi
        assert!(ids("php:php", "7.4.3").contains(&"CVE-2007-3205".to_string()));
        // CVE-2018-5711: end_including saja, start_excluding+end_including, start_including+end_including
        assert!(ids("php:php", "5.0.1").contains(&"CVE-2018-5711".to_string()));
        assert!(ids("php:php", "7.1.12").contains(&"CVE-2018-5711".to_string()));
        assert!(!ids("php:php", "7.1.0").contains(&"CVE-2018-5711".to_string()));
        assert!(ids("php:php", "7.0.26").contains(&"CVE-2018-5711".to_string()));
        assert!(!ids("php:php", "7.4.3").contains(&"CVE-2018-5711".to_string()));
    }

    #[test]
    fn openssl_letter_suffixes_in_real_bounds() {
        // CVE-2022-0778: [1.0.2, 1.0.2zd), [1.1.0, 1.1.1n), [3.0.0, 3.0.2)
        assert!(ids("openssl:openssl", "1.0.2k").contains(&"CVE-2022-0778".to_string()));
        assert!(ids("openssl:openssl", "1.0.2zc").contains(&"CVE-2022-0778".to_string()));
        assert!(!ids("openssl:openssl", "1.0.2zd").contains(&"CVE-2022-0778".to_string()));
        assert!(ids("openssl:openssl", "1.1.1f").contains(&"CVE-2022-0778".to_string()));
        assert!(!ids("openssl:openssl", "1.1.1n").contains(&"CVE-2022-0778".to_string()));
        // CVE-2009-1378: (0.9.8, 0.9.8m)
        assert!(ids("openssl:openssl", "0.9.8k").contains(&"CVE-2009-1378".to_string()));
        assert!(!ids("openssl:openssl", "0.9.8").contains(&"CVE-2009-1378".to_string()));
    }

    #[test]
    fn other_products() {
        assert!(ids("lighttpd:lighttpd", "1.4.35").contains(&"CVE-2015-3200".to_string()));
        assert!(!ids("lighttpd:lighttpd", "1.4.36").contains(&"CVE-2015-3200".to_string()));
        assert!(ids("microsoft:internet_information_services", "6.0")
            .contains(&"CVE-2008-1446".to_string()));
        assert!(ids("eclipse:jetty", "9.4.12").contains(&"CVE-2020-27216".to_string()));
        assert!(ids("apache:tomcat", "9.0.30").contains(&"CVE-2021-33037".to_string()));
        assert!(!ids("apache:tomcat", "9.0.0").contains(&"CVE-2021-33037".to_string()));
        assert!(ids("nodejs:node.js", "14.10.0").contains(&"CVE-2022-0778".to_string()));
        assert!(!ids("nodejs:node.js", "14.0.0").contains(&"CVE-2022-0778".to_string()));
    }
}
