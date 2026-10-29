mod common;

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use common::{make_zip, serve, Resp, Server};
use sdrscan_vulndb::VulnDb;

const ALLOW: &str = "--allow-private-networks-for-tests";

fn cve_json(id: &str, product: &str, end_excl: &str, score: f64, modified: &str) -> String {
    format!(
        r#"{{"cve":{{"id":"{id}","vulnStatus":"Analyzed","lastModified":"{modified}",
"descriptions":[{{"lang":"en","value":"Ringkasan {id}"}}],
"metrics":{{"cvssMetricV31":[{{"type":"Primary","cvssData":{{"baseScore":{score},"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","baseSeverity":"HIGH"}}}}]}},
"weaknesses":[{{"description":[{{"lang":"en","value":"CWE-79"}}]}}],
"configurations":[{{"nodes":[{{"operator":"OR","cpeMatch":[{{"vulnerable":true,"criteria":"cpe:2.3:a:{product}:*:*:*:*:*:*:*:*","versionEndExcluding":"{end_excl}"}}]}}]}}]}}}}"#
    )
}

fn page(items: &[String], total: usize, start: usize) -> Vec<u8> {
    format!(
        r#"{{"resultsPerPage":{},"startIndex":{start},"totalResults":{total},"format":"NVD_CVE","vulnerabilities":[{}]}}"#,
        items.len(),
        items.join(",")
    )
    .into_bytes()
}

fn query_param(target: &str, key: &str) -> Option<String> {
    let q = target.split_once('?')?.1;
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.replace("%3A", ":").replace("%2B", "+"))
}

/// Server NVD: apache http_server punya 3 CVE dalam 2 halaman (2 + 1); produk lain kosong.
/// `v2` mengubah CVE-2099-0002 (batas diperbarui) dan menambah CVE-2099-0004 untuk jawaban inkremental.
fn nvd_server(incremental: bool) -> Server {
    serve(move |req| {
        let Some(cpe) = query_param(&req.target, "virtualMatchString") else {
            return Resp::status(400);
        };
        let start: usize = query_param(&req.target, "startIndex")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if cpe != "cpe:2.3:a:apache:http_server" {
            return Resp::ok(page(&[], 0, 0));
        }
        if incremental {
            assert!(query_param(&req.target, "lastModStartDate").is_some());
            let items = vec![
                cve_json(
                    "CVE-2099-0002",
                    "apache:http_server",
                    "2.4.60",
                    8.1,
                    "2026-10-20T00:00:00.000",
                ),
                cve_json(
                    "CVE-2099-0004",
                    "apache:http_server",
                    "2.4.61",
                    5.0,
                    "2026-10-21T00:00:00.000",
                ),
            ];
            return Resp::ok(page(&items, 2, 0));
        }
        let all = [
            cve_json(
                "CVE-2099-0001",
                "apache:http_server",
                "2.4.50",
                7.5,
                "2026-01-01T00:00:00.000",
            ),
            cve_json(
                "CVE-2099-0002",
                "apache:http_server",
                "2.4.51",
                6.0,
                "2026-01-01T00:00:00.000",
            ),
            cve_json(
                "CVE-2099-0003",
                "apache:http_server",
                "2.4.52",
                9.8,
                "2026-01-01T00:00:00.000",
            ),
        ];
        let end = (start + 2).min(3);
        Resp::ok(page(&all[start..end], 3, start))
    })
}

fn update_nvd(db: &Path, base: &str, extra: &[&str]) -> (Option<i32>, String) {
    let mut c = Command::cargo_bin("sdrscan-vuln").unwrap();
    c.env_remove("SDRSCAN_VULN_DB").env_remove("NVD_API_KEY");
    let o = c
        .args([
            "update",
            ALLOW,
            "--no-osv",
            "--nvd",
            "--nvd-delay-ms",
            "0",
            "--retry-delay-ms",
            "10",
            "--db",
        ])
        .arg(db)
        .args(["--nvd-base-url", base])
        .args(extra)
        .output()
        .unwrap();
    (
        o.status.code(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn nvd_full_then_incremental_update() {
    let tmp = tempfile::tempdir().unwrap();
    let db_dir = tmp.path().join("vulndb");

    let server = nvd_server(false);
    let (code, stderr) = update_nvd(&db_dir, &format!("{}/cves", server.base), &[]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("NVD: 3 entri (penuh)"), "{stderr}");
    let reqs = server.requests();
    // 13 awalan CPE (11 produk + 2 alternatif: f5:nginx, openjsf:express); apache butuh 2 halaman
    assert_eq!(reqs.len(), 14, "{reqs:?}");
    assert!(reqs
        .iter()
        .all(|r| query_param(&r.target, "lastModStartDate").is_none()));
    assert!(reqs.iter().all(|r| r.header("apiKey").is_none()));
    assert!(reqs
        .iter()
        .all(|r| query_param(&r.target, "resultsPerPage").as_deref() == Some("2000")));

    let db = VulnDb::open(&db_dir).unwrap();
    assert!(db.has_nvd());
    assert_eq!(db.meta().advisory_count, 3);
    let nvd = db.meta().sources.nvd.as_ref().unwrap();
    assert_eq!(nvd.entries, 3);
    assert_eq!(nvd.products.len(), 13);
    let q = db
        .query_product("cpe:2.3:a:apache:http_server", "2.4.49")
        .unwrap();
    let mut ids: Vec<&str> = q.hits.iter().map(|h| h.entry.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"]);
    assert_eq!(q.hits[0].entry.cvss.as_ref().unwrap().score, 7.5);
    assert_eq!(q.hits[0].entry.cwe, ["CWE-79"]);
    assert_eq!(q.hits[0].fixed, ["2.4.50"]);

    // daftar produk di meta berbeda dengan daftar terkurasi saat ini -> unduh penuh (bukan inkremental)
    {
        let meta_path = db_dir.join("meta.json");
        let mut meta: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
        meta["sources"]["nvd"]["products"] = serde_json::json!(["cpe:2.3:a:apache:http_server"]);
        fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();
        let refetch = nvd_server(false);
        let (code, stderr) = update_nvd(&db_dir, &format!("{}/cves", refetch.base), &[]);
        assert_eq!(code, Some(0), "{stderr}");
        assert!(stderr.contains("(penuh)"), "{stderr}");
        assert!(refetch
            .requests()
            .iter()
            .all(|r| query_param(&r.target, "lastModStartDate").is_none()));
    }

    // pembaruan inkremental: hanya perubahan; entri lama dipertahankan, yang berubah diganti, baru ditambah
    let server2 = nvd_server(true);
    let (code, stderr) = update_nvd(&db_dir, &format!("{}/cves", server2.base), &[]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("NVD: 4 entri (inkremental)"), "{stderr}");
    for r in server2.requests() {
        let start = query_param(&r.target, "lastModStartDate").unwrap();
        let end = query_param(&r.target, "lastModEndDate").unwrap();
        assert!(
            start.ends_with(".000+00:00") && end.ends_with(".000+00:00"),
            "{start} {end}"
        );
        assert!(start < end);
    }
    let db = VulnDb::open(&db_dir).unwrap();
    assert_eq!(db.meta().sources.nvd.as_ref().unwrap().entries, 4);
    let all = db.read_nvd_entries().unwrap();
    let find = |id: &str| all.iter().find(|e| e.id == id).unwrap();
    assert_eq!(
        find("CVE-2099-0001").matches[0].end_excluding.as_deref(),
        Some("2.4.50")
    );
    assert_eq!(
        find("CVE-2099-0002").matches[0].end_excluding.as_deref(),
        Some("2.4.60")
    );
    assert_eq!(find("CVE-2099-0002").cvss.as_ref().unwrap().score, 8.1);
    assert_eq!(
        find("CVE-2099-0004").matches[0].end_excluding.as_deref(),
        Some("2.4.61")
    );
}

#[test]
fn nvd_api_key_is_sent_as_header_and_rate_limit_responses_are_retried() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let server = serve(move |req| {
        assert_eq!(req.header("apiKey"), Some("kunci-uji"));
        if h.fetch_add(1, Ordering::SeqCst) == 0 {
            return Resp::status(429);
        }
        let cpe = query_param(&req.target, "virtualMatchString").unwrap();
        if cpe == "cpe:2.3:a:nginx:nginx" {
            Resp::ok(page(
                &[cve_json(
                    "CVE-2099-0009",
                    "nginx:nginx",
                    "1.20.2",
                    7.0,
                    "2026-01-01T00:00:00.000",
                )],
                1,
                0,
            ))
        } else {
            Resp::ok(page(&[], 0, 0))
        }
    });
    let tmp = tempfile::tempdir().unwrap();
    let db_dir = tmp.path().join("db");
    let mut c = Command::cargo_bin("sdrscan-vuln").unwrap();
    let o = c
        .env("NVD_API_KEY", "kunci-uji")
        .args([
            "update",
            ALLOW,
            "--no-osv",
            "--nvd",
            "--nvd-delay-ms",
            "0",
            "--retry-delay-ms",
            "10",
            "--db",
        ])
        .arg(&db_dir)
        .args(["--nvd-base-url", &format!("{}/cves", server.base)])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let db = VulnDb::open(&db_dir).unwrap();
    assert_eq!(
        db.query_product("cpe:2.3:a:nginx:nginx", "1.18.0")
            .unwrap()
            .hits
            .len(),
        1
    );
}

#[test]
fn nvd_from_dir_reads_saved_pages_without_network() {
    let tmp = tempfile::tempdir().unwrap();
    let dumps = tmp.path().join("dumps");
    fs::create_dir_all(dumps.join("nvd")).unwrap();
    fs::write(
        dumps.join("nvd/page1.json"),
        page(
            &[cve_json(
                "CVE-2099-0100",
                "php:php",
                "8.0.0",
                9.0,
                "2026-01-01T00:00:00.000",
            )],
            1,
            0,
        ),
    )
    .unwrap();
    let db_dir = tmp.path().join("db");
    let o = Command::cargo_bin("sdrscan-vuln")
        .unwrap()
        .env_remove("SDRSCAN_VULN_DB")
        .args(["update", "--no-osv", "--nvd", "--db"])
        .arg(&db_dir)
        .arg("--from-dir")
        .arg(&dumps)
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let db = VulnDb::open(&db_dir).unwrap();
    assert_eq!(
        db.query_product("cpe:2.3:a:php:php", "7.4.3")
            .unwrap()
            .hits
            .len(),
        1
    );
    let _ = make_zip(&[]);
}

#[test]
fn nvd_error_keeps_old_database() {
    let tmp = tempfile::tempdir().unwrap();
    let db_dir = tmp.path().join("db");
    let ok = nvd_server(false);
    assert_eq!(
        update_nvd(&db_dir, &format!("{}/cves", ok.base), &[]).0,
        Some(0)
    );
    let before = fs::read(db_dir.join("nvd/products.jsonl")).unwrap();
    let broken = serve(|_| Resp::ok(b"{\"bukan\":\"nvd\"}".to_vec()));
    let (code, stderr) = update_nvd(&db_dir, &format!("{}/cves", broken.base), &["--force"]);
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(fs::read(db_dir.join("nvd/products.jsonl")).unwrap(), before);
}
