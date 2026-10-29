use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;

use assert_cmd::Command;
use serde_json::Value;

const ALLOW: &str = "--allow-private-networks-for-tests";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn serve(headers: &str) -> String {
    let response =
        format!("HTTP/1.1 200 OK\r\n{headers}Content-Length: 2\r\nConnection: close\r\n\r\nok");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}/")
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for e in fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &to);
        } else {
            fs::copy(e.path(), to).unwrap();
        }
    }
}

fn fixture_db() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    copy_tree(&root().join("tests/fixtures/vulndb"), tmp.path());
    let p = tmp.path().join("meta.json");
    let mut meta: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
    meta["updated_at"] = serde_json::json!(sdrscan_vulndb::time::now_rfc3339());
    fs::write(&p, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
    tmp
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn scan(url: &str, db: Option<&Path>, extra: &[&str]) -> Out {
    let mut c = Command::cargo_bin("sdrscan-dast").unwrap();
    c.args(["scan", ALLOW, url]);
    if let Some(db) = db {
        c.arg("--vuln-db").arg(db);
    }
    c.args(extra);
    let o = c.output().unwrap();
    Out {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn sarif(url: &str, db: Option<&Path>) -> (Value, Out) {
    let o = scan(url, db, &["--format", "sarif", "--fail-on", "critical"]);
    let doc: Value =
        serde_json::from_str(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", o.stdout));
    (doc, o)
}

fn cve_results(doc: &Value) -> Vec<&Value> {
    doc["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ruleId"].as_str().unwrap().starts_with("CVE-"))
        .collect()
}

fn assert_schema_valid(doc: &Value) {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(root().join("tests/schemas/sarif-schema-2.1.0.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::draft4::new(&schema).unwrap();
    let errors: Vec<String> = validator.iter_errors(doc).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn vulnerable_banners_produce_low_confidence_cve_findings() {
    let db = fixture_db();
    let url = serve("Server: Apache/2.4.41 (Ubuntu)\r\nX-Powered-By: PHP/7.4.3\r\n");
    let (doc, out) = sarif(&url, Some(db.path()));
    // CVE-2099-1200 (PHP, 9.8) critical -> melewati --fail-on critical
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert_schema_valid(&doc);

    let cves = cve_results(&doc);
    let mut ids: Vec<&str> = cves.iter().map(|r| r["ruleId"].as_str().unwrap()).collect();
    ids.sort();
    assert_eq!(ids, ["CVE-2099-1000", "CVE-2099-1001", "CVE-2099-1200"]);

    let apache = cves
        .iter()
        .find(|r| r["ruleId"] == "CVE-2099-1000")
        .unwrap();
    assert_eq!(apache["level"], "error");
    assert_eq!(
        apache["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        url.as_str()
    );
    assert!(apache["locations"][0]["physicalLocation"]["region"].is_null());
    assert_eq!(apache["properties"]["evidence"], "Server: Apache/2.4.41");
    let v = &apache["properties"]["vulnerability"];
    assert_eq!(v["ids"], serde_json::json!(["CVE-2099-1000"]));
    assert_eq!(
        v["package"],
        serde_json::json!({"product":"cpe:2.3:a:apache:http_server","version":"2.4.41"})
    );
    assert_eq!(v["fixed_versions"], serde_json::json!(["2.4.50"]));
    assert_eq!(v["source"], "nvd");
    assert_eq!(v["confidence"], "low");
    assert_eq!(v["cvss"]["score"], 7.5);
    assert!(v.get("scope").is_none());
    assert!(apache["message"]["text"]
        .as_str()
        .unwrap()
        .contains("verifikasi"));

    let php = cves
        .iter()
        .find(|r| r["ruleId"] == "CVE-2099-1200")
        .unwrap();
    assert_eq!(php["level"], "error");
    assert_eq!(php["properties"]["evidence"], "X-Powered-By: PHP/7.4.3");

    // severity tanpa skor CVSS: dari label ("low" -> note)
    let exact = cves
        .iter()
        .find(|r| r["ruleId"] == "CVE-2099-1001")
        .unwrap();
    assert_eq!(exact["level"], "note");

    // rule dinamis, termasuk rule pemeriksaan pasif yang sudah ada
    let rules = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert!(rules.iter().any(|r| r["id"] == "dast-missing-csp"));
    let rule = rules.iter().find(|r| r["id"] == "CVE-2099-1200").unwrap();
    assert_eq!(rule["properties"]["security-severity"], "9.8");
    assert!(rule["properties"]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "external/cwe/cwe-190"));
    assert!(rule["properties"]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "external/cve/cve-2099-1200"));
    for r in &cves {
        let idx = r["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[idx]["id"], r["ruleId"]);
    }
}

#[test]
fn text_output_and_exit_code_follow_fail_on() {
    let db = fixture_db();
    let url = serve("Server: nginx/1.18.0\r\n");
    let o = scan(&url, Some(db.path()), &["--fail-on", "critical"]);
    assert_eq!(o.code, Some(1), "{}", o.stderr);
    assert!(o.stdout.contains("[CVE-2099-1100]"), "{}", o.stdout);
    assert!(o.stdout.contains("Server: nginx/1.18.0"), "{}", o.stdout);
}

#[test]
fn patched_or_unaffected_versions_have_no_cve_findings() {
    let db = fixture_db();
    let url = serve("Server: Apache/2.4.58 (Debian)\r\nX-Powered-By: PHP/8.3.0\r\n");
    let (doc, out) = sarif(&url, Some(db.path()));
    assert!(cve_results(&doc).is_empty(), "{doc}");
    assert!(!out.stderr.contains("peringatan:"), "{}", out.stderr);
}

#[test]
fn no_database_skips_with_warning_only_when_a_versioned_banner_exists() {
    let url = serve("Server: Apache/2.4.41\r\n");
    let (doc, out) = sarif(&url, None);
    assert_eq!(out.code, Some(0));
    assert!(cve_results(&doc).is_empty());
    assert!(
        out.stderr.contains("basis data kerentanan tidak diset"),
        "{}",
        out.stderr
    );

    let quiet = serve("Server: nginx\r\n");
    let (_, out) = sarif(&quiet, None);
    assert!(!out.stderr.contains("peringatan:"), "{}", out.stderr);
}

#[test]
fn unusable_or_nvd_less_database_warns_instead_of_failing() {
    let url = serve("Server: Apache/2.4.41\r\n");
    let (_, out) = sarif(&url, Some(Path::new("/tidak/ada/vulndb")));
    assert_eq!(out.code, Some(0));
    assert!(out.stderr.contains("tidak dapat dipakai"), "{}", out.stderr);

    let db = fixture_db();
    fs::remove_file(db.path().join("nvd/products.jsonl")).unwrap();
    let p = db.path().join("meta.json");
    let mut meta: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
    meta["sources"].as_object_mut().unwrap().remove("nvd");
    fs::write(&p, serde_json::to_string(&meta).unwrap()).unwrap();
    let (_, out) = sarif(&url, Some(db.path()));
    assert!(
        out.stderr.contains("tidak memuat data NVD"),
        "{}",
        out.stderr
    );
}

#[test]
fn env_var_selects_database() {
    let db = fixture_db();
    let url = serve("Server: lighttpd/1.4.55\r\nX-Powered-By: PHP/7.4.3\r\n");
    let o = Command::cargo_bin("sdrscan-dast")
        .unwrap()
        .env("SDRSCAN_VULN_DB", db.path())
        .args(["scan", ALLOW, &url, "--fail-on", "critical"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("CVE-2099-1200"));
}

#[test]
fn findings_are_capped_at_25_highest_severity_first_with_warning() {
    let db = fixture_db();
    // 30 CVE tambahan untuk nginx 1.18.0: 10 critical, 10 high, 10 medium (ditambah 1 critical bawaan fixture)
    let path = db.path().join("nvd/products.jsonl");
    let mut text = fs::read_to_string(&path).unwrap();
    for (n, label) in ["critical", "high", "medium"].iter().enumerate() {
        for i in 0..10 {
            text.push_str(&format!(
                "{{\"product\":\"cpe:2.3:a:nginx:nginx\",\"id\":\"CVE-2098-{}{:02}\",\"summary\":\"x\",\"severity\":\"{label}\",\"matches\":[{{\"end_excluding\":\"1.20.2\"}}],\"modified\":\"\"}}\n",
                n + 1,
                i
            ));
        }
    }
    fs::write(&path, text).unwrap();
    let url = serve("Server: nginx/1.18.0\r\n");
    let (doc, out) = sarif(&url, Some(db.path()));
    let cves = cve_results(&doc);
    assert_eq!(cves.len(), 25);
    assert!(
        out.stderr.contains("6 temuan CVE dari banner dipotong"),
        "{}",
        out.stderr
    );
    let levels: Vec<&str> = cves.iter().map(|r| r["level"].as_str().unwrap()).collect();
    // 11 critical + 10 high + 4 medium; urut severity menurun
    assert_eq!(levels.iter().filter(|l| **l == "error").count(), 21);
    assert_eq!(levels.iter().filter(|l| **l == "warning").count(), 4);
    let ids: Vec<&str> = cves.iter().map(|r| r["ruleId"].as_str().unwrap()).collect();
    assert!(ids.contains(&"CVE-2099-1100"));
    assert!(ids.contains(&"CVE-2098-300"));
    assert!(ids.contains(&"CVE-2098-303"));
    assert!(
        !ids.contains(&"CVE-2098-304"),
        "id terbesar dari severity terendah yang dipotong"
    );
    assert_schema_valid(&doc);
}

#[test]
fn output_is_deterministic() {
    let db = fixture_db();
    let url = serve("Server: Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f\r\nX-Powered-By: PHP/7.4.3\r\n");
    let a = scan(
        &url,
        Some(db.path()),
        &["--format", "sarif", "--fail-on", "critical"],
    );
    let b = scan(
        &url,
        Some(db.path()),
        &["--format", "sarif", "--fail-on", "critical"],
    );
    assert_eq!(a.stdout, b.stdout);
    let text_a = scan(&url, Some(db.path()), &["--fail-on", "critical"]);
    let text_b = scan(&url, Some(db.path()), &["--fail-on", "critical"]);
    assert_eq!(text_a.stdout, text_b.stdout);
}

fn real_excerpt_db() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    copy_tree(&root().join("tests/fixtures/vulndb-real"), tmp.path());
    let p = tmp.path().join("meta.json");
    let mut meta: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
    meta["updated_at"] = serde_json::json!(sdrscan_vulndb::time::now_rfc3339());
    fs::write(&p, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
    tmp
}

fn cve_ids_for(headers: &str, db: &Path) -> Vec<String> {
    let url = serve(headers);
    let (doc, _) = sarif(&url, Some(db));
    let mut ids: Vec<String> = cve_results(&doc)
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

/// Regresi: kutipan baris NVD nyata. Rentang tanpa batas awal (CVE-2021-44790) dan header Server ganda
/// (mis. http.server Python menambahkan `Server: BaseHTTP/...` di depan) pernah menghasilkan 0 CVE.
#[test]
fn real_nvd_excerpt_banners_find_cves() {
    let db = real_excerpt_db();
    let apache = cve_ids_for("Server: Apache/2.4.41 (Ubuntu)\r\n", db.path());
    assert_eq!(apache, ["CVE-2020-11984", "CVE-2021-44790"]);

    // header Server ganda: yang pertama bukan produk terkurasi
    let dup = cve_ids_for(
        "Server: BaseHTTP/0.6 Python/3.9.6\r\nDate: x\r\nServer: Apache/2.4.41 (Ubuntu)\r\n",
        db.path(),
    );
    assert_eq!(dup, apache);

    assert_eq!(
        cve_ids_for("Server: nginx/0.6.1516\r\n", db.path()),
        ["CVE-2009-3896"]
    );
    assert!(cve_ids_for("Server: nginx/1.18.0\r\n", db.path()).is_empty());
    assert_eq!(
        cve_ids_for("Server: lighttpd/1.4.35\r\n", db.path()),
        ["CVE-2015-3200"]
    );
    assert_eq!(
        cve_ids_for("Server: Microsoft-IIS/6.0\r\n", db.path()),
        ["CVE-2008-1446"]
    );
    assert_eq!(
        cve_ids_for("Server: Jetty(9.4.12.v20180830)\r\n", db.path()),
        ["CVE-2020-27216"]
    );
    assert_eq!(
        cve_ids_for("Server: Apache Tomcat/9.0.30\r\n", db.path()),
        ["CVE-2021-33037"]
    );
    assert_eq!(
        cve_ids_for("X-Powered-By: Node.js/14.10.0\r\n", db.path()),
        ["CVE-2022-0778"]
    );
    assert_eq!(
        cve_ids_for("Server: Apache/2.4.58 OpenSSL/1.0.2k\r\n", db.path()),
        ["CVE-2022-0778"]
    );
    assert_eq!(
        cve_ids_for("X-Powered-By: PHP/7.4.3\r\n", db.path()),
        ["CVE-2007-3205"],
        "entri tanpa batas versi = semua versi"
    );
}
