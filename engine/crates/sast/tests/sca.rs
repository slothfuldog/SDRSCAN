mod common;

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use common::{copy_tree, fixture_db, root};
use serde_json::Value;

fn cmd() -> Command {
    Command::cargo_bin("sdrscan-sast").unwrap()
}

fn sca_fixture(name: &str) -> PathBuf {
    root().join("tests/fixtures/sca").join(name)
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let o = cmd().args(args).output().unwrap();
    Run {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// Memindai `target` dengan basis data fixture; `extra` argumen tambahan. Keluaran SARIF sebagai JSON.
fn scan_sarif(target: &Path, db: &Path, extra: &[&str]) -> (Option<i32>, Value, String) {
    let tpl = root().join("templates/php");
    let mut args: Vec<String> = vec![
        "scan".into(),
        target.display().to_string(),
        "--templates".into(),
        tpl.display().to_string(),
        "--vuln-db".into(),
        db.display().to_string(),
        "--format".into(),
        "sarif".into(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = run(&refs);
    let doc: Value = serde_json::from_str(&r.stdout)
        .unwrap_or_else(|e| panic!("bukan JSON SARIF: {e}\n{}\n{}", r.stdout, r.stderr));
    (r.code, doc, r.stderr)
}

fn results(doc: &Value) -> Vec<&Value> {
    doc["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .collect()
}

fn line_of(file: &Path, needle: &str) -> u64 {
    let text = fs::read_to_string(file).unwrap();
    text.lines()
        .position(|l| l.contains(needle))
        .map(|i| i as u64 + 1)
        .unwrap_or_else(|| panic!("{needle} tidak ada di {}", file.display()))
}

fn rule_ids(doc: &Value) -> Vec<String> {
    results(doc)
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn composer_lock_reports_exact_expected_findings() {
    let db = fixture_db();
    let target = sca_fixture("php-vulnerable");
    let (code, doc, stderr) = scan_sarif(&target, db.path(), &[]);
    assert_eq!(code, Some(1), "{stderr}");
    let res = results(&doc);
    let mut got: Vec<(String, String, u64)> = res
        .iter()
        .map(|r| {
            (
                r["ruleId"].as_str().unwrap().to_string(),
                r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                r["locations"][0]["physicalLocation"]["region"]["startLine"]
                    .as_u64()
                    .unwrap(),
            )
        })
        .collect();
    got.sort();
    let lock = target.join("composer.lock");
    let mut want = vec![
        (
            "CVE-2099-0001".to_string(),
            "acme/web-framework@v2.4.0".to_string(),
            line_of(&lock, "acme/web-framework"),
        ),
        (
            "CVE-2099-0002".to_string(),
            "acme/dev-tool@1.2.0".to_string(),
            line_of(&lock, "acme/dev-tool"),
        ),
        (
            "CVE-2099-0004".to_string(),
            "acme/version-zoo@3.0.0-RC2".to_string(),
            line_of(&lock, "acme/version-zoo"),
        ),
    ];
    want.sort();
    assert_eq!(got, want);

    let fw = res.iter().find(|r| r["ruleId"] == "CVE-2099-0001").unwrap();
    assert_eq!(fw["level"], "error");
    assert_eq!(
        fw["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "composer.lock"
    );
    let v = &fw["properties"]["vulnerability"];
    assert_eq!(
        v["ids"],
        serde_json::json!([
            "CVE-2099-0001",
            "GHSA-2099-fram-0001",
            "PKSA-2099-fram-0001"
        ])
    );
    assert_eq!(
        v["package"],
        serde_json::json!({"ecosystem":"Packagist","name":"acme/web-framework","version":"v2.4.0"})
    );
    assert_eq!(v["fixed_versions"], serde_json::json!(["2.5.3"]));
    assert_eq!(v["source"], "osv");
    assert_eq!(v["confidence"], "high");
    assert_eq!(v["scope"], "runtime");
    assert_eq!(v["cvss"]["score"], 9.8);
    assert!(v["cvss"]["vector"]
        .as_str()
        .unwrap()
        .starts_with("CVSS:3.1/"));
    assert_eq!(v["references"].as_array().unwrap().len(), 2);
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        [
            "confidence",
            "cvss",
            "fixed_versions",
            "ids",
            "package",
            "references",
            "scope",
            "source"
        ]
    );
    assert!(fw["message"]["text"]
        .as_str()
        .unwrap()
        .contains("acme/web-framework@v2.4.0"));
    assert!(fw["message"]["text"].as_str().unwrap().contains("2.5.3"));

    // rule dinamis
    let rules = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    let rule = rules.iter().find(|r| r["id"] == "CVE-2099-0001").unwrap();
    assert_eq!(
        rule["shortDescription"]["text"],
        "SQL injection pada query builder acme/web-framework"
    );
    assert_eq!(rule["properties"]["security-severity"], "9.8");
    let tags: Vec<&str> = rule["properties"]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(tags.contains(&"security"));
    assert!(tags.contains(&"external/cve/cve-2099-0001"));
    assert!(tags.contains(&"external/cwe/cwe-89"));
    // ruleIndex menunjuk rule yang benar
    let idx = fw["ruleIndex"].as_u64().unwrap() as usize;
    assert_eq!(rules[idx]["id"], "CVE-2099-0001");
    assert!(rules.len() >= 12 + 3, "template tetap ada: {}", rules.len());
}

#[test]
fn dev_dependencies_are_flagged_with_scope_dev() {
    let db = fixture_db();
    let (_, doc, _) = scan_sarif(&sca_fixture("php-vulnerable"), db.path(), &[]);
    let dev = results(&doc)
        .into_iter()
        .find(|r| r["ruleId"] == "CVE-2099-0002")
        .unwrap();
    assert_eq!(dev["properties"]["vulnerability"]["scope"], "dev");
    assert_eq!(dev["level"], "warning");
    assert!(dev["message"]["text"]
        .as_str()
        .unwrap()
        .contains("dependensi dev"));
}

#[test]
fn fixed_versions_report_clean() {
    let db = fixture_db();
    let (code, doc, stderr) = scan_sarif(&sca_fixture("php-safe"), db.path(), &[]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(results(&doc).is_empty(), "{doc}");
    assert!(!stderr.contains("peringatan:"), "{stderr}");
}

#[test]
fn npm_v3_v1_and_yarn_lockfiles() {
    let db = fixture_db();
    let (_, v3, _) = scan_sarif(&sca_fixture("node-npm"), db.path(), &[]);
    let mut ids = rule_ids(&v3);
    ids.sort();
    assert_eq!(ids, ["CVE-2099-0100", "GHSA-2099-npm0-0002"]);
    let scoped = results(&v3)
        .into_iter()
        .find(|r| r["ruleId"] == "GHSA-2099-npm0-0002")
        .unwrap();
    assert_eq!(scoped["properties"]["vulnerability"]["scope"], "dev");
    assert_eq!(
        scoped["properties"]["vulnerability"]["package"],
        serde_json::json!({"ecosystem":"npm","name":"@acme/scoped","version":"1.2.3"})
    );
    // tanpa skor CVSS: severity medium dari label, tanpa kunci cvss
    assert!(scoped["properties"]["vulnerability"].get("cvss").is_none());
    assert_eq!(scoped["level"], "warning");
    let lock = sca_fixture("node-npm").join("package-lock.json");
    assert_eq!(
        scoped["locations"][0]["physicalLocation"]["region"]["startLine"]
            .as_u64()
            .unwrap(),
        line_of(&lock, "node_modules/@acme/scoped")
    );

    // v1: left-padz 1.0.0 terdampak, @acme/scoped 1.3.0 (di luar last_affected 1.2.3) tidak
    let (_, v1, _) = scan_sarif(&sca_fixture("node-npm-v1"), db.path(), &[]);
    assert_eq!(rule_ids(&v1), ["CVE-2099-0100"]);

    // yarn.lock v1: kedua paket terdampak; baris = baris header entri
    let (_, y, _) = scan_sarif(&sca_fixture("node-yarn"), db.path(), &[]);
    let mut ids = rule_ids(&y);
    ids.sort();
    assert_eq!(ids, ["CVE-2099-0100", "GHSA-2099-npm0-0002"]);
    let lock = sca_fixture("node-yarn").join("yarn.lock");
    let left = results(&y)
        .into_iter()
        .find(|r| r["ruleId"] == "CVE-2099-0100")
        .unwrap();
    assert_eq!(
        left["locations"][0]["physicalLocation"]["region"]["startLine"]
            .as_u64()
            .unwrap(),
        line_of(&lock, "left-padz@^1.0.0")
    );
    assert_eq!(
        left["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "yarn.lock"
    );
}

#[test]
fn go_uses_gomod_selected_versions_and_gosum_only_otherwise() {
    let db = fixture_db();
    // go.mod: lib v1.2.3 (terdampak, <1.2.4); old v0.1.0 (rentang tanpa perbaikan); fine aman
    let (_, doc, _) = scan_sarif(&sca_fixture("go-app"), db.path(), &[]);
    let mut got: Vec<(String, String, String)> = results(&doc)
        .iter()
        .map(|r| {
            (
                r["ruleId"].as_str().unwrap().to_string(),
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            (
                "CVE-2099-0200".to_string(),
                "go.mod".to_string(),
                "example.com/acme/lib@v1.2.3".to_string()
            ),
            (
                "GO-2099-0002".to_string(),
                "go.mod".to_string(),
                "example.com/acme/old@v0.1.0".to_string()
            ),
        ]
    );
    let old = results(&doc)
        .into_iter()
        .find(|r| r["ruleId"] == "GO-2099-0002")
        .unwrap();
    assert_eq!(
        old["properties"]["vulnerability"]["fixed_versions"],
        serde_json::json!([])
    );
    assert!(old["message"]["text"]
        .as_str()
        .unwrap()
        .contains("Belum ada versi perbaikan"));

    // go.sum saja: versi tertinggi per modul dari baris berhash zip; baris /go.mod diabaikan
    let (_, sum, _) = scan_sarif(&sca_fixture("go-sum-only"), db.path(), &[]);
    assert_eq!(rule_ids(&sum), ["CVE-2099-0200"]);
    let r = results(&sum)[0];
    assert_eq!(
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "go.sum"
    );
    assert_eq!(
        r["locations"][0]["physicalLocation"]["region"]["startLine"]
            .as_u64()
            .unwrap(),
        2
    );
    let ids = r["properties"]["vulnerability"]["ids"].as_array().unwrap();
    assert_eq!(ids[0], "CVE-2099-0200");
    assert_eq!(ids[1], "GHSA-2099-go00-0001");
}

#[test]
fn cargo_lock_registry_packages() {
    let db = fixture_db();
    let (code, doc, _) = scan_sarif(&sca_fixture("rust-app"), db.path(), &[]);
    assert_eq!(code, Some(1));
    assert_eq!(rule_ids(&doc), ["CVE-2099-0300"]);
    let r = results(&doc)[0];
    assert_eq!(r["level"], "error");
    assert_eq!(
        r["properties"]["vulnerability"]["package"],
        serde_json::json!({"ecosystem":"crates.io","name":"acme-parser","version":"0.8.0"})
    );
    let lock = sca_fixture("rust-app").join("Cargo.lock");
    assert_eq!(
        r["locations"][0]["physicalLocation"]["region"]["startLine"]
            .as_u64()
            .unwrap(),
        line_of(&lock, "name = \"acme-parser\"")
    );
    let rule = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "CVE-2099-0300")
        .unwrap();
    assert!(rule["properties"]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "external/cwe/cwe-416"));
}

#[test]
fn ignore_file_suppresses_by_id_or_alias() {
    let db = fixture_db();
    let (code, doc, _) = scan_sarif(&sca_fixture("ignored"), db.path(), &["--fail-on", "high"]);
    // CVE-2099-0001 ditekan; tersisa dev-tool (medium) yang di bawah ambang high
    assert_eq!(rule_ids(&doc), ["CVE-2099-0002"]);
    assert_eq!(code, Some(0));
    let (code, _, _) = scan_sarif(&sca_fixture("ignored"), db.path(), &["--fail-on", "medium"]);
    assert_eq!(code, Some(1));

    // penekanan lewat alias GHSA juga bekerja
    let tmp = tempfile::tempdir().unwrap();
    copy_tree(&sca_fixture("ignored"), tmp.path());
    fs::write(
        tmp.path().join(".sdrscan-vuln-ignore"),
        "ghsa-2099-fram-0001\nCVE-2099-0002\n",
    )
    .unwrap();
    let (code, doc, _) = scan_sarif(tmp.path(), db.path(), &[]);
    assert!(results(&doc).is_empty());
    assert_eq!(code, Some(0));
}

#[test]
fn vendor_node_modules_and_gitignored_lockfiles_are_not_scanned() {
    let db = fixture_db();
    let (code, doc, stderr) = scan_sarif(&sca_fixture("vendored"), db.path(), &[]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(results(&doc).is_empty(), "{doc}");
    assert!(
        stderr.contains("1 file dipindai"),
        "hanya satu lockfile: {stderr}"
    );

    let (code, doc, stderr) = scan_sarif(&sca_fixture("gitignored"), db.path(), &[]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(results(&doc).is_empty(), "{doc}");
}

#[test]
fn missing_database_skips_sca_with_warning_not_error() {
    let target = sca_fixture("php-vulnerable");
    let r = run(&[
        "scan",
        target.to_str().unwrap(),
        "--templates",
        root().join("templates/php").to_str().unwrap(),
    ]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.contains("peringatan:"), "{}", r.stderr);
    assert!(r.stderr.contains("basis data kerentanan"), "{}", r.stderr);
    assert!(r.stderr.contains("SCA dilewati"), "{}", r.stderr);

    // direktori yang ditunjuk tidak ada -> peringatan juga, bukan galat
    let r = run(&[
        "scan",
        target.to_str().unwrap(),
        "--templates",
        root().join("templates/php").to_str().unwrap(),
        "--vuln-db",
        "/tidak/ada/vulndb",
    ]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stderr.contains("tidak dapat dipakai"), "{}", r.stderr);
}

#[test]
fn no_lockfile_and_no_database_stays_silent() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("a.php"), "<?php echo 1;").unwrap();
    let r = run(&[
        "scan",
        tmp.path().to_str().unwrap(),
        "--templates",
        root().join("templates/php").to_str().unwrap(),
    ]);
    assert_eq!(r.code, Some(0));
    assert!(!r.stderr.contains("peringatan:"), "{}", r.stderr);
}

#[test]
fn env_var_selects_database_and_no_sca_disables() {
    let db = fixture_db();
    let target = sca_fixture("php-vulnerable");
    let tpl = root().join("templates/php");
    let o = cmd()
        .env("SDRSCAN_VULN_DB", db.path())
        .args([
            "scan",
            target.to_str().unwrap(),
            "--templates",
            tpl.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(stdout.contains("CVE-2099-0001"), "{stdout}");
    assert!(stdout.contains("composer.lock:"), "{stdout}");

    let o = cmd()
        .env("SDRSCAN_VULN_DB", db.path())
        .args([
            "scan",
            target.to_str().unwrap(),
            "--templates",
            tpl.to_str().unwrap(),
            "--no-sca",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(o.stdout.is_empty());
}

#[test]
fn profile_controls_sca() {
    let db = fixture_db();
    let target = sca_fixture("php-vulnerable");
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, body: &str| {
        let p = dir.path().join(name);
        fs::write(&p, body).unwrap();
        p.display().to_string()
    };
    // min_severity: high menyaring temuan SCA di bawah high
    let p = write("min.yaml", "min_severity: high\n");
    let (_, doc, _) = scan_sarif(&target, db.path(), &["--profile", &p]);
    assert_eq!(rule_ids(&doc), ["CVE-2099-0001"]);
    // exclude_tags: [sca] mematikan SCA
    let p = write("ex.yaml", "exclude_tags: [sca]\n");
    let (code, doc, _) = scan_sarif(&target, db.path(), &["--profile", &p]);
    assert!(results(&doc).is_empty());
    assert_eq!(code, Some(0));
    // include_tags tanpa tag sca (mis. secrets) juga mematikan SCA; dengan sca tetap jalan
    let p = write("inc.yaml", "include_tags: [secrets]\n");
    let (_, doc, _) = scan_sarif(&target, db.path(), &["--profile", &p]);
    assert!(results(&doc).is_empty());
    let p = write("inc2.yaml", "include_tags: [secrets, sca]\n");
    let (_, doc, _) = scan_sarif(&target, db.path(), &["--profile", &p]);
    assert_eq!(results(&doc).len(), 3);
    // fail_on dari profil berlaku untuk temuan SCA
    let p = write("fail.yaml", "fail_on: critical\n");
    let (code, _, _) = scan_sarif(&sca_fixture("node-npm"), db.path(), &["--profile", &p]);
    assert_eq!(code, Some(0));
}

#[test]
fn corrupt_lines_and_missing_ecosystem_become_warnings() {
    let db = fixture_db();
    let npm = db.path().join("osv/npm.jsonl");
    let mut text = fs::read_to_string(&npm).unwrap();
    text.push_str("{\"package\":\"left-padz\",\"rusak\n");
    fs::write(&npm, text).unwrap();
    let (code, doc, stderr) = scan_sarif(&sca_fixture("node-npm"), db.path(), &[]);
    assert_eq!(code, Some(1));
    assert_eq!(
        results(&doc).len(),
        2,
        "baris rusak dilewati, sisanya tetap diproses"
    );
    assert!(stderr.contains("1 baris rusak"), "{stderr}");

    fs::remove_file(db.path().join("osv/Go.jsonl")).unwrap();
    let meta_path = db.path().join("meta.json");
    let mut meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    meta["sources"]["osv"]["ecosystems"]
        .as_object_mut()
        .unwrap()
        .remove("Go");
    fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();
    let (code, doc, stderr) = scan_sarif(&sca_fixture("go-app"), db.path(), &[]);
    assert_eq!(code, Some(0));
    assert!(results(&doc).is_empty());
    assert!(stderr.contains("tidak memuat ekosistem Go"), "{stderr}");
}

#[test]
fn stale_database_warns() {
    let db = fixture_db();
    let meta_path = db.path().join("meta.json");
    let mut meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    meta["updated_at"] = serde_json::json!("2020-01-01T00:00:00Z");
    fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();
    let (_, _, stderr) = scan_sarif(&sca_fixture("php-safe"), db.path(), &[]);
    assert!(stderr.contains("berumur"), "{stderr}");
}

#[test]
fn unparsable_lockfile_is_skipped_with_warning() {
    let db = fixture_db();
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("composer.lock"), "{ rusak").unwrap();
    fs::write(tmp.path().join("yarn.lock"), "__metadata:\n  version: 6\n").unwrap();
    let (code, doc, stderr) = scan_sarif(tmp.path(), db.path(), &[]);
    assert_eq!(code, Some(0));
    assert!(results(&doc).is_empty());
    assert!(stderr.contains("composer.lock"), "{stderr}");
    assert!(stderr.contains("Berry"), "{stderr}");
}

#[test]
fn sca_findings_coexist_with_php_findings_in_stable_order() {
    let db = fixture_db();
    let tmp = tempfile::tempdir().unwrap();
    copy_tree(&sca_fixture("php-vulnerable"), tmp.path());
    fs::copy(
        root().join("tests/fixtures/php/php-eval/vulnerable.php"),
        tmp.path().join("evil.php"),
    )
    .unwrap();
    let (code, doc, _) = scan_sarif(tmp.path(), db.path(), &[]);
    assert_eq!(code, Some(1));
    let ids = rule_ids(&doc);
    assert!(ids.contains(&"php-eval".to_string()), "{ids:?}");
    assert!(ids.contains(&"CVE-2099-0001".to_string()));
    // urutan berdasarkan path: composer.lock sebelum evil.php
    let uris: Vec<String> = results(&doc)
        .iter()
        .map(|r| {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let mut sorted = uris.clone();
    sorted.sort();
    assert_eq!(uris, sorted);
    // rule template dan rule turunan sama-sama ada; ruleIndex valid untuk keduanya
    let rules = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    for r in results(&doc) {
        let idx = r["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[idx]["id"], r["ruleId"]);
    }
}

#[test]
fn output_is_deterministic_and_fingerprints_ignore_the_snippet() {
    let db = fixture_db();
    let target = sca_fixture("php-vulnerable");
    let (_, a, _) = scan_sarif(&target, db.path(), &[]);
    let (_, b, _) = scan_sarif(&target, db.path(), &[]);
    assert_eq!(a, b);
    let fps: Vec<&str> = results(&a)
        .iter()
        .map(|r| {
            r["partialFingerprints"]["sdrscanFingerprint/v1"]
                .as_str()
                .unwrap()
        })
        .collect();
    let mut uniq = fps.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), fps.len(), "sidik jari harus unik per temuan");

    // menggeser baris (mis. komentar/format ulang lockfile) tidak mengubah sidik jari
    let tmp = tempfile::tempdir().unwrap();
    let text = fs::read_to_string(target.join("composer.lock")).unwrap();
    fs::write(tmp.path().join("composer.lock"), format!("\n\n\n{text}")).unwrap();
    let (_, shifted, _) = scan_sarif(tmp.path(), db.path(), &[]);
    let fp_of = |doc: &Value, id: &str| -> String {
        results(doc)
            .into_iter()
            .find(|r| r["ruleId"] == id)
            .unwrap()["partialFingerprints"]["sdrscanFingerprint/v1"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(fp_of(&a, "CVE-2099-0001"), fp_of(&shifted, "CVE-2099-0001"));
    let line_a = results(&a)
        .into_iter()
        .find(|r| r["ruleId"] == "CVE-2099-0001")
        .unwrap()["locations"][0]["physicalLocation"]["region"]["startLine"]
        .as_u64()
        .unwrap();
    let line_s = results(&shifted)
        .into_iter()
        .find(|r| r["ruleId"] == "CVE-2099-0001")
        .unwrap()["locations"][0]["physicalLocation"]["region"]["startLine"]
        .as_u64()
        .unwrap();
    assert_eq!(line_s, line_a + 3);
}

#[test]
fn text_report_lists_sca_findings() {
    let db = fixture_db();
    let target = sca_fixture("rust-app");
    let r = run(&[
        "scan",
        target.to_str().unwrap(),
        "--templates",
        root().join("templates/php").to_str().unwrap(),
        "--vuln-db",
        db.path().to_str().unwrap(),
    ]);
    assert_eq!(r.code, Some(1));
    assert!(r.stdout.contains("Cargo.lock:"), "{}", r.stdout);
    assert!(
        r.stdout.contains("critical [CVE-2099-0300]"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("acme-parser@0.8.0"), "{}", r.stdout);
    assert!(
        r.stderr.contains("1 file dipindai, 1 temuan"),
        "{}",
        r.stderr
    );
}
