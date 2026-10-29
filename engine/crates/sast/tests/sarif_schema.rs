mod common;

use std::fs;

use common::{all_templates, root};
use sdrscan_core::sarif;

fn validator() -> jsonschema::Validator {
    let schema: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root().join("tests/schemas/sarif-schema-2.1.0.json")).unwrap(),
    )
    .unwrap();
    jsonschema::draft4::new(&schema).expect("skema SARIF resmi harus dapat dikompilasi")
}

fn assert_valid(doc: &serde_json::Value) {
    let errors: Vec<String> = validator()
        .iter_errors(doc)
        .map(|e| format!("{e} (di {})", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "SARIF tidak valid:\n{}",
        errors.join("\n")
    );
}

#[test]
fn sarif_for_all_fixtures_matches_official_schema() {
    let templates = all_templates();
    let out = sdrscan_sast::scan(&root().join("tests/fixtures/php"), &templates).unwrap();
    assert!(out.findings.len() > 20);
    assert_valid(&sarif::to_sarif(&out, &templates, "sdrscan-sast", "0.1.0"));
}

#[test]
fn sarif_with_ambiguous_taint_warning_matches_schema() {
    let templates = all_templates();
    let out = sdrscan_sast::scan(&root().join("tests/fixtures/taint"), &templates).unwrap();
    assert!(!out.warnings.is_empty());
    assert_valid(&sarif::to_sarif(&out, &templates, "sdrscan-sast", "0.1.0"));
}

#[test]
fn empty_sarif_matches_schema() {
    let out = sdrscan_core::ScanOutput::default();
    assert_valid(&sarif::to_sarif(
        &out,
        &all_templates(),
        "sdrscan-sast",
        "0.1.0",
    ));
}

#[test]
fn schema_rejects_a_broken_document() {
    let bad = serde_json::json!({ "version": "2.1.0", "runs": [{ "results": [] }] });
    assert!(
        !validator().is_valid(&bad),
        "validator harus menolak run tanpa tool"
    );
}

#[test]
fn sarif_for_sca_findings_matches_official_schema() {
    use assert_cmd::Command;
    let db = common::fixture_db();
    let mut total = 0;
    for name in [
        "php-vulnerable",
        "node-npm",
        "node-npm-v1",
        "node-yarn",
        "go-app",
        "go-sum-only",
        "rust-app",
        "ignored",
        "php-safe",
    ] {
        let o = Command::cargo_bin("sdrscan-sast")
            .unwrap()
            .args(["scan"])
            .arg(root().join("tests/fixtures/sca").join(name))
            .arg("--templates")
            .arg(root().join("templates/php"))
            .arg("--vuln-db")
            .arg(db.path())
            .args(["--format", "sarif"])
            .output()
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        total += doc["runs"][0]["results"].as_array().unwrap().len();
        assert_valid(&doc);
    }
    assert!(
        total >= 10,
        "fixture harus menghasilkan banyak temuan: {total}"
    );
}
