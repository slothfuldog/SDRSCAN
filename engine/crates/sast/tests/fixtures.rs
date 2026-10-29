mod common;

use std::fs;

use common::{all_templates, root, template};
use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Expected {
    rule_id: String,
    line: u32,
}

#[test]
fn every_template_has_a_fixture_directory() {
    let fixtures = root().join("tests/fixtures/php");
    for t in all_templates() {
        let dir = fixtures.join(&t.id);
        for file in ["vulnerable.php", "safe.php", "expected.json"] {
            assert!(dir.join(file).is_file(), "template {} tanpa {}", t.id, file);
        }
    }
}

#[test]
fn there_are_twelve_templates() {
    assert_eq!(all_templates().len(), 12);
}

#[test]
fn vulnerable_detected_and_safe_clean() {
    let fixtures = root().join("tests/fixtures/php");
    for t in all_templates() {
        let dir = fixtures.join(&t.id);
        let templates = [template(&t.id)];

        let vulnerable = sdrscan_sast::scan(&dir.join("vulnerable.php"), &templates).unwrap();
        let mut got: Vec<Expected> = vulnerable
            .findings
            .iter()
            .map(|f| Expected {
                rule_id: f.rule_id.clone(),
                line: f.location.start_line,
            })
            .collect();
        got.sort();
        let mut want: Vec<Expected> =
            serde_json::from_str(&fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
        want.sort();
        assert_eq!(got, want, "vulnerable.php untuk {}", t.id);
        assert!(
            vulnerable.warnings.is_empty(),
            "peringatan tak terduga untuk {}: {:?}",
            t.id,
            vulnerable.warnings
        );

        let safe = sdrscan_sast::scan(&dir.join("safe.php"), &templates).unwrap();
        assert!(
            safe.findings.is_empty(),
            "safe.php untuk {} punya temuan: {:?}",
            t.id,
            safe.findings
        );
        assert!(
            safe.warnings.is_empty(),
            "safe.php untuk {} punya peringatan: {:?}",
            t.id,
            safe.warnings
        );
    }
}
