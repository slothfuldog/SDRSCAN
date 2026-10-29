mod common;

use common::{root, template};
use sdrscan_core::WarningKind;

fn scan(file: &str) -> sdrscan_core::ScanOutput {
    let templates = [template("php-xss-echo")];
    sdrscan_sast::scan(&root().join("tests/fixtures/taint").join(file), &templates).unwrap()
}

fn lines(out: &sdrscan_core::ScanOutput) -> Vec<u32> {
    out.findings.iter().map(|f| f.location.start_line).collect()
}

#[test]
fn ambiguous_assignment_is_warning_not_finding() {
    let out = scan("ambiguous.php");
    assert!(out.findings.is_empty());
    assert_eq!(out.warnings.len(), 1);
    let w = &out.warnings[0];
    assert_eq!(w.kind, WarningKind::AmbiguousTaint);
    assert_eq!(w.rule_id.as_deref(), Some("php-xss-echo"));
    assert_eq!(w.location.as_ref().unwrap().start_line, 5);
}

#[test]
fn flow_across_functions_is_not_tracked() {
    let out = scan("cross_function.php");
    assert!(out.findings.is_empty());
    assert!(out.warnings.is_empty());
}

#[test]
fn self_referencing_and_compound_assignment_stay_tainted() {
    assert_eq!(lines(&scan("accumulate.php")), vec![5, 8]);
}

#[test]
fn variables_are_scoped_per_function() {
    let out = scan("scopes.php");
    assert!(out.findings.is_empty());
    assert!(out.warnings.is_empty());
}

#[test]
fn taint_flows_through_chained_assignments() {
    assert_eq!(lines(&scan("transitive.php")), vec![5]);
}

#[test]
fn sdrscan_ignore_on_same_or_previous_line() {
    assert_eq!(lines(&scan("suppressed.php")), vec![6]);
}

#[test]
fn syntax_error_warns_but_still_scans() {
    let out = scan("broken.php");
    assert!(out
        .warnings
        .iter()
        .any(|w| w.kind == WarningKind::ParseError));
    assert_eq!(lines(&out), vec![2]);
}

#[test]
fn output_is_deterministic() {
    let templates = sdrscan_core::load_templates(&root().join("templates/php")).unwrap();
    let dir = root().join("tests/fixtures/php");
    let a = sdrscan_sast::scan(&dir, &templates).unwrap();
    let b = sdrscan_sast::scan(&dir, &templates).unwrap();
    assert_eq!(a, b);
}
