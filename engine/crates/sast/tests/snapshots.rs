mod common;

use common::{all_templates, root};
use sdrscan_core::{report, sarif};

fn scan_fixtures() -> sdrscan_core::ScanOutput {
    let templates = all_templates();
    sdrscan_sast::scan(
        &root().join("tests/fixtures/php/php-sql-injection"),
        &templates,
    )
    .unwrap()
}

#[test]
fn text_report_snapshot() {
    insta::assert_snapshot!(report::format_text(&scan_fixtures()));
}

#[test]
fn sarif_snapshot() {
    let out = scan_fixtures();
    let doc = sarif::to_sarif(&out, &all_templates(), "sdrscan-sast", "0.0.0-test");
    insta::assert_json_snapshot!(doc);
}
