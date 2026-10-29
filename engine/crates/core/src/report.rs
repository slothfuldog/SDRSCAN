use std::fmt::Write;

use crate::finding::{ScanOutput, Severity};

pub const EXIT_OK: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

/// 1 bila ada temuan di atau di atas ambang; peringatan tidak ikut dihitung.
pub fn exit_code(output: &ScanOutput, fail_on: Severity) -> i32 {
    if output.findings.iter().any(|f| f.severity >= fail_on) {
        EXIT_FINDINGS
    } else {
        EXIT_OK
    }
}

pub fn format_text(output: &ScanOutput) -> String {
    let mut s = String::new();
    for f in &output.findings {
        let l = &f.location;
        if l.has_region() {
            let _ = writeln!(
                s,
                "{}:{}:{}: {} [{}] {}",
                l.path, l.start_line, l.start_column, f.severity, f.rule_id, f.message
            );
        } else {
            let _ = writeln!(
                s,
                "{}: {} [{}] {}",
                l.path, f.severity, f.rule_id, f.message
            );
        }
        if let Some(first) = f.snippet.lines().next() {
            let _ = writeln!(s, "    {}", first.trim());
        }
    }
    s
}

/// Satu baris peringatan per entri, untuk stderr.
pub fn format_warnings(output: &ScanOutput) -> String {
    let mut s = String::new();
    for w in &output.warnings {
        let place = match (&w.location, &w.path) {
            (Some(l), _) => format!("{}:{}", l.path, l.start_line),
            (None, Some(p)) => p.clone(),
            (None, None) => "-".to_string(),
        };
        let _ = writeln!(s, "peringatan: {place}: {}", w.message);
    }
    s
}

pub fn summary(output: &ScanOutput) -> String {
    format!(
        "Ringkasan: {} file dipindai, {} temuan, {} peringatan",
        output.files_scanned,
        output.findings.len(),
        output.warnings.len()
    )
}
