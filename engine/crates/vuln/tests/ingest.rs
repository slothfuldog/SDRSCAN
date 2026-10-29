mod common;

use std::io::Write;

use common::{make_zip, osv_json};
use sdrscan_vuln::ingest::{ingest, Limits, Source};
use sdrscan_vulndb::Ecosystem;

fn write_zip(bytes: &[u8]) -> (tempfile::TempDir, Source) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("all.zip");
    std::fs::write(&p, bytes).unwrap();
    (dir, Source::Zip(p))
}

#[test]
fn too_many_entries_is_rejected_before_reading() {
    let entries: Vec<(String, Vec<u8>)> = (0..50)
        .map(|i| {
            (
                format!("a{i}.json"),
                osv_json(&format!("GHSA-{i}"), "npm", "p", "0", "1.0.0", None),
            )
        })
        .collect();
    let refs: Vec<(&str, Vec<u8>)> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let (_d, src) = write_zip(&make_zip(&refs));
    let limits = Limits {
        max_entries: 10,
        ..Limits::default()
    };
    let err = ingest(&src, Ecosystem::Npm, &limits).unwrap_err();
    assert!(err.to_string().contains("melebihi batas"), "{err:#}");
    assert!(ingest(&src, Ecosystem::Npm, &Limits::default()).is_ok());
}

#[test]
fn oversized_entry_is_skipped_even_when_compressed_size_is_tiny() {
    // 20 MiB nol terkompresi menjadi puluhan KiB: pertahanan zip-bomb harus berdasarkan ukuran terurai.
    let bomb = vec![b' '; 20 * 1024 * 1024];
    let (_d, src) = write_zip(&make_zip(&[
        ("bomb.json", bomb),
        (
            "ok1.json",
            osv_json("GHSA-1", "npm", "p", "0", "1.0.0", None),
        ),
        (
            "ok2.json",
            osv_json("GHSA-2", "npm", "p", "0", "1.0.0", None),
        ),
        (
            "ok3.json",
            osv_json("GHSA-3", "npm", "p", "0", "1.0.0", None),
        ),
        (
            "ok4.json",
            osv_json("GHSA-4", "npm", "p", "0", "1.0.0", None),
        ),
        (
            "ok5.json",
            osv_json("GHSA-5", "npm", "p", "0", "1.0.0", None),
        ),
    ]));
    let limits = Limits {
        max_entry_bytes: 1024 * 1024,
        ..Limits::default()
    };
    let (advs, stats) = ingest(&src, Ecosystem::Npm, &limits).unwrap();
    assert_eq!(advs.len(), 5);
    assert_eq!(stats.invalid, 1);
}

#[test]
fn total_uncompressed_limit_aborts() {
    let entries: Vec<(String, Vec<u8>)> = (0..20)
        .map(|i| {
            (
                format!("a{i}.json"),
                osv_json(&format!("GHSA-{i}"), "npm", "p", "0", "1.0.0", None),
            )
        })
        .collect();
    let refs: Vec<(&str, Vec<u8>)> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let (_d, src) = write_zip(&make_zip(&refs));
    let limits = Limits {
        max_total_bytes: 2000,
        ..Limits::default()
    };
    let err = ingest(&src, Ecosystem::Npm, &limits).unwrap_err();
    assert!(err.to_string().contains("zip-bomb"), "{err:#}");
}

#[test]
fn zip_slip_names_are_never_written_anywhere() {
    // nama entri berbahaya hanya dibaca ke memori; tidak ada berkas yang ditulis
    let (d, src) = write_zip(&make_zip(&[
        (
            "../../evil.json",
            osv_json("GHSA-1", "npm", "p", "0", "1.0.0", None),
        ),
        (
            "/abs/evil2.json",
            osv_json("GHSA-2", "npm", "p", "0", "1.0.0", None),
        ),
    ]));
    let (advs, _) = ingest(&src, Ecosystem::Npm, &Limits::default()).unwrap();
    assert_eq!(advs.len(), 2);
    assert!(!d.path().parent().unwrap().join("evil.json").exists());
    let mut names: Vec<_> = std::fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names.len(), 1);
    let _ = std::io::stdout().flush();
}

#[test]
fn empty_and_non_json_zips_are_errors() {
    let (_d, src) = write_zip(&make_zip(&[("catatan.txt", b"x".to_vec())]));
    assert!(ingest(&src, Ecosystem::Npm, &Limits::default()).is_err());
}
