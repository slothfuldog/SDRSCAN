mod common;

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use common::{dir_listing, ecosystem_zip, make_zip, osv_json, serve, Resp, Server};
use sdrscan_vulndb::{Ecosystem, VulnDb};

const ALLOW: &str = "--allow-private-networks-for-tests";

fn cmd() -> Command {
    let mut c = Command::cargo_bin("sdrscan-vuln").unwrap();
    c.env_remove("SDRSCAN_VULN_DB").env_remove("NVD_API_KEY");
    c
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(c: &mut Command) -> Out {
    let o = c.output().unwrap();
    Out {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn osv_server() -> Server {
    serve(|req| match req.target.as_str() {
        "/Packagist/all.zip" => Resp::ok(ecosystem_zip("Packagist", "acme/pkg", 3)),
        "/npm/all.zip" => Resp::ok(ecosystem_zip("npm", "acme-pkg", 2)),
        "/Go/all.zip" => Resp::ok(ecosystem_zip("Go", "example.com/acme/pkg", 2)),
        "/crates.io/all.zip" => Resp::ok(ecosystem_zip("crates.io", "acme-pkg", 1)),
        _ => Resp::status(404),
    })
}

fn update(db: &Path, base: &str, extra: &[&str]) -> Out {
    run(cmd()
        .args(["update", ALLOW, "--db"])
        .arg(db)
        .args([
            "--osv-base-url",
            base,
            "--retry-delay-ms",
            "10",
            "--timeout",
            "10",
        ])
        .args(extra))
}

fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if e.file_type().unwrap().is_dir() {
                walk(base, &e.path(), out);
            } else {
                out.push((
                    e.path().strip_prefix(base).unwrap().display().to_string(),
                    fs::read(e.path()).unwrap(),
                ));
            }
        }
    }
    walk(dir, dir, &mut out);
    out
}

#[test]
fn downloads_all_four_ecosystems_by_default_and_builds_the_index() {
    let server = osv_server();
    let tmp = tempfile::tempdir().unwrap();
    let db_dir = tmp.path().join("vulndb");
    let o = update(&db_dir, &server.base, &[]);
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    assert!(o.stderr.contains("Packagist: 3 advisory"), "{}", o.stderr);
    assert!(
        o.stderr.contains("1 dilewati"),
        "entri rusak dihitung: {}",
        o.stderr
    );

    assert_eq!(dir_listing(&db_dir), ["meta.json", "nvd", "osv"]);
    assert_eq!(
        dir_listing(&db_dir.join("osv")),
        [
            "Go.jsonl",
            "Packagist.jsonl",
            "crates.io.jsonl",
            "npm.jsonl"
        ]
    );
    assert_eq!(
        dir_listing(tmp.path()),
        ["vulndb"],
        "tidak ada direktori sementara tersisa"
    );

    let db = VulnDb::open(&db_dir).unwrap();
    assert_eq!(db.meta().advisory_count, 3 + 2 + 2 + 1);
    assert_eq!(db.meta().format_version, 1);
    let (merged, corrupt) = db
        .lookup(Ecosystem::Packagist, "ACME/pkg", "0.5.0")
        .unwrap();
    assert_eq!(corrupt, 0);
    assert_eq!(merged.len(), 3);
    assert_eq!(merged[0].ids[0], "CVE-2099-0000");
    assert_eq!(merged[0].fixed_versions, ["1.0.0"]);
    assert_eq!(merged[0].cvss.as_ref().unwrap().score, 9.8);
    // advisory malware (MAL-) tidak ikut
    assert!(db
        .lookup(Ecosystem::Packagist, "evil", "1.0.0")
        .unwrap()
        .0
        .is_empty());
    assert!(db
        .lookup(Ecosystem::Packagist, "acme/pkg", "1.0.0")
        .unwrap()
        .0
        .is_empty());

    let reqs = server.requests();
    assert_eq!(reqs.len(), 4);
    assert!(reqs.iter().all(|r| r.target.ends_with("/all.zip")));

    // status dan lookup lewat CLI
    let s = run(cmd().args(["status", "--json", "--db"]).arg(&db_dir));
    assert_eq!(s.code, Some(0), "{}", s.stderr);
    let j: serde_json::Value = serde_json::from_str(&s.stdout).unwrap();
    assert_eq!(j["advisory_count"], 8);
    assert_eq!(j["stale"], false);
    assert_eq!(j["osv"]["Packagist"]["advisories"], 3);
    assert!(j["nvd"].is_null());
    let l = run(cmd()
        .args([
            "lookup",
            "--ecosystem",
            "npm",
            "--package",
            "acme-pkg",
            "--version",
            "0.1.0",
            "--db",
        ])
        .arg(&db_dir));
    assert_eq!(l.code, Some(0), "{}", l.stderr);
    assert!(l.stdout.contains("CVE-2099-0000"), "{}", l.stdout);
    assert!(l.stdout.contains("perbaikan: 1.0.0"), "{}", l.stdout);
}

#[test]
fn update_is_deterministic_apart_from_timestamps() {
    let server = osv_server();
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
    assert_eq!(update(&a, &server.base, &[]).code, Some(0));
    assert_eq!(update(&b, &server.base, &[]).code, Some(0));
    for f in [
        "osv/Packagist.jsonl",
        "osv/npm.jsonl",
        "osv/Go.jsonl",
        "osv/crates.io.jsonl",
    ] {
        assert_eq!(
            fs::read(a.join(f)).unwrap(),
            fs::read(b.join(f)).unwrap(),
            "{f}"
        );
    }
}

#[test]
fn partial_update_keeps_other_ecosystems_and_replaces_atomically() {
    let server = osv_server();
    let tmp = tempfile::tempdir().unwrap();
    let db_dir = tmp.path().join("vulndb");
    assert_eq!(update(&db_dir, &server.base, &[]).code, Some(0));
    let npm_before = fs::read(db_dir.join("osv/npm.jsonl")).unwrap();
    let o = update(&db_dir, &server.base, &["--ecosystems", "Packagist"]);
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    assert_eq!(fs::read(db_dir.join("osv/npm.jsonl")).unwrap(), npm_before);
    let db = VulnDb::open(&db_dir).unwrap();
    assert_eq!(db.meta().advisory_count, 8);
    assert_eq!(dir_listing(tmp.path()), ["vulndb"]);
}

#[test]
fn failures_leave_the_existing_database_untouched() {
    let good = osv_server();
    let tmp = tempfile::tempdir().unwrap();
    let db_dir = tmp.path().join("vulndb");
    assert_eq!(update(&db_dir, &good.base, &[]).code, Some(0));
    let before = snapshot(&db_dir);

    // 404
    let bad = serve(|_| Resp::status(404));
    let o = update(&db_dir, &bad.base, &["--ecosystems", "npm"]);
    assert_eq!(o.code, Some(2));
    assert!(o.stderr.contains("404"), "{}", o.stderr);

    // zip terpotong
    let truncated = serve(|_| {
        let z = ecosystem_zip("npm", "acme-pkg", 5);
        Resp::ok(z[..z.len() / 2].to_vec())
    });
    let o = update(&db_dir, &truncated.base, &["--ecosystems", "npm"]);
    assert_eq!(o.code, Some(2));
    assert!(o.stderr.contains("zip"), "{}", o.stderr);

    // bukan zip
    let junk = serve(|_| Resp::ok(b"<html>bukan zip</html>".to_vec()));
    assert_eq!(
        update(&db_dir, &junk.base, &["--ecosystems", "npm"]).code,
        Some(2)
    );

    // zip valid tetapi mayoritas entri rusak
    let corrupt = serve(|_| {
        Resp::ok(make_zip(&[
            ("a.json", b"{x".to_vec()),
            ("b.json", b"{y".to_vec()),
            ("c.json", osv_json("GHSA-1", "npm", "p", "0", "1.0.0", None)),
        ]))
    });
    let o = update(&db_dir, &corrupt.base, &["--ecosystems", "npm"]);
    assert_eq!(o.code, Some(2));
    assert!(o.stderr.contains("korup"), "{}", o.stderr);

    // dump yang menyusut tajam ditolak tanpa --force
    let shrunk = serve(|_| {
        Resp::ok(make_zip(&[(
            "a.json",
            osv_json("GHSA-1", "Packagist", "acme/pkg", "0", "1.0.0", None),
        )]))
    });
    let o = update(&db_dir, &shrunk.base, &["--ecosystems", "Packagist"]);
    assert_eq!(o.code, Some(2));
    assert!(o.stderr.contains("mencurigakan"), "{}", o.stderr);

    // dump tanpa satu pun advisory ekosistem ini
    let empty = serve(|_| {
        Resp::ok(make_zip(&[(
            "a.json",
            osv_json("GHSA-1", "PyPI", "p", "0", "1.0.0", None),
        )]))
    });
    assert_eq!(
        update(&db_dir, &empty.base, &["--ecosystems", "npm"]).code,
        Some(2)
    );

    assert_eq!(
        snapshot(&db_dir),
        before,
        "basis data lama tidak boleh berubah"
    );
    assert_eq!(
        dir_listing(tmp.path()),
        ["vulndb"],
        "direktori sementara dibersihkan"
    );

    // --force menerima hasil yang menyusut
    let o = update(
        &db_dir,
        &shrunk.base,
        &["--ecosystems", "Packagist", "--force"],
    );
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    assert_eq!(
        VulnDb::open(&db_dir).unwrap().meta().sources.osv.ecosystems["Packagist"].advisories,
        1
    );
}

#[test]
fn download_size_limit_is_enforced() {
    let big = serve(|_| Resp::ok(vec![7u8; 1_600_000]));
    let tmp = tempfile::tempdir().unwrap();
    let o = update(
        &tmp.path().join("db"),
        &big.base,
        &["--ecosystems", "Go", "--max-download-mb", "1"],
    );
    assert_eq!(o.code, Some(2));
    assert!(o.stderr.contains("melebihi batas"), "{}", o.stderr);
    assert!(!tmp.path().join("db").exists());
}

#[test]
fn server_errors_are_retried() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let flaky = serve(move |_| {
        if h.fetch_add(1, Ordering::SeqCst) == 0 {
            Resp::status(503)
        } else {
            Resp::ok(ecosystem_zip("Go", "example.com/acme/pkg", 2))
        }
    });
    let tmp = tempfile::tempdir().unwrap();
    let o = update(&tmp.path().join("db"), &flaky.base, &["--ecosystems", "Go"]);
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn private_networks_are_refused_without_the_test_flag() {
    let server = osv_server();
    let tmp = tempfile::tempdir().unwrap();
    let o = run(cmd()
        .args(["update", "--ecosystems", "Go", "--db"])
        .arg(tmp.path().join("db"))
        .args(["--osv-base-url", &server.base, "--retry-delay-ms", "10"]));
    assert_eq!(o.code, Some(2));
    assert!(o.stderr.contains("jaringan privat"), "{}", o.stderr);
    assert!(o.stderr.contains("--from-dir"), "{}", o.stderr);
    assert!(server.requests().is_empty());
}

#[test]
fn from_dir_needs_no_network_and_accepts_zip_and_json_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let dumps = tmp.path().join("dumps");
    fs::create_dir_all(dumps.join("Packagist")).unwrap();
    fs::write(
        dumps.join("Packagist/all.zip"),
        ecosystem_zip("Packagist", "acme/pkg", 3),
    )
    .unwrap();
    fs::write(
        dumps.join("Go.zip"),
        ecosystem_zip("Go", "example.com/acme/pkg", 2),
    )
    .unwrap();
    fs::create_dir_all(dumps.join("npm")).unwrap();
    fs::write(
        dumps.join("npm/GHSA-x.json"),
        osv_json(
            "GHSA-x",
            "npm",
            "acme-pkg",
            "0",
            "2.0.0",
            Some("CVE-2099-7777"),
        ),
    )
    .unwrap();
    fs::write(dumps.join("npm/catatan.txt"), "diabaikan").unwrap();
    let db_dir = tmp.path().join("vulndb");
    let o = run(cmd()
        .args(["update", "--db"])
        .arg(&db_dir)
        .arg("--from-dir")
        .arg(&dumps)
        // basis URL tak terjangkau membuktikan tidak ada koneksi
        .args(["--osv-base-url", "http://127.0.0.1:9"]));
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    let db = VulnDb::open(&db_dir).unwrap();
    assert!(db.has_ecosystem(Ecosystem::Packagist));
    assert!(db.has_ecosystem(Ecosystem::Go));
    assert!(db.has_ecosystem(Ecosystem::Npm));
    assert!(
        !db.has_ecosystem(Ecosystem::CratesIo),
        "tanpa dump -> dilewati"
    );
    assert_eq!(
        db.lookup(Ecosystem::Npm, "acme-pkg", "1.0.0")
            .unwrap()
            .0
            .len(),
        1
    );

    // ekosistem diminta eksplisit tetapi dumpnya tidak ada -> galat
    let o = run(cmd()
        .args(["update", "--ecosystems", "crates.io", "--db"])
        .arg(tmp.path().join("db2"))
        .arg("--from-dir")
        .arg(&dumps));
    assert_eq!(o.code, Some(2));
    assert!(o.stderr.contains("tidak ditemukan"), "{}", o.stderr);
}

#[test]
fn bad_arguments_exit_2() {
    let o = run(cmd().args(["update", "--ecosystems", "PyPI", "--db", "/tmp/x"]));
    assert_eq!(o.code, Some(2));
    let o = run(cmd().args(["update"]));
    assert_eq!(o.code, Some(2));
    assert!(o.stderr.contains("SDRSCAN_VULN_DB"), "{}", o.stderr);
    let o = run(cmd().args(["status", "--db", "/tidak/ada"]));
    assert_eq!(o.code, Some(2));
    let o = run(cmd().args([
        "update",
        "--db",
        "/tmp/x",
        "--ca-cert",
        "/tidak/ada.pem",
        "--ecosystems",
        "Go",
    ]));
    assert_eq!(o.code, Some(2));
    assert!(o.stderr.contains("berkas CA"), "{}", o.stderr);
}

#[test]
fn env_var_selects_the_database_directory() {
    let server = osv_server();
    let tmp = tempfile::tempdir().unwrap();
    let db_dir: PathBuf = tmp.path().join("fromenv");
    let o = run(cmd().env("SDRSCAN_VULN_DB", &db_dir).args([
        "update",
        ALLOW,
        "--ecosystems",
        "Go",
        "--osv-base-url",
        &server.base,
    ]));
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    assert!(db_dir.join("meta.json").exists());
    let s = run(cmd().env("SDRSCAN_VULN_DB", &db_dir).arg("status"));
    assert_eq!(s.code, Some(0));
    assert!(s.stdout.contains("Jumlah advisory: 2"), "{}", s.stdout);
}

#[test]
fn status_warns_when_stale_but_still_exits_zero() {
    let server = osv_server();
    let tmp = tempfile::tempdir().unwrap();
    let db_dir = tmp.path().join("vulndb");
    assert_eq!(
        update(&db_dir, &server.base, &["--ecosystems", "Go"]).code,
        Some(0)
    );
    let fresh = run(cmd().args(["status", "--db"]).arg(&db_dir));
    assert_eq!(fresh.code, Some(0));
    assert!(!fresh.stdout.contains("PERINGATAN"), "{}", fresh.stdout);

    let p = db_dir.join("meta.json");
    let mut meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
    meta["updated_at"] = serde_json::json!("2020-01-01T00:00:00Z");
    fs::write(&p, serde_json::to_string(&meta).unwrap()).unwrap();
    let stale = run(cmd().args(["status", "--db"]).arg(&db_dir));
    assert_eq!(stale.code, Some(0));
    assert!(
        stale
            .stdout
            .contains("PERINGATAN: data lebih tua dari 7 hari"),
        "{}",
        stale.stdout
    );
    let j = run(cmd()
        .args(["status", "--json", "--max-age-days", "100000", "--db"])
        .arg(&db_dir));
    let j: serde_json::Value = serde_json::from_str(&j.stdout).unwrap();
    assert_eq!(j["stale"], false);
    assert!(j["age_days"].as_i64().unwrap() > 1000);
}

#[test]
fn lookup_without_match_and_with_missing_ecosystem() {
    let server = osv_server();
    let tmp = tempfile::tempdir().unwrap();
    let db_dir = tmp.path().join("vulndb");
    assert_eq!(
        update(&db_dir, &server.base, &["--ecosystems", "Go"]).code,
        Some(0)
    );
    let l = run(cmd()
        .args([
            "lookup",
            "--ecosystem",
            "Go",
            "--package",
            "example.com/acme/pkg",
            "--version",
            "v1.0.0",
            "--db",
        ])
        .arg(&db_dir));
    assert_eq!(l.code, Some(0));
    assert!(l.stdout.contains("tidak ada advisory"), "{}", l.stdout);
    let l = run(cmd()
        .args([
            "lookup",
            "--ecosystem",
            "npm",
            "--package",
            "x",
            "--version",
            "1.0.0",
            "--db",
        ])
        .arg(&db_dir));
    assert_eq!(l.code, Some(2));
}
