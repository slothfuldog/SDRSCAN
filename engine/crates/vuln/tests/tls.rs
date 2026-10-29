//! Unduhan lewat HTTPS dengan CA uji milik DAST (tests/fixtures/tls; kunci hanya untuk pengujian).

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use assert_cmd::Command;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sdrscan_vulndb::VulnDb;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../dast/tests/fixtures/tls")
}

fn serve_tls(body: Vec<u8>) -> String {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(fixtures().join("server.pem"))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_file(fixtures().join("server.key")).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(mut tcp) = tcp else { break };
            let Ok(mut conn) = rustls::ServerConnection::new(config.clone()) else {
                continue;
            };
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            let mut buf = [0u8; 4096];
            if tls.read(&mut buf).is_err() {
                continue;
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = tls.write_all(head.as_bytes());
            let _ = tls.write_all(&body);
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    format!("https://{addr}")
}

fn update(base: &str, db: &Path, extra: &[&std::ffi::OsStr]) -> std::process::Output {
    let mut c = Command::cargo_bin("sdrscan-vuln").unwrap();
    c.env_remove("SDRSCAN_VULN_DB")
        .args([
            "update",
            "--allow-private-networks-for-tests",
            "--ecosystems",
            "Go",
            "--retry-delay-ms",
            "10",
            "--timeout",
            "10",
            "--osv-base-url",
            base,
            "--db",
        ])
        .arg(db);
    for e in extra {
        c.arg(e);
    }
    c.output().unwrap()
}

#[test]
fn untrusted_ca_fails_with_hint_and_custom_ca_succeeds() {
    let base = serve_tls(common::ecosystem_zip("Go", "example.com/acme/pkg", 2));
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("db");

    let o = update(&base, &db, &[]);
    assert_eq!(o.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("--ca-cert"), "{stderr}");
    assert!(!db.exists());

    let ca = fixtures().join("ca.pem");
    let o = update(&base, &db, &["--ca-cert".as_ref(), ca.as_os_str()]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(VulnDb::open(&db).unwrap().meta().advisory_count, 2);
}
