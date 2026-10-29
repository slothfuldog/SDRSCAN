//! Pengujian TLS dengan server HTTPS lokal (CA uji di tests/fixtures/tls; kunci hanya untuk pengujian).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use assert_cmd::Command;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const ALLOW: &str = "--allow-private-networks-for-tests";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls")
}

/// Server HTTPS di loopback dengan sertifikat yang ditandatangani CA uji.
fn serve_tls() -> String {
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
                continue; // klien menolak sertifikat
            }
            let _ = tls.write_all(
                b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            );
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    format!("https://{addr}/")
}

fn cmd() -> Command {
    Command::cargo_bin("sdrscan-dast").unwrap()
}

#[test]
fn untrusted_issuer_fails_with_a_helpful_hint() {
    let url = serve_tls();
    let o = cmd()
        .args(["scan", ALLOW, &url, "--timeout", "5"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("--ca-cert"), "{stderr}");
    assert!(stderr.contains("--insecure"), "{stderr}");
}

#[test]
fn custom_ca_makes_the_scan_succeed() {
    let url = serve_tls();
    let ca = fixtures().join("ca.pem");
    let o = cmd()
        .args(["scan", ALLOW, &url, "--fail-on", "info", "--ca-cert"])
        .arg(&ca)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert_eq!(
        o.status.code(),
        Some(1),
        "{stdout}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // Halaman HTTPS tanpa HSTS harus dilaporkan; transport tidak lagi dianggap tak aman.
    assert!(stdout.contains("dast-missing-hsts"), "{stdout}");
    assert!(!stdout.contains("dast-insecure-transport"));
}

#[test]
fn insecure_flag_skips_verification_and_warns() {
    let url = serve_tls();
    let o = cmd()
        .args(["scan", ALLOW, &url, "--insecure", "--fail-on", "critical"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("verifikasi sertifikat TLS dimatikan"),
        "{stderr}"
    );
}

#[test]
fn invalid_ca_file_is_a_usage_error() {
    let url = serve_tls();
    let dir = std::env::temp_dir().join(format!("sdrscan-dast-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.pem");
    std::fs::write(&bad, "not a certificate").unwrap();
    let o = cmd()
        .args(["scan", ALLOW, &url, "--ca-cert"])
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("CA"));
    let o = cmd()
        .args(["scan", ALLOW, &url, "--ca-cert", "/nonexistent/ca.pem"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    std::fs::remove_dir_all(dir).unwrap();
}
