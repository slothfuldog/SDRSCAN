use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;

use assert_cmd::Command;

/// Server HTTP di loopback: membalas setiap koneksi dengan `response` mentah.
fn serve(response: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}/")
}

fn ok(headers: &str) -> String {
    format!("HTTP/1.1 200 OK\r\n{headers}Content-Length: 2\r\nConnection: close\r\n\r\nok")
}

fn cmd() -> Command {
    Command::cargo_bin("sdrscan-dast").unwrap()
}

/// Loopback dipakai server uji; default produksi menolaknya, jadi pengecualian uji wajib dipasang.
const ALLOW: &str = "--allow-private-networks-for-tests";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn insecure_target_fails_at_medium_but_not_at_critical() {
    let url = serve(ok("Server: Apache/2.4.41\r\nSet-Cookie: sid=abc\r\n"));
    let run = |fail_on: &str| {
        cmd()
            .args(["scan", ALLOW, &url, "--fail-on", fail_on])
            .output()
            .unwrap()
    };
    let o = run("medium");
    assert_eq!(o.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(stdout.contains("dast-insecure-transport"), "{stdout}");
    assert!(stdout.contains("dast-cookie-missing-httponly"));
    assert!(
        !stdout.contains("abc"),
        "nilai cookie tidak boleh bocor: {stdout}"
    );
    assert_eq!(run("critical").status.code(), Some(0));
}

#[test]
fn sarif_uses_url_location_and_validates_against_official_schema() {
    let url = serve(ok(""));
    let dir = std::env::temp_dir().join(format!("sdrscan-dast-sarif-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("out.sarif");
    let o = cmd()
        .args(["scan", ALLOW, &url, "--format", "sarif", "--output"])
        .arg(&file)
        .args(["--fail-on", "critical"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(o.stdout.is_empty());
    let doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();

    let schema: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root().join("tests/schemas/sarif-schema-2.1.0.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::draft4::new(&schema).unwrap();
    let errors: Vec<String> = validator.iter_errors(&doc).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{errors:?}");

    let first = &doc["runs"][0]["results"][0];
    let loc = &first["locations"][0]["physicalLocation"];
    assert_eq!(loc["artifactLocation"]["uri"], url.as_str());
    assert!(loc["region"].is_null());
    assert!(first["properties"]["evidence"].is_string());
    assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "sdrscan-dast");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unreachable_target_and_bad_scheme_exit_2() {
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/", l.local_addr().unwrap())
    };
    let o = cmd()
        .args(["scan", ALLOW, &closed, "--timeout", "3"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let o = cmd().args(["scan", "ftp://example.com/"]).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("skema"));
}

#[test]
fn cross_origin_redirect_is_not_followed() {
    let other = serve(ok("X-Marker: other\r\n"));
    let origin = serve(format!(
        "HTTP/1.1 302 Found\r\nLocation: {other}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ));
    let o = cmd()
        .args(["scan", ALLOW, &origin, "--fail-on", "info"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        stdout.contains(&origin),
        "temuan harus menunjuk origin awal: {stdout}"
    );
    assert!(!stdout.contains(&other));
}

#[test]
fn same_origin_redirect_is_followed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let reply = if req.starts_with("GET /final") {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            } else {
                "HTTP/1.1 301 Moved\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    let o = cmd()
        .args([
            "scan",
            ALLOW,
            &format!("http://{addr}/"),
            "--fail-on",
            "info",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(stdout.contains(&format!("http://{addr}/final")), "{stdout}");
}

#[test]
fn private_and_loopback_targets_are_rejected_with_block_private_networks() {
    let url = serve(ok(""));
    let o = cmd()
        .args(["scan", "--block-private-networks", &url])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("jaringan privat"), "{stderr}");

    for target in [
        "http://127.0.0.1:9/",
        "http://10.0.0.5/",
        "http://192.168.1.10/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://[::1]:9/",
        "http://[fd00::1]/",
        "http://localhost:9/",
    ] {
        let o = cmd()
            .args(["scan", "--block-private-networks", target, "--timeout", "3"])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{target}");
        let stderr = String::from_utf8_lossy(&o.stderr);
        assert!(stderr.contains("jaringan privat"), "{target}: {stderr}");
    }
}

#[test]
fn private_networks_are_allowed_by_default_but_not_cloud_metadata() {
    let url = serve(ok(""));
    let o = cmd()
        .args(["scan", &url, "--fail-on", "critical"])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );

    for target in [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.253/",
        "http://169.254.170.2/",
        "http://100.100.100.200/",
        "http://[fd00:ec2::254]/",
        "http://0.0.0.0/",
    ] {
        let o = cmd()
            .args(["scan", target, "--timeout", "3"])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{target}");
        let stderr = String::from_utf8_lossy(&o.stderr);
        assert!(stderr.contains("jaringan privat"), "{target}: {stderr}");
    }
}
