mod common;

use std::fs;
use std::path::Path;

use common::*;

const FAST: &str = "100";

fn schema_validate(doc: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/schemas/sarif-schema-2.1.0.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::draft4::new(&schema).unwrap();
    let errors: Vec<String> = validator.iter_errors(doc).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{errors:?}");
}

/// Menjalankan `scan` dan mengembalikan (keluaran, dokumen SARIF).
fn crawl_sarif(
    dir: &Path,
    app: &App,
    start: &str,
    auth: &Path,
    extra: &[&str],
) -> (std::process::Output, serde_json::Value) {
    let out = dir.join("out.sarif");
    let o = cmd()
        .args(["scan", &app.url(start), "--auth-file"])
        .arg(auth)
        .args(["--crawl", "--max-rps", FAST, "--fail-on", "critical"])
        .args(["--format", "sarif", "--output"])
        .arg(&out)
        .args(extra)
        .output()
        .unwrap();
    let doc = fs::read_to_string(&out)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    (o, doc)
}

fn results<'a>(doc: &'a serde_json::Value, rule: &str) -> Vec<&'a serde_json::Value> {
    doc["runs"][0]["results"]
        .as_array()
        .map(|a| a.iter().filter(|r| r["ruleId"] == rule).collect())
        .unwrap_or_default()
}

fn loc(r: &serde_json::Value) -> &str {
    r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .unwrap()
}

#[test]
fn form_login_with_csrf_from_html_input_then_crawl() {
    let (app, other) = App::pair(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, doc) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &[]);
    let (_, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert_eq!(app.logins(), 1);

    // POST login memakai CSRF dari input HTML dan cookie awal; halaman di balik login terambil.
    let log = app.log();
    let post = log.iter().find(|r| r.method == "POST").unwrap();
    assert_eq!(post.path_only(), "/login");
    assert!(post.body.contains("csrf_token="));
    let gets = app.crawl_gets();
    for p in [
        "/dashboard",
        "/page1",
        "/page2",
        "/links",
        "/deep/1",
        "/deep/2",
    ] {
        assert!(gets.contains(&p.to_string()), "{p} tidak diambil: {gets:?}");
    }
    // Halaman terautentikasi dikirim dengan cookie sesi.
    let dash = log.iter().rfind(|r| r.path_only() == "/dashboard").unwrap();
    assert!(dash
        .header("cookie")
        .unwrap()
        .contains("session=SESS-VALUE-1"));
    app.assert_only_get_except_login();
    assert!(other.log().is_empty(), "origin lain tidak boleh diakses");

    // Header Server berversi di dashboard terdeteksi; ringkasan menyebut halaman.
    assert!(!results(&doc, "dast-server-version-disclosure").is_empty());
    assert!(stderr.contains("halaman dipindai"), "{stderr}");
    schema_validate(&doc);
}

#[test]
fn csrf_from_cookie_and_json_login() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let json = format!(
        r#"{{"version":1,"login":{{"type":"form","url":"{}/login-cookie","method":"POST","body_format":"json",
        "username_field":"user","password_field":"password","username":"{USER}","password":"{PASS}",
        "extra_fields":{{"remember":"true"}},
        "csrf":{{"source":"cookie","name":"csrf","send_as":"header","header_name":"X-CSRF-Token"}}}}}}"#,
        app.base
    );
    let auth = write_auth(dir.path(), "a.json", &json);
    let o = cmd()
        .args(["scan", &app.url("/welcome"), "--login-check", "--auth-file"])
        .arg(&auth)
        .args(["--max-rps", FAST])
        .output()
        .unwrap();
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert!(stdout.starts_with("login berhasil: "), "{stdout}");
    assert!(stdout.contains("cookie diterima"), "{stdout}");
    let post = app.log().into_iter().find(|r| r.method == "POST").unwrap();
    assert_eq!(post.header("x-csrf-token"), Some(CSRF_COOKIE));
    assert_eq!(post.header("content-type"), Some("application/json"));
}

#[test]
fn json_login_without_csrf() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let json = format!(
        r#"{{"version":1,"login":{{"type":"form","url":"{}/api/login","body_format":"json",
        "username_field":"user","password_field":"password","username":"{USER}","password":"{PASS}",
        "extra_fields":{{"remember":"true"}},"success":{{"statuses":[200],"cookie_set":"session","body_contains":"ok"}}}}}}"#,
        app.base
    );
    let auth = write_auth(dir.path(), "a.json", &json);
    let o = cmd()
        .args(["scan", &app.url("/welcome"), "--login-check", "--auth-file"])
        .arg(&auth)
        .args(["--max-rps", FAST])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o).1);
}

#[test]
fn wrong_credentials_exit_2_without_leaking_secrets() {
    for path in ["/login", "/login2"] {
        let app = App::start(Cfg::default());
        let dir = tempfile::tempdir().unwrap();
        let json = form_login_json(&app.base, path).replace(PASS, "WRONG-PASSWORD-ZZ");
        let auth = write_auth(dir.path(), "a.json", &json);
        let o = cmd()
            .args([
                "scan",
                &app.url("/dashboard"),
                "--crawl",
                "--max-rps",
                FAST,
                "--auth-file",
            ])
            .arg(&auth)
            .output()
            .unwrap();
        let (stdout, stderr) = text(&o);
        assert_eq!(o.status.code(), Some(2), "{path}: {stderr}");
        assert!(stderr.contains("login gagal"), "{stderr}");
        for secret in ["WRONG-PASSWORD-ZZ", USER, CSRF_FIELD] {
            assert!(
                !stderr.contains(secret) && !stdout.contains(secret),
                "{secret} bocor"
            );
        }
        // Tidak ada crawl setelah login gagal.
        assert!(!app.was_requested("/dashboard"), "{path}");
        assert!(!app.was_requested("/page1"));
    }
}

#[test]
fn login_url_on_other_origin_is_rejected_before_sending_anything() {
    let (app, other) = App::pair(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(
        dir.path(),
        "a.json",
        &form_login_json(&other.base, "/login"),
    );
    let o = cmd()
        .args(["scan", &app.url("/dashboard"), "--crawl", "--auth-file"])
        .arg(&auth)
        .output()
        .unwrap();
    let (_, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("satu origin"), "{stderr}");
    assert!(
        app.log().is_empty(),
        "target tidak boleh menerima permintaan"
    );
    assert!(other.log().is_empty(), "kredensial tidak boleh terkirim");
    let o = cmd()
        .args([
            "scan",
            &app.url("/dashboard"),
            "--login-check",
            "--auth-file",
        ])
        .arg(&auth)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(other.log().is_empty() && app.log().is_empty());
}

#[test]
fn fixed_headers_go_only_to_the_target_origin() {
    let (app, other) = App::pair(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let json = format!(
        r#"{{"version":1,"headers":{{"Authorization":"Bearer {BEARER}","X-Api-Key":"{API_KEY}"}}}}"#
    );
    let auth = write_auth(dir.path(), "a.json", &json);
    let (o, doc) = crawl_sarif(dir.path(), &app, "/api/home", &auth, &[]);
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    let log = app.log();
    assert!(log.len() >= 3, "{log:?}");
    for r in &log {
        assert_eq!(
            r.header("authorization"),
            Some(format!("Bearer {BEARER}").as_str()),
            "{}",
            r.path
        );
        assert_eq!(r.header("x-api-key"), Some(API_KEY));
    }
    assert!(app.was_requested("/public"));
    // /redir-out mengarah ke origin lain: tidak diikuti; origin lain tidak menerima apa pun.
    assert!(app.was_requested("/redir-out"));
    assert!(other.log().is_empty(), "{:?}", other.log());
    for s in [BEARER, API_KEY] {
        assert!(!stdout.contains(s) && !stderr.contains(s));
        assert!(!doc.to_string().contains(s));
    }
}

#[test]
fn wrong_bearer_token_is_reported_as_401_warning() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(
        dir.path(),
        "a.json",
        r#"{"version":1,"headers":{"Authorization":"Bearer WRONG-TOKEN-1","X-Api-Key":"k"}}"#,
    );
    let o = cmd()
        .args([
            "scan",
            &app.url("/api/home"),
            "--fail-on",
            "critical",
            "--auth-file",
        ])
        .arg(&auth)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("401"), "{stderr}");
    assert!(!stdout.contains("WRONG-TOKEN-1") && !stderr.contains("WRONG-TOKEN-1"));
}

#[test]
fn pasted_cookie_is_sent_to_target_only() {
    let (app, other) = App::pair(Cfg {
        accept_pasted: true,
        ..Cfg::default()
    });
    let dir = tempfile::tempdir().unwrap();
    let json = format!(r#"{{"version":1,"cookies":{{"session":"{PASTED_SESSION}"}}}}"#);
    let auth = write_auth(dir.path(), "a.json", &json);
    let (o, _) = crawl_sarif(dir.path(), &app, "/cookie-home", &auth, &[]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o).1);
    for r in app.log() {
        assert!(
            r.header("cookie").unwrap().contains(PASTED_SESSION),
            "{}",
            r.path
        );
    }
    assert!(app.was_requested("/public"));
    assert!(other.log().is_empty());
}

#[test]
fn crawl_never_visits_excluded_or_static_or_foreign_urls() {
    let (app, other) = App::pair(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, doc) = crawl_sarif(
        dir.path(),
        &app,
        "/dashboard",
        &auth,
        &["--exclude-path", "^/page2"],
    );
    let (_, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    for p in [
        "/logout",
        "/delete",
        "/style.css",
        "/logo.png",
        "/page2",
        "/hidden-json",
    ] {
        assert!(!app.was_requested(p), "{p} tidak boleh diakses");
    }
    // /go-out mengarah ke /logout: respons redirect diperiksa tetapi tujuan tidak diambil.
    assert!(app.was_requested("/go-out"));
    assert!(other.log().is_empty());
    assert!(stderr.contains("dilewati karena pengecualian"), "{stderr}");
    app.assert_only_get_except_login();
    schema_validate(&doc);
}

#[test]
fn depth_limit_and_warning() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, _) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &["--max-depth", "1"]);
    let (_, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert!(app.was_requested("/page1"));
    assert!(
        !app.was_requested("/deep/1"),
        "kedalaman 2 tidak boleh diambil"
    );
    assert!(stderr.contains("batas kedalaman"), "{stderr}");

    let app = App::start(Cfg::default());
    let auth = write_auth(dir.path(), "b.json", &form_login_json(&app.base, "/login"));
    let (o, _) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &["--max-depth", "0"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(!app.was_requested("/page1"));
}

#[test]
fn page_limit_and_warning() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, _) = crawl_sarif(
        dir.path(),
        &app,
        "/dashboard",
        &auth,
        &["--max-pages", "4", "--max-depth", "5"],
    );
    let (_, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert_eq!(app.crawl_gets().len(), 4, "{:?}", app.crawl_gets());
    assert!(stderr.contains("batas jumlah halaman"), "{stderr}");
}

#[test]
fn hard_limits_are_enforced() {
    for args in [
        ["--max-pages", "501"],
        ["--max-pages", "0"],
        ["--max-depth", "11"],
        ["--max-rps", "0"],
    ] {
        let o = cmd()
            .args(["scan", "http://127.0.0.1:9/", "--crawl"])
            .args(args)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn query_variants_per_path_are_capped() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, _) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &["--max-depth", "2"]);
    assert_eq!(o.status.code(), Some(0));
    let lists = app.crawl_gets().iter().filter(|p| *p == "/list").count();
    assert_eq!(lists, 3);
}

#[test]
fn findings_are_deduplicated_across_pages() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, doc) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &[]);
    assert_eq!(o.status.code(), Some(0));
    let csp = results(&doc, "dast-missing-csp");
    assert_eq!(csp.len(), 1, "{csp:?}");
    let ev = csp[0]["properties"]["evidence"].as_str().unwrap();
    assert!(
        ev.starts_with("Content-Security-Policy: (tidak ada) (berlaku juga di "),
        "{ev}"
    );
    assert!(ev.contains("halaman lain"), "{ev}");
    assert!(ev.matches("http://").count() <= 5, "{ev}");
    assert_eq!(results(&doc, "dast-insecure-transport").len(), 1);
    // Satu temuan per (aturan, bukti): tidak ada pasangan ganda.
    let mut keys: Vec<(String, String)> = doc["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["ruleId"].as_str().unwrap().to_string(),
                r["properties"]["evidence"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    let n = keys.len();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), n);
}

#[test]
fn session_cookie_flags_and_masking() {
    let app = App::start(Cfg {
        cookie_attrs: Some("; Path=/"),
        ..Cfg::default()
    });
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, doc) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &["--max-depth", "0"]);
    assert_eq!(o.status.code(), Some(0));
    let httponly = results(&doc, "dast-cookie-missing-httponly");
    assert!(
        httponly
            .iter()
            .any(|r| r["properties"]["evidence"] == "Set-Cookie: session=<disamarkan>"),
        "{httponly:?}"
    );
    assert!(!doc.to_string().contains("SESS-VALUE"));
    assert!(!results(&doc, "dast-cookie-missing-samesite").is_empty());
}

#[test]
fn new_passive_html_checks() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, doc) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &[]);
    assert_eq!(o.status.code(), Some(0));
    // Halaman login (http) memuat input password tanpa autocomplete.
    let p = results(&doc, "dast-form-password-over-http");
    assert!(p.iter().any(|r| loc(r).ends_with("/login")), "{p:?}");
    let a = results(&doc, "dast-autocomplete-password");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0]["level"], "note");
    // Parameter rahasia di tautan: hanya nama, tidak pernah nilainya.
    let s = results(&doc, "dast-sensitive-info-in-url");
    let evidences: Vec<&str> = s
        .iter()
        .map(|r| r["properties"]["evidence"].as_str().unwrap())
        .collect();
    assert!(
        evidences.iter().any(|e| e.contains("'token'")),
        "{evidences:?}"
    );
    assert!(
        evidences.iter().any(|e| e.contains("'api_key'")),
        "{evidences:?}"
    );
    let all = doc.to_string();
    assert!(!all.contains(URL_SECRET), "nilai parameter rahasia bocor");
}

#[test]
fn session_expiry_triggers_one_relogin() {
    let app = App::start(Cfg {
        expire_after: Some(4),
        ..Cfg::default()
    });
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, _) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &[]);
    let (_, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert_eq!(app.logins(), 2, "harus login ulang tepat sekali");
    assert!(stderr.contains("sesi kedaluwarsa"), "{stderr}");
    assert!(
        app.was_requested("/deep/2"),
        "crawl harus berlanjut setelah login ulang"
    );
}

#[test]
fn repeated_expiry_stops_after_single_relogin() {
    let app = App::start(Cfg {
        expire_after: Some(4),
        repeat_expiry: true,
        ..Cfg::default()
    });
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, _) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &["--max-depth", "5"]);
    let (_, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert_eq!(app.logins(), 2, "login ulang hanya sekali per pemindaian");
    assert!(stderr.contains("sesi berakhir lagi"), "{stderr}");
}

#[test]
fn login_check_does_not_crawl_or_report_findings() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let o = cmd()
        .args([
            "scan",
            &app.url("/dashboard"),
            "--crawl",
            "--login-check",
            "--max-rps",
            FAST,
            "--auth-file",
        ])
        .arg(&auth)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert!(stdout.starts_with("login berhasil: "), "{stdout}");
    assert!(
        stdout.contains(&format!("halaman awal {}/welcome", app.base)),
        "{stdout}"
    );
    assert!(stdout.contains("2 cookie diterima"), "{stdout}");
    assert!(
        !stdout.contains("dast-"),
        "tidak boleh ada temuan: {stdout}"
    );
    assert!(!app.was_requested("/dashboard"));
    assert!(!app.was_requested("/page1"));
    assert_eq!(app.logins(), 1);
    // Tanpa bagian login: galat.
    let a2 = write_auth(dir.path(), "b.json", r#"{"version":1,"headers":{"A":"b"}}"#);
    let o = cmd()
        .args(["scan", &app.url("/"), "--login-check", "--auth-file"])
        .arg(&a2)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn login_check_failure_exits_2() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let json = form_login_json(&app.base, "/login")
        .replace(CSRF_FIELD, "x")
        .replace("csrf_token", "nope");
    let auth = write_auth(dir.path(), "a.json", &json);
    let o = cmd()
        .args(["scan", &app.url("/"), "--login-check", "--auth-file"])
        .arg(&auth)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr.contains("CSRF"), "{stderr}");
    assert!(stdout.is_empty());
    assert!(!stderr.contains(PASS) && !stderr.contains(USER));
}

#[test]
fn verbose_logging_never_leaks_secrets() {
    let (app, _other) = App::pair(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let json = format!(
        r#"{{"version":1,"login":{{"type":"form","url":"{}/login","body_format":"form",
        "username_field":"user","password_field":"password","username":"{USER}","password":"{PASS}",
        "csrf":{{"source":"html_input","name":"csrf_token"}}}},
        "headers":{{"X-Api-Key":"{API_KEY}","Authorization":"Bearer {BEARER}"}}}}"#,
        app.base
    );
    let auth = write_auth(dir.path(), "a.json", &json);
    let (o, doc) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &["-vv"]);
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    let combined = format!("{stdout}\n{stderr}\n{doc}");
    for secret in [
        PASS,
        USER,
        CSRF_FIELD,
        BEARER,
        API_KEY,
        "SESS-VALUE",
        URL_SECRET,
        "INITCOOKIE",
    ] {
        assert!(!combined.contains(secret), "rahasia '{secret}' bocor");
    }
    // Log -vv tetap tampil (tanpa rahasia).
    assert!(stderr.contains("GET http"), "{stderr}");
}

#[test]
fn sarif_is_valid_and_results_are_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let mut docs = Vec::new();
    for i in 0..2 {
        let app = App::start(Cfg::default());
        // Port berbeda tiap putaran: samakan dengan mengganti origin sebelum membandingkan.
        let auth = write_auth(
            dir.path(),
            &format!("a{i}.json"),
            &form_login_json(&app.base, "/login"),
        );
        let (o, doc) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &[]);
        assert_eq!(o.status.code(), Some(0));
        schema_validate(&doc);
        // Sidik jari memuat origin (port acak): bandingkan setelah dibuang.
        let mut doc = doc;
        for r in doc["runs"][0]["results"].as_array_mut().unwrap() {
            r.as_object_mut().unwrap().remove("partialFingerprints");
        }
        docs.push(doc.to_string().replace(&app.base, "http://ORIGIN"));
    }
    assert_eq!(docs[0], docs[1]);
}

#[test]
fn rate_limit_spaces_requests() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let o = cmd()
        .args([
            "scan",
            &app.url("/dashboard"),
            "--crawl",
            "--max-pages",
            "3",
            "--max-rps",
            "4",
            "--auth-file",
        ])
        .arg(&auth)
        .args(["--fail-on", "critical"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o).1);
    let log = app.log();
    assert!(log.len() >= 6, "{}", log.len());
    for w in log.windows(2) {
        let gap = w[1].at.duration_since(w[0].at).as_millis();
        assert!(
            gap >= 200,
            "jeda {gap}ms antara {} dan {}",
            w[0].path,
            w[1].path
        );
    }
}

#[test]
fn block_private_networks_still_rejects_authenticated_scans() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let o = cmd()
        .args([
            "scan",
            &app.url("/dashboard"),
            "--block-private-networks",
            "--crawl",
            "--auth-file",
        ])
        .arg(&auth)
        .output()
        .unwrap();
    let (_, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("jaringan privat"), "{stderr}");
    assert!(app.log().is_empty());
}

#[test]
fn oversized_response_is_reported_and_not_parsed() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, _) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &[]);
    let (_, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("respons terlalu besar"), "{stderr}");
    assert!(!app.was_requested("/after-big"));
}

#[test]
fn non_html_responses_are_scanned_but_not_followed() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let (o, _) = crawl_sarif(dir.path(), &app, "/dashboard", &auth, &[]);
    assert_eq!(o.status.code(), Some(0));
    assert!(app.was_requested("/nonhtml"));
    assert!(!app.was_requested("/hidden-json"));
}

#[test]
fn redirect_into_excluded_path_is_not_followed_without_crawl() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let auth = write_auth(dir.path(), "a.json", &form_login_json(&app.base, "/login"));
    let o = cmd()
        .args([
            "scan",
            &app.url("/go-out"),
            "--max-rps",
            FAST,
            "--fail-on",
            "critical",
            "--auth-file",
        ])
        .arg(&auth)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o).1);
    assert!(!app.was_requested("/logout"));
    assert!(text(&o).1.contains("dilewati karena pengecualian"));
}

#[test]
fn auth_file_rules() {
    let app = App::start(Cfg::default());
    let dir = tempfile::tempdir().unwrap();
    let url = app.url("/");
    let run = |p: &Path| {
        cmd()
            .args([
                "scan",
                &url,
                "--fail-on",
                "critical",
                "--max-rps",
                FAST,
                "--auth-file",
            ])
            .arg(p)
            .output()
            .unwrap()
    };
    // bukan berkas biasa
    let o = run(dir.path());
    assert_eq!(o.status.code(), Some(2));
    // terlalu besar
    let big = dir.path().join("big.json");
    fs::write(&big, vec![b' '; 70 * 1024]).unwrap();
    assert_eq!(run(&big).status.code(), Some(2));
    // JSON tidak valid: isi tidak ditampilkan
    let bad = write_auth(dir.path(), "bad.json", "{\"password\": \"TOPSECRET-INVALID");
    let o = run(&bad);
    assert_eq!(o.status.code(), Some(2));
    assert!(!text(&o).1.contains("TOPSECRET"), "{}", text(&o).1);
    // tipe salah: nilai tidak ditampilkan
    let wrong = write_auth(
        dir.path(),
        "wrong.json",
        r#"{"version":1,"login":{"type":"form","url":"http://127.0.0.1:1/l","username_field":"u","password_field":"p","username":"TOPSECRET-U","password":12345}}"#,
    );
    let o = run(&wrong);
    assert_eq!(o.status.code(), Some(2));
    assert!(!text(&o).1.contains("TOPSECRET"));
    // izin longgar: hanya peringatan
    let ok = write_auth(
        dir.path(),
        "ok.json",
        r#"{"version":1,"headers":{"X-A":"b"}}"#,
    );
    let o = run(&ok);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o).1);
    assert!(!text(&o).1.contains("izin berkas auth"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&ok, fs::Permissions::from_mode(0o644)).unwrap();
        let o = run(&ok);
        assert_eq!(o.status.code(), Some(0));
        assert!(
            text(&o).1.contains("izin berkas auth terlalu longgar"),
            "{}",
            text(&o).1
        );
    }
    // tidak ada berkas
    assert_eq!(run(&dir.path().join("none.json")).status.code(), Some(2));
}

#[test]
fn invalid_exclude_regex_is_a_usage_error() {
    let app = App::start(Cfg::default());
    let o = cmd()
        .args(["scan", &app.url("/"), "--crawl", "--exclude-path", "("])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(app.log().is_empty());
}

#[test]
fn crawl_without_auth_works_on_public_pages() {
    let app = App::start(Cfg::default());
    let o = cmd()
        .args([
            "scan",
            &app.url("/"),
            "--crawl",
            "--max-rps",
            FAST,
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o).1);
    assert!(app.was_requested("/public"));
    assert!(text(&o).1.contains("2 halaman dipindai"), "{}", text(&o).1);
}
