mod common;

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use common::root;
fn cmd() -> Command {
    Command::cargo_bin("sdrscan-sast").unwrap()
}

fn templates() -> PathBuf {
    root().join("templates/php")
}

fn fixture(id: &str, name: &str) -> PathBuf {
    root().join("tests/fixtures/php").join(id).join(name)
}

fn out(o: &std::process::Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn findings_above_threshold_exit_1() {
    let o = cmd()
        .args(["scan"])
        .arg(fixture("php-sql-injection", "vulnerable.php"))
        .arg("--templates")
        .arg(templates())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let (stdout, stderr) = out(&o);
    assert!(stdout.contains("php-sql-injection"));
    assert!(stderr.contains("Ringkasan: 1 file dipindai, 3 temuan"));
    assert!(!stdout.contains("Ringkasan"), "stdout hanya berisi hasil");
}

#[test]
fn clean_scan_exits_0() {
    let o = cmd()
        .args(["scan"])
        .arg(fixture("php-sql-injection", "safe.php"))
        .arg("--templates")
        .arg(templates())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
}

#[test]
fn fail_on_threshold_is_respected() {
    // php-xss-echo bersifat high; ambang critical tidak menggagalkan.
    let base = |threshold: &str| {
        cmd()
            .args(["scan"])
            .arg(fixture("php-xss-echo", "vulnerable.php"))
            .arg("--templates")
            .arg(templates())
            .args(["--fail-on", threshold])
            .output()
            .unwrap()
            .status
            .code()
    };
    assert_eq!(base("critical"), Some(0));
    assert_eq!(base("high"), Some(1));
    assert_eq!(base("low"), Some(1));
}

#[test]
fn sarif_goes_to_file_with_expected_shape() {
    let dir = std::env::temp_dir().join(format!("sdrscan-cli-sarif-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("out.sarif");
    let o = cmd()
        .args(["scan"])
        .arg(fixture("php-command-injection", "vulnerable.php"))
        .arg("--templates")
        .arg(templates())
        .args(["--format", "sarif", "--output"])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(o.stdout.is_empty());
    let doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(doc["version"], "2.1.0");
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["ruleId"], "php-command-injection");
    assert_eq!(results[0]["level"], "error");
    assert!(results[0]["partialFingerprints"]["sdrscanFingerprint/v1"].is_string());
    let rules = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 12);
    let rule = rules
        .iter()
        .find(|r| r["id"] == "php-command-injection")
        .unwrap();
    assert_eq!(rule["properties"]["security-severity"], "9.5");
    assert!(rule["properties"]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "external/cwe/cwe-78"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_template_exits_2_with_file_and_line() {
    let dir = std::env::temp_dir().join(format!("sdrscan-cli-badtpl-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("bad.yaml"),
        "id: Bad_Id\ntype: sast\nlanguages: [php]\nseverity: high\nmessage: x\nquery: \"(program)\"\n",
    )
    .unwrap();
    let o = cmd()
        .args(["scan"])
        .arg(fixture("php-eval", "safe.php"))
        .arg("--templates")
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let (_, stderr) = out(&o);
    assert!(stderr.contains("bad.yaml:1"), "{stderr}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_query_exits_2_naming_the_template() {
    let dir = std::env::temp_dir().join(format!("sdrscan-cli-badquery-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("q.yaml"),
        "id: bad-query\ntype: sast\nlanguages: [php]\nseverity: high\nmessage: x\nquery: \"(no_such_node_kind)\"\n",
    )
    .unwrap();
    let o = cmd()
        .args(["scan"])
        .arg(fixture("php-eval", "safe.php"))
        .arg("--templates")
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(out(&o).1.contains("bad-query"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_target_exits_2() {
    let o = cmd()
        .args(["scan", "/nonexistent/sdrscan-target"])
        .arg("--templates")
        .arg(templates())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn profile_filters_templates_and_sets_threshold() {
    let o = cmd()
        .args(["scan"])
        .arg(root().join("tests/fixtures/php"))
        .arg("--templates")
        .arg(templates())
        .arg("--profile")
        .arg(root().join("profiles/secrets.yaml"))
        .arg("--fail-on")
        .arg("critical")
        .output()
        .unwrap();
    let (stdout, _) = out(&o);
    assert!(stdout.contains("php-hardcoded-secret"));
    assert!(!stdout.contains("php-sql-injection"));
    assert!(!stdout.contains("php-eval"));
    assert_eq!(
        o.status.code(),
        Some(0),
        "explicit --fail-on mengalahkan profil"
    );
}

#[test]
fn gitignore_is_honored_even_outside_a_git_repo() {
    let dir = std::env::temp_dir().join(format!("sdrscan-cli-gitignore-{}", std::process::id()));
    fs::create_dir_all(dir.join("vendor")).unwrap();
    fs::write(dir.join(".gitignore"), "vendor/\n").unwrap();
    fs::write(dir.join("vendor/x.php"), "<?php eval($_GET['a']);").unwrap();
    fs::write(dir.join("app.php"), "<?php eval($_GET['a']);").unwrap();
    let o = cmd()
        .args(["scan"])
        .arg(&dir)
        .arg("--templates")
        .arg(templates())
        .output()
        .unwrap();
    let (stdout, _) = out(&o);
    assert!(stdout.contains("app.php"));
    assert!(!stdout.contains("vendor"), "{stdout}");
    fs::remove_dir_all(dir).unwrap();
}
