use std::path::Path;

use sdrscan_core::{Profile, Severity, Template};

const VALID: &str = "id: php-demo\ntype: sast\nlanguages: [php]\nseverity: high\nmessage: demo\nquery: \"(program) @finding\"\n";

fn parse(src: &str) -> Result<Template, sdrscan_core::CoreError> {
    Template::parse(src, Path::new("demo.yaml"))
}

#[test]
fn valid_template_parses() {
    let t = parse(VALID).unwrap();
    assert_eq!(t.id, "php-demo");
    assert_eq!(t.severity, Severity::High);
}

#[test]
fn errors_name_file_and_line() {
    let e = parse(&VALID.replace("severity: high", "severity: urgent")).unwrap_err();
    let msg = e.to_string();
    assert!(msg.starts_with("demo.yaml:"), "{msg}");

    let e = parse(&VALID.replace("php-demo", "Php_Demo")).unwrap_err();
    assert!(e.to_string().starts_with("demo.yaml:1:"), "{e}");
}

#[test]
fn unknown_field_and_missing_query_are_rejected() {
    assert!(parse(&format!("{VALID}extra: 1\n")).is_err());
    assert!(parse("id: a\ntype: sast\nlanguages: [php]\nseverity: low\nmessage: m\n").is_err());
}

#[test]
fn http_type_is_reserved_but_loadable() {
    let t = parse("id: web-demo\ntype: http\nseverity: low\nmessage: m\n").unwrap();
    assert_eq!(t.kind, sdrscan_core::TemplateType::Http);
}

#[test]
fn only_php_is_supported_in_v1() {
    assert!(parse(&VALID.replace("[php]", "[go]")).is_err());
}

#[test]
fn profile_selects_by_tag_and_severity() {
    let mut a = parse(VALID).unwrap();
    a.tags = vec!["secrets".into()];
    let mut b = parse(&VALID.replace("php-demo", "php-other")).unwrap();
    b.severity = Severity::Low;
    let profile = Profile {
        include_tags: vec!["secrets".into()],
        ..Profile::default()
    };
    let picked = profile.select(vec![a.clone(), b.clone()]);
    assert_eq!(picked.len(), 1);
    let profile = Profile {
        min_severity: Some(Severity::Medium),
        ..Profile::default()
    };
    let picked = profile.select(vec![a, b]);
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].id, "php-demo");
}

#[test]
fn severity_orders_and_parses() {
    assert!(Severity::Critical > Severity::High);
    assert_eq!("MEDIUM".parse::<Severity>().unwrap(), Severity::Medium);
    assert!("x".parse::<Severity>().is_err());
}

mod vulnerability_sarif {
    use sdrscan_core::sarif::to_sarif;
    use sdrscan_core::{Cvss, Finding, Location, ScanOutput, Severity, VulnTarget, Vulnerability};

    fn finding(path: &str, snippet: &str, version: &str, score: Option<f32>) -> Finding {
        Finding {
            rule_id: "CVE-2024-1234".into(),
            severity: Severity::High,
            message: "pesan".into(),
            location: Location {
                path: path.into(),
                start_line: 7,
                start_column: 1,
                end_line: 7,
                end_column: 30,
            },
            snippet: snippet.into(),
            vulnerability: Some(Vulnerability {
                ids: vec!["CVE-2024-1234".into(), "GHSA-aaaa-bbbb-cccc".into()],
                package: VulnTarget::Package {
                    ecosystem: "npm".into(),
                    name: "lodash".into(),
                    version: version.into(),
                },
                fixed_versions: vec!["4.17.21".into()],
                source: "osv".into(),
                references: vec!["https://example.test/a".into()],
                cvss: score.map(|s| Cvss {
                    score: s,
                    vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".into()),
                }),
                confidence: "high".into(),
                scope: Some("runtime".into()),
                summary: "Ringkasan".into(),
                cwe: vec!["CWE-1321".into()],
            }),
        }
    }

    fn doc(findings: Vec<Finding>) -> serde_json::Value {
        let out = ScanOutput {
            findings,
            ..ScanOutput::default()
        };
        to_sarif(&out, &[], "sdrscan-sast", "0.1.0")
    }

    #[test]
    fn derived_rule_and_vulnerability_properties() {
        let d = doc(vec![finding(
            "package-lock.json",
            "lodash@4.17.15",
            "4.17.15",
            Some(9.8),
        )]);
        let run = &d["runs"][0];
        let rule = &run["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "CVE-2024-1234");
        assert_eq!(rule["shortDescription"]["text"], "Ringkasan");
        assert_eq!(rule["properties"]["security-severity"], "9.8");
        assert_eq!(
            rule["properties"]["tags"],
            serde_json::json!([
                "security",
                "vulnerability",
                "sca",
                "external/cve/cve-2024-1234",
                "external/cwe/cwe-1321"
            ])
        );
        assert_eq!(
            rule["helpUri"],
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
        );
        let r = &run["results"][0];
        assert_eq!(r["ruleIndex"], 0);
        let v = &r["properties"]["vulnerability"];
        assert_eq!(v["cvss"]["score"], 9.8, "tanpa derau f32");
        assert_eq!(v["package"]["name"], "lodash");
        // summary dan cwe hanya untuk rule; tidak bocor ke properti hasil
        assert!(v.get("summary").is_none() && v.get("cwe").is_none());
    }

    #[test]
    fn fingerprint_depends_on_package_not_on_snippet_or_line() {
        let a = doc(vec![finding(
            "package-lock.json",
            "lodash@4.17.15",
            "4.17.15",
            None,
        )]);
        let mut moved = finding(
            "package-lock.json",
            "teks lain sama sekali",
            "4.17.15",
            None,
        );
        moved.location.start_line = 99;
        let b = doc(vec![moved]);
        let fp = |d: &serde_json::Value| {
            d["runs"][0]["results"][0]["partialFingerprints"]["sdrscanFingerprint/v1"].clone()
        };
        assert_eq!(fp(&a), fp(&b));
        let other_version = doc(vec![finding(
            "package-lock.json",
            "lodash@4.17.15",
            "4.17.16",
            None,
        )]);
        assert_ne!(fp(&a), fp(&other_version));
        let other_path = doc(vec![finding(
            "sub/package-lock.json",
            "lodash@4.17.15",
            "4.17.15",
            None,
        )]);
        assert_ne!(fp(&a), fp(&other_path));
    }

    #[test]
    fn without_cvss_score_security_severity_comes_from_severity_and_cvss_key_is_absent() {
        let d = doc(vec![finding("a", "b", "1.0.0", None)]);
        let rule = &d["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["properties"]["security-severity"], "8.0");
        assert!(d["runs"][0]["results"][0]["properties"]["vulnerability"]
            .get("cvss")
            .is_none());
    }

    #[test]
    fn one_rule_per_advisory_even_with_several_findings() {
        let d = doc(vec![
            finding(
                "a/package-lock.json",
                "lodash@4.17.15",
                "4.17.15",
                Some(7.5),
            ),
            finding(
                "b/package-lock.json",
                "lodash@4.17.15",
                "4.17.15",
                Some(7.5),
            ),
        ]);
        assert_eq!(
            d["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(d["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn product_target_serializes_as_product_and_version() {
        let mut f = finding("http://t.example/", "Server: Apache/2.4.41", "x", Some(5.0));
        f.location = Location::url("http://t.example/");
        if let Some(v) = &mut f.vulnerability {
            v.package = VulnTarget::Product {
                product: "cpe:2.3:a:apache:http_server".into(),
                version: "2.4.41".into(),
            };
            v.source = "nvd".into();
            v.confidence = "low".into();
            v.scope = None;
        }
        let d = doc(vec![f]);
        let r = &d["runs"][0]["results"][0];
        assert_eq!(
            r["properties"]["vulnerability"]["package"],
            serde_json::json!({"product":"cpe:2.3:a:apache:http_server","version":"2.4.41"})
        );
        assert!(r["properties"]["vulnerability"].get("scope").is_none());
        assert_eq!(r["properties"]["evidence"], "Server: Apache/2.4.41");
        assert_eq!(
            d["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"][2],
            "dast"
        );
    }
}

#[test]
fn fingerprint_ignores_multi_page_suffix() {
    use sdrscan_core::{sarif::to_sarif, Finding, Location, ScanOutput};
    let make = |snippet: &str| {
        let out = ScanOutput {
            findings: vec![Finding {
                rule_id: "dast-missing-csp".into(),
                severity: Severity::Low,
                message: "m".into(),
                location: Location::url("http://t.example/"),
                snippet: snippet.into(),
                vulnerability: None,
            }],
            ..ScanOutput::default()
        };
        let d = to_sarif(&out, &[], "sdrscan-dast", "0.1.0");
        d["runs"][0]["results"][0]["partialFingerprints"]["sdrscanFingerprint/v1"].clone()
    };
    let base = make("Content-Security-Policy: (tidak ada)");
    assert_eq!(
        base,
        make("Content-Security-Policy: (tidak ada) (berlaku juga di 3 halaman lain: a, b, c)")
    );
    assert_ne!(base, make("Content-Security-Policy: (ada)"));
}
