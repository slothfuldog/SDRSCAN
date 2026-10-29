use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::finding::{Finding, Location, ScanOutput, Severity, VulnTarget, Vulnerability};
use crate::template::Template;

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.1",
    }
}

fn fingerprint(rule_id: &str, path: &str, snippet: &str) -> String {
    let normalized = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(path.as_bytes());
    hasher.update([0]);
    hasher.update(normalized.as_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut acc, b| {
            acc.push_str(&format!("{b:02x}"));
            acc
        })
}

fn physical_location(l: &Location, snippet: &str) -> Value {
    if !l.has_region() {
        return json!({ "physicalLocation": { "artifactLocation": { "uri": l.path } } });
    }
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": l.path, "uriBaseId": "%SRCROOT%" },
            "region": {
                "startLine": l.start_line,
                "startColumn": l.start_column,
                "endLine": l.end_line,
                "endColumn": l.end_column,
                "snippet": { "text": snippet }
            }
        }
    })
}

/// Lokasi URL tidak punya `region.snippet`; buktinya ditulis di `properties.evidence`.
fn add_evidence(result: &mut Value, l: &Location, snippet: &str) {
    if !l.has_region() && !snippet.is_empty() {
        set_property(result, "evidence", json!(snippet));
    }
}

fn set_property(result: &mut Value, key: &str, value: Value) {
    let props = result["properties"].take();
    let mut props = if props.is_object() { props } else { json!({}) };
    props[key] = value;
    result["properties"] = props;
}

/// Skor satu desimal sebagai angka JSON (f32 langsung ke f64 akan menghasilkan 9.800000190734863).
fn score_number(score: f32) -> Value {
    let rounded: f64 = format!("{score:.1}").parse().unwrap_or(0.0);
    json!(rounded)
}

/// Objek `properties.vulnerability`: kunci persis ids, package, fixed_versions, source, references,
/// cvss (opsional), confidence, scope (opsional).
fn vulnerability_json(v: &Vulnerability) -> Value {
    let mut o = Map::new();
    o.insert("ids".into(), json!(v.ids));
    o.insert(
        "package".into(),
        serde_json::to_value(&v.package).unwrap_or(Value::Null),
    );
    o.insert("fixed_versions".into(), json!(v.fixed_versions));
    o.insert("source".into(), json!(v.source));
    o.insert("references".into(), json!(v.references));
    if let Some(c) = &v.cvss {
        let mut cv = Map::new();
        cv.insert("score".into(), score_number(c.score));
        if let Some(vector) = &c.vector {
            cv.insert("vector".into(), json!(vector));
        }
        o.insert("cvss".into(), Value::Object(cv));
    }
    o.insert("confidence".into(), json!(v.confidence));
    if let Some(scope) = &v.scope {
        o.insert("scope".into(), json!(scope));
    }
    Value::Object(o)
}

/// Rule turunan dari temuan kerentanan: id advisory tidak ada di template, jadi rule dibuat dari data temuan.
fn vulnerability_rule(f: &Finding, v: &Vulnerability) -> Value {
    let mut tags: Vec<String> = vec!["security".to_string(), "vulnerability".to_string()];
    tags.push(
        match v.package {
            VulnTarget::Package { .. } => "sca",
            VulnTarget::Product { .. } => "dast",
        }
        .to_string(),
    );
    for id in &v.ids {
        if id.len() > 4 && id[..4].eq_ignore_ascii_case("cve-") {
            tags.push(format!("external/cve/{}", id.to_ascii_lowercase()));
        }
    }
    for c in &v.cwe {
        tags.push(format!("external/cwe/{}", c.to_ascii_lowercase()));
    }
    tags.dedup();
    let severity_score = match &v.cvss {
        Some(c) => format!("{:.1}", c.score),
        None => security_severity(f.severity).to_string(),
    };
    let summary = if v.summary.trim().is_empty() {
        f.rule_id.clone()
    } else {
        v.summary.clone()
    };
    let mut rule = json!({
        "id": f.rule_id,
        "shortDescription": { "text": summary },
        "defaultConfiguration": { "level": level(f.severity) },
        "properties": {
            "tags": tags,
            "security-severity": severity_score
        }
    });
    let help = v
        .ids
        .iter()
        .find(|i| i.len() > 4 && i[..4].eq_ignore_ascii_case("cve-"))
        .map(|i| {
            format!(
                "https://nvd.nist.gov/vuln/detail/{}",
                i.to_ascii_uppercase()
            )
        })
        .or_else(|| {
            v.ids
                .iter()
                .find(|i| i.starts_with("GHSA-"))
                .map(|i| format!("https://github.com/advisories/{i}"))
        });
    if let Some(uri) = help {
        rule["helpUri"] = json!(uri);
    }
    rule
}

fn sarif_fingerprint(f: &Finding) -> String {
    match &f.vulnerability {
        Some(v) => fingerprint(&f.rule_id, &f.location.path, &v.package.key()),
        None => fingerprint(
            &f.rule_id,
            &f.location.path,
            crate::finding::base_evidence(&f.snippet),
        ),
    }
}

fn rule(t: &Template) -> Value {
    let mut tags: Vec<String> = vec!["security".to_string()];
    tags.extend(t.tags.iter().cloned());
    tags.extend(
        t.cwe
            .iter()
            .map(|c| format!("external/cwe/{}", c.to_ascii_lowercase())),
    );
    json!({
        "id": t.id,
        "shortDescription": { "text": t.message },
        "defaultConfiguration": { "level": level(t.severity) },
        "properties": {
            "tags": tags,
            "security-severity": security_severity(t.severity)
        }
    })
}

/// SARIF 2.1.0 dengan satu `run`. `templates` adalah template yang aktif pada pemindaian ini.
/// Peringatan taint ambigu ditulis sebagai hasil `note` berkeyakinan rendah; peringatan lain tidak.
/// Temuan dengan `vulnerability` yang `rule_id`-nya bukan template mendapat rule turunan
/// (ditambahkan setelah rule template, urut menurut id) dan properti `vulnerability`; sidik jarinya
/// dihitung dari (rule_id, path, paket@versi), bukan snippet.
pub fn to_sarif(
    output: &ScanOutput,
    templates: &[Template],
    tool_name: &str,
    tool_version: &str,
) -> Value {
    let mut derived: BTreeMap<String, Value> = BTreeMap::new();
    for f in &output.findings {
        if let Some(v) = &f.vulnerability {
            if !templates.iter().any(|t| t.id == f.rule_id) && !derived.contains_key(&f.rule_id) {
                derived.insert(f.rule_id.clone(), vulnerability_rule(f, v));
            }
        }
    }
    let rule_index = |id: &str| {
        templates.iter().position(|t| t.id == id).or_else(|| {
            derived
                .keys()
                .position(|k| k == id)
                .map(|i| templates.len() + i)
        })
    };

    let mut results: Vec<Value> = Vec::new();
    for f in &output.findings {
        let mut r = json!({
            "ruleId": f.rule_id,
            "level": level(f.severity),
            "message": { "text": f.message },
            "locations": [physical_location(&f.location, &f.snippet)],
            "partialFingerprints": {
                "sdrscanFingerprint/v1": sarif_fingerprint(f)
            }
        });
        if let Some(i) = rule_index(&f.rule_id) {
            r["ruleIndex"] = json!(i);
        }
        add_evidence(&mut r, &f.location, &f.snippet);
        if let Some(v) = &f.vulnerability {
            set_property(&mut r, "vulnerability", vulnerability_json(v));
        }
        results.push(r);
    }
    for w in &output.warnings {
        let (Some(rule_id), Some(loc)) = (&w.rule_id, &w.location) else {
            continue;
        };
        let snippet = w.snippet.as_deref().unwrap_or_default();
        let mut r = json!({
            "ruleId": rule_id,
            "level": "note",
            "message": { "text": w.message },
            "locations": [physical_location(loc, snippet)],
            "partialFingerprints": {
                "sdrscanFingerprint/v1": fingerprint(rule_id, &loc.path, snippet)
            },
            "properties": { "confidence": "low" }
        });
        if let Some(i) = rule_index(rule_id) {
            r["ruleIndex"] = json!(i);
        }
        results.push(r);
    }

    json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": tool_name,
                "version": tool_version,
                "rules": templates
                    .iter()
                    .map(rule)
                    .chain(derived.values().cloned())
                    .collect::<Vec<_>>()
            }},
            "results": results
        }]
    })
}
