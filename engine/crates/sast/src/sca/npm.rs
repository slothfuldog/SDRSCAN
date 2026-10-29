use std::collections::HashSet;

use super::json::{self, Jn};
use super::RawDep;

/// Nama dari kunci `node_modules/a/node_modules/@s/b` -> `@s/b`.
fn name_from_key(key: &str) -> Option<&str> {
    let idx = key.rfind("node_modules/")?;
    let name = &key[idx + "node_modules/".len()..];
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// `npm:paket@1.2.3` (alias) -> (paket, 1.2.3).
fn split_alias(version: &str) -> Option<(&str, &str)> {
    let rest = version.strip_prefix("npm:")?;
    let at = rest.rfind('@').filter(|i| *i > 0)?;
    Some((&rest[..at], &rest[at + 1..]))
}

fn walk_v1(node: &Jn, out: &mut Vec<RawDep>) {
    let Some(deps) = node.get("dependencies") else {
        return;
    };
    for m in deps.value.members() {
        let d = &m.value;
        if let Some(version) = d.str_of("version") {
            let (name, version) = split_alias(version)
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .unwrap_or_else(|| (m.key.clone(), version.to_string()));
            out.push(RawDep {
                name,
                version,
                dev: d.bool_of("dev") == Some(true),
                line: m.key_line,
            });
        }
        walk_v1(d, out);
    }
}

/// `package-lock.json` v1 (`dependencies` bersarang), v2 dan v3 (`packages`). Baris = baris kunci entri.
pub fn parse(text: &str) -> Result<Vec<RawDep>, String> {
    let root = json::parse(text)?;
    if root.members().is_empty() {
        return Err("bukan objek JSON package-lock".to_string());
    }
    let mut raw = Vec::new();
    if let Some(packages) = root.get("packages") {
        for m in packages.value.members() {
            if m.key.is_empty() {
                continue; // paket akar
            }
            let e = &m.value;
            if e.bool_of("link") == Some(true) {
                continue;
            }
            let Some(key_name) = name_from_key(&m.key) else {
                continue; // anggota workspace: kode sendiri
            };
            let Some(version) = e.str_of("version") else {
                continue;
            };
            let name = e.str_of("name").unwrap_or(key_name);
            let dev = e.bool_of("dev") == Some(true) || e.bool_of("devOptional") == Some(true);
            raw.push(RawDep {
                name: name.to_string(),
                version: version.to_string(),
                dev,
                line: m.key_line,
            });
        }
    } else {
        walk_v1(&root, &mut raw);
    }

    // satu entri per (nama, versi): dependensi runtime mengalahkan dev; baris = kemunculan pertama
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<RawDep> = Vec::new();
    for d in raw.iter().filter(|d| !d.dev) {
        if seen.insert((d.name.clone(), d.version.clone())) {
            out.push(d.clone());
        }
    }
    for d in raw.iter().filter(|d| d.dev) {
        if seen.insert((d.name.clone(), d.version.clone())) {
            out.push(d.clone());
        }
    }
    out.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_packages() {
        let src = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.15" },
    "node_modules/jest": { "version": "29.0.0", "dev": true },
    "node_modules/jest/node_modules/@babel/core": { "version": "7.0.0", "dev": true },
    "node_modules/alias": { "name": "real-name", "version": "2.0.0" },
    "node_modules/linked": { "resolved": "packages/linked", "link": true },
    "packages/linked": { "version": "0.0.1" }
  }
}"#;
        let d = parse(src).unwrap();
        let got: Vec<(&str, &str, bool, u32)> = d
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.dev, d.line))
            .collect();
        assert_eq!(
            got,
            [
                ("lodash", "4.17.15", false, 6),
                ("jest", "29.0.0", true, 7),
                ("@babel/core", "7.0.0", true, 8),
                ("real-name", "2.0.0", false, 9),
            ]
        );
    }

    #[test]
    fn v1_nested_dependencies_with_alias() {
        let src = r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "minimist": { "version": "0.0.8", "dependencies": { "deep": { "version": "1.0.0", "dev": true } } },
    "al": { "version": "npm:other@3.0.0" }
  }
}"#;
        let d = parse(src).unwrap();
        let got: Vec<(&str, &str, bool)> = d
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.dev))
            .collect();
        assert_eq!(
            got,
            [
                ("deep", "1.0.0", true),
                ("minimist", "0.0.8", false),
                ("other", "3.0.0", false)
            ]
        );
    }

    #[test]
    fn duplicates_collapse_and_runtime_wins_over_dev() {
        let src = r#"{"packages":{
  "node_modules/a": {"version":"1.0.0","dev":true},
  "node_modules/x/node_modules/a": {"version":"1.0.0"},
  "node_modules/y/node_modules/a": {"version":"1.0.0"}
}}"#;
        let d = parse(src).unwrap();
        assert_eq!(d.len(), 1);
        assert!(!d[0].dev);
        assert_eq!(d[0].line, 3);
    }

    #[test]
    fn errors() {
        assert!(parse("{").is_err());
        assert!(parse("[]").is_err());
        assert!(parse("{\"lockfileVersion\":3}").unwrap().is_empty());
    }
}
