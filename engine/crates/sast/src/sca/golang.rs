use std::collections::BTreeMap;

/// Satu entri modul Go dengan baris tempat ditulis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoDep {
    pub module: String,
    pub version: String,
    pub line: u32,
}

/// `go.sum`: baris `modul versi hash`; baris `versi/go.mod` hanya untuk graf modul (kode tidak dipakai)
/// sehingga dilewati. Mengembalikan semua versi per modul.
pub fn parse_sum(text: &str) -> Vec<GoDep> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let mut parts = raw.split_whitespace();
        let (Some(module), Some(version), Some(_hash)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if version.ends_with("/go.mod") {
            continue;
        }
        out.push(GoDep {
            module: module.to_string(),
            version: version.to_string(),
            line: idx as u32 + 1,
        });
    }
    out
}

fn strip_comment(line: &str) -> &str {
    line.split("//").next().unwrap_or("").trim()
}

fn is_local_path(p: &str) -> bool {
    p.starts_with("./") || p.starts_with("../") || p.starts_with('/') || p == "." || p == ".."
}

/// `go.mod`: direktif `require` (satu baris atau blok) dengan penanganan `replace` ke modul lain
/// (ganti nama+versi) atau ke path lokal (modul dibuang: kode sendiri).
pub fn parse_mod(text: &str) -> Vec<GoDep> {
    let mut requires: BTreeMap<String, GoDep> = BTreeMap::new();
    let mut replaces: Vec<(String, Option<String>, String, Option<String>)> = Vec::new();
    let mut block: Option<&str> = None;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx as u32 + 1;
        let line = strip_comment(raw);
        if line.is_empty() {
            continue;
        }
        if block.is_some() && line == ")" {
            block = None;
            continue;
        }
        let (kind, rest) = match block {
            Some(k) => (k, line),
            None => {
                let (k, r) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
                let r = r.trim();
                if r == "(" {
                    block = match k {
                        "require" => Some("require"),
                        "replace" => Some("replace"),
                        _ => Some("other"),
                    };
                    continue;
                }
                (k, r)
            }
        };
        match kind {
            "require" => {
                let mut p = rest.split_whitespace();
                if let (Some(m), Some(v)) = (p.next(), p.next()) {
                    requires.insert(
                        m.to_string(),
                        GoDep {
                            module: m.to_string(),
                            version: v.to_string(),
                            line: line_no,
                        },
                    );
                }
            }
            "replace" => {
                if let Some((lhs, rhs)) = rest.split_once("=>") {
                    let l: Vec<&str> = lhs.split_whitespace().collect();
                    let r: Vec<&str> = rhs.split_whitespace().collect();
                    if let (Some(lm), Some(rm)) = (l.first(), r.first()) {
                        replaces.push((
                            lm.to_string(),
                            l.get(1).map(|s| s.to_string()),
                            rm.to_string(),
                            r.get(1).map(|s| s.to_string()),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    for (old, old_ver, new, new_ver) in replaces {
        let Some(dep) = requires.get(&old).cloned() else {
            continue;
        };
        if old_ver.as_ref().is_some_and(|v| *v != dep.version) {
            continue;
        }
        if is_local_path(&new) {
            requires.remove(&old);
        } else if let Some(nv) = new_ver {
            requires.remove(&old);
            requires.insert(
                new.clone(),
                GoDep {
                    module: new,
                    version: nv,
                    line: dep.line,
                },
            );
        }
    }
    requires.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum_skips_gomod_hashes() {
        let src = "github.com/a/b v1.2.3 h1:abc=\ngithub.com/a/b v1.2.3/go.mod h1:def=\ngithub.com/c/d v0.1.0/go.mod h1:x=\nbroken line\n";
        let d = parse_sum(src);
        assert_eq!(d.len(), 1);
        assert_eq!(
            (d[0].module.as_str(), d[0].version.as_str(), d[0].line),
            ("github.com/a/b", "v1.2.3", 1)
        );
    }

    #[test]
    fn mod_requires_blocks_comments_and_replace() {
        let src = "module example.com/app\n\ngo 1.21\n\nrequire github.com/single/one v1.0.0 // indirect\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgithub.com/c/d v0.5.0 // indirect\n\tgithub.com/local/x v1.0.0\n\tgithub.com/old/mod v1.0.0\n)\n\nreplace github.com/local/x => ../x\nreplace (\n\tgithub.com/old/mod v1.0.0 => github.com/new/mod v1.1.0\n)\nexclude github.com/a/b v1.0.0\n";
        let d = parse_mod(src);
        let got: Vec<(&str, &str, u32)> = d
            .iter()
            .map(|d| (d.module.as_str(), d.version.as_str(), d.line))
            .collect();
        assert_eq!(
            got,
            [
                ("github.com/a/b", "v1.2.3", 8),
                ("github.com/c/d", "v0.5.0", 9),
                ("github.com/new/mod", "v1.1.0", 11),
                ("github.com/single/one", "v1.0.0", 5),
            ]
        );
    }
}
