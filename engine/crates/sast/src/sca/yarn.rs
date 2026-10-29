use super::RawDep;

/// Nama paket dari spesifikasi `name@range` / `"@scope/name@range"`.
fn name_of(spec: &str) -> Option<&str> {
    let spec = spec.trim().trim_matches('"');
    let at = spec.rfind('@').filter(|i| *i > 0)?;
    Some(&spec[..at])
}

/// `yarn.lock` v1 saja. Yarn Berry (v2+, ada `__metadata:`) ditolak dengan galat yang jelas.
/// Baris = baris header entri. Yarn v1 tidak mencatat dev/runtime.
pub fn parse(text: &str) -> Result<Vec<RawDep>, String> {
    if text.lines().any(|l| l.trim_end() == "__metadata:") {
        return Err("yarn.lock format Berry (v2+) belum didukung; hanya yarn.lock v1".to_string());
    }
    let mut out: Vec<RawDep> = Vec::new();
    let mut current: Option<(String, u32)> = None;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx as u32 + 1;
        if raw.trim().is_empty() || raw.starts_with('#') {
            if raw.trim().is_empty() {
                current = None;
            }
            continue;
        }
        if !raw.starts_with(' ') {
            current = raw
                .trim_end()
                .strip_suffix(':')
                .and_then(|h| h.split(',').next())
                .and_then(name_of)
                .map(|n| (n.to_string(), line_no));
            continue;
        }
        if let Some((name, line)) = &current {
            let t = raw.trim();
            if let Some(v) = t.strip_prefix("version ") {
                let version = v.trim().trim_matches('"');
                if !version.is_empty() {
                    out.push(RawDep {
                        name: name.clone(),
                        version: version.to_string(),
                        dev: false,
                        line: *line,
                    });
                }
                current = None;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v1_entries() {
        let src = "# yarn lockfile v1\n\n\nlodash@^4.17.0, lodash@^4.17.11:\n  version \"4.17.15\"\n  resolved \"https://x\"\n  dependencies:\n    foo \"^1\"\n\n\"@babel/core@^7.0.0\":\n  version \"7.1.0\"\n\nunversioned@1:\n  resolved \"x\"\n";
        let d = parse(src).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(
            (d[0].name.as_str(), d[0].version.as_str(), d[0].line),
            ("lodash", "4.17.15", 4)
        );
        assert_eq!(
            (d[1].name.as_str(), d[1].version.as_str(), d[1].line),
            ("@babel/core", "7.1.0", 10)
        );
    }

    #[test]
    fn berry_is_rejected() {
        let err = parse("__metadata:\n  version: 6\n").unwrap_err();
        assert!(err.contains("Berry"), "{err}");
    }

    #[test]
    fn name_extraction() {
        assert_eq!(name_of("a@^1"), Some("a"));
        assert_eq!(name_of("\"@s/p@npm:1\""), Some("@s/p"));
        assert_eq!(name_of("@s/p"), None);
    }
}
