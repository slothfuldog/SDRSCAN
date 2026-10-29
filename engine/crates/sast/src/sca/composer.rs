use super::json;
use super::RawDep;

/// `composer.lock`: `packages` (runtime) dan `packages-dev` (dev). Baris = baris kunci `name`.
pub fn parse(text: &str) -> Result<Vec<RawDep>, String> {
    let root = json::parse(text)?;
    if root.members().is_empty() {
        return Err("bukan objek JSON composer.lock".to_string());
    }
    let mut out = Vec::new();
    for (section, dev) in [("packages", false), ("packages-dev", true)] {
        let Some(list) = root.get(section) else {
            continue;
        };
        for pkg in list.value.items() {
            let (Some(name), Some(version)) = (pkg.str_of("name"), pkg.str_of("version")) else {
                continue;
            };
            // cabang dev-* dan "x.y.x-dev" bukan rilis bernomor; tidak dapat dicocokkan dengan rentang advisory
            if version.starts_with("dev-") || version.ends_with("-dev") {
                tracing::debug!(name, version, "composer.lock: versi dev dilewati");
                continue;
            }
            let line = pkg.get("name").map_or(pkg.line, |m| m.key_line);
            out.push(RawDep {
                name: name.to_string(),
                version: version.to_string(),
                dev,
                line,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_runtime_and_dev_packages_with_lines() {
        let src = "{\n  \"_readme\": [\"x\"],\n  \"packages\": [\n    {\n      \"name\": \"monolog/monolog\",\n      \"version\": \"2.0.0\"\n    },\n    {\n      \"name\": \"foo/dev-branch\",\n      \"version\": \"dev-main\"\n    }\n  ],\n  \"packages-dev\": [\n    {\n      \"name\": \"phpunit/phpunit\",\n      \"version\": \"v9.5.0\"\n    }\n  ]\n}\n";
        let deps = parse(src).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "monolog/monolog");
        assert_eq!(deps[0].line, 5);
        assert!(!deps[0].dev);
        assert_eq!(deps[1].version, "v9.5.0");
        assert_eq!(deps[1].line, 15);
        assert!(deps[1].dev);
    }

    #[test]
    fn empty_lock_and_errors() {
        assert!(parse("{\"packages\": [], \"packages-dev\": []}")
            .unwrap()
            .is_empty());
        assert!(parse("{\"packages\": [").is_err());
        assert!(parse("[]").is_err());
    }
}
