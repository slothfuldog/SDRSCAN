use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::CoreError;
use crate::finding::Severity;
use crate::template::Template;

/// Profil pemindaian: menyaring template dan dapat menetapkan ambang `--fail-on`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub include_tags: Vec<String>,
    #[serde(default)]
    pub exclude_tags: Vec<String>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub fail_on: Option<Severity>,
}

impl Profile {
    /// `spec` berupa nama profil bawaan (dicari di `profiles_dir`) atau path berkas YAML.
    pub fn load(spec: &str, profiles_dir: &Path) -> Result<Profile, CoreError> {
        let looks_like_path = spec.contains('/')
            || spec.contains('\\')
            || spec.ends_with(".yaml")
            || spec.ends_with(".yml");
        let path: PathBuf = if looks_like_path {
            PathBuf::from(spec)
        } else {
            profiles_dir.join(format!("{spec}.yaml"))
        };
        let src = fs::read_to_string(&path).map_err(|source| CoreError::Io {
            path: path.clone(),
            source,
        })?;
        serde_yaml_ng::from_str(&src).map_err(|e| CoreError::Config {
            line: e.location().map_or(1, |l| l.line()),
            file: path,
            message: e.to_string(),
        })
    }

    /// Tag yang mewakili pemeriksaan kerentanan dependensi/versi (SCA, CVE) di `include_tags`/`exclude_tags`.
    pub const VULN_TAGS: [&'static str; 3] = ["sca", "cve", "dependency"];

    /// SCA/CVE ikut dijalankan bila `include_tags` kosong atau memuat salah satu tag kerentanan,
    /// dan `exclude_tags` tidak memuatnya. `min_severity` diterapkan lewat [`Profile::keeps_severity`].
    pub fn includes_vulnerability_checks(&self) -> bool {
        let has = |tags: &[String]| tags.iter().any(|t| Self::VULN_TAGS.contains(&t.as_str()));
        (self.include_tags.is_empty() || has(&self.include_tags)) && !has(&self.exclude_tags)
    }

    pub fn keeps_severity(&self, severity: Severity) -> bool {
        self.min_severity.is_none_or(|min| severity >= min)
    }

    pub fn select(&self, templates: Vec<Template>) -> Vec<Template> {
        templates
            .into_iter()
            .filter(|t| {
                let has_any = |wanted: &[String]| t.tags.iter().any(|tag| wanted.contains(tag));
                (self.include_tags.is_empty() || has_any(&self.include_tags))
                    && !has_any(&self.exclude_tags)
                    && self.min_severity.is_none_or(|min| t.severity >= min)
            })
            .collect()
    }
}
