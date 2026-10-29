use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::CoreError;
use crate::finding::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TemplateType {
    Sast,
    /// Dicadangkan untuk DAST; dimuat dan divalidasi dasarnya, tetapi belum dijalankan.
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaintRequire {
    Tainted,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintSpec {
    pub capture: String,
    pub require: TaintRequire,
    #[serde(default)]
    pub sanitizers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: TemplateType,
    #[serde(default)]
    pub languages: Vec<String>,
    pub severity: Severity,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub message: String,
    pub query: Option<String>,
    pub taint: Option<TaintSpec>,
    #[serde(skip)]
    pub source: PathBuf,
}

fn config_err(file: &Path, line: usize, message: impl Into<String>) -> CoreError {
    CoreError::Config {
        file: file.to_path_buf(),
        line,
        message: message.into(),
    }
}

/// Baris pertama yang diawali `key:`; 1 bila tidak ketemu.
fn line_of(src: &str, key: &str) -> usize {
    let needle = format!("{key}:");
    src.lines()
        .position(|l| l.trim_start().starts_with(&needle))
        .map_or(1, |i| i + 1)
}

fn is_kebab_case(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && !id.ends_with('-')
        && !id.contains("--")
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl Template {
    pub fn parse(src: &str, file: &Path) -> Result<Template, CoreError> {
        let mut t: Template = serde_yaml_ng::from_str(src).map_err(|e| {
            let line = e.location().map_or(1, |l| l.line());
            config_err(file, line, e.to_string())
        })?;
        t.source = file.to_path_buf();
        t.validate(src)?;
        Ok(t)
    }

    fn validate(&self, src: &str) -> Result<(), CoreError> {
        let file = &self.source;
        if !is_kebab_case(&self.id) {
            return Err(config_err(
                file,
                line_of(src, "id"),
                format!(
                    "id '{}' harus kebab-case (huruf kecil, angka, tanda hubung)",
                    self.id
                ),
            ));
        }
        if self.message.trim().is_empty() {
            return Err(config_err(
                file,
                line_of(src, "message"),
                "message tidak boleh kosong",
            ));
        }
        if self.kind == TemplateType::Sast {
            if self.languages.is_empty() {
                return Err(config_err(
                    file,
                    line_of(src, "type"),
                    "template sast wajib memuat 'languages'",
                ));
            }
            if let Some(lang) = self.languages.iter().find(|l| l.as_str() != "php") {
                return Err(config_err(
                    file,
                    line_of(src, "languages"),
                    format!("bahasa '{lang}' belum didukung; v1 hanya php"),
                ));
            }
            match &self.query {
                Some(q) if !q.trim().is_empty() => {}
                _ => {
                    return Err(config_err(
                        file,
                        line_of(src, "type"),
                        "template sast wajib memuat 'query'",
                    ))
                }
            }
        }
        if let Some(taint) = &self.taint {
            if taint.capture.trim().is_empty() {
                return Err(config_err(
                    file,
                    line_of(src, "capture"),
                    "taint.capture tidak boleh kosong",
                ));
            }
        }
        Ok(())
    }
}

fn collect_yaml(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CoreError> {
    let entries = fs::read_dir(dir).map_err(|source| CoreError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let path = entry
            .map_err(|source| CoreError::Io {
                path: dir.to_path_buf(),
                source,
            })?
            .path();
        if path.is_dir() {
            collect_yaml(&path, out)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml" | "yml")
        ) {
            out.push(path);
        }
    }
    Ok(())
}

/// Memuat semua template di direktori (rekursif). Satu template salah menghentikan pemuatan.
/// Hasil diurutkan menurut id agar deterministik.
pub fn load_templates(dir: &Path) -> Result<Vec<Template>, CoreError> {
    if !dir.is_dir() {
        return Err(CoreError::DirNotFound(dir.to_path_buf()));
    }
    let mut files = Vec::new();
    collect_yaml(dir, &mut files)?;
    files.sort();

    let mut by_id: BTreeMap<String, Template> = BTreeMap::new();
    for file in files {
        let src = fs::read_to_string(&file).map_err(|source| CoreError::Io {
            path: file.clone(),
            source,
        })?;
        let template = Template::parse(&src, &file)?;
        if let Some(first) = by_id.get(&template.id) {
            return Err(CoreError::DuplicateTemplate {
                id: template.id,
                first: first.source.clone(),
                second: file,
            });
        }
        by_id.insert(template.id.clone(), template);
    }
    Ok(by_id.into_values().collect())
}
