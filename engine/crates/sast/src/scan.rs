use std::path::{Path, PathBuf};

use rayon::prelude::*;
use sdrscan_core::{Finding, Location, ScanOutput, Template, TemplateType, Warning, WarningKind};
use streaming_iterator::StreamingIterator;
use tracing::{debug, warn};
use tree_sitter::{Language, Node, Parser, Query, QueryCursor};

use crate::suppress::is_suppressed;
use crate::taint::{self, Taint};
use crate::SastError;

const FINDING_CAPTURE: &str = "finding";
const SNIPPET_MAX_CHARS: usize = 200;

struct Compiled<'a> {
    template: &'a Template,
    query: Query,
    finding_idx: Option<u32>,
    taint_idx: Option<u32>,
}

fn php_language() -> Language {
    tree_sitter_php::LANGUAGE_PHP.into()
}

fn compile<'a>(templates: &'a [Template]) -> Result<Vec<Compiled<'a>>, SastError> {
    let language = php_language();
    let mut out = Vec::new();
    for t in templates
        .iter()
        .filter(|t| t.kind == TemplateType::Sast && t.languages.iter().any(|l| l == "php"))
    {
        let source = t.query.as_deref().unwrap_or_default();
        let query = Query::new(&language, source).map_err(|e| SastError::Template {
            id: t.id.clone(),
            message: format!("query tidak valid (baris {}): {}", e.row + 1, e.message),
        })?;
        let names = query.capture_names();
        let finding_idx = names
            .iter()
            .position(|n| *n == FINDING_CAPTURE)
            .map(|i| i as u32);
        let taint_idx =
            match &t.taint {
                Some(spec) => Some(names.iter().position(|n| *n == spec.capture).ok_or_else(
                    || SastError::Template {
                        id: t.id.clone(),
                        message: format!("taint.capture '{}' tidak ada di query", spec.capture),
                    },
                )? as u32),
                None => None,
            };
        out.push(Compiled {
            template: t,
            query,
            finding_idx,
            taint_idx,
        });
    }
    Ok(out)
}

fn is_php(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("php"))
}

fn list_files(target: &Path) -> Result<Vec<PathBuf>, SastError> {
    if target.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    let mut files = Vec::new();
    for entry in ignore::WalkBuilder::new(target).require_git(false).build() {
        let entry = entry.map_err(|e| SastError::Walk(e.to_string()))?;
        let path = entry.path();
        if entry.file_type().is_some_and(|t| t.is_file()) && is_php(path) {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn relative_path(file: &Path, root: &Path) -> String {
    let rel = file.strip_prefix(root).unwrap_or(file);
    let rel = if rel.as_os_str().is_empty() {
        file.file_name().map(Path::new).unwrap_or(file)
    } else {
        rel
    };
    rel.to_string_lossy().replace('\\', "/")
}

fn location(node: Node, path: &str) -> Location {
    let (s, e) = (node.start_position(), node.end_position());
    Location {
        path: path.to_string(),
        start_line: s.row as u32 + 1,
        start_column: s.column as u32 + 1,
        end_line: e.row as u32 + 1,
        end_column: e.column as u32 + 1,
    }
}

fn snippet(node: Node, src: &str) -> String {
    let text = node.utf8_text(src.as_bytes()).unwrap_or_default();
    text.chars().take(SNIPPET_MAX_CHARS).collect()
}

#[derive(Default)]
struct FileResult {
    findings: Vec<Finding>,
    warnings: Vec<Warning>,
}

fn file_warning(kind: WarningKind, path: &str, message: String) -> Warning {
    Warning {
        kind,
        message,
        path: Some(path.to_string()),
        rule_id: None,
        location: None,
        snippet: None,
    }
}

fn scan_file(file: &Path, root: &Path, compiled: &[Compiled]) -> FileResult {
    let path = relative_path(file, root);
    let mut result = FileResult::default();

    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            result.warnings.push(file_warning(
                WarningKind::Skipped,
                &path,
                format!("file tidak terbaca, dilewati: {e}"),
            ));
            return result;
        }
    };
    let Ok(src) = String::from_utf8(bytes) else {
        result.warnings.push(file_warning(
            WarningKind::Skipped,
            &path,
            "bukan UTF-8, dilewati".to_string(),
        ));
        return result;
    };

    let mut parser = Parser::new();
    if parser.set_language(&php_language()).is_err() {
        result.warnings.push(file_warning(
            WarningKind::Skipped,
            &path,
            "parser PHP tidak dapat dimuat".to_string(),
        ));
        return result;
    }
    let Some(tree) = parser.parse(&src, None) else {
        result.warnings.push(file_warning(
            WarningKind::ParseError,
            &path,
            "gagal diparse, dilewati".to_string(),
        ));
        return result;
    };
    let root_node = tree.root_node();
    if root_node.has_error() {
        result.warnings.push(file_warning(
            WarningKind::ParseError,
            &path,
            "memuat galat sintaks; pohon parsial tetap dipindai".to_string(),
        ));
    }

    let lines: Vec<&str> = src.lines().collect();
    let mut cursor = QueryCursor::new();
    for c in compiled {
        let t = c.template;
        let mut matches = cursor.matches(&c.query, root_node, src.as_bytes());
        while let Some(m) = matches.next() {
            let node_of = |idx: u32| {
                m.captures()
                    .iter()
                    .find(|cap| cap.index == idx)
                    .map(|cap| cap.node)
            };
            let taint_node = c.taint_idx.and_then(node_of);
            let Some(place) = c
                .finding_idx
                .and_then(node_of)
                .or(taint_node)
                .or_else(|| m.captures().first().map(|cap| cap.node))
            else {
                continue;
            };

            let mut ambiguous = false;
            if let (Some(spec), Some(node)) = (&t.taint, taint_node) {
                match taint::evaluate(node, src.as_bytes(), &spec.sanitizers) {
                    Taint::Tainted => {}
                    Taint::Ambiguous => ambiguous = true,
                    Taint::Clean => continue,
                }
            }

            let loc = location(place, &path);
            if is_suppressed(&lines, loc.start_line, &t.id) {
                debug!(rule = %t.id, path = %path, line = loc.start_line, "temuan ditekan sdrscan-ignore");
                continue;
            }
            let snip = snippet(place, &src);
            if ambiguous {
                result.warnings.push(Warning {
                    kind: WarningKind::AmbiguousTaint,
                    message: format!(
                        "{} (ambigu: variabel diberi nilai lebih dari sekali dan sebagian tidak tercemar)",
                        t.message
                    ),
                    path: Some(path.clone()),
                    rule_id: Some(t.id.clone()),
                    location: Some(loc),
                    snippet: Some(snip),
                });
            } else {
                result.findings.push(Finding {
                    rule_id: t.id.clone(),
                    severity: t.severity,
                    message: t.message.clone(),
                    location: loc,
                    snippet: snip,
                    vulnerability: None,
                });
            }
        }
    }
    result
}

/// Memindai `target` (file atau direktori) dengan template `type: sast` untuk PHP.
/// Hasil diurutkan deterministik: path, baris, kolom, id template.
pub fn scan(target: &Path, templates: &[Template]) -> Result<ScanOutput, SastError> {
    if !target.exists() {
        return Err(SastError::TargetNotFound(target.to_path_buf()));
    }
    let compiled = compile(templates)?;
    let files = list_files(target)?;
    let root: PathBuf = if target.is_file() {
        target.parent().map(Path::to_path_buf).unwrap_or_default()
    } else {
        target.to_path_buf()
    };
    debug!(
        files = files.len(),
        templates = compiled.len(),
        "mulai memindai"
    );
    if compiled.is_empty() {
        warn!("tidak ada template sast aktif");
    }

    let results: Vec<FileResult> = files
        .par_iter()
        .map(|f| scan_file(f, &root, &compiled))
        .collect();

    let mut output = ScanOutput {
        files_scanned: files.len(),
        ..ScanOutput::default()
    };
    for r in results {
        output.findings.extend(r.findings);
        output.warnings.extend(r.warnings);
    }
    output
        .findings
        .sort_by(|a, b| (&a.location, &a.rule_id).cmp(&(&b.location, &b.rule_id)));
    output.findings.dedup();
    output.warnings.sort_by(|a, b| {
        (&a.path, &a.location, &a.rule_id, &a.message).cmp(&(
            &b.path,
            &b.location,
            &b.rule_id,
            &b.message,
        ))
    });
    output.warnings.dedup();
    Ok(output)
}
