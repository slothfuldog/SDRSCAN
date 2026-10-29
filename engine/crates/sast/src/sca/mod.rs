//! SCA: temuan kerentanan dependensi dari lockfile, dicocokkan dengan basis data lokal (offline).

mod cargo;
mod composer;
mod golang;
pub mod json;
mod npm;
mod yarn;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use sdrscan_core::{
    Cvss, Finding, Location, ScanOutput, VulnTarget, Vulnerability, Warning, WarningKind,
};
use sdrscan_vulndb::{
    merge_advisories, resolve_db_dir, Advisory, Ecosystem, MergedAdvisory, VulnDb,
};
use tracing::debug;

/// Berkas penekan advisory di akar target: satu id per baris, `#` untuk komentar.
pub const IGNORE_FILE: &str = ".sdrscan-vuln-ignore";
/// Basis data lebih tua dari ini memicu peringatan.
pub const STALE_AFTER_DAYS: i64 = 30;
const MAX_LOCKFILE_BYTES: u64 = 64 * 1024 * 1024;

/// Entri hasil parser sebelum diberi ekosistem dan berkas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDep {
    pub name: String,
    pub version: String,
    pub dev: bool,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub dev: bool,
    /// Path relatif terhadap akar pemindaian.
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Composer,
    Npm,
    Yarn,
    GoMod,
    GoSum,
    Cargo,
}

fn kind_of(file_name: &str) -> Option<Kind> {
    match file_name {
        "composer.lock" => Some(Kind::Composer),
        "package-lock.json" | "npm-shrinkwrap.json" => Some(Kind::Npm),
        "yarn.lock" => Some(Kind::Yarn),
        "go.mod" => Some(Kind::GoMod),
        "go.sum" => Some(Kind::GoSum),
        "Cargo.lock" => Some(Kind::Cargo),
        _ => None,
    }
}

fn is_vendor_dir(name: &str) -> bool {
    name == "vendor" || name == "node_modules"
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

/// Mencari lockfile (urut). `.gitignore` dihormati; direktori `vendor` dan `node_modules` selalu dilewati.
pub fn find_lockfiles(target: &Path) -> Result<Vec<PathBuf>, String> {
    if target.is_file() {
        return Ok(target
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(kind_of)
            .map(|_| vec![target.to_path_buf()])
            .unwrap_or_default());
    }
    let mut files = Vec::new();
    let walker = ignore::WalkBuilder::new(target)
        .require_git(false)
        .filter_entry(|e| {
            e.depth() == 0
                || !(e.file_type().is_some_and(|t| t.is_dir())
                    && e.file_name().to_str().is_some_and(is_vendor_dir))
        })
        .build();
    for entry in walker {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().is_some_and(|t| t.is_file())
            && entry.file_name().to_str().and_then(kind_of).is_some()
        {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

/// Id yang ditekan lewat `.sdrscan-vuln-ignore` (huruf besar).
pub fn load_ignore(root: &Path) -> BTreeSet<String> {
    let dir = if root.is_file() {
        root.parent().unwrap_or(root)
    } else {
        root
    };
    let Ok(text) = fs::read_to_string(dir.join(IGNORE_FILE)) else {
        return BTreeSet::new();
    };
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_ascii_uppercase())
        .collect()
}

/// (go.mod, go.sum) sebagai pasangan (path relatif, isi) di satu direktori.
type GoFiles = (Option<(String, String)>, Option<(String, String)>);

struct Parsed {
    deps: Vec<Dependency>,
    lines: HashMap<String, Vec<String>>,
}

fn warn(kind: WarningKind, path: Option<&str>, message: String) -> Warning {
    Warning {
        kind,
        message,
        path: path.map(str::to_string),
        rule_id: None,
        location: None,
        snippet: None,
    }
}

fn read_lockfile(path: &Path, rel: &str, warnings: &mut Vec<Warning>) -> Option<String> {
    match fs::metadata(path) {
        Ok(m) if m.len() > MAX_LOCKFILE_BYTES => {
            warnings.push(warn(
                WarningKind::Lockfile,
                Some(rel),
                format!("lockfile terlalu besar ({} byte), dilewati", m.len()),
            ));
            return None;
        }
        Err(e) => {
            warnings.push(warn(
                WarningKind::Lockfile,
                Some(rel),
                format!("lockfile tidak terbaca, dilewati: {e}"),
            ));
            return None;
        }
        _ => {}
    }
    match fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => Some(s),
            Err(_) => {
                warnings.push(warn(
                    WarningKind::Lockfile,
                    Some(rel),
                    "lockfile bukan UTF-8, dilewati".to_string(),
                ));
                None
            }
        },
        Err(e) => {
            warnings.push(warn(
                WarningKind::Lockfile,
                Some(rel),
                format!("lockfile tidak terbaca, dilewati: {e}"),
            ));
            None
        }
    }
}

fn to_deps(eco: Ecosystem, file: &str, raw: Vec<RawDep>, out: &mut Vec<Dependency>) {
    out.extend(raw.into_iter().map(|r| Dependency {
        ecosystem: eco,
        name: r.name,
        version: r.version,
        dev: r.dev,
        file: file.to_string(),
        line: r.line,
    }));
}

/// Go: versi dari `go.mod` bila ada (versi terpilih), lalu `go.sum` untuk modul yang tidak tercantum di
/// `go.mod` (versi tertinggi per modul; baris `/go.mod` yang hanya untuk graf diabaikan).
fn go_deps(
    mod_file: Option<(&str, &str)>,
    sum_file: Option<(&str, &str)>,
    out: &mut Vec<Dependency>,
) {
    let mut chosen: BTreeMap<String, (String, String, u32)> = BTreeMap::new();
    if let Some((rel, text)) = mod_file {
        for d in golang::parse_mod(text) {
            chosen.insert(d.module.clone(), (d.version, rel.to_string(), d.line));
        }
    }
    if let Some((rel, text)) = sum_file {
        let mut best: BTreeMap<String, golang::GoDep> = BTreeMap::new();
        for d in golang::parse_sum(text) {
            let newer = match best.get(&d.module) {
                None => true,
                Some(old) => matches!(
                    sdrscan_vulndb::version::compare(
                        sdrscan_vulndb::version::Scheme::Semver,
                        &d.version,
                        &old.version
                    ),
                    Some(std::cmp::Ordering::Greater)
                ),
            };
            if newer {
                best.insert(d.module.clone(), d);
            }
        }
        for (module, d) in best {
            chosen
                .entry(module)
                .or_insert((d.version, rel.to_string(), d.line));
        }
    }
    for (module, (version, file, line)) in chosen {
        out.push(Dependency {
            ecosystem: Ecosystem::Go,
            name: module,
            version,
            dev: false,
            file,
            line,
        });
    }
}

fn parse_all(files: &[PathBuf], root: &Path, warnings: &mut Vec<Warning>) -> (Parsed, usize) {
    let mut deps = Vec::new();
    let mut lines: HashMap<String, Vec<String>> = HashMap::new();
    let mut parsed_files = 0usize;
    // Go: go.mod dan go.sum di direktori yang sama diproses bersama.
    let mut go_groups: BTreeMap<PathBuf, GoFiles> = BTreeMap::new();
    let base = if root.is_file() {
        root.parent().unwrap_or(root).to_path_buf()
    } else {
        root.to_path_buf()
    };
    for path in files {
        let rel = relative_path(path, &base);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Some(kind) = kind_of(name) else { continue };
        let Some(text) = read_lockfile(path, &rel, warnings) else {
            continue;
        };
        parsed_files += 1;
        let result: Result<(), String> = match kind {
            Kind::Composer => {
                composer::parse(&text).map(|r| to_deps(Ecosystem::Packagist, &rel, r, &mut deps))
            }
            Kind::Npm => npm::parse(&text).map(|r| to_deps(Ecosystem::Npm, &rel, r, &mut deps)),
            Kind::Yarn => yarn::parse(&text).map(|r| to_deps(Ecosystem::Npm, &rel, r, &mut deps)),
            Kind::Cargo => {
                cargo::parse(&text).map(|r| to_deps(Ecosystem::CratesIo, &rel, r, &mut deps))
            }
            Kind::GoMod | Kind::GoSum => {
                let dir = path.parent().unwrap_or(Path::new("")).to_path_buf();
                let entry = go_groups.entry(dir).or_default();
                if kind == Kind::GoMod {
                    entry.0 = Some((rel.clone(), text.clone()));
                } else {
                    entry.1 = Some((rel.clone(), text.clone()));
                }
                Ok(())
            }
        };
        if let Err(e) = result {
            parsed_files -= 1;
            warnings.push(warn(
                WarningKind::Lockfile,
                Some(&rel),
                format!("lockfile tidak dapat dibaca, dilewati: {e}"),
            ));
            continue;
        }
        lines.insert(rel, text.lines().map(str::to_string).collect());
    }
    for (_, (m, s)) in go_groups {
        go_deps(
            m.as_ref().map(|(r, t)| (r.as_str(), t.as_str())),
            s.as_ref().map(|(r, t)| (r.as_str(), t.as_str())),
            &mut deps,
        );
    }
    (Parsed { deps, lines }, parsed_files)
}

fn dedup_deps(deps: &mut Vec<Dependency>) {
    // satu entri per (berkas, ekosistem, nama, versi); runtime mengalahkan dev
    deps.sort_by(|a, b| {
        (&a.file, a.ecosystem, &a.name, &a.version, a.dev, a.line).cmp(&(
            &b.file,
            b.ecosystem,
            &b.name,
            &b.version,
            b.dev,
            b.line,
        ))
    });
    deps.dedup_by(|b, a| {
        a.file == b.file && a.ecosystem == b.ecosystem && a.name == b.name && a.version == b.version
    });
}

fn finding_for(
    dep: &Dependency,
    m: &MergedAdvisory,
    lines: &HashMap<String, Vec<String>>,
) -> Finding {
    let id = m.rule_id().to_string();
    let pkg = format!("{}@{}", dep.name, dep.version);
    let line = dep.line.max(1);
    let end_col = lines
        .get(&dep.file)
        .and_then(|l| l.get(line as usize - 1))
        .map_or(1, |l| l.chars().count() as u32)
        + 1;
    let summary = if m.summary.is_empty() {
        id.clone()
    } else {
        m.summary.clone()
    };
    let fixed = if m.fixed_versions.is_empty() {
        "Belum ada versi perbaikan yang diketahui.".to_string()
    } else {
        format!("Versi perbaikan: {}.", m.fixed_versions.join(", "))
    };
    let scope = if dep.dev { " (dependensi dev)" } else { "" };
    let message = format!(
        "Paket {pkg}{scope} rentan: {summary} ({}). {fixed}",
        m.ids.join(", ")
    );
    Finding {
        rule_id: id,
        severity: m.severity,
        message,
        location: Location {
            path: dep.file.clone(),
            start_line: line,
            start_column: 1,
            end_line: line,
            end_column: end_col,
        },
        snippet: pkg,
        vulnerability: Some(Vulnerability {
            ids: m.ids.clone(),
            package: VulnTarget::Package {
                ecosystem: dep.ecosystem.as_str().to_string(),
                name: dep.name.clone(),
                version: dep.version.clone(),
            },
            fixed_versions: m.fixed_versions.clone(),
            source: "osv".to_string(),
            references: m.references.clone(),
            cvss: m.cvss.as_ref().map(|c| Cvss {
                score: c.score,
                vector: c.vector.clone(),
            }),
            confidence: "high".to_string(),
            scope: Some(if dep.dev { "dev" } else { "runtime" }.to_string()),
            summary: m.summary.clone(),
            cwe: m.cwe.clone(),
        }),
    }
}

/// Mencocokkan dependensi dengan basis data. Hasil belum diurutkan.
fn match_deps(
    db: &VulnDb,
    deps: &[Dependency],
    lines: &HashMap<String, Vec<String>>,
    ignore: &BTreeSet<String>,
    warnings: &mut Vec<Warning>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut by_eco: BTreeMap<Ecosystem, Vec<&Dependency>> = BTreeMap::new();
    for d in deps {
        by_eco.entry(d.ecosystem).or_default().push(d);
    }
    for (eco, list) in by_eco {
        if !db.has_ecosystem(eco) {
            warnings.push(warn(
                WarningKind::VulnDb,
                None,
                format!(
                    "basis data kerentanan tidak memuat ekosistem {eco}; dependensi {eco} dilewati (jalankan: sdrscan-vuln update --ecosystems {eco})"
                ),
            ));
            continue;
        }
        let mut wanted: Vec<(String, String)> = list
            .iter()
            .map(|d| (d.name.clone(), d.version.clone()))
            .collect();
        wanted.sort();
        wanted.dedup();
        let q = match db.query_packages(eco, &wanted) {
            Ok(q) => q,
            Err(e) => {
                warnings.push(warn(
                    WarningKind::VulnDb,
                    None,
                    format!("gagal membaca basis data {eco}: {e}"),
                ));
                continue;
            }
        };
        if q.corrupt_lines > 0 {
            warnings.push(warn(
                WarningKind::VulnDb,
                None,
                format!(
                    "basis data {eco}: {} baris rusak dilewati; jalankan sdrscan-vuln update",
                    q.corrupt_lines
                ),
            ));
        }
        let mut hits: HashMap<(String, String), Vec<Advisory>> = HashMap::new();
        for h in q.hits {
            hits.entry((h.name, h.version))
                .or_default()
                .push(h.advisory);
        }
        for d in list {
            let key = (eco.normalize_name(&d.name), d.version.clone());
            let Some(advs) = hits.get(&key) else { continue };
            for m in merge_advisories(advs.clone(), &d.version) {
                if m.ids
                    .iter()
                    .any(|i| ignore.contains(&i.to_ascii_uppercase()))
                {
                    debug!(id = %m.ids[0], package = %d.name, "advisory ditekan .sdrscan-vuln-ignore");
                    continue;
                }
                findings.push(finding_for(d, &m, lines));
            }
        }
    }
    findings
}

/// Menjalankan SCA untuk `target`. `db_flag` = `--vuln-db`; bila kosong dipakai env `SDRSCAN_VULN_DB`.
/// Tanpa basis data yang dapat dipakai: SCA dilewati dengan peringatan, bukan galat.
pub fn run(target: &Path, db_flag: Option<&Path>) -> ScanOutput {
    let mut out = ScanOutput::default();
    let files = match find_lockfiles(target) {
        Ok(f) => f,
        Err(e) => {
            out.warnings.push(warn(
                WarningKind::Lockfile,
                None,
                format!("gagal mencari lockfile: {e}"),
            ));
            return out;
        }
    };
    let configured = resolve_db_dir(db_flag);
    let db = match &configured {
        Some(dir) => match VulnDb::open(dir) {
            Ok(db) if db.has_data() => Some(db),
            Ok(_) => {
                out.warnings.push(warn(
                    WarningKind::VulnDb,
                    None,
                    format!(
                        "basis data kerentanan {} kosong; SCA dilewati (jalankan: sdrscan-vuln update)",
                        dir.display()
                    ),
                ));
                None
            }
            Err(e) => {
                out.warnings.push(warn(
                    WarningKind::VulnDb,
                    None,
                    format!("basis data kerentanan tidak dapat dipakai, SCA dilewati: {e}"),
                ));
                None
            }
        },
        None => {
            if !files.is_empty() {
                out.warnings.push(warn(
                    WarningKind::VulnDb,
                    None,
                    format!(
                        "ditemukan {} lockfile tetapi basis data kerentanan tidak diset (--vuln-db atau env SDRSCAN_VULN_DB); SCA dilewati",
                        files.len()
                    ),
                ));
            }
            None
        }
    };
    let Some(db) = db else { return out };
    if files.is_empty() {
        return out;
    }
    if let Some(age) = db.age_days(sdrscan_vulndb::time::now_epoch()) {
        if age > STALE_AFTER_DAYS {
            out.warnings.push(warn(
                WarningKind::VulnDb,
                None,
                format!(
                    "basis data kerentanan berumur {age} hari (diperbarui {}); jalankan sdrscan-vuln update",
                    db.meta().updated_at
                ),
            ));
        }
    }

    let (mut parsed, parsed_files) = parse_all(&files, target, &mut out.warnings);
    out.files_scanned = parsed_files;
    dedup_deps(&mut parsed.deps);
    debug!(
        lockfiles = parsed_files,
        dependencies = parsed.deps.len(),
        "SCA: mencocokkan dependensi"
    );
    let ignore = load_ignore(target);
    out.findings = match_deps(&db, &parsed.deps, &parsed.lines, &ignore, &mut out.warnings);
    out.findings.sort_by(|a, b| {
        (&a.location, &a.rule_id, &a.snippet).cmp(&(&b.location, &b.rule_id, &b.snippet))
    });
    out.findings.dedup();
    out.warnings
        .sort_by(|a, b| (&a.path, &a.message).cmp(&(&b.path, &b.message)));
    out.warnings.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_file_parsing() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join(IGNORE_FILE),
            "# komentar\nCVE-2024-1\n  ghsa-aaaa-bbbb-cccc  # alasan\n\n",
        )
        .unwrap();
        let s = load_ignore(tmp.path());
        assert_eq!(
            s.into_iter().collect::<Vec<_>>(),
            ["CVE-2024-1", "GHSA-AAAA-BBBB-CCCC"]
        );
        assert!(load_ignore(&tmp.path().join("none")).is_empty());
    }

    #[test]
    fn lockfiles_skip_vendor_and_node_modules_and_honor_gitignore() {
        let tmp = tempfile::tempdir().unwrap();
        let r = tmp.path();
        for p in [
            "composer.lock",
            "sub/package-lock.json",
            "vendor/pkg/composer.lock",
            "web/node_modules/x/package-lock.json",
            "ignored/Cargo.lock",
            "go.sum",
            "readme.md",
        ] {
            let f = r.join(p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, "{}").unwrap();
        }
        fs::write(r.join(".gitignore"), "ignored/\n").unwrap();
        let found: Vec<String> = find_lockfiles(r)
            .unwrap()
            .iter()
            .map(|p| relative_path(p, r))
            .collect();
        assert_eq!(found, ["composer.lock", "go.sum", "sub/package-lock.json"]);
    }

    #[test]
    fn go_prefers_gomod_versions_and_highest_sum_version() {
        let mut deps = Vec::new();
        go_deps(
            Some((
                "go.mod",
                "module x\nrequire (\n\tgithub.com/a/b v1.2.0\n)\n",
            )),
            Some((
                "go.sum",
                "github.com/a/b v1.1.0 h1:x=\ngithub.com/a/b v1.2.0 h1:x=\ngithub.com/c/d v0.1.0 h1:x=\ngithub.com/c/d v0.3.0 h1:x=\ngithub.com/c/d v0.9.0/go.mod h1:x=\ngithub.com/e/f v1.0.0/go.mod h1:x=\n",
            )),
            &mut deps,
        );
        let got: Vec<(&str, &str, &str, u32)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.file.as_str(), d.line))
            .collect();
        assert_eq!(
            got,
            [
                ("github.com/a/b", "v1.2.0", "go.mod", 3),
                ("github.com/c/d", "v0.3.0", "go.sum", 4),
            ]
        );
    }
}
