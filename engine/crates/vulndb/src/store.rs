//! Basis data lokal di disk: `meta.json`, `osv/<Ekosistem>.jsonl`, `nvd/products.jsonl`.
//! Berkas indeks adalah JSON Lines terurut (paket/produk, id) sehingga deterministik. Pembaca
//! memuat per ekosistem secara lazy dan hanya mengurai baris yang paketnya diminta.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::ecosystem::Ecosystem;
use crate::model::{merge_advisories, Advisory, MergedAdvisory, NvdEntry, PackageHit, ProductHit};
use crate::time;
use crate::VulnDbError;

pub const FORMAT_VERSION: u32 = 1;
const META_FILE: &str = "meta.json";
const NVD_FILE: &str = "nvd/products.jsonl";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemStat {
    pub updated_at: String,
    pub advisories: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvStat {
    pub updated_at: String,
    pub ecosystems: BTreeMap<String, EcosystemStat>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvdStat {
    pub updated_at: String,
    /// Batas atas `lastModEndDate` pembaruan terakhir; dasar unduhan inkremental berikutnya.
    pub last_modified: String,
    pub entries: u64,
    pub products: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sources {
    #[serde(default)]
    pub osv: OsvStat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvd: Option<NvdStat>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub format_version: u32,
    /// Pembaruan terakhir sumber mana pun.
    pub updated_at: String,
    /// Jumlah advisory OSV (semua ekosistem) ditambah entri NVD.
    pub advisory_count: u64,
    pub sources: Sources,
}

impl Meta {
    pub fn empty(now: &str) -> Meta {
        Meta {
            format_version: FORMAT_VERSION,
            updated_at: now.to_string(),
            advisory_count: 0,
            sources: Sources::default(),
        }
    }

    fn recount(&mut self) {
        let osv: u64 = self
            .sources
            .osv
            .ecosystems
            .values()
            .map(|e| e.advisories)
            .sum();
        let nvd = self.sources.nvd.as_ref().map_or(0, |n| n.entries);
        self.advisory_count = osv + nvd;
    }
}

fn osv_rel(eco: Ecosystem) -> String {
    format!("osv/{}.jsonl", eco.as_str())
}

/// Nama dari awalan baris `{"<field>":"<nilai>"`; nilai di-unescape bila perlu.
fn leading_value<'a>(line: &'a str, prefix: &str) -> Option<Cow<'a, str>> {
    let rest = line.strip_prefix(prefix)?;
    let b = rest.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => {
                let raw = &rest[..i];
                if raw.contains('\\') {
                    return serde_json::from_str::<String>(&format!("\"{raw}\""))
                        .ok()
                        .map(Cow::Owned);
                }
                return Some(Cow::Borrowed(raw));
            }
            _ => i += 1,
        }
    }
    None
}

const PACKAGE_PREFIX: &str = r#"{"package":""#;
const PRODUCT_PREFIX: &str = r#"{"product":""#;

/// Hasil pencarian paket.
#[derive(Debug, Default)]
pub struct PackageQuery {
    /// Terurut menurut (nama, versi, id).
    pub hits: Vec<PackageHit>,
    /// Baris rusak yang dilewati.
    pub corrupt_lines: usize,
}

#[derive(Debug, Default)]
pub struct ProductQuery {
    pub hits: Vec<ProductHit>,
    pub corrupt_lines: usize,
}

#[derive(Debug, Clone)]
pub struct VulnDb {
    dir: PathBuf,
    meta: Meta,
}

impl VulnDb {
    /// Membuka direktori: hanya membaca `meta.json` (indeks dimuat lazy saat dicari).
    pub fn open(dir: &Path) -> Result<VulnDb, VulnDbError> {
        if !dir.is_dir() {
            return Err(VulnDbError::NotFound(dir.to_path_buf()));
        }
        let path = dir.join(META_FILE);
        let text = fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VulnDbError::NotFound(path.clone())
            } else {
                VulnDbError::io(&path, e)
            }
        })?;
        let meta: Meta = serde_json::from_str(&text).map_err(|e| VulnDbError::BadMeta {
            path: path.clone(),
            message: e.to_string(),
        })?;
        if meta.format_version != FORMAT_VERSION {
            return Err(VulnDbError::UnsupportedFormat {
                found: meta.format_version,
                supported: FORMAT_VERSION,
            });
        }
        Ok(VulnDb {
            dir: dir.to_path_buf(),
            meta,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// False bila basis data tidak memuat satu advisory pun.
    pub fn has_data(&self) -> bool {
        self.meta.advisory_count > 0
    }

    pub fn has_ecosystem(&self, eco: Ecosystem) -> bool {
        self.meta
            .sources
            .osv
            .ecosystems
            .get(eco.as_str())
            .is_some_and(|e| e.advisories > 0)
    }

    pub fn has_nvd(&self) -> bool {
        self.meta
            .sources
            .nvd
            .as_ref()
            .is_some_and(|n| n.entries > 0)
    }

    pub fn age_days(&self, now: i64) -> Option<i64> {
        time::age_days(&self.meta.updated_at, now)
    }

    /// Mencari advisory untuk daftar (nama, versi). Satu kali baca berkas ekosistem; hanya baris
    /// dengan nama yang diminta yang diurai. Hasil cocok = versi berada di rentang terdampak.
    pub fn query_packages(
        &self,
        eco: Ecosystem,
        wanted: &[(String, String)],
    ) -> Result<PackageQuery, VulnDbError> {
        let mut result = PackageQuery::default();
        let path = self.dir.join(osv_rel(eco));
        if wanted.is_empty() || !path.exists() {
            return Ok(result);
        }
        let mut by_name: HashMap<String, Vec<&str>> = HashMap::new();
        for (name, version) in wanted {
            by_name
                .entry(eco.normalize_name(name))
                .or_default()
                .push(version);
        }
        for_each_line(&path, |line| {
            let Some(name) = leading_value(line, PACKAGE_PREFIX) else {
                result.corrupt_lines += 1;
                return;
            };
            let Some(versions) = by_name.get(name.as_ref()) else {
                return;
            };
            match serde_json::from_str::<Advisory>(line) {
                Ok(adv) => {
                    for v in versions {
                        if adv.affects(v) {
                            result.hits.push(PackageHit {
                                name: name.to_string(),
                                version: (*v).to_string(),
                                advisory: adv.clone(),
                            });
                        }
                    }
                }
                Err(_) => result.corrupt_lines += 1,
            }
        })?;
        result.hits.sort_by(|a, b| {
            (&a.name, &a.version, &a.advisory.id).cmp(&(&b.name, &b.version, &b.advisory.id))
        });
        result.hits.dedup();
        debug!(ecosystem = %eco, hits = result.hits.len(), "pencarian paket selesai");
        Ok(result)
    }

    /// Satu paket+versi, advisory yang beririsan digabung (untuk SCA dan `lookup`).
    pub fn lookup(
        &self,
        eco: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<(Vec<MergedAdvisory>, usize), VulnDbError> {
        let q = self.query_packages(eco, &[(name.to_string(), version.to_string())])?;
        let advisories: Vec<Advisory> = q.hits.into_iter().map(|h| h.advisory).collect();
        Ok((merge_advisories(advisories, version), q.corrupt_lines))
    }

    /// Entri NVD untuk produk (awalan CPE) yang rentangnya mencakup `version`.
    pub fn query_product(&self, product: &str, version: &str) -> Result<ProductQuery, VulnDbError> {
        let mut result = ProductQuery::default();
        let path = self.dir.join(NVD_FILE);
        if !path.exists() {
            return Ok(result);
        }
        for_each_line(&path, |line| {
            let Some(p) = leading_value(line, PRODUCT_PREFIX) else {
                result.corrupt_lines += 1;
                return;
            };
            if p != product {
                return;
            }
            match serde_json::from_str::<NvdEntry>(line) {
                Ok(entry) => {
                    if entry.affects(version) {
                        let fixed = entry.fixed_for(version);
                        result.hits.push(ProductHit { entry, fixed });
                    }
                }
                Err(_) => result.corrupt_lines += 1,
            }
        })?;
        result.hits.sort_by(|a, b| a.entry.id.cmp(&b.entry.id));
        Ok(result)
    }

    /// Semua entri NVD yang tersimpan (untuk digabung pada pembaruan inkremental).
    pub fn read_nvd_entries(&self) -> Result<Vec<NvdEntry>, VulnDbError> {
        let path = self.dir.join(NVD_FILE);
        let mut out = Vec::new();
        if !path.exists() {
            return Ok(out);
        }
        for_each_line(&path, |line| {
            if let Ok(e) = serde_json::from_str::<NvdEntry>(line) {
                out.push(e);
            }
        })?;
        Ok(out)
    }
}

/// Membaca JSON Lines baris demi baris; baris tak terbaca (UTF-8 rusak) diteruskan sebagai kosong
/// sehingga penghitung baris rusak pemanggil menambah.
fn for_each_line(path: &Path, mut f: impl FnMut(&str)) -> Result<(), VulnDbError> {
    let file = File::open(path).map_err(|e| VulnDbError::io(path, e))?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        let n = reader
            .read_until(b'\n', &mut buf)
            .map_err(|e| VulnDbError::io(path, e))?;
        if n == 0 {
            break;
        }
        match std::str::from_utf8(&buf) {
            Ok(s) => {
                let s = s.trim_end_matches(['\n', '\r']);
                if !s.trim().is_empty() {
                    f(s);
                }
            }
            Err(_) => f("\u{0}"),
        }
    }
    Ok(())
}

/// Penulis basis data ke direktori (biasanya direktori sementara yang kemudian dipasang dengan
/// [`install_dir`]). Berkas ekosistem/NVD yang tidak ditulis ulang disalin dari basis data lama.
pub struct DbWriter {
    dir: PathBuf,
    meta: Meta,
}

impl DbWriter {
    /// `existing`: basis data lama; berkas dan statistik yang tidak diperbarui dipertahankan.
    pub fn new(dir: &Path, existing: Option<&VulnDb>, now: &str) -> Result<DbWriter, VulnDbError> {
        fs::create_dir_all(dir.join("osv")).map_err(|e| VulnDbError::io(dir, e))?;
        fs::create_dir_all(dir.join("nvd")).map_err(|e| VulnDbError::io(dir, e))?;
        let mut meta = Meta::empty(now);
        if let Some(old) = existing {
            meta = old.meta.clone();
            meta.updated_at = now.to_string();
            for rel in Ecosystem::ALL
                .iter()
                .map(|e| osv_rel(*e))
                .chain([NVD_FILE.to_string()])
            {
                let src = old.dir.join(&rel);
                if src.is_file() {
                    fs::copy(&src, dir.join(&rel)).map_err(|e| VulnDbError::io(&src, e))?;
                }
            }
        }
        Ok(DbWriter {
            dir: dir.to_path_buf(),
            meta,
        })
    }

    fn write_lines<T: Serialize>(&self, rel: &str, rows: &[T]) -> Result<(), VulnDbError> {
        let path = self.dir.join(rel);
        let tmp = path.with_extension("jsonl.tmp");
        {
            let file = File::create(&tmp).map_err(|e| VulnDbError::io(&tmp, e))?;
            let mut w = BufWriter::new(file);
            for row in rows {
                serde_json::to_writer(&mut w, row)
                    .map_err(|e| VulnDbError::Other(format!("{}: {e}", path.display())))?;
                w.write_all(b"\n").map_err(|e| VulnDbError::io(&tmp, e))?;
            }
            w.flush().map_err(|e| VulnDbError::io(&tmp, e))?;
        }
        fs::rename(&tmp, &path).map_err(|e| VulnDbError::io(&path, e))
    }

    /// Menulis ulang `osv/<eco>.jsonl`: terurut menurut (paket, id); duplikat (paket, id) diambil
    /// yang `modified`-nya terbaru. Mengembalikan jumlah baris.
    pub fn put_osv(
        &mut self,
        eco: Ecosystem,
        advisories: Vec<Advisory>,
        now: &str,
    ) -> Result<u64, VulnDbError> {
        let mut map: BTreeMap<(String, String), Advisory> = BTreeMap::new();
        for a in advisories {
            let key = (a.package.clone(), a.id.clone());
            match map.get(&key) {
                Some(old) if old.modified >= a.modified => {}
                _ => {
                    map.insert(key, a);
                }
            }
        }
        let rows: Vec<Advisory> = map.into_values().collect();
        self.write_lines(&osv_rel(eco), &rows)?;
        let count = rows.len() as u64;
        self.meta.sources.osv.updated_at = now.to_string();
        self.meta.sources.osv.ecosystems.insert(
            eco.as_str().to_string(),
            EcosystemStat {
                updated_at: now.to_string(),
                advisories: count,
            },
        );
        Ok(count)
    }

    /// Menulis ulang `nvd/products.jsonl` (terurut menurut (produk, id); duplikat -> `modified` terbaru).
    pub fn put_nvd(
        &mut self,
        entries: Vec<NvdEntry>,
        last_modified: &str,
        products: &[&str],
        now: &str,
    ) -> Result<u64, VulnDbError> {
        let mut map: BTreeMap<(String, String), NvdEntry> = BTreeMap::new();
        for e in entries {
            let key = (e.product.clone(), e.id.clone());
            match map.get(&key) {
                Some(old) if old.modified > e.modified => {}
                _ => {
                    map.insert(key, e);
                }
            }
        }
        let rows: Vec<NvdEntry> = map.into_values().collect();
        self.write_lines(NVD_FILE, &rows)?;
        let count = rows.len() as u64;
        self.meta.sources.nvd = Some(NvdStat {
            updated_at: now.to_string(),
            last_modified: last_modified.to_string(),
            entries: count,
            products: products.iter().map(|p| p.to_string()).collect(),
        });
        Ok(count)
    }

    /// Menulis `meta.json` (terakhir, sebagai tanda basis data lengkap) dan mengembalikan meta.
    pub fn finish(mut self, now: &str) -> Result<Meta, VulnDbError> {
        self.meta.updated_at = now.to_string();
        self.meta.recount();
        let path = self.dir.join(META_FILE);
        let mut text = serde_json::to_string_pretty(&self.meta)
            .map_err(|e| VulnDbError::Other(e.to_string()))?;
        text.push('\n');
        fs::write(&path, text).map_err(|e| VulnDbError::io(&path, e))?;
        Ok(self.meta)
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }
}

/// Memasang `tmp` sebagai `target`: rename atomik bila target belum ada; bila sudah ada, target
/// lama dipindah ke samping lalu dihapus setelah yang baru terpasang (dikembalikan bila gagal).
pub fn install_dir(tmp: &Path, target: &Path) -> Result<(), VulnDbError> {
    if !target.exists() {
        if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| VulnDbError::io(parent, e))?;
        }
        return fs::rename(tmp, target).map_err(|e| VulnDbError::io(target, e));
    }
    let mut old_name = target
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    old_name.push(format!(".old-{}", std::process::id()));
    let old = target.with_file_name(old_name);
    fs::rename(target, &old).map_err(|e| VulnDbError::io(target, e))?;
    if let Err(e) = fs::rename(tmp, target) {
        let _ = fs::rename(&old, target);
        return Err(VulnDbError::io(target, e));
    }
    let _ = fs::remove_dir_all(&old);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CpeRange, Event, Range, RangeKind};

    fn adv(eco: Ecosystem, pkg: &str, id: &str, events: Vec<Event>) -> Advisory {
        Advisory {
            package: pkg.into(),
            ecosystem: eco,
            id: id.into(),
            aliases: vec![],
            summary: format!("ringkasan {id}"),
            cvss: None,
            severity: None,
            ranges: vec![Range {
                kind: RangeKind::Semver,
                events,
            }],
            versions: vec![],
            fixed: vec![],
            references: vec![],
            cwe: vec![],
            modified: "2024-01-01T00:00:00Z".into(),
            withdrawn: None,
        }
    }

    fn build(dir: &Path) {
        let mut w = DbWriter::new(dir, None, "2026-01-01T00:00:00Z").unwrap();
        w.put_osv(
            Ecosystem::Npm,
            vec![
                adv(
                    Ecosystem::Npm,
                    "zeta",
                    "GHSA-2",
                    vec![Event::Introduced("0".into())],
                ),
                adv(
                    Ecosystem::Npm,
                    "alpha",
                    "GHSA-1",
                    vec![Event::Introduced("0".into()), Event::Fixed("2.0.0".into())],
                ),
                adv(
                    Ecosystem::Npm,
                    "we\"ird\\name",
                    "GHSA-3",
                    vec![Event::Introduced("0".into())],
                ),
            ],
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        w.put_nvd(
            vec![NvdEntry {
                product: "cpe:2.3:a:nginx:nginx".into(),
                id: "CVE-2022-0001".into(),
                summary: "x".into(),
                cvss: None,
                severity: None,
                cwe: vec![],
                matches: vec![CpeRange {
                    end_excluding: Some("1.20.2".into()),
                    ..Default::default()
                }],
                references: vec![],
                modified: String::new(),
            }],
            "2026-01-01T00:00:00Z",
            &["cpe:2.3:a:nginx:nginx"],
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        w.finish("2026-01-01T00:00:00Z").unwrap();
    }

    #[test]
    fn write_then_query_roundtrip_is_sorted_and_lazy() {
        let tmp = tempfile::tempdir().unwrap();
        build(tmp.path());
        let text = fs::read_to_string(tmp.path().join("osv/npm.jsonl")).unwrap();
        let packages: Vec<String> = text
            .lines()
            .map(|l| leading_value(l, PACKAGE_PREFIX).unwrap().into_owned())
            .collect();
        assert_eq!(packages, ["alpha", "we\"ird\\name", "zeta"]);
        assert!(!tmp.path().join("osv/Go.jsonl").exists());

        let db = VulnDb::open(tmp.path()).unwrap();
        assert_eq!(db.meta().advisory_count, 4);
        assert!(db.has_ecosystem(Ecosystem::Npm));
        assert!(!db.has_ecosystem(Ecosystem::Go));
        assert!(db.has_nvd());

        let q = db
            .query_packages(
                Ecosystem::Npm,
                &[
                    ("alpha".into(), "1.0.0".into()),
                    ("alpha".into(), "2.0.0".into()),
                    ("we\"ird\\name".into(), "1.0.0".into()),
                    ("zeta".into(), "3.1.4".into()),
                    ("absent".into(), "1.0.0".into()),
                ],
            )
            .unwrap();
        let got: Vec<(String, String, String)> = q
            .hits
            .iter()
            .map(|h| (h.name.clone(), h.version.clone(), h.advisory.id.clone()))
            .collect();
        assert_eq!(
            got,
            [
                ("alpha".into(), "1.0.0".into(), "GHSA-1".into()),
                ("we\"ird\\name".into(), "1.0.0".into(), "GHSA-3".into()),
                ("zeta".into(), "3.1.4".into(), "GHSA-2".into()),
            ]
        );
        assert_eq!(q.corrupt_lines, 0);
        let missing = db
            .query_packages(Ecosystem::Go, &[("x".into(), "1.0.0".into())])
            .unwrap();
        assert!(missing.hits.is_empty());
    }

    #[test]
    fn corrupt_lines_are_skipped_and_counted() {
        let tmp = tempfile::tempdir().unwrap();
        build(tmp.path());
        let path = tmp.path().join("osv/npm.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str("{\"package\":\"alpha\",\"truncated\n");
        text.push_str("garbage line\n");
        let mut bytes = text.into_bytes();
        bytes.extend_from_slice(b"{\"package\":\"\xff\xfe\"}\n");
        fs::write(&path, bytes).unwrap();
        let db = VulnDb::open(tmp.path()).unwrap();
        let q = db
            .query_packages(Ecosystem::Npm, &[("alpha".into(), "1.0.0".into())])
            .unwrap();
        assert_eq!(q.hits.len(), 1);
        assert_eq!(q.corrupt_lines, 3);
    }

    #[test]
    fn product_query_and_unknown_product() {
        let tmp = tempfile::tempdir().unwrap();
        build(tmp.path());
        let db = VulnDb::open(tmp.path()).unwrap();
        let q = db.query_product("cpe:2.3:a:nginx:nginx", "1.18.0").unwrap();
        assert_eq!(q.hits.len(), 1);
        assert_eq!(q.hits[0].fixed, ["1.20.2"]);
        assert!(db
            .query_product("cpe:2.3:a:nginx:nginx", "1.21.0")
            .unwrap()
            .hits
            .is_empty());
        assert!(db
            .query_product("cpe:2.3:a:php:php", "1.0")
            .unwrap()
            .hits
            .is_empty());
    }

    #[test]
    fn open_errors() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            VulnDb::open(&tmp.path().join("nope")),
            Err(VulnDbError::NotFound(_))
        ));
        assert!(matches!(
            VulnDb::open(tmp.path()),
            Err(VulnDbError::NotFound(_))
        ));
        fs::write(tmp.path().join("meta.json"), "{ rusak").unwrap();
        assert!(matches!(
            VulnDb::open(tmp.path()),
            Err(VulnDbError::BadMeta { .. })
        ));
        fs::write(
            tmp.path().join("meta.json"),
            r#"{"format_version":99,"updated_at":"x","advisory_count":0,"sources":{}}"#,
        )
        .unwrap();
        assert!(matches!(
            VulnDb::open(tmp.path()),
            Err(VulnDbError::UnsupportedFormat { found: 99, .. })
        ));
    }

    #[test]
    fn partial_update_keeps_other_ecosystems() {
        let tmp = tempfile::tempdir().unwrap();
        let old_dir = tmp.path().join("old");
        build(&old_dir);
        let old = VulnDb::open(&old_dir).unwrap();
        let new_dir = tmp.path().join("new");
        let mut w = DbWriter::new(&new_dir, Some(&old), "2026-02-01T00:00:00Z").unwrap();
        w.put_osv(
            Ecosystem::Go,
            vec![adv(
                Ecosystem::Go,
                "example.com/m",
                "GHSA-9",
                vec![Event::Introduced("0".into())],
            )],
            "2026-02-01T00:00:00Z",
        )
        .unwrap();
        w.finish("2026-02-01T00:00:00Z").unwrap();
        let db = VulnDb::open(&new_dir).unwrap();
        assert_eq!(db.meta().advisory_count, 5);
        assert!(db.has_ecosystem(Ecosystem::Npm) && db.has_ecosystem(Ecosystem::Go));
        assert_eq!(
            db.meta().sources.osv.ecosystems["npm"].updated_at,
            "2026-01-01T00:00:00Z"
        );
        assert_eq!(db.meta().updated_at, "2026-02-01T00:00:00Z");
        assert!(db.has_nvd());
    }

    #[test]
    fn install_replaces_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("db");
        let t1 = tmp.path().join("t1");
        fs::create_dir_all(&t1).unwrap();
        fs::write(t1.join("a"), "1").unwrap();
        install_dir(&t1, &target).unwrap();
        let t2 = tmp.path().join("t2");
        fs::create_dir_all(&t2).unwrap();
        fs::write(t2.join("b"), "2").unwrap();
        install_dir(&t2, &target).unwrap();
        assert!(target.join("b").exists() && !target.join("a").exists());
        assert!(!t2.exists());
        let leftovers: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "hanya db yang tersisa (tanpa .old-*)");
    }

    #[test]
    fn writer_is_deterministic() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        build(a.path());
        build(b.path());
        for f in ["osv/npm.jsonl", "nvd/products.jsonl", "meta.json"] {
            assert_eq!(
                fs::read(a.path().join(f)).unwrap(),
                fs::read(b.path().join(f)).unwrap(),
                "{f}"
            );
        }
    }
}
