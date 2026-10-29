//! Membaca dump OSV (zip atau direktori berkas JSON) menjadi advisory. Tidak ada isi dump yang
//! diekstrak ke disk atau dijalankan; setiap entri dibaca ke memori dengan batas ukuran.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sdrscan_vulndb::{osv, Advisory, Ecosystem};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct Limits {
    /// Ukuran unduhan satu zip.
    pub max_download_bytes: u64,
    /// Jumlah entri per zip (anti zip-bomb).
    pub max_entries: usize,
    /// Ukuran terurai satu entri JSON.
    pub max_entry_bytes: u64,
    /// Total ukuran terurai satu zip.
    pub max_total_bytes: u64,
    /// Ukuran satu halaman respons NVD.
    pub max_nvd_page_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_download_bytes: 2 * 1024 * 1024 * 1024,
            max_entries: 2_000_000,
            max_entry_bytes: 32 * 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024 * 1024,
            max_nvd_page_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct IngestStats {
    /// Entri `.json` yang dibaca.
    pub entries: usize,
    /// Entri rusak/terlalu besar yang dilewati.
    pub invalid: usize,
    pub advisories: usize,
}

#[derive(Debug, Clone)]
pub enum Source {
    Zip(PathBuf),
    JsonDir(PathBuf),
}

/// Lokasi dump ekosistem di `--from-dir`: `<dir>/<Eco>/all.zip`, `<dir>/<Eco>.zip`, atau direktori `<dir>/<Eco>/`.
pub fn find_source(dir: &Path, eco: Ecosystem) -> Option<Source> {
    let name = eco.as_str();
    let candidates = [
        (dir.join(name).join("all.zip"), true),
        (dir.join(format!("{name}.zip")), true),
        (dir.join(name), false),
    ];
    candidates.into_iter().find_map(|(p, zip)| {
        if zip && p.is_file() {
            Some(Source::Zip(p))
        } else if !zip && p.is_dir() {
            Some(Source::JsonDir(p))
        } else {
            None
        }
    })
}

struct Acc<'a> {
    eco: Ecosystem,
    limits: &'a Limits,
    stats: IngestStats,
    out: Vec<Advisory>,
}

impl Acc<'_> {
    fn feed(&mut self, name: &str, bytes: &[u8]) {
        self.stats.entries += 1;
        match osv::parse_record(bytes, self.eco) {
            Ok(mut advs) => {
                self.stats.advisories += advs.len();
                self.out.append(&mut advs);
            }
            Err(e) => {
                self.stats.invalid += 1;
                debug!(entry = name, error = %e, "entri OSV rusak dilewati");
            }
        }
    }
}

fn read_limited(mut r: impl Read, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    (&mut r).take(max + 1).read_to_end(&mut buf)?;
    Ok(if buf.len() as u64 > max {
        None
    } else {
        Some(buf)
    })
}

fn ingest_zip(path: &Path, acc: &mut Acc) -> Result<()> {
    let file = File::open(path).with_context(|| format!("membuka {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(BufReader::new(file)).with_context(|| {
        format!(
            "{} bukan zip yang valid (unduhan terpotong atau rusak?)",
            path.display()
        )
    })?;
    if archive.len() > acc.limits.max_entries {
        bail!(
            "{}: {} entri melebihi batas {}",
            path.display(),
            archive.len(),
            acc.limits.max_entries
        );
    }
    let mut total = 0u64;
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                acc.stats.invalid += 1;
                debug!(index = i, error = %e, "entri zip tidak terbaca, dilewati");
                continue;
            }
        };
        let name = match entry.name() {
            Ok(n) => n.to_string(),
            Err(_) => {
                acc.stats.invalid += 1;
                continue;
            }
        };
        if entry.is_dir() || !name.to_ascii_lowercase().ends_with(".json") {
            continue;
        }
        if entry.size() > acc.limits.max_entry_bytes {
            acc.stats.entries += 1;
            acc.stats.invalid += 1;
            warn!(entry = %name, "entri melebihi batas ukuran, dilewati");
            continue;
        }
        match read_limited(&mut entry, acc.limits.max_entry_bytes) {
            Ok(Some(bytes)) => {
                total += bytes.len() as u64;
                if total > acc.limits.max_total_bytes {
                    bail!(
                        "{}: total ukuran terurai melebihi batas {} byte (kemungkinan zip-bomb)",
                        path.display(),
                        acc.limits.max_total_bytes
                    );
                }
                acc.feed(&name, &bytes);
            }
            Ok(None) => {
                acc.stats.entries += 1;
                acc.stats.invalid += 1;
                warn!(entry = %name, "entri melebihi batas ukuran, dilewati");
            }
            Err(e) => {
                acc.stats.entries += 1;
                acc.stats.invalid += 1;
                debug!(entry = %name, error = %e, "entri zip rusak, dilewati");
            }
        }
    }
    Ok(())
}

fn ingest_dir(dir: &Path, acc: &mut Acc) -> Result<()> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("membaca {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        })
        .collect();
    files.sort();
    if files.len() > acc.limits.max_entries {
        bail!("{}: terlalu banyak berkas", dir.display());
    }
    for f in files {
        let name = f
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let file = File::open(&f).with_context(|| format!("membuka {}", f.display()))?;
        match read_limited(file, acc.limits.max_entry_bytes) {
            Ok(Some(bytes)) => acc.feed(&name, &bytes),
            _ => {
                acc.stats.entries += 1;
                acc.stats.invalid += 1;
            }
        }
    }
    Ok(())
}

/// Membaca satu sumber dump untuk `eco`. Galat keras bila batas dilanggar, tidak ada entri, atau
/// dua atau lebih entri dan lebih dari 10% di antaranya rusak (indikasi unduhan/dump korup).
pub fn ingest(
    source: &Source,
    eco: Ecosystem,
    limits: &Limits,
) -> Result<(Vec<Advisory>, IngestStats)> {
    let mut acc = Acc {
        eco,
        limits,
        stats: IngestStats::default(),
        out: Vec::new(),
    };
    match source {
        Source::Zip(p) => ingest_zip(p, &mut acc)?,
        Source::JsonDir(p) => ingest_dir(p, &mut acc)?,
    }
    let stats = acc.stats;
    if stats.entries == 0 {
        bail!("dump {eco} tidak berisi entri .json");
    }
    if stats.invalid >= 2 && stats.invalid * 10 > stats.entries {
        bail!(
            "dump {eco}: {} dari {} entri rusak (>10%); dump dianggap korup",
            stats.invalid,
            stats.entries
        );
    }
    if stats.invalid > 0 {
        warn!(
            ecosystem = %eco,
            invalid = stats.invalid,
            entries = stats.entries,
            "sebagian entri rusak dilewati"
        );
    }
    Ok((acc.out, stats))
}
