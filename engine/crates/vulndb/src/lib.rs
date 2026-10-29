//! Basis data kerentanan lokal SDRScan: model advisory, format berkas di disk, pencocokan versi,
//! dan pengolah dump OSV/NVD. Pustaka ini murni lokal (tanpa jaringan); pengunduhan ada di `sdrscan-vuln`.
//!
//! Tata letak direktori (format versi 1):
//!
//! ```text
//! <db>/meta.json              waktu pembaruan per sumber, jumlah advisory, versi format
//! <db>/osv/<Ekosistem>.jsonl  satu advisory per paket per baris, urut (paket, id); Packagist, npm, Go, crates.io
//! <db>/nvd/products.jsonl     satu entri per (produk CPE, CVE) per baris, urut (produk, id)
//! ```

pub mod cvss;
pub mod ecosystem;
pub mod model;
pub mod nvd;
pub mod osv;
pub mod products;
pub mod store;
pub mod time;
pub mod version;

pub use ecosystem::Ecosystem;
pub use model::{
    merge_advisories, Advisory, CpeRange, Cvss, Event, MergedAdvisory, NvdEntry, PackageHit,
    ProductHit, Range, RangeKind,
};
pub use store::{
    install_dir, DbWriter, EcosystemStat, Meta, NvdStat, OsvStat, Sources, VulnDb, FORMAT_VERSION,
};

use std::path::PathBuf;

/// Nama variabel lingkungan yang menunjuk direktori basis data.
pub const ENV_DB: &str = "SDRSCAN_VULN_DB";

/// Direktori dari flag, atau dari env `SDRSCAN_VULN_DB` (nilai kosong dianggap tidak ada).
pub fn resolve_db_dir(flag: Option<&std::path::Path>) -> Option<PathBuf> {
    if let Some(p) = flag {
        return Some(p.to_path_buf());
    }
    match std::env::var_os(ENV_DB) {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VulnDbError {
    #[error("basis data kerentanan tidak ditemukan: {0}")]
    NotFound(PathBuf),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("meta.json rusak ({path}): {message}")]
    BadMeta { path: PathBuf, message: String },
    #[error("format basis data versi {found} tidak didukung (didukung: {supported}); jalankan sdrscan-vuln update")]
    UnsupportedFormat { found: u32, supported: u32 },
    #[error("{0}")]
    Other(String),
}

impl VulnDbError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        VulnDbError::Io {
            path: path.into(),
            source,
        }
    }
}
