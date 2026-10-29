use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(CoreError::UnknownSeverity(s.to_string())),
        }
    }
}

/// Lokasi dalam file; baris dan kolom dimulai dari 1, path relatif terhadap akar pemindaian.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

impl Location {
    /// Lokasi berjenis URL (hasil DAST): tanpa baris dan kolom.
    pub fn url(url: &str) -> Location {
        Location {
            path: url.to_string(),
            start_line: 0,
            start_column: 0,
            end_line: 0,
            end_column: 0,
        }
    }

    /// False untuk lokasi URL, yang tidak punya rentang baris.
    pub fn has_region(&self) -> bool {
        self.start_line > 0
    }
}

/// Paket yang rentan (hasil SCA) atau produk yang terbaca dari banner (hasil DAST).
/// Tersusun ke SARIF sebagai `{ecosystem,name,version}` atau `{product,version}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VulnTarget {
    Package {
        ecosystem: String,
        name: String,
        version: String,
    },
    Product {
        product: String,
        version: String,
    },
}

impl VulnTarget {
    pub fn version(&self) -> &str {
        match self {
            VulnTarget::Package { version, .. } | VulnTarget::Product { version, .. } => version,
        }
    }

    /// Kunci stabil `ekosistem:nama@versi` atau `produk@versi`; dasar sidik jari (bukan snippet).
    pub fn key(&self) -> String {
        match self {
            VulnTarget::Package {
                ecosystem,
                name,
                version,
            } => format!("{ecosystem}:{name}@{version}"),
            VulnTarget::Product { product, version } => format!("{product}@{version}"),
        }
    }
}

/// Skor CVSS; `score` 0.0 sampai 10.0.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cvss {
    pub score: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
}

/// Keterangan kerentanan sebuah temuan (SCA/CVE). `ids`: CVE dulu, lalu GHSA/OSV.
/// Kunci JSON di SARIF `result.properties.vulnerability`: ids, package, fixed_versions, source,
/// references, cvss, confidence, scope. `summary` dan `cwe` hanya dipakai untuk membuat rule SARIF
/// (shortDescription dan tag `external/cwe/...`) dan tidak ikut ditulis ke properti hasil.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub ids: Vec<String>,
    pub package: VulnTarget,
    pub fixed_versions: Vec<String>,
    /// "osv" atau "nvd".
    pub source: String,
    /// Maksimum 5 URL.
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<Cvss>,
    /// "high" atau "low" (banner versi dapat ditambal distro, jadi "low").
    pub confidence: String,
    /// "runtime" atau "dev".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Ringkasan advisory (untuk rule SARIF).
    #[serde(default)]
    pub summary: String,
    /// CWE advisory, mis. `CWE-79` (untuk tag rule SARIF).
    #[serde(default)]
    pub cwe: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub location: Location,
    pub snippet: String,
    /// Terisi hanya untuk temuan kerentanan dependensi/versi perangkat lunak.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulnerability: Option<Vulnerability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningKind {
    /// File tidak terbaca atau bukan UTF-8; dilewati.
    Skipped,
    /// File memuat galat sintaks; pohon parsial tetap dipindai.
    ParseError,
    /// Verifikasi sertifikat TLS dimatikan atas permintaan pengguna; hasil tidak menjamin identitas target.
    InsecureTls,
    /// Taint ambigu: variabel diberi nilai lebih dari sekali dan sebagian tidak tercemar.
    AmbiguousTaint,
    /// Basis data kerentanan tidak tersedia, usang, rusak, atau tidak memuat ekosistem yang dibutuhkan.
    VulnDb,
    /// Lockfile tidak terbaca, terlalu besar, atau formatnya tidak didukung; dilewati.
    Lockfile,
    /// Hasil dipotong (batas jumlah temuan).
    Truncated,
    /// DAST: crawl dibatasi atau halaman dilewati (batas halaman/kedalaman, pengecualian jalur, respons terlalu besar).
    Crawl,
    /// DAST: masalah autentikasi (izin berkas auth, sesi kedaluwarsa, login ulang).
    Auth,
}

/// Penanda pada bukti temuan DAST yang sama di banyak halaman: `<bukti> (berlaku juga di N halaman lain: ...)`.
/// Bagian ini tidak ikut sidik jari agar sidik jari stabil walau jumlah halaman berubah.
pub const MULTI_PAGE_MARKER: &str = " (berlaku juga di ";

/// Bukti tanpa keterangan `berlaku juga di ...`.
pub fn base_evidence(snippet: &str) -> &str {
    match snippet.find(MULTI_PAGE_MARKER) {
        Some(i) => &snippet[..i],
        None => snippet,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    pub kind: WarningKind,
    pub message: String,
    pub path: Option<String>,
    pub rule_id: Option<String>,
    pub location: Option<Location>,
    pub snippet: Option<String>,
}

/// Hasil satu pemindaian; dipakai bersama oleh semua mesin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanOutput {
    pub findings: Vec<Finding>,
    pub warnings: Vec<Warning>,
    pub files_scanned: usize,
}
