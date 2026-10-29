use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Ekosistem paket yang didukung SCA. Nama di berkas/JSON mengikuti OSV.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    #[serde(rename = "Packagist")]
    Packagist,
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "Go")]
    Go,
    #[serde(rename = "crates.io")]
    CratesIo,
}

impl Ecosystem {
    pub const ALL: [Ecosystem; 4] = [
        Ecosystem::Packagist,
        Ecosystem::Npm,
        Ecosystem::Go,
        Ecosystem::CratesIo,
    ];

    /// Nama resmi OSV; juga nama berkas `osv/<nama>.jsonl`.
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Packagist => "Packagist",
            Ecosystem::Npm => "npm",
            Ecosystem::Go => "Go",
            Ecosystem::CratesIo => "crates.io",
        }
    }

    pub fn scheme(self) -> crate::version::Scheme {
        match self {
            Ecosystem::Packagist => crate::version::Scheme::Composer,
            _ => crate::version::Scheme::Semver,
        }
    }

    /// Packagist tidak membedakan huruf besar/kecil; ekosistem lain memakai nama apa adanya.
    pub fn normalize_name(self, name: &str) -> String {
        match self {
            Ecosystem::Packagist => name.to_ascii_lowercase(),
            _ => name.to_string(),
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Ecosystem {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "packagist" | "composer" => Ok(Ecosystem::Packagist),
            "npm" => Ok(Ecosystem::Npm),
            "go" | "golang" => Ok(Ecosystem::Go),
            "crates.io" | "crates" | "cargo" => Ok(Ecosystem::CratesIo),
            _ => Err(format!(
                "ekosistem tidak dikenal '{s}' (Packagist, npm, Go, crates.io)"
            )),
        }
    }
}
