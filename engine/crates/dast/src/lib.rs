//! Mesin DAST: pemeriksaan pasif atas satu halaman atau crawl pasif terbatas (hanya GET, satu origin),
//! dengan login opsional (formulir atau header/cookie tetap). Tidak ada pemeriksaan aktif dan tidak ada payload.

pub mod active;
pub mod auth;
pub mod banner;
pub mod checks;
pub mod collect;
pub mod crawl;
pub mod html;
pub mod jsonpath;
pub mod login;
pub mod netguard;
pub mod openapi;
pub mod scan;
pub mod session;
pub mod urlutil;

use std::path::PathBuf;
use std::time::Duration;

use sdrscan_core::ScanOutput;
use url::Url;

pub use scan::LoginSummary;

#[derive(Debug)]
pub enum DastError {
    InvalidTarget(String),
    AddressNotAllowed(String),
    Request(String),
    /// Opsi atau berkas auth tidak valid (pesan tanpa nilai rahasia).
    Config(String),
    /// Login gagal atau URL login tidak diizinkan (pesan tanpa kredensial).
    Auth(String),
}

impl std::fmt::Display for DastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DastError::InvalidTarget(m) => write!(f, "target tidak valid: {m}"),
            DastError::AddressNotAllowed(m) => {
                write!(f, "alamat jaringan privat tidak diizinkan: {m}")
            }
            DastError::Request(m) => write!(f, "permintaan ke target gagal: {m}"),
            DastError::Config(m) | DastError::Auth(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for DastError {}

#[derive(Debug, Clone)]
pub struct Options {
    pub timeout: Duration,
    /// Redirect hanya diikuti bila tetap di host dan port yang sama.
    pub max_redirects: usize,
    pub user_agent: String,
    /// Hanya untuk pengujian: mengizinkan loopback dan jaringan privat.
    pub allow_private_networks: bool,
    /// Menolak jaringan privat (loopback, RFC1918, CGNAT, ULA, link-local). Default false: jaringan
    /// privat diizinkan; endpoint metadata cloud selalu ditolak.
    pub block_private: bool,
    /// Berkas PEM berisi CA tepercaya tambahan/pengganti (mis. CA internal perusahaan).
    /// Bila diisi, hanya CA di berkas ini yang dipercaya; bila kosong dipakai penyimpanan sertifikat sistem.
    pub ca_pem: Option<Vec<u8>>,
    /// Matikan verifikasi sertifikat TLS (tidak aman; hasil diberi peringatan).
    pub insecure_tls: bool,
    /// Direktori basis data kerentanan lokal untuk CVE dari banner (default: env SDRSCAN_VULN_DB).
    pub vuln_db: Option<PathBuf>,
    /// Crawl pasif dari URL target (hanya GET, satu origin).
    pub crawl: bool,
    /// Kedalaman maksimum (0 = hanya URL target); dibatasi `crawl::MAX_DEPTH_LIMIT`.
    pub max_depth: u32,
    /// Jumlah halaman maksimum; dibatasi `crawl::MAX_PAGES_LIMIT`.
    pub max_pages: usize,
    /// Permintaan per detik (semua permintaan, termasuk login).
    pub max_rps: u32,
    /// Regex tambahan (tidak peka huruf besar-kecil) untuk jalur yang tidak diambil.
    pub exclude_paths: Vec<String>,
    /// Autentikasi (login formulir, header, cookie tetap).
    pub auth: Option<auth::AuthConfig>,
    /// Pemeriksaan aktif (opt-in, berisiko): lihat `active::ActiveOptions`.
    pub active: active::ActiveOptions,
    /// Lokasi eksplisit spesifikasi OpenAPI/Swagger (berkas lokal atau URL satu origin dengan target).
    pub openapi_spec: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            timeout: Duration::from_secs(15),
            max_redirects: 3,
            user_agent: format!("sdrscan-dast/{}", env!("CARGO_PKG_VERSION")),
            allow_private_networks: false,
            block_private: false,
            ca_pem: None,
            insecure_tls: false,
            vuln_db: None,
            crawl: false,
            max_depth: 3,
            max_pages: 50,
            max_rps: 5,
            exclude_paths: Vec::new(),
            auth: None,
            active: active::ActiveOptions::default(),
            openapi_spec: None,
        }
    }
}

pub fn parse_target(raw: &str) -> Result<Url, DastError> {
    let url = Url::parse(raw).map_err(|e| DastError::InvalidTarget(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(DastError::InvalidTarget(format!(
            "skema '{}' tidak didukung (http atau https)",
            url.scheme()
        )));
    }
    if url.host_str().is_none() {
        return Err(DastError::InvalidTarget("host tidak ada".to_string()));
    }
    Ok(url)
}

/// Membangun agen HTTP dengan verifikasi TLS (sistem atau `ca_pem`) dan resolver penjaga alamat privat.
/// `max_redirects` diserahkan ke ureq (DAST mengurus redirect sendiri: 0). `long_transfer`: batas waktu
/// per baca/koneksi alih-alih batas global, untuk unduhan berukuran besar.
pub fn build_agent(
    opts: &Options,
    max_redirects: u32,
    long_transfer: bool,
) -> Result<ureq::Agent, DastError> {
    let root_certs = match &opts.ca_pem {
        Some(pem) => {
            let certs = ureq::tls::parse_pem(pem)
                .filter_map(|item| match item {
                    Ok(ureq::tls::PemItem::Certificate(c)) => Some(Ok(c)),
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| DastError::InvalidTarget(format!("berkas CA tidak valid: {e}")))?;
            if certs.is_empty() {
                return Err(DastError::InvalidTarget(
                    "berkas CA tidak berisi sertifikat PEM".to_string(),
                ));
            }
            ureq::tls::RootCerts::new_with_certs(&certs)
        }
        None => ureq::tls::RootCerts::PlatformVerifier,
    };
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(root_certs)
        .disable_verification(opts.insecure_tls)
        .build();
    let builder = ureq::Agent::config_builder()
        .tls_config(tls)
        .max_redirects(max_redirects)
        .http_status_as_error(false)
        .user_agent(opts.user_agent.clone());
    let builder = if long_transfer {
        builder
            .timeout_global(None)
            .timeout_connect(Some(opts.timeout))
            .timeout_per_read(Some(opts.timeout))
    } else {
        builder.timeout_global(Some(opts.timeout))
    };
    // Resolver khusus: koneksi hanya dibuka ke alamat yang sudah lolos pemeriksaan, pada tiap redirect.
    Ok(ureq::Agent::with_parts(
        builder.build(),
        ureq::unversioned::transport::DefaultConnector::default(),
        netguard::GuardedResolver {
            policy: if opts.allow_private_networks {
                netguard::Policy::AllowAll
            } else if opts.block_private {
                netguard::Policy::Strict
            } else {
                netguard::Policy::AllowPrivate
            },
        },
    ))
}

/// Memindai target dengan pemeriksaan pasif: satu halaman, atau crawl bila `opts.crawl`; login lebih
/// dulu bila `opts.auth` memuat login. Hasil diurutkan deterministik dan temuan yang sama di banyak
/// halaman digabung. Bila `opts.active.enabled`, pemeriksaan aktif (lihat `active`) juga dijalankan;
/// nilai kedua yang dikembalikan adalah jumlah permintaan aktif yang terkirim (0 bila tidak dipakai).
pub fn scan(target: &Url, opts: &Options) -> Result<(ScanOutput, usize), DastError> {
    scan::ScanRun::new(target, opts)?.run()
}

/// Hanya login (tanpa crawl dan tanpa temuan); galat bila login gagal.
pub fn login_check(target: &Url, opts: &Options) -> Result<LoginSummary, DastError> {
    scan::ScanRun::new(target, opts)?.login_only()
}
