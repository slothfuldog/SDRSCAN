use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use sdrscan_vuln::http::ClientOptions;
use sdrscan_vuln::ingest::Limits;
use sdrscan_vuln::update::{run_update, UpdateOptions, DEFAULT_NVD_BASE, DEFAULT_OSV_BASE};
use sdrscan_vulndb::time::{age_days, now_epoch};
use sdrscan_vulndb::{resolve_db_dir, Ecosystem, VulnDb};
use tracing::Level;

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(
    name = "sdrscan-vuln",
    version,
    about = "Mengelola basis data kerentanan lokal SDRScan (OSV dan NVD) untuk SCA dan DAST"
)]
struct Cli {
    /// Tambah detail log (stderr)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,
    /// Kurangi detail log (stderr)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    quiet: u8,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Memperbarui basis data dari dump OSV (dan NVD dengan --nvd); satu-satunya perintah yang memakai jaringan
    Update(UpdateArgs),
    /// Menampilkan umur dan isi basis data
    Status(StatusArgs),
    /// Mencari advisory untuk satu paket dan versi (untuk debug)
    Lookup(LookupArgs),
}

#[derive(clap::Args)]
struct UpdateArgs {
    /// Ekosistem yang diperbarui, dipisah koma (default: Packagist,npm,Go,crates.io)
    #[arg(long, value_delimiter = ',', value_parser = parse_ecosystem)]
    ecosystems: Vec<Ecosystem>,
    /// Direktori basis data (default: env SDRSCAN_VULN_DB)
    #[arg(long, value_name = "DIR")]
    db: Option<PathBuf>,
    /// Lewati OSV; perbarui hanya NVD (butuh --nvd)
    #[arg(long, requires = "nvd", conflicts_with = "ecosystems")]
    no_osv: bool,
    /// Ambil juga data NVD (API 2.0) untuk produk web terkurasi; env NVD_API_KEY dipakai bila ada
    #[arg(long)]
    nvd: bool,
    /// Baca dump yang sudah diunduh (instalasi tertutup): <dir>/<Ekosistem>/all.zip, <dir>/<Ekosistem>.zip,
    /// atau direktori berkas JSON; untuk NVD: <dir>/nvd/*.json. Tidak memakai jaringan
    #[arg(long, value_name = "DIR")]
    from_dir: Option<PathBuf>,
    /// Batas waktu koneksi/baca per permintaan (detik)
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    /// Berkas PEM berisi CA yang dipercaya (proksi/CA internal); bila diisi hanya CA ini yang dipercaya
    #[arg(long, value_name = "FILE")]
    ca_cert: Option<PathBuf>,
    /// Jangan verifikasi sertifikat HTTPS (TIDAK AMAN)
    #[arg(long)]
    insecure: bool,
    /// Basis URL dump OSV (default: bucket publik OSV); berguna untuk cermin
    #[arg(long, default_value = DEFAULT_OSV_BASE, value_name = "URL")]
    osv_base_url: String,
    /// URL API NVD 2.0
    #[arg(long, default_value = DEFAULT_NVD_BASE, value_name = "URL")]
    nvd_base_url: String,
    /// Terima hasil pembaruan yang jauh lebih kecil dari basis data lama
    #[arg(long)]
    force: bool,
    /// Batas ukuran unduhan per ekosistem (MiB)
    #[arg(long, default_value_t = 2048, value_name = "MIB")]
    max_download_mb: u64,
    /// Hanya untuk pengujian: izinkan loopback dan jaringan privat
    #[arg(long, hide = true)]
    allow_private_networks_for_tests: bool,
    /// Hanya untuk pengujian: jeda antarpermintaan NVD (milidetik)
    #[arg(long, hide = true)]
    nvd_delay_ms: Option<u64>,
    /// Hanya untuk pengujian: jeda sebelum mengulang permintaan (milidetik)
    #[arg(long, hide = true, default_value_t = 2000)]
    retry_delay_ms: u64,
}

#[derive(clap::Args)]
struct StatusArgs {
    /// Direktori basis data (default: env SDRSCAN_VULN_DB)
    #[arg(long, value_name = "DIR")]
    db: Option<PathBuf>,
    /// Peringatkan bila data lebih tua dari sekian hari
    #[arg(long, default_value_t = 7, value_name = "HARI")]
    max_age_days: i64,
    /// Keluaran JSON (untuk mesin)
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct LookupArgs {
    #[arg(long, value_parser = parse_ecosystem)]
    ecosystem: Ecosystem,
    #[arg(long)]
    package: String,
    #[arg(long)]
    version: String,
    /// Direktori basis data (default: env SDRSCAN_VULN_DB)
    #[arg(long, value_name = "DIR")]
    db: Option<PathBuf>,
}

fn parse_ecosystem(s: &str) -> Result<Ecosystem, String> {
    s.parse()
}

fn init_logging(verbose: u8, quiet: u8) {
    let level = match (verbose as i8) - (quiet as i8) {
        i8::MIN..=-2 => Level::ERROR,
        -1 => Level::WARN,
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

fn db_dir(flag: &Option<PathBuf>) -> Result<PathBuf> {
    resolve_db_dir(flag.as_deref()).ok_or_else(|| {
        anyhow!("direktori basis data belum ditentukan: pakai --db <dir> atau env SDRSCAN_VULN_DB")
    })
}

fn cmd_update(a: UpdateArgs) -> Result<()> {
    let db = db_dir(&a.db)?;
    let ca_pem = match &a.ca_cert {
        Some(p) => {
            Some(std::fs::read(p).with_context(|| format!("membaca berkas CA {}", p.display()))?)
        }
        None => None,
    };
    let explicit = !a.ecosystems.is_empty();
    let ecosystems = if a.no_osv {
        Vec::new()
    } else if explicit {
        let mut e = a.ecosystems.clone();
        e.sort();
        e.dedup();
        e
    } else {
        Ecosystem::ALL.to_vec()
    };
    let opts = UpdateOptions {
        db: db.clone(),
        ecosystems,
        ecosystems_explicit: explicit,
        nvd: a.nvd,
        from_dir: a.from_dir.clone(),
        osv_base_url: a.osv_base_url,
        nvd_base_url: a.nvd_base_url,
        nvd_api_key: std::env::var("NVD_API_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty()),
        nvd_delay: a.nvd_delay_ms.map(Duration::from_millis),
        client: ClientOptions {
            timeout: Duration::from_secs(a.timeout),
            ca_pem,
            insecure_tls: a.insecure,
            allow_private_networks: a.allow_private_networks_for_tests,
            retries: 2,
            retry_delay: Duration::from_millis(a.retry_delay_ms),
        },
        limits: Limits {
            max_download_bytes: a.max_download_mb.saturating_mul(1024 * 1024),
            ..Limits::default()
        },
        force: a.force,
    };
    if a.insecure && a.from_dir.is_none() {
        eprintln!("peringatan: verifikasi sertifikat TLS dimatikan (--insecure); sumber data tidak terverifikasi");
    }
    let report = run_update(&opts)?;
    for e in &report.ecosystems {
        eprintln!(
            "{}: {} advisory ({} entri dibaca, {} dilewati)",
            e.ecosystem, e.advisories, e.stats.entries, e.stats.invalid
        );
    }
    if let Some(n) = report.nvd_entries {
        eprintln!(
            "NVD: {n} entri ({})",
            if report.nvd_incremental {
                "inkremental"
            } else {
                "penuh"
            }
        );
    }
    eprintln!(
        "Basis data diperbarui: {} ({} advisory)",
        db.display(),
        report.meta.advisory_count
    );
    Ok(())
}

fn cmd_status(a: StatusArgs) -> Result<()> {
    let dir = db_dir(&a.db)?;
    let db = VulnDb::open(&dir)?;
    let meta = db.meta();
    let now = now_epoch();
    let age = db.age_days(now);
    let stale = age.is_none_or(|d| d > a.max_age_days);
    if a.json {
        let osv: serde_json::Map<String, serde_json::Value> = meta
            .sources
            .osv
            .ecosystems
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    serde_json::json!({
                        "advisories": v.advisories,
                        "updated_at": v.updated_at,
                        "age_days": age_days(&v.updated_at, now),
                    }),
                )
            })
            .collect();
        let nvd = meta.sources.nvd.as_ref().map(|n| {
            serde_json::json!({
                "entries": n.entries,
                "updated_at": n.updated_at,
                "last_modified": n.last_modified,
                "age_days": age_days(&n.updated_at, now),
                "products": n.products,
            })
        });
        let doc = serde_json::json!({
            "path": dir.display().to_string(),
            "format_version": meta.format_version,
            "updated_at": meta.updated_at,
            "age_days": age,
            "stale": stale,
            "max_age_days": a.max_age_days,
            "advisory_count": meta.advisory_count,
            "osv": osv,
            "nvd": nvd,
        });
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }
    println!("Basis data: {}", dir.display());
    println!("Format: v{}", meta.format_version);
    match age {
        Some(d) => println!("Diperbarui: {} ({d} hari lalu)", meta.updated_at),
        None => println!("Diperbarui: {} (waktu tidak terbaca)", meta.updated_at),
    }
    println!("Jumlah advisory: {}", meta.advisory_count);
    for (name, e) in &meta.sources.osv.ecosystems {
        println!(
            "  OSV {name}: {} advisory (diperbarui {})",
            e.advisories, e.updated_at
        );
    }
    if let Some(n) = &meta.sources.nvd {
        println!(
            "  NVD: {} entri, {} produk (diperbarui {}, perubahan terakhir sampai {})",
            n.entries,
            n.products.len(),
            n.updated_at,
            n.last_modified
        );
    }
    if stale {
        println!(
            "PERINGATAN: data lebih tua dari {} hari; jalankan: sdrscan-vuln update",
            a.max_age_days
        );
    }
    Ok(())
}

fn cmd_lookup(a: LookupArgs) -> Result<()> {
    let dir = db_dir(&a.db)?;
    let db = VulnDb::open(&dir)?;
    if !db.has_ecosystem(a.ecosystem) {
        bail!(
            "basis data tidak memuat ekosistem {} (jalankan: sdrscan-vuln update --ecosystems {})",
            a.ecosystem,
            a.ecosystem
        );
    }
    let (merged, corrupt) = db.lookup(a.ecosystem, &a.package, &a.version)?;
    if corrupt > 0 {
        eprintln!("peringatan: {corrupt} baris rusak dilewati");
    }
    if merged.is_empty() {
        println!("{}@{}: tidak ada advisory yang cocok", a.package, a.version);
        return Ok(());
    }
    println!("{}@{}: {} advisory", a.package, a.version, merged.len());
    for m in merged {
        let score = m
            .cvss
            .as_ref()
            .map_or(String::new(), |c| format!(" CVSS {:.1}", c.score));
        println!(
            "- {} [{}{score}] {}",
            m.ids.join(", "),
            m.severity,
            m.summary
        );
        if m.fixed_versions.is_empty() {
            println!("    perbaikan: belum diketahui");
        } else {
            println!("    perbaikan: {}", m.fixed_versions.join(", "));
        }
        for r in &m.references {
            println!("    {r}");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose, cli.quiet);
    let result = match cli.command {
        Command::Update(a) => cmd_update(a),
        Command::Status(a) => cmd_status(a),
        Command::Lookup(a) => cmd_lookup(a),
    };
    match result {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            eprintln!("galat: {e:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}
