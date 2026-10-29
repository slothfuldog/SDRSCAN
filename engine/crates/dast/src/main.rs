use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use sdrscan_core::report::{self, EXIT_USAGE};
use sdrscan_core::{sarif, Severity};
use sdrscan_dast::active::{ActiveOptions, MAX_PARAMS_LIMIT, MAX_REQUESTS_LIMIT, MAX_TIMEOUT_SECS};
use sdrscan_dast::auth::AuthConfig;
use sdrscan_dast::crawl::{MAX_DEPTH_LIMIT, MAX_PAGES_LIMIT};
use sdrscan_dast::{active, checks, parse_target, Options};
use tracing::Level;

const TOOL_NAME: &str = "sdrscan-dast";

#[derive(Parser)]
#[command(
    name = "sdrscan-dast",
    version,
    about = "Pemindai keamanan dinamis (DAST) untuk aplikasi web: pemeriksaan pasif, login terautentikasi, dan crawl pasif terbatas"
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
    /// Memindai satu URL target (hanya pemeriksaan pasif; tidak mengirim payload). Opsional: login dan crawl pasif
    Scan(ScanArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Sarif,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// URL target (http atau https)
    url: String,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Tulis hasil ke berkas (default: stdout)
    #[arg(long)]
    output: Option<PathBuf>,
    /// Ambang severity yang menggagalkan build
    #[arg(long, default_value = "high", value_parser = parse_severity)]
    fail_on: Severity,
    /// Batas waktu permintaan (detik)
    #[arg(long, default_value_t = 15)]
    timeout: u64,
    /// Berkas PEM berisi CA yang dipercaya untuk HTTPS (mis. CA internal). Bila diisi, hanya CA ini
    /// yang dipercaya; bila tidak, dipakai penyimpanan sertifikat sistem
    #[arg(long, value_name = "FILE")]
    ca_cert: Option<PathBuf>,
    /// Jangan verifikasi sertifikat HTTPS target (TIDAK AMAN; hanya untuk percobaan)
    #[arg(long)]
    insecure: bool,
    /// Direktori basis data kerentanan lokal untuk CVE dari versi di header Server/X-Powered-By
    /// (default: env SDRSCAN_VULN_DB); dibuat dengan `sdrscan-vuln update --nvd`. Tanpa basis data dilewati
    #[arg(long, value_name = "DIR")]
    vuln_db: Option<PathBuf>,
    /// Tolak target di jaringan privat (loopback, RFC1918, CGNAT, ULA, link-local). Default: jaringan
    /// privat diizinkan; endpoint metadata cloud (169.254.169.0/24, 169.254.170.0/24, 100.100.100.200,
    /// fd00:ec2::/32) selalu ditolak
    #[arg(long)]
    block_private_networks: bool,
    /// Tidak berpengaruh (jaringan privat sudah diizinkan secara default); dipertahankan agar skrip lama tetap jalan
    #[arg(long, hide = true)]
    allow_private_networks: bool,
    /// Hanya untuk pengujian: izinkan loopback dan jaringan privat (default: ditolak)
    #[arg(long, hide = true)]
    allow_private_networks_for_tests: bool,
    /// Berkas JSON autentikasi (login formulir, header, atau cookie tetap). Kredensial hanya lewat
    /// berkas ini (izin 0600), tidak pernah lewat argumen atau env; isinya tidak pernah dicetak
    #[arg(long, value_name = "PATH")]
    auth_file: Option<PathBuf>,
    /// Crawl pasif dari URL target: hanya GET, satu origin, tautan <a href> dan formulir GET
    #[arg(long)]
    crawl: bool,
    /// Kedalaman crawl maksimum (0 = hanya URL target)
    #[arg(long, default_value_t = 3, value_name = "N", value_parser = clap::value_parser!(u32).range(0..=MAX_DEPTH_LIMIT as i64))]
    max_depth: u32,
    /// Jumlah halaman maksimum yang diambil
    #[arg(long, default_value_t = 50, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=MAX_PAGES_LIMIT as i64))]
    max_pages: u32,
    /// Permintaan per detik (berlaku untuk semua permintaan, termasuk login)
    #[arg(long, default_value_t = 5, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=100))]
    max_rps: u32,
    /// Regex jalur (tidak peka huruf besar-kecil) yang tidak boleh diambil, ditambah pengecualian bawaan
    /// (logout, delete, remove, reset, ...). Dapat diulang
    #[arg(long, value_name = "REGEX")]
    exclude_path: Vec<String>,
    /// Hanya login lalu keluar: kode 0 bila berhasil, 2 bila gagal; tidak crawl dan tidak membuat temuan
    #[arg(long, requires = "auth_file")]
    login_check: bool,
    /// AKTIFKAN pemeriksaan aktif (BERISIKO, mati secara default): mengirim payload uji (SQL injection,
    /// XSS reflected, open redirect, CRLF/header injection) ke parameter GET, formulir GET/POST hasil
    /// crawl, dan endpoint API (OpenAPI/Swagger, bukan DELETE) yang ditemukan. Hanya pada target yang
    /// Anda miliki/berwenang; dapat memicu efek samping pada aplikasi yang menulis data lewat GET/POST
    #[arg(long)]
    active: bool,
    /// Opt-in ganda: time-based blind SQLi (payload SLEEP/pg_sleep); hanya berlaku bersama --active,
    /// dibatasi maksimum 3 parameter diuji time-based per pemindaian (membebani server bila disalahgunakan)
    #[arg(long, requires = "active")]
    active_timing: bool,
    /// Jumlah parameter maksimum yang diuji pemeriksaan aktif (gabungan GET/POST/API)
    #[arg(long, default_value_t = 30, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=MAX_PARAMS_LIMIT as i64))]
    active_max_params: u32,
    /// Jumlah permintaan pemeriksaan aktif maksimum (total, gabungan semua parameter)
    #[arg(long, default_value_t = 300, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=MAX_REQUESTS_LIMIT as i64))]
    active_max_requests: u32,
    /// Batas waktu total pemeriksaan aktif (detik)
    #[arg(long, default_value_t = 600, value_name = "DETIK", value_parser = clap::value_parser!(u32).range(1..=MAX_TIMEOUT_SECS as i64))]
    active_timeout: u32,
    /// Lokasi eksplisit spesifikasi OpenAPI/Swagger (berkas lokal atau URL satu origin dengan target,
    /// JSON saja) untuk pemeriksaan aktif; tanpa ini, jalur umum (/openapi.json, /v3/api-docs, dst.) dicoba otomatis
    #[arg(long, value_name = "PATH-atau-URL")]
    openapi_spec: Option<String>,
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    s.parse::<Severity>().map_err(|e| e.to_string())
}

/// Log hanya dari tracing milik DAST (tanpa jembatan `log`): log pustaka HTTP/TLS di level TRACE dapat
/// memuat URL redirect, sehingga sengaja tidak diteruskan. Kode DAST sendiri tidak pernah mencatat
/// header, cookie, badan permintaan, atau query URL.
fn init_logging(verbose: u8, quiet: u8) {
    let level = match (verbose as i8) - (quiet as i8) {
        i8::MIN..=-2 => Level::ERROR,
        -1 => Level::WARN,
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

fn run_scan(args: ScanArgs, quiet: u8) -> Result<i32> {
    let target = parse_target(&args.url)?;
    let ca_pem = match &args.ca_cert {
        Some(path) => Some(
            std::fs::read(path).with_context(|| format!("membaca berkas CA {}", path.display()))?,
        ),
        None => None,
    };
    let auth = match &args.auth_file {
        Some(path) => Some(AuthConfig::from_file(path)?),
        None => None,
    };
    let opts = Options {
        ca_pem,
        insecure_tls: args.insecure,
        timeout: Duration::from_secs(args.timeout),
        allow_private_networks: args.allow_private_networks_for_tests,
        block_private: args.block_private_networks,
        vuln_db: args.vuln_db.clone(),
        crawl: args.crawl,
        max_depth: args.max_depth,
        max_pages: args.max_pages as usize,
        max_rps: args.max_rps,
        exclude_paths: args.exclude_path.clone(),
        auth,
        active: ActiveOptions {
            enabled: args.active,
            timing: args.active_timing,
            max_params: args.active_max_params as usize,
            max_requests: args.active_max_requests as usize,
            timeout: Duration::from_secs(args.active_timeout as u64),
        },
        openapi_spec: args.openapi_spec.clone(),
        ..Options::default()
    };
    if args.login_check {
        let summary = sdrscan_dast::login_check(&target, &opts)?;
        for w in opts.auth.iter().flat_map(|a| &a.load_warnings) {
            eprintln!("peringatan: {}", w.message);
        }
        match &summary.token {
            Some(t) if summary.cookies_received == 0 => println!(
                "login berhasil: token diterima ({t}), halaman awal {}",
                summary.landing
            ),
            Some(t) => println!(
                "login berhasil: token diterima ({t}), {} cookie diterima, halaman awal {}",
                summary.cookies_received, summary.landing
            ),
            None => println!(
                "login berhasil: {} cookie diterima, halaman awal {}",
                summary.cookies_received, summary.landing
            ),
        }
        return Ok(report::EXIT_OK);
    }
    let (output, active_requests_sent) = sdrscan_dast::scan(&target, &opts)?;

    let rendered = match args.format {
        Format::Text => report::format_text(&output),
        Format::Sarif => {
            let mut rules = checks::builtin_rules();
            rules.extend(active::builtin_rules());
            let doc = sarif::to_sarif(&output, &rules, TOOL_NAME, env!("CARGO_PKG_VERSION"));
            let mut s = serde_json::to_string_pretty(&doc)?;
            s.push('\n');
            s
        }
    };
    match &args.output {
        Some(path) => std::fs::write(path, rendered)
            .with_context(|| format!("menulis keluaran ke {}", path.display()))?,
        None => print!("{rendered}"),
    }
    eprint!("{}", report::format_warnings(&output));
    if quiet < 2 {
        eprintln!(
            "Ringkasan: {} halaman dipindai, {} temuan, {} peringatan",
            output.files_scanned,
            output.findings.len(),
            output.warnings.len()
        );
        if opts.active.enabled {
            let active_findings = output
                .findings
                .iter()
                .filter(|f| f.rule_id.starts_with("dast-active-"))
                .count();
            eprintln!(
                "{active_requests_sent} permintaan aktif dikirim, {active_findings} temuan aktif"
            );
        }
    }
    Ok(report::exit_code(&output, args.fail_on))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose, cli.quiet);
    let result = match cli.command {
        Command::Scan(args) => run_scan(args, cli.quiet),
    };
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("galat: {e:#}");
            ExitCode::from(EXIT_USAGE as u8)
        }
    }
}
