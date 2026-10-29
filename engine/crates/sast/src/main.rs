use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use sdrscan_core::report::{self, EXIT_USAGE};
use sdrscan_core::{load_templates, sarif, Profile, Severity};
use tracing::Level;

const TOOL_NAME: &str = "sdrscan-sast";

#[derive(Parser)]
#[command(
    name = "sdrscan-sast",
    version,
    about = "Pemindai keamanan statis (SAST) untuk PHP"
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
    /// Memindai file atau direktori PHP
    Scan(ScanArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Sarif,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// File atau direktori yang dipindai
    path: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Tulis hasil ke berkas (default: stdout)
    #[arg(long)]
    output: Option<PathBuf>,
    /// Ambang severity yang menggagalkan build (default: high, atau nilai dari profil)
    #[arg(long, value_parser = parse_severity)]
    fail_on: Option<Severity>,
    /// Profil bawaan (nama) atau path berkas YAML
    #[arg(long)]
    profile: Option<String>,
    /// Direktori template (default: templates/ di samping binary)
    #[arg(long)]
    templates: Option<PathBuf>,
    /// Direktori basis data kerentanan lokal untuk SCA (default: env SDRSCAN_VULN_DB); dibuat dengan
    /// `sdrscan-vuln update`. Tanpa basis data, SCA dilewati dengan peringatan
    #[arg(long, value_name = "DIR")]
    vuln_db: Option<PathBuf>,
    /// Matikan SCA (pencocokan lockfile dengan basis data kerentanan)
    #[arg(long)]
    no_sca: bool,
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    s.parse::<Severity>().map_err(|e| e.to_string())
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_default()
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

/// Mengembalikan kode keluar: 0 bersih, 1 ada temuan di atas ambang. Galat -> Err (kode 2).
fn run_scan(args: ScanArgs, quiet: u8) -> Result<i32> {
    let templates_dir = args
        .templates
        .clone()
        .unwrap_or_else(|| exe_dir().join("templates"));
    let mut templates = load_templates(&templates_dir)
        .with_context(|| format!("memuat template dari {}", templates_dir.display()))?;

    let mut profile_fail_on = None;
    let mut profile_used: Option<Profile> = None;
    if let Some(spec) = &args.profile {
        let profile = Profile::load(spec, &exe_dir().join("profiles"))?;
        profile_fail_on = profile.fail_on;
        templates = profile.clone().select(templates);
        profile_used = Some(profile);
    }
    let fail_on = args.fail_on.or(profile_fail_on).unwrap_or(Severity::High);

    let mut output = sdrscan_sast::scan(&args.path, &templates)?;

    let sca_enabled = !args.no_sca
        && profile_used
            .as_ref()
            .is_none_or(Profile::includes_vulnerability_checks);
    if sca_enabled {
        let mut sca = sdrscan_sast::sca::run(&args.path, args.vuln_db.as_deref());
        if let Some(p) = &profile_used {
            sca.findings.retain(|f| p.keeps_severity(f.severity));
        }
        output.files_scanned += sca.files_scanned;
        output.findings.extend(sca.findings);
        output.warnings.extend(sca.warnings);
        output
            .findings
            .sort_by(|a, b| (&a.location, &a.rule_id).cmp(&(&b.location, &b.rule_id)));
    }

    let rendered = match args.format {
        Format::Text => report::format_text(&output),
        Format::Sarif => {
            let doc = sarif::to_sarif(&output, &templates, TOOL_NAME, env!("CARGO_PKG_VERSION"));
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
        eprintln!("{}", report::summary(&output));
    }
    Ok(report::exit_code(&output, fail_on))
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
