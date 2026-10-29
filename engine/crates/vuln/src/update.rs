//! Pembaruan basis data: unduh (atau baca `--from-dir`), bangun indeks di direktori sementara,
//! lalu pasang secara atomik. Basis data lama tidak disentuh bila ada kegagalan.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use sdrscan_vulndb::nvd as nvd_parse;
use sdrscan_vulndb::products::cpe_prefixes;
use sdrscan_vulndb::time::{format_nvd, format_rfc3339, now_epoch, parse_rfc3339};
use sdrscan_vulndb::{install_dir, DbWriter, Ecosystem, Meta, NvdEntry, VulnDb};
use tracing::{info, warn};
use url::Url;

use crate::http::{Client, ClientOptions};
use crate::ingest::{find_source, ingest, IngestStats, Limits, Source};

pub const DEFAULT_OSV_BASE: &str = "https://osv-vulnerabilities.storage.googleapis.com";
pub const DEFAULT_NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
/// NVD membatasi rentang `lastModStartDate`..`lastModEndDate` maksimum 120 hari; sisakan margin.
const NVD_MAX_INCREMENTAL_DAYS: i64 = 110;
const NVD_PAGE_SIZE: u64 = 2000;
/// Pembaruan yang menghasilkan kurang dari separuh advisory lama ditolak (indikasi unduhan terpotong).
const SHRINK_FACTOR: u64 = 2;

#[derive(Debug, Clone)]
pub struct UpdateOptions {
    pub db: PathBuf,
    pub ecosystems: Vec<Ecosystem>,
    /// `--ecosystems` tidak diberikan: pada `--from-dir` pakai semua ekosistem yang ada dumpnya.
    pub ecosystems_explicit: bool,
    pub nvd: bool,
    pub from_dir: Option<PathBuf>,
    pub osv_base_url: String,
    pub nvd_base_url: String,
    pub nvd_api_key: Option<String>,
    pub nvd_delay: Option<Duration>,
    pub client: ClientOptions,
    pub limits: Limits,
    pub force: bool,
}

#[derive(Debug)]
pub struct EcosystemReport {
    pub ecosystem: Ecosystem,
    pub advisories: u64,
    pub stats: IngestStats,
}

#[derive(Debug)]
pub struct UpdateReport {
    pub meta: Meta,
    pub ecosystems: Vec<EcosystemReport>,
    pub nvd_entries: Option<u64>,
    pub nvd_incremental: bool,
}

fn tmp_dir_for(db: &Path) -> PathBuf {
    let mut name = db
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "vulndb".into());
    name.push(format!(".tmp-{}", std::process::id()));
    db.with_file_name(name)
}

fn validate_base(raw: &str) -> Result<String> {
    let u = Url::parse(raw).with_context(|| format!("URL tidak valid: {raw}"))?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        bail!("URL harus http/https: {raw}");
    }
    Ok(raw.trim_end_matches('/').to_string())
}

fn osv_for(
    opts: &UpdateOptions,
    client: Option<&Client>,
    eco: Ecosystem,
    scratch: &Path,
) -> Result<(Vec<sdrscan_vulndb::Advisory>, IngestStats)> {
    let source = match &opts.from_dir {
        Some(dir) => find_source(dir, eco).ok_or_else(|| {
            anyhow!(
                "dump {eco} tidak ditemukan di {} (cari: {eco}/all.zip, {eco}.zip, atau direktori {eco}/)",
                dir.display()
            )
        })?,
        None => {
            let client = client.ok_or_else(|| anyhow!("klien HTTP tidak tersedia"))?;
            let url = format!("{}/{}/all.zip", validate_base(&opts.osv_base_url)?, eco);
            let dest = scratch.join(format!("{eco}.zip"));
            info!(ecosystem = %eco, %url, "mengunduh dump OSV");
            let bytes = client.download(&url, &dest, opts.limits.max_download_bytes)?;
            info!(ecosystem = %eco, bytes, "unduhan selesai");
            Source::Zip(dest)
        }
    };
    ingest(&source, eco, &opts.limits).with_context(|| format!("memproses dump {eco}"))
}

fn nvd_delay(opts: &UpdateOptions) -> Duration {
    opts.nvd_delay.unwrap_or(if opts.nvd_api_key.is_some() {
        // batas NVD dengan kunci: 50 permintaan per 30 detik
        Duration::from_millis(700)
    } else {
        // tanpa kunci: 5 permintaan per 30 detik
        Duration::from_millis(6500)
    })
}

fn nvd_fetch(
    opts: &UpdateOptions,
    client: &Client,
    window: Option<(i64, i64)>,
) -> Result<Vec<NvdEntry>> {
    let base = validate_base(&opts.nvd_base_url)?;
    let products = cpe_prefixes();
    let delay = nvd_delay(opts);
    let mut headers: Vec<(&str, &str)> = Vec::new();
    if let Some(k) = &opts.nvd_api_key {
        headers.push(("apiKey", k.as_str()));
    }
    let mut all: Vec<NvdEntry> = Vec::new();
    let mut first_request = true;
    for cpe in &products {
        let mut start_index = 0u64;
        loop {
            let mut url = Url::parse(&base)?;
            {
                let mut q = url.query_pairs_mut();
                q.append_pair("virtualMatchString", cpe);
                q.append_pair("resultsPerPage", &NVD_PAGE_SIZE.to_string());
                q.append_pair("startIndex", &start_index.to_string());
                if let Some((from, to)) = window {
                    q.append_pair("lastModStartDate", &format_nvd(from));
                    q.append_pair("lastModEndDate", &format_nvd(to));
                }
            }
            if !first_request {
                sleep(delay);
            }
            first_request = false;
            info!(product = cpe, start_index, "mengambil halaman NVD");
            let body = client.get_bytes(
                url.as_str(),
                &headers,
                &[403, 429],
                opts.limits.max_nvd_page_bytes,
            )?;
            let page = nvd_parse::parse_page(&body, &products)
                .map_err(|e| anyhow!("respons NVD untuk {cpe} tidak valid: {e}"))?;
            let got = page.cve_count as u64;
            all.extend(page.entries);
            start_index += got;
            if got == 0 || start_index >= page.total_results {
                break;
            }
        }
    }
    Ok(all)
}

fn nvd_from_dir(opts: &UpdateOptions, dir: &Path) -> Result<Vec<NvdEntry>> {
    let nvd_dir = dir.join("nvd");
    if !nvd_dir.is_dir() {
        bail!(
            "{} tidak ada; letakkan halaman respons NVD (*.json) di sana",
            nvd_dir.display()
        );
    }
    let products = cpe_prefixes();
    let mut files: Vec<PathBuf> = fs::read_dir(&nvd_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        })
        .collect();
    files.sort();
    if files.is_empty() {
        bail!("{} tidak berisi berkas .json", nvd_dir.display());
    }
    let mut out = Vec::new();
    for f in files {
        let meta = fs::metadata(&f)?;
        if meta.len() > opts.limits.max_nvd_page_bytes {
            bail!("{} terlalu besar", f.display());
        }
        let bytes = fs::read(&f)?;
        let page = nvd_parse::parse_page(&bytes, &products)
            .map_err(|e| anyhow!("{}: {e}", f.display()))?;
        out.extend(page.entries);
    }
    Ok(out)
}

pub fn run_update(opts: &UpdateOptions) -> Result<UpdateReport> {
    let existing = match VulnDb::open(&opts.db) {
        Ok(db) => Some(db),
        Err(sdrscan_vulndb::VulnDbError::NotFound(_)) => None,
        Err(e) => {
            warn!("basis data lama tidak dapat dibaca ({e}); dibangun ulang dari awal");
            None
        }
    };
    let tmp = tmp_dir_for(&opts.db);
    let _ = fs::remove_dir_all(&tmp);
    let result = build(opts, existing.as_ref(), &tmp);
    match result {
        Ok(report) => {
            install_dir(&tmp, &opts.db).map_err(|e| {
                let _ = fs::remove_dir_all(&tmp);
                anyhow!("{e}")
            })?;
            Ok(report)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

fn build(opts: &UpdateOptions, existing: Option<&VulnDb>, tmp: &Path) -> Result<UpdateReport> {
    let now_secs = now_epoch();
    let now = format_rfc3339(now_secs);
    let mut writer = DbWriter::new(tmp, existing, &now).map_err(|e| anyhow!("{e}"))?;
    let scratch = tmp.join("dl");
    fs::create_dir_all(&scratch)?;

    let client = if opts.from_dir.is_some() {
        None
    } else {
        Some(Client::new(opts.client.clone())?)
    };

    let mut ecosystems = opts.ecosystems.clone();
    if let (Some(dir), false) = (&opts.from_dir, opts.ecosystems_explicit) {
        ecosystems.retain(|e| find_source(dir, *e).is_some());
        if ecosystems.is_empty() && !opts.nvd {
            bail!("tidak ada dump OSV di {}", dir.display());
        }
    }
    if ecosystems.is_empty() && !opts.nvd {
        bail!("tidak ada ekosistem untuk diperbarui");
    }

    let mut reports = Vec::new();
    for eco in ecosystems {
        let (advisories, stats) = osv_for(opts, client.as_ref(), eco, &scratch)?;
        if advisories.is_empty() {
            bail!("dump {eco} tidak menghasilkan advisory satu pun (format tidak dikenali?)");
        }
        let old_count = existing
            .and_then(|d| d.meta().sources.osv.ecosystems.get(eco.as_str()))
            .map_or(0, |e| e.advisories);
        let count = writer
            .put_osv(eco, advisories, &now)
            .map_err(|e| anyhow!("{e}"))?;
        if !opts.force && old_count > 0 && count * SHRINK_FACTOR < old_count {
            bail!(
                "pembaruan {eco} hanya menghasilkan {count} advisory (sebelumnya {old_count}); ditolak karena mencurigakan (gunakan --force bila memang benar)"
            );
        }
        info!(ecosystem = %eco, advisories = count, "indeks ditulis");
        reports.push(EcosystemReport {
            ecosystem: eco,
            advisories: count,
            stats,
        });
    }

    let mut nvd_entries = None;
    let mut nvd_incremental = false;
    if opts.nvd {
        let products = cpe_prefixes();
        let (fresh, incremental) = match &opts.from_dir {
            Some(dir) => (nvd_from_dir(opts, dir)?, false),
            None => {
                let client = client
                    .as_ref()
                    .ok_or_else(|| anyhow!("klien HTTP tidak tersedia"))?;
                // Daftar produk berubah (mis. awalan CPE baru): unduh penuh agar entri lama produk itu ikut terisi.
                let mut wanted: Vec<&str> = products.clone();
                wanted.sort_unstable();
                let same_products = existing
                    .and_then(|d| d.meta().sources.nvd.as_ref())
                    .is_some_and(|n| {
                        let mut have: Vec<&str> = n.products.iter().map(String::as_str).collect();
                        have.sort_unstable();
                        have == wanted
                    });
                let since = existing
                    .and_then(|d| d.meta().sources.nvd.as_ref())
                    .filter(|_| same_products)
                    .and_then(|n| parse_rfc3339(&n.last_modified))
                    // margin 5 menit agar perubahan tepat di batas tidak terlewat
                    .map(|t| t - 300)
                    .filter(|t| now_secs - t < NVD_MAX_INCREMENTAL_DAYS * 86_400);
                let window = since.map(|t| (t, now_secs));
                (nvd_fetch(opts, client, window)?, since.is_some())
            }
        };
        nvd_incremental = incremental;
        let mut entries: Vec<NvdEntry> = if incremental {
            existing
                .map(|d| d.read_nvd_entries())
                .transpose()
                .map_err(|e| anyhow!("{e}"))?
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let fresh_count = fresh.len();
        let mut index: HashMap<(String, String), usize> = entries
            .iter()
            .enumerate()
            .map(|(i, e)| ((e.product.clone(), e.id.clone()), i))
            .collect();
        for e in fresh {
            match index.get(&(e.product.clone(), e.id.clone())) {
                Some(&i) => entries[i] = e,
                None => {
                    index.insert((e.product.clone(), e.id.clone()), entries.len());
                    entries.push(e);
                }
            }
        }
        if !incremental && fresh_count == 0 {
            bail!("NVD tidak menghasilkan entri satu pun untuk produk terkurasi");
        }
        let old_nvd = existing
            .and_then(|d| d.meta().sources.nvd.as_ref())
            .map_or(0, |n| n.entries);
        let count = writer
            .put_nvd(entries, &now, &products, &now)
            .map_err(|e| anyhow!("{e}"))?;
        if !opts.force && !incremental && old_nvd > 0 && count * SHRINK_FACTOR < old_nvd {
            bail!(
                "pembaruan NVD hanya menghasilkan {count} entri (sebelumnya {old_nvd}); ditolak karena mencurigakan (gunakan --force bila memang benar)"
            );
        }
        nvd_entries = Some(count);
    }

    let _ = fs::remove_dir_all(&scratch);
    let meta = writer.finish(&now).map_err(|e| anyhow!("{e}"))?;
    Ok(UpdateReport {
        meta,
        ecosystems: reports,
        nvd_entries,
        nvd_incremental,
    })
}
