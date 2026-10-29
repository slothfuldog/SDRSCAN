//! Klien HTTP pembaruan: ureq dengan TLS sistem (atau `--ca-cert`) dan penjaga alamat privat yang sama
//! dengan DAST. Hanya mengunduh data; tidak ada yang dijalankan dari konten unduhan.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use sdrscan_dast::Options;

#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub timeout: Duration,
    pub ca_pem: Option<Vec<u8>>,
    pub insecure_tls: bool,
    pub allow_private_networks: bool,
    /// Percobaan ulang untuk galat transport, 5xx, dan status tambahan pemanggil.
    pub retries: u32,
    pub retry_delay: Duration,
}

pub struct Client {
    agent: ureq::Agent,
    opts: ClientOptions,
}

#[derive(Debug)]
pub enum HttpError {
    Status(u16),
    Transport(String),
    TooLarge(u64),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Status(s) => write!(f, "server membalas status HTTP {s}"),
            HttpError::Transport(m) => f.write_str(m),
            HttpError::TooLarge(n) => write!(f, "respons melebihi batas {n} byte"),
        }
    }
}

impl std::error::Error for HttpError {}

fn explain(msg: String) -> HttpError {
    let lower = msg.to_ascii_lowercase();
    if msg.contains("alamat jaringan privat tidak diizinkan") {
        HttpError::Transport(format!(
            "{msg}. Sumber pembaruan di jaringan privat ditolak; untuk instalasi tertutup unduh dump di mesin lain dan pakai --from-dir"
        ))
    } else if lower.contains("certificate") || lower.contains("unknownissuer") {
        HttpError::Transport(format!(
            "{msg}. Sertifikat HTTPS tidak dipercaya. Untuk proksi/CA internal pakai --ca-cert <berkas.pem> atau pasang CA di penyimpanan sertifikat sistem; --insecure melewati verifikasi (tidak aman)"
        ))
    } else {
        HttpError::Transport(msg)
    }
}

impl Client {
    pub fn new(opts: ClientOptions) -> Result<Client> {
        let dast_opts = Options {
            timeout: opts.timeout,
            user_agent: format!("sdrscan-vuln/{}", env!("CARGO_PKG_VERSION")),
            allow_private_networks: opts.allow_private_networks,
            ca_pem: opts.ca_pem.clone(),
            insecure_tls: opts.insecure_tls,
            // Pembaruan basis data hanya menghubungi sumber publik: jaringan privat tetap ditolak.
            block_private: true,
            ..Options::default()
        };
        let agent = sdrscan_dast::build_agent(&dast_opts, 5, true).map_err(|e| anyhow!("{e}"))?;
        Ok(Client { agent, opts })
    }

    /// GET dengan percobaan ulang; `retry_statuses` = status 4xx tambahan yang layak diulang (mis. 403/429 NVD).
    fn request(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        retry_statuses: &[u16],
    ) -> Result<ureq::http::Response<ureq::Body>, HttpError> {
        let mut attempt = 0u32;
        loop {
            let mut req = self.agent.get(url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let outcome = match req.call() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if (200..300).contains(&status) {
                        return Ok(resp);
                    }
                    let retry = status >= 500 || retry_statuses.contains(&status);
                    (HttpError::Status(status), retry)
                }
                Err(e) => {
                    let err = explain(e.to_string());
                    let retry = !e.to_string().contains("jaringan privat");
                    (err, retry)
                }
            };
            attempt += 1;
            if !outcome.1 || attempt > self.opts.retries {
                return Err(outcome.0);
            }
            tracing::warn!(url, attempt, error = %outcome.0, "permintaan gagal, mengulang");
            sleep(self.opts.retry_delay * attempt);
        }
    }

    /// Mengunduh ke berkas dengan batas ukuran; berkas parsial dihapus bila gagal.
    pub fn download(&self, url: &str, dest: &Path, max_bytes: u64) -> Result<u64> {
        let resp = self
            .request(url, &[], &[])
            .with_context(|| format!("mengunduh {url}"))?;
        let declared = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|n| n > max_bytes) {
            bail!(
                "{url}: ukuran {} byte melebihi batas {max_bytes} byte",
                declared.unwrap_or(0)
            );
        }
        let mut reader = resp.into_body().into_reader().take(max_bytes + 1);
        let result = (|| -> Result<u64> {
            let mut file =
                File::create(dest).with_context(|| format!("membuat {}", dest.display()))?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut total = 0u64;
            loop {
                let n = reader
                    .read(&mut buf)
                    .with_context(|| format!("membaca respons {url}"))?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > max_bytes {
                    bail!("{url}: unduhan melebihi batas {max_bytes} byte, dibatalkan");
                }
                file.write_all(&buf[..n])
                    .with_context(|| format!("menulis {}", dest.display()))?;
            }
            file.flush()?;
            if let Some(d) = declared {
                if d != total {
                    bail!("{url}: unduhan terpotong ({total} dari {d} byte)");
                }
            }
            Ok(total)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(dest);
        }
        result
    }

    /// GET kecil (halaman JSON) ke memori dengan batas ukuran.
    pub fn get_bytes(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        retry_statuses: &[u16],
        max_bytes: u64,
    ) -> Result<Vec<u8>> {
        let resp = self
            .request(url, headers, retry_statuses)
            .with_context(|| format!("GET {url}"))?;
        let mut out = Vec::new();
        resp.into_body()
            .into_reader()
            .take(max_bytes + 1)
            .read_to_end(&mut out)
            .with_context(|| format!("membaca respons {url}"))?;
        if out.len() as u64 > max_bytes {
            return Err(HttpError::TooLarge(max_bytes)).with_context(|| format!("GET {url}"));
        }
        Ok(out)
    }
}
