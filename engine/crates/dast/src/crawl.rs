//! Frontier crawl pasif: BFS satu origin, hanya GET, dengan batas kedalaman, jumlah halaman,
//! pengecualian jalur, ekstensi statis, dan variasi query per jalur.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use url::Url;

use crate::session::ExcludeSet;
use crate::urlutil;

/// Batas keras yang tidak dapat dilewati opsi pengguna.
pub const MAX_DEPTH_LIMIT: u32 = 10;
pub const MAX_PAGES_LIMIT: usize = 500;
/// Variasi query berbeda yang diikuti per jalur.
pub const MAX_QUERY_VARIANTS: usize = 3;

const STATIC_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "avif", "tif", "tiff", "css", "js",
    "mjs", "map", "woff", "woff2", "ttf", "otf", "eot", "zip", "gz", "tgz", "tar", "rar", "7z",
    "bz2", "xz", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "mp3", "mp4", "m4a", "avi",
    "mov", "wav", "webm", "ogg", "mkv", "flac", "exe", "dmg", "iso", "apk", "bin", "msi", "deb",
    "rpm", "jar",
];

pub fn is_static_asset(url: &Url) -> bool {
    let last = url.path().rsplit('/').next().unwrap_or("");
    last.rsplit_once('.')
        .is_some_and(|(_, ext)| STATIC_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

pub struct Frontier {
    queue: VecDeque<(Url, u32)>,
    seen: HashSet<String>,
    variants: HashMap<String, HashSet<String>>,
    max_depth: u32,
    /// URL (tanpa query) yang dilewati karena pengecualian.
    pub excluded: BTreeSet<String>,
    /// Ada tautan baru yang tidak diikuti karena batas kedalaman.
    pub depth_limited: bool,
    /// Jumlah tautan yang dilewati karena batas variasi query.
    pub variant_limited: usize,
}

impl Frontier {
    pub fn new(start: &Url, max_depth: u32) -> Frontier {
        let mut f = Frontier {
            queue: VecDeque::new(),
            seen: HashSet::new(),
            variants: HashMap::new(),
            max_depth: max_depth.min(MAX_DEPTH_LIMIT),
            excluded: BTreeSet::new(),
            depth_limited: false,
            variant_limited: 0,
        };
        let n = urlutil::normalize(start);
        f.seen.insert(n.to_string());
        f.variants
            .entry(path_key(&n))
            .or_default()
            .insert(n.query().unwrap_or("").to_string());
        f.queue.push_back((start.clone(), 0));
        f
    }

    pub fn pop(&mut self) -> Option<(Url, u32)> {
        self.queue.pop_front()
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Menawarkan tautan mentah dari halaman `base` pada kedalaman `depth`.
    pub fn offer(&mut self, target: &Url, base: &Url, raw: &str, depth: u32, ex: &ExcludeSet) {
        let Ok(joined) = base.join(raw) else { return };
        if !matches!(joined.scheme(), "http" | "https") || !urlutil::same_origin(target, &joined) {
            return;
        }
        let url = urlutil::normalize(&joined);
        if is_static_asset(&url) {
            return;
        }
        let key = url.to_string();
        if self.seen.contains(&key) {
            return;
        }
        if ex.is_excluded(&url) {
            self.seen.insert(key);
            self.excluded.insert(urlutil::no_query(&url));
            return;
        }
        if depth + 1 > self.max_depth {
            self.depth_limited = true;
            return;
        }
        let variants = self.variants.entry(path_key(&url)).or_default();
        let q = url.query().unwrap_or("").to_string();
        if !variants.contains(&q) && variants.len() >= MAX_QUERY_VARIANTS {
            self.variant_limited += 1;
            self.seen.insert(key);
            return;
        }
        variants.insert(q);
        self.seen.insert(key);
        self.queue.push_back((url, depth + 1));
    }
}

fn path_key(u: &Url) -> String {
    format!(
        "{}://{}:{}{}",
        u.scheme(),
        u.host_str().unwrap_or(""),
        u.port_or_known_default().unwrap_or(0),
        u.path()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn static_assets_are_detected_by_extension() {
        for p in [
            "/a.png",
            "/x/y.CSS",
            "/app.js",
            "/f.woff2",
            "/d.PDF",
            "/z.tar.gz",
        ] {
            assert!(is_static_asset(&u(&format!("http://h{p}"))), "{p}");
        }
        for p in ["/", "/page", "/a.html", "/dir.v2/page", "/api/x.json"] {
            assert!(!is_static_asset(&u(&format!("http://h{p}"))), "{p}");
        }
    }

    #[test]
    fn frontier_filters_and_limits() {
        let t = u("http://h/");
        let ex = ExcludeSet::new(&[]).unwrap();
        let mut f = Frontier::new(&t, 1);
        let base = u("http://h/");
        for raw in [
            "/a",
            "/a#frag",
            "/b?y=2&x=1",
            "/b?x=1&y=2",
            "http://other/c",
            "mailto:x@y",
            "javascript:void(0)",
            "/logo.png",
            "/logout",
            "/delete?id=1",
            "https://h/secure",
        ] {
            f.offer(&t, &base, raw, 0, &ex);
        }
        assert_eq!(f.pending(), 2 + 1, "start + /a + /b");
        assert_eq!(f.excluded.len(), 2);
        // depth 1 page: nothing further is followed
        let (page, d) = (u("http://h/a"), 1);
        f.offer(&t, &page, "/deeper", d, &ex);
        assert!(f.depth_limited);
        assert_eq!(f.pending(), 3);
    }

    #[test]
    fn query_variants_are_capped_per_path() {
        let t = u("http://h/");
        let ex = ExcludeSet::new(&[]).unwrap();
        let mut f = Frontier::new(&t, 3);
        for i in 0..10 {
            f.offer(&t, &t, &format!("/list?page={i}"), 0, &ex);
        }
        assert_eq!(f.pending(), 1 + MAX_QUERY_VARIANTS);
        assert_eq!(f.variant_limited, 10 - MAX_QUERY_VARIANTS);
    }
}
