//! Perbandingan versi: semver (npm, Go, crates.io), gaya Composer/Packagist, dan "longgar"
//! untuk banner produk (mis. `1.0.2k`, `7.4.0RC1`). Versi yang tidak dapat dibaca -> `None`.

use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Semver,
    Composer,
    Loose,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    Num(u64),
    Alpha(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tail {
    /// Peringkat stabilitas (dev 0, alpha 1, beta 2, RC 3, stabil 4, patch 5) dan nomornya.
    Stab(u8, u64),
    /// Pra-rilis semver (identifier bertitik); selalu lebih kecil daripada rilis.
    Idents(Vec<Ident>),
}

const STABLE: u8 = 4;
const WILDCARD: u64 = 9_999_999;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    nums: Vec<u64>,
    /// Akhiran huruf gaya OpenSSL (`k` = 11, `z` = 26, `za` = 27, `zd` = 30); 0 = tanpa.
    letter: u16,
    tail: Tail,
}

fn parse_digits(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Angka terlalu besar (mis. cap waktu) dipotong ke u64::MAX alih-alih gagal.
    Some(s.parse::<u64>().unwrap_or(u64::MAX))
}

fn parse_semver(raw: &str) -> Option<Version> {
    let s = raw.trim();
    let s = s.strip_prefix(['v', 'V', '=']).unwrap_or(s);
    let s = s.split('+').next().unwrap_or(s);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let nums: Vec<u64> = core
        .split('.')
        .map(parse_digits)
        .collect::<Option<Vec<_>>>()?;
    if nums.is_empty() {
        return None;
    }
    let tail = match pre {
        None => Tail::Stab(STABLE, 0),
        Some("") => return None,
        Some(p) => Tail::Idents(
            p.split('.')
                .map(|id| match parse_digits(id) {
                    Some(n) => Ident::Num(n),
                    None => Ident::Alpha(id.to_string()),
                })
                .collect(),
        ),
    };
    Some(Version {
        nums,
        letter: 0,
        tail,
    })
}

/// Sisa string berupa 1-3 huruf kecil yang bukan kata stabilitas: akhiran huruf OpenSSL (`k`, `zd`).
fn letter_word(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 3
        && r.bytes().all(|c| c.is_ascii_lowercase())
        && !matches!(r, "dev" | "rc" | "pl")
}

/// Nilai berurutan: tiap `z` di depan bernilai 26, huruf terakhir a=1..z=26 (`z` < `za` < `zb`).
fn letter_value(r: &str) -> u16 {
    let b = r.as_bytes();
    let (last, lead) = match b.split_last() {
        Some(x) => x,
        None => return 0,
    };
    lead.len() as u16 * 26 + u16::from(last - b'a' + 1)
}

/// Kata stabilitas -> peringkat. `p`/`pl`/`patch` = patch level.
fn stability(word: &str) -> Option<u8> {
    match word {
        "dev" => Some(0),
        "alpha" | "a" => Some(1),
        "beta" | "b" => Some(2),
        "rc" => Some(3),
        "stable" => Some(STABLE),
        "patch" | "pl" | "p" => Some(5),
        _ => None,
    }
}

/// Dasar Composer dan "longgar": angka bertitik, opsional huruf (hanya longgar), opsional stabilitas + nomor,
/// opsional akhiran `-dev`. `x`/`*` di akhir dianggap wildcard.
fn parse_dotted(raw: &str, allow_letter: bool) -> Option<Version> {
    let lower = raw.trim().to_ascii_lowercase();
    let mut s = lower.as_str();
    s = s.strip_prefix('v').unwrap_or(s);
    if s.starts_with("dev-") || s.is_empty() {
        return None;
    }
    let s = s.split('+').next().unwrap_or(s);
    let b = s.as_bytes();
    let mut i = 0;
    let mut nums = Vec::new();
    loop {
        let st = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i > st {
            nums.push(parse_digits(&s[st..i])?);
        } else if i < b.len() && (b[i] == b'x' || b[i] == b'*') && !nums.is_empty() {
            nums.push(WILDCARD);
            i += 1;
        } else {
            return None;
        }
        if i < b.len() && b[i] == b'.' && i + 1 < b.len() && !b[i + 1].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        if i < b.len() && b[i] == b'.' && i + 1 < b.len() && (b[i + 1] == b'x' || b[i + 1] == b'*')
        {
            i += 1;
            continue;
        }
        break;
    }
    let mut rest = &s[i..];
    let mut letter = 0u16;
    if allow_letter && letter_word(rest) {
        letter = letter_value(rest);
        rest = "";
    } else if allow_letter {
        let rb = rest.as_bytes();
        // Satu huruf langsung setelah angka dan bukan awal kata stabilitas ("1.0.2k", bukan "1.0.0rc1").
        if rb.len() == 1 && rb[0].is_ascii_lowercase()
            || rb.len() > 1 && rb[0].is_ascii_lowercase() && !rb[1].is_ascii_alphabetic()
        {
            let single_word = stability(&rest[..1]).is_some()
                && rb.len() > 1
                && rb[1..].iter().all(|c| c.is_ascii_digit());
            if !single_word {
                letter = letter_value(&rest[..1]);
                rest = &rest[1..];
            }
        }
    }
    let mut rank = STABLE;
    let mut num = 0u64;
    let mut trimmed = rest.trim_start_matches(['.', '-', '_']);
    if !trimmed.is_empty() {
        let word_end = trimmed
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(trimmed.len());
        let word = &trimmed[..word_end];
        match stability(word) {
            Some(r) if !word.is_empty() => {
                rank = r;
                trimmed = trimmed[word_end..].trim_start_matches(['.', '-', '_']);
                let digits_end = trimmed
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(trimmed.len());
                if digits_end > 0 {
                    num = parse_digits(&trimmed[..digits_end])?;
                    trimmed = trimmed[digits_end..].trim_start_matches(['.', '-', '_']);
                }
            }
            _ if word.is_empty() => return None,
            _ => {
                // kata asing ("-ubuntu1", "-fips") tidak dikenal: tidak dapat dibandingkan dengan aman
                return None;
            }
        }
        if trimmed == "dev" {
            rank = 0;
            num = 0;
        } else if !trimmed.is_empty() {
            return None;
        }
    }
    Some(Version {
        nums,
        letter,
        tail: Tail::Stab(rank, num),
    })
}

impl Version {
    /// Versi paling awal (`0`, `0.0.0`): di OSV, `introduced: 0` berarti "sejak awal" dan mencakup
    /// juga pra-rilis dan pseudo-versi (mis. `v0.0.0-2019...`) yang secara semver lebih kecil dari `0.0.0`.
    pub fn is_zero(&self) -> bool {
        self.nums.iter().all(|n| *n == 0) && self.letter == 0 && self.tail == Tail::Stab(STABLE, 0)
    }

    pub fn parse(scheme: Scheme, s: &str) -> Option<Version> {
        match scheme {
            Scheme::Semver => parse_semver(s),
            Scheme::Composer => parse_dotted(s, false),
            Scheme::Loose => parse_dotted(s, true),
        }
    }
}

fn cmp_idents(a: &[Ident], b: &[Ident]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let o = match (x, y) {
            (Ident::Num(p), Ident::Num(q)) => p.cmp(q),
            (Ident::Num(_), Ident::Alpha(_)) => Ordering::Less,
            (Ident::Alpha(_), Ident::Num(_)) => Ordering::Greater,
            (Ident::Alpha(p), Ident::Alpha(q)) => p.cmp(q),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.nums.len().max(other.nums.len());
        for i in 0..n {
            let a = self.nums.get(i).copied().unwrap_or(0);
            let b = other.nums.get(i).copied().unwrap_or(0);
            if a != b {
                return a.cmp(&b);
            }
        }
        if self.letter != other.letter {
            return self.letter.cmp(&other.letter);
        }
        match (&self.tail, &other.tail) {
            (Tail::Stab(r1, n1), Tail::Stab(r2, n2)) => (r1, n1).cmp(&(r2, n2)),
            (Tail::Idents(a), Tail::Idents(b)) => cmp_idents(a, b),
            (Tail::Idents(_), Tail::Stab(..)) => Ordering::Less,
            (Tail::Stab(..), Tail::Idents(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Bandingkan dua string versi menurut skema; `None` bila salah satunya tidak terbaca.
pub fn compare(scheme: Scheme, a: &str, b: &str) -> Option<Ordering> {
    Some(Version::parse(scheme, a)?.cmp(&Version::parse(scheme, b)?))
}

/// Urutan total deterministik untuk menampilkan versi; yang tak terbaca diurutkan setelahnya menurut teks.
pub fn sort_versions(scheme: Scheme, versions: &mut [String]) {
    versions.sort_by(
        |a, b| match (Version::parse(scheme, a), Version::parse(scheme, b)) {
            (Some(x), Some(y)) => x.cmp(&y).then_with(|| a.cmp(b)),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => a.cmp(b),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    fn cmp(s: Scheme, a: &str, b: &str) -> Option<Ordering> {
        compare(s, a, b)
    }

    #[test]
    fn semver_basics() {
        let s = Scheme::Semver;
        assert_eq!(cmp(s, "1.2.3", "1.2.3"), Some(Equal));
        assert_eq!(cmp(s, "1.2.3", "1.10.0"), Some(Less));
        assert_eq!(cmp(s, "2.0.0", "1.99.99"), Some(Greater));
        assert_eq!(cmp(s, "1.2", "1.2.0"), Some(Equal));
        assert_eq!(cmp(s, "1", "1.0.0"), Some(Equal));
        assert_eq!(cmp(s, "0", "0.0.1"), Some(Less));
    }

    #[test]
    fn semver_prerelease_and_build() {
        let s = Scheme::Semver;
        assert_eq!(cmp(s, "1.0.0-alpha", "1.0.0"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-alpha", "1.0.0-alpha.1"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-alpha.1", "1.0.0-alpha.beta"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-alpha.beta", "1.0.0-beta"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-beta.2", "1.0.0-beta.11"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-beta.11", "1.0.0-rc.1"), Some(Less));
        assert_eq!(cmp(s, "1.0.0+build5", "1.0.0+build9"), Some(Equal));
        assert_eq!(cmp(s, "1.0.0-rc.1+x", "1.0.0"), Some(Less));
    }

    #[test]
    fn semver_go_style() {
        let s = Scheme::Semver;
        assert_eq!(cmp(s, "v1.2.3", "1.2.3"), Some(Equal));
        assert_eq!(cmp(s, "v2.0.0+incompatible", "v2.0.0"), Some(Equal));
        assert_eq!(
            cmp(s, "v0.0.0-20190101000000-abcdef123456", "v0.0.1"),
            Some(Less)
        );
        assert_eq!(
            cmp(
                s,
                "v0.0.0-20190101000000-abcdef123456",
                "v0.0.0-20200101000000-fedcba654321"
            ),
            Some(Less)
        );
        assert_eq!(cmp(s, "v1.17.3", "1.17.4"), Some(Less));
    }

    #[test]
    fn semver_rejects_garbage() {
        let s = Scheme::Semver;
        assert_eq!(cmp(s, "latest", "1.0.0"), None);
        assert_eq!(cmp(s, "1.x", "1.0.0"), None);
        assert_eq!(cmp(s, "", "1.0.0"), None);
        assert_eq!(cmp(s, "github:foo/bar#abc", "1.0.0"), None);
        assert_eq!(cmp(s, "1.0.0-", "1.0.0"), None);
    }

    #[test]
    fn semver_huge_numbers_do_not_panic() {
        let s = Scheme::Semver;
        assert_eq!(
            cmp(s, "99999999999999999999999.0.0", "1.0.0"),
            Some(Greater)
        );
    }

    #[test]
    fn composer_basics() {
        let s = Scheme::Composer;
        assert_eq!(cmp(s, "v1.2.3", "1.2.3"), Some(Equal));
        assert_eq!(cmp(s, "1.2", "1.2.0.0"), Some(Equal));
        assert_eq!(cmp(s, "2.4.10", "2.4.9"), Some(Greater));
        assert_eq!(cmp(s, "10.0", "9.9.9.9"), Some(Greater));
    }

    #[test]
    fn composer_stabilities() {
        let s = Scheme::Composer;
        assert_eq!(cmp(s, "1.0.0-dev", "1.0.0-alpha1"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-alpha1", "1.0.0-alpha2"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-alpha2", "1.0.0-beta1"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-beta1", "1.0.0-RC1"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-RC1", "1.0.0-RC2"), Some(Less));
        assert_eq!(cmp(s, "1.0.0RC2", "1.0.0"), Some(Less));
        assert_eq!(cmp(s, "1.0.0", "1.0.0-patch1"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-p1", "1.0.0-pl2"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-a1", "1.0.0-alpha1"), Some(Equal));
        assert_eq!(cmp(s, "1.0.0-b.2", "1.0.0-beta2"), Some(Equal));
        assert_eq!(cmp(s, "1.0.0-rc1", "1.0.0-RC1"), Some(Equal));
        assert_eq!(cmp(s, "1.0.0-beta", "1.0.0-beta1"), Some(Less));
    }

    #[test]
    fn composer_dev_and_wildcards() {
        let s = Scheme::Composer;
        assert_eq!(cmp(s, "dev-master", "1.0.0"), None);
        assert_eq!(cmp(s, "dev-main", "dev-main"), None);
        assert_eq!(cmp(s, "1.0.x-dev", "1.0.0"), Some(Greater));
        assert_eq!(cmp(s, "1.0.x-dev", "1.0.99999"), Some(Greater));
        assert_eq!(cmp(s, "1.1.0-dev", "1.1.0"), Some(Less));
        assert_eq!(cmp(s, "1.x-dev", "2.0.0"), Some(Less));
        assert_eq!(cmp(s, "1.0.0-banana", "1.0.0"), None);
        assert_eq!(cmp(s, "", "1.0.0"), None);
    }

    #[test]
    fn composer_date_style_versions() {
        let s = Scheme::Composer;
        assert_eq!(cmp(s, "2019.10.1", "2019.9.12"), Some(Greater));
        assert_eq!(cmp(s, "20190101", "20180101"), Some(Greater));
    }

    #[test]
    fn loose_openssl_letters() {
        let s = Scheme::Loose;
        assert_eq!(cmp(s, "1.0.2", "1.0.2a"), Some(Less));
        assert_eq!(cmp(s, "1.0.2a", "1.0.2k"), Some(Less));
        assert_eq!(cmp(s, "1.0.2k", "1.0.2zi"), Some(Less));
        assert_eq!(cmp(s, "1.0.2z", "1.0.2za"), Some(Less));
        assert_eq!(cmp(s, "1.0.2za", "1.0.2zd"), Some(Less));
        assert_eq!(cmp(s, "1.0.2zd", "1.0.2zd"), Some(Equal));
        assert_eq!(cmp(s, "1.0.2zd", "1.1.0"), Some(Less));
        assert_eq!(cmp(s, "1.0.2", "1.0.2zd"), Some(Less));
        assert_eq!(cmp(s, "1.0.2k", "1.1.0"), Some(Less));
        assert_eq!(cmp(s, "1.1.1f", "1.1.1"), Some(Greater));
        assert_eq!(cmp(s, "3.0.0", "1.1.1w"), Some(Greater));
    }

    #[test]
    fn loose_product_versions() {
        let s = Scheme::Loose;
        assert_eq!(cmp(s, "7.4.3", "7.4.30"), Some(Less));
        assert_eq!(cmp(s, "2.4.41", "2.4.41"), Some(Equal));
        assert_eq!(cmp(s, "8.1.0RC1", "8.1.0"), Some(Less));
        assert_eq!(cmp(s, "10.0", "10.0.0"), Some(Equal));
        assert_eq!(cmp(s, "9.4.12", "9.4.2"), Some(Greater));
        assert_eq!(cmp(s, "7.0.0beta2", "7.0.0rc1"), Some(Less));
    }

    #[test]
    fn odd_inputs_never_panic() {
        let long = "9".repeat(10_000);
        let inputs = [
            "é",
            "1.0é",
            "1.é.2",
            "v",
            "vv1",
            "1..2",
            ".1",
            "1.",
            "-",
            "+",
            "1-+",
            "1.0.0-é",
            "\u{0}",
            "1.0.0+",
            "1e5",
            "0x10",
            "1.0.0-rc.é",
            "1,2",
            "٣.١",
            "1.0.0 ",
            " 1.0.0",
            "dev-",
            "1.x.x",
            "x",
            "*",
            "1.*",
            &long,
        ];
        for s in inputs {
            for scheme in [Scheme::Semver, Scheme::Composer, Scheme::Loose] {
                let _ = Version::parse(scheme, s);
                let _ = compare(scheme, s, "1.0.0");
            }
        }
        assert_eq!(cmp(Scheme::Composer, " 1.0.0 ", "1.0.0"), Some(Equal));
    }

    #[test]
    fn sorting_is_total_and_deterministic() {
        let mut v: Vec<String> = ["1.10.0", "1.2.0", "banana", "1.2.0-rc1", "apple"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        sort_versions(Scheme::Semver, &mut v);
        assert_eq!(v, ["1.2.0-rc1", "1.2.0", "1.10.0", "apple", "banana"]);
    }
}
