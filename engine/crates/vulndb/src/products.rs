//! Daftar produk web terkurasi untuk pemeriksaan versi dari banner (DAST) dan pembaruan NVD.

/// Satu produk terkurasi. `cpe` adalah awalan CPE 2.3 (`cpe:2.3:a:<vendor>:<produk>`) yang menjadi kunci
/// di `nvd/products.jsonl`. `aliases` adalah nama (huruf kecil) yang dikenali di banner HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Product {
    pub key: &'static str,
    pub display: &'static str,
    pub cpe: &'static str,
    /// Awalan CPE lain yang dipakai NVD untuk produk yang sama (mis. nginx sejak 2021 tercatat di bawah `f5:nginx`);
    /// entri dari sini dinormalkan ke `cpe` saat diindeks.
    pub alt_cpes: &'static [&'static str],
    pub aliases: &'static [&'static str],
}

pub const PRODUCTS: &[Product] = &[
    Product {
        key: "apache-httpd",
        display: "Apache httpd",
        cpe: "cpe:2.3:a:apache:http_server",
        alt_cpes: &[],
        aliases: &["apache", "apache-httpd"],
    },
    Product {
        key: "nginx",
        display: "nginx",
        cpe: "cpe:2.3:a:nginx:nginx",
        alt_cpes: &["cpe:2.3:a:f5:nginx"],
        aliases: &["nginx"],
    },
    Product {
        key: "iis",
        display: "Microsoft IIS",
        cpe: "cpe:2.3:a:microsoft:internet_information_services",
        alt_cpes: &[],
        aliases: &["microsoft-iis", "iis"],
    },
    Product {
        key: "php",
        display: "PHP",
        cpe: "cpe:2.3:a:php:php",
        alt_cpes: &[],
        aliases: &["php"],
    },
    Product {
        key: "openssl",
        display: "OpenSSL",
        cpe: "cpe:2.3:a:openssl:openssl",
        alt_cpes: &[],
        aliases: &["openssl"],
    },
    Product {
        key: "tomcat",
        display: "Apache Tomcat",
        cpe: "cpe:2.3:a:apache:tomcat",
        alt_cpes: &[],
        aliases: &["tomcat"],
    },
    Product {
        key: "jetty",
        display: "Eclipse Jetty",
        cpe: "cpe:2.3:a:eclipse:jetty",
        alt_cpes: &[],
        aliases: &["jetty"],
    },
    Product {
        key: "nodejs",
        display: "Node.js",
        cpe: "cpe:2.3:a:nodejs:node.js",
        alt_cpes: &[],
        aliases: &["node.js", "nodejs"],
    },
    Product {
        key: "express",
        display: "Express",
        cpe: "cpe:2.3:a:expressjs:express",
        alt_cpes: &["cpe:2.3:a:openjsf:express"],
        aliases: &["express"],
    },
    Product {
        key: "lighttpd",
        display: "lighttpd",
        cpe: "cpe:2.3:a:lighttpd:lighttpd",
        alt_cpes: &[],
        aliases: &["lighttpd"],
    },
    Product {
        key: "aspnet",
        display: "ASP.NET",
        cpe: "cpe:2.3:a:microsoft:asp.net",
        alt_cpes: &[],
        aliases: &["asp.net", "aspnet"],
    },
];

pub fn by_alias(name: &str) -> Option<&'static Product> {
    let lower = name.to_ascii_lowercase();
    PRODUCTS
        .iter()
        .find(|p| p.aliases.iter().any(|a| *a == lower))
}

/// Produk menurut awalan CPE utama atau alternatifnya.
pub fn by_cpe(cpe: &str) -> Option<&'static Product> {
    PRODUCTS
        .iter()
        .find(|p| p.cpe == cpe || p.alt_cpes.contains(&cpe))
}

/// Semua awalan CPE yang diambil dari NVD dan disaring saat diindeks (utama dan alternatif).
pub fn cpe_prefixes() -> Vec<&'static str> {
    PRODUCTS
        .iter()
        .flat_map(|p| std::iter::once(p.cpe).chain(p.alt_cpes.iter().copied()))
        .collect()
}

/// Awalan CPE utama (kunci di `nvd/products.jsonl`) untuk awalan apa pun; tak dikenal -> apa adanya.
pub fn canonical_cpe(cpe: &str) -> &str {
    by_cpe(cpe).map_or(cpe, |p| p.cpe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_cpes_are_unique_and_well_formed() {
        for (i, a) in PRODUCTS.iter().enumerate() {
            assert_eq!(a.cpe.split(':').count(), 5, "{}", a.cpe);
            assert!(a.cpe.starts_with("cpe:2.3:a:"));
            for alt in a.alt_cpes {
                assert_eq!(alt.split(':').count(), 5, "{alt}");
            }
            for b in &PRODUCTS[i + 1..] {
                assert_ne!(a.key, b.key);
                assert_ne!(a.cpe, b.cpe);
                assert!(!b.alt_cpes.contains(&a.cpe) && !a.alt_cpes.contains(&b.cpe));
                assert!(!a.aliases.iter().any(|x| b.aliases.contains(x)));
            }
        }
    }

    #[test]
    fn alternative_cpes_map_to_the_primary_one() {
        assert_eq!(canonical_cpe("cpe:2.3:a:f5:nginx"), "cpe:2.3:a:nginx:nginx");
        assert_eq!(canonical_cpe("cpe:2.3:a:php:php"), "cpe:2.3:a:php:php");
        assert_eq!(canonical_cpe("cpe:2.3:a:x:y"), "cpe:2.3:a:x:y");
        let all = cpe_prefixes();
        assert!(all.contains(&"cpe:2.3:a:f5:nginx") && all.contains(&"cpe:2.3:a:nginx:nginx"));
    }

    #[test]
    fn alias_lookup_is_case_insensitive() {
        assert_eq!(by_alias("Microsoft-IIS").unwrap().key, "iis");
        assert_eq!(by_alias("Apache").unwrap().key, "apache-httpd");
        assert!(by_alias("apache-coyote").is_none());
    }
}
