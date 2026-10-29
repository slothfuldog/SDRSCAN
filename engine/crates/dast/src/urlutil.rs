//! Utilitas URL untuk DAST: origin, penyamaran parameter rahasia, dan normalisasi untuk crawl.

use url::Url;

pub fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Nama parameter query yang biasanya memuat rahasia (token, kunci, kata sandi, sesi).
pub fn is_sensitive_param(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if matches!(
        n.as_str(),
        "key" | "sid" | "jwt" | "pwd" | "auth" | "authorization" | "passwd" | "sessid" | "sess"
    ) {
        return true;
    }
    [
        "token",
        "password",
        "passwd",
        "secret",
        "session",
        "sessionid",
        "apikey",
        "_key",
        "-key",
    ]
    .iter()
    .any(|s| n.ends_with(s))
}

/// Nama parameter sensitif pada query URL, urut dan unik.
pub fn sensitive_params(url: &Url) -> Vec<String> {
    let mut names: Vec<String> = url
        .query_pairs()
        .map(|(k, _)| k.into_owned())
        .filter(|k| is_sensitive_param(k))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// URL yang aman ditampilkan (lokasi temuan, peringatan, log): tanpa userinfo, tanpa fragmen, dan nilai
/// parameter sensitif diganti `***`.
pub fn redact_url(url: &Url) -> String {
    let mut u = url.clone();
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_fragment(None);
    if sensitive_params(&u).is_empty() {
        return u.to_string();
    }
    let pairs: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| {
            let v = if is_sensitive_param(&k) {
                "***".to_string()
            } else {
                v.into_owned()
            };
            (k.into_owned(), v)
        })
        .collect();
    u.query_pairs_mut().clear().extend_pairs(pairs);
    u.to_string()
}

/// `skema://host[:port]/path` tanpa query, fragmen, dan userinfo.
pub fn no_query(url: &Url) -> String {
    let mut u = url.clone();
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

/// Normalisasi untuk deteksi duplikat: tanpa fragmen/userinfo, parameter query diurutkan, query kosong dibuang.
pub fn normalize(url: &Url) -> Url {
    let mut u = url.clone();
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_fragment(None);
    if u.query().is_some() {
        let mut pairs: Vec<(String, String)> = u
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if pairs.is_empty() {
            u.set_query(None);
        } else {
            pairs.sort();
            u.query_pairs_mut().clear().extend_pairs(pairs);
        }
    }
    u
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn sensitive_names() {
        for n in [
            "token",
            "csrf_token",
            "access_token",
            "api_key",
            "apikey",
            "password",
            "new-password",
            "secret",
            "client_secret",
            "session",
            "PHPSESSION",
            "key",
            "sid",
        ] {
            assert!(is_sensitive_param(n), "{n}");
        }
        for n in ["keyword", "page", "id", "monkey", "q", "sort"] {
            assert!(!is_sensitive_param(n), "{n}");
        }
    }

    #[test]
    fn redaction_hides_values_but_keeps_other_params() {
        let r = redact_url(&u("http://u:p@h/p?a=1&token=SECRETVAL&b=2#frag"));
        assert!(!r.contains("SECRETVAL") && !r.contains("u:p") && !r.contains("frag"));
        assert!(r.contains("a=1") && r.contains("b=2") && r.contains("token=***"));
        assert_eq!(redact_url(&u("http://h/p?a=1")), "http://h/p?a=1");
    }

    #[test]
    fn normalization_sorts_query_and_drops_fragment() {
        assert_eq!(
            normalize(&u("http://h/p?b=2&a=1#x")).as_str(),
            normalize(&u("http://h/p?a=1&b=2")).as_str()
        );
        assert_eq!(normalize(&u("http://h/p?")).as_str(), "http://h/p");
    }

    #[test]
    fn origin_comparison() {
        assert!(same_origin(&u("http://h/a"), &u("http://h:80/b")));
        assert!(!same_origin(&u("http://h/a"), &u("https://h/a")));
        assert!(!same_origin(&u("http://h:1/a"), &u("http://h:2/a")));
    }
}
