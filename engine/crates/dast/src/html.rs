//! Pemindai HTML ringan (tanpa dependensi) untuk crawl pasif dan pemeriksaan formulir.
//! Hanya mengenali tag dan atributnya; isi `<script>`, `<style>`, komentar, dan teks diabaikan.

const MAX_TAGS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    /// Nama tag huruf kecil.
    pub name: String,
    /// Pasangan (nama huruf kecil, nilai dengan entitas sudah didekode).
    pub attrs: Vec<(String, String)>,
    pub closing: bool,
}

impl Tag {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let decoded = rest.find(';').filter(|&e| e <= 10).and_then(|e| {
            let ent = &rest[1..e];
            let ch = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => ent.strip_prefix('#').and_then(|n| {
                    let code = match n.strip_prefix(['x', 'X']) {
                        Some(h) => u32::from_str_radix(h, 16).ok(),
                        None => n.parse::<u32>().ok(),
                    };
                    code.and_then(char::from_u32)
                }),
            };
            ch.map(|c| (c, e + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Semua tag pembuka dan penutup dalam urutan dokumen (maksimum 100.000).
pub fn parse_tags(html: &str) -> Vec<Tag> {
    let b = html.as_bytes();
    let lower = html.to_ascii_lowercase();
    let mut tags = Vec::new();
    let mut i = 0;
    while i < b.len() && tags.len() < MAX_TAGS {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if lower[i..].starts_with("<!--") {
            i = lower[i + 4..]
                .find("-->")
                .map_or(b.len(), |p| i + 4 + p + 3);
            continue;
        }
        let closing = b.get(i + 1) == Some(&b'/');
        let ns = i + 1 + usize::from(closing);
        if !b.get(ns).is_some_and(|c| c.is_ascii_alphabetic()) {
            i += 1;
            continue;
        }
        let mut j = ns;
        while j < b.len() && !(b[j].is_ascii_whitespace() || b[j] == b'>' || b[j] == b'/') {
            j += 1;
        }
        let name = lower[ns..j].to_string();
        let mut attrs: Vec<(String, String)> = Vec::new();
        loop {
            while j < b.len() && (b[j].is_ascii_whitespace() || b[j] == b'/') {
                j += 1;
            }
            if j >= b.len() {
                break;
            }
            if b[j] == b'>' {
                j += 1;
                break;
            }
            let an = j;
            while j < b.len()
                && !(b[j].is_ascii_whitespace() || b[j] == b'=' || b[j] == b'>' || b[j] == b'/')
            {
                j += 1;
            }
            if j == an {
                j += 1;
                continue;
            }
            let attr_name = lower[an..j].to_string();
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            let mut value = String::new();
            if b.get(j) == Some(&b'=') {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                match b.get(j) {
                    Some(&q) if q == b'"' || q == b'\'' => {
                        let vs = j + 1;
                        let ve = html[vs..].find(q as char).map_or(b.len(), |p| vs + p);
                        value = decode_entities(&html[vs..ve]);
                        j = (ve + 1).min(b.len());
                    }
                    Some(_) => {
                        let vs = j;
                        while j < b.len() && !(b[j].is_ascii_whitespace() || b[j] == b'>') {
                            j += 1;
                        }
                        value = decode_entities(&html[vs..j]);
                    }
                    None => {}
                }
            }
            if !attrs.iter().any(|(k, _)| *k == attr_name) {
                attrs.push((attr_name, value));
            }
        }
        i = j;
        let raw_text =
            !closing && matches!(name.as_str(), "script" | "style" | "textarea" | "title");
        if raw_text {
            let close = format!("</{name}");
            i = lower[i..].find(&close).map_or(b.len(), |p| i + p);
        }
        tags.push(Tag {
            name,
            attrs,
            closing,
        });
    }
    tags
}

/// Input (non-password) di dalam formulir, dipakai pemeriksaan aktif untuk membangun permintaan dasar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormField {
    pub name: String,
    /// Atribut `value` (atau placeholder untuk textarea); dapat kosong.
    pub value: String,
    /// Jenis input huruf kecil (`text`, `email`, `number`, `hidden`, `textarea`, `checkbox`, `radio`, dst).
    pub ty: String,
    /// Checkbox/radio: dikirim apa adanya (nilai/checked bawaan), tidak pernah diinjeksi payload.
    pub fixed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FormInfo {
    /// Metode GET (atribut kosong atau `get`).
    pub get: bool,
    pub action: Option<String>,
    pub has_password: bool,
    /// Input yang dapat diuji aktif (tanpa password/submit/button/image/reset/file; checkbox/radio
    /// hanya disertakan bila `checked`).
    pub fields: Vec<FormField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordInput {
    pub name: String,
    /// Nilai atribut autocomplete input (huruf kecil), bila ada.
    pub autocomplete: Option<String>,
    /// Nilai autocomplete formulir pembungkus (huruf kecil), bila ada.
    pub form_autocomplete: Option<String>,
    /// Indeks formulir pembungkus di `PageInfo::forms`.
    pub form: Option<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageInfo {
    /// Nilai `href` mentah dari `<a>`.
    pub links: Vec<String>,
    pub forms: Vec<FormInfo>,
    pub passwords: Vec<PasswordInput>,
}

pub fn analyze(html: &str) -> PageInfo {
    let mut info = PageInfo::default();
    let mut current: Option<usize> = None;
    let mut form_autocomplete: Option<String> = None;
    for tag in parse_tags(html) {
        match (tag.name.as_str(), tag.closing) {
            ("a", false) => {
                if let Some(h) = tag.attr("href") {
                    let h = h.trim();
                    if !h.is_empty() {
                        info.links.push(h.to_string());
                    }
                }
            }
            ("form", false) => {
                let method = tag.attr("method").map(|m| m.trim().to_ascii_lowercase());
                info.forms.push(FormInfo {
                    get: matches!(method.as_deref(), None | Some("") | Some("get")),
                    action: tag.attr("action").map(|a| a.trim().to_string()),
                    has_password: false,
                    fields: Vec::new(),
                });
                current = Some(info.forms.len() - 1);
                form_autocomplete = tag
                    .attr("autocomplete")
                    .map(|a| a.trim().to_ascii_lowercase());
            }
            ("form", true) => {
                current = None;
                form_autocomplete = None;
            }
            ("input", false) => {
                let ty = tag
                    .attr("type")
                    .map(|t| t.trim().to_ascii_lowercase())
                    .unwrap_or_default();
                if ty == "password" {
                    if let Some(f) = current {
                        info.forms[f].has_password = true;
                    }
                    info.passwords.push(PasswordInput {
                        name: tag.attr("name").unwrap_or("").trim().to_string(),
                        autocomplete: tag
                            .attr("autocomplete")
                            .map(|a| a.trim().to_ascii_lowercase()),
                        form_autocomplete: form_autocomplete.clone(),
                        form: current,
                    });
                } else if let (Some(f), Some(name)) = (
                    current,
                    tag.attr("name").map(str::trim).filter(|n| !n.is_empty()),
                ) {
                    match ty.as_str() {
                        "submit" | "button" | "image" | "reset" | "file" => {}
                        "checkbox" | "radio" => {
                            if tag.attr("checked").is_some() {
                                let value = tag.attr("value").unwrap_or("on").to_string();
                                info.forms[f].fields.push(FormField {
                                    name: name.to_string(),
                                    value,
                                    ty,
                                    fixed: true,
                                });
                            }
                        }
                        _ => {
                            let value = tag.attr("value").unwrap_or("").trim().to_string();
                            info.forms[f].fields.push(FormField {
                                name: name.to_string(),
                                value,
                                ty: if ty.is_empty() {
                                    "text".to_string()
                                } else {
                                    ty
                                },
                                fixed: false,
                            });
                        }
                    }
                }
            }
            ("textarea", false) => {
                if let (Some(f), Some(name)) = (
                    current,
                    tag.attr("name").map(str::trim).filter(|n| !n.is_empty()),
                ) {
                    let value = tag.attr("placeholder").unwrap_or("").trim().to_string();
                    info.forms[f].fields.push(FormField {
                        name: name.to_string(),
                        value,
                        ty: "textarea".to_string(),
                        fixed: false,
                    });
                }
            }
            _ => {}
        }
    }
    info
}

/// Nilai atribut `value` dari `<input name=NAME>` pertama.
pub fn input_value(html: &str, name: &str) -> Option<String> {
    parse_tags(html)
        .into_iter()
        .find(|t| t.name == "input" && !t.closing && t.attr("name") == Some(name))
        .map(|t| t.attr("value").unwrap_or("").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_attributes_quotes_and_entities() {
        let tags = parse_tags(
            r#"<A HREF="/a?x=1&amp;y=2" class=c data-x='q"q'>t</a><input disabled name=n value="">"#,
        );
        assert_eq!(tags[0].name, "a");
        assert_eq!(tags[0].attr("href"), Some("/a?x=1&y=2"));
        assert_eq!(tags[0].attr("class"), Some("c"));
        assert_eq!(tags[0].attr("data-x"), Some("q\"q"));
        assert!(tags[1].closing);
        assert_eq!(tags[2].attr("disabled"), Some(""));
        assert_eq!(tags[2].attr("value"), Some(""));
    }

    #[test]
    fn ignores_comments_scripts_and_styles() {
        let info = analyze(
            "<!-- <a href='/c'> --><script>var s='<a href=\"/s\">'</script><style>a{}</style>\
             <a href=/real>x</a><title><a href=/t></title>",
        );
        assert_eq!(info.links, vec!["/real"]);
    }

    #[test]
    fn forms_and_password_inputs() {
        let info = analyze(
            r#"<form method="POST" action="/login" autocomplete="off">
                 <input type="password" name="p">
               </form>
               <form action="/search"><input type="PASSWORD" name="q2" autocomplete="new-password"></form>
               <input type=password name=free>"#,
        );
        assert_eq!(info.forms.len(), 2);
        assert!(!info.forms[0].get);
        assert!(info.forms[1].get);
        assert!(info.forms[0].has_password);
        assert_eq!(info.passwords.len(), 3);
        assert_eq!(info.passwords[0].form_autocomplete.as_deref(), Some("off"));
        assert_eq!(
            info.passwords[1].autocomplete.as_deref(),
            Some("new-password")
        );
        assert_eq!(info.passwords[2].form, None);
    }

    #[test]
    fn input_value_lookup() {
        let h = r#"<form><input type="hidden" name="csrf_token" value="abc&#49;23"></form>"#;
        assert_eq!(input_value(h, "csrf_token").as_deref(), Some("abc123"));
        assert_eq!(input_value(h, "other"), None);
    }

    #[test]
    fn malformed_html_does_not_hang_or_panic() {
        for s in [
            "<",
            "<a",
            "<a href",
            "<a href=",
            "<a href=\"x",
            "<<<>>>",
            "<a =>",
            "&",
            "<!--",
        ] {
            let _ = analyze(s);
        }
        assert_eq!(
            decode_entities("a&b&amp;c&#x41;&#66;&bogus;"),
            "a&b&cAB&bogus;"
        );
    }
}
