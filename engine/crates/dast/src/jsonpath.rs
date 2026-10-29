//! Jalur titik sederhana ke nilai di dokumen JSON: `data.access_token`, `items[0].token`,
//! `[0].token`. Hanya untuk membaca; tidak ada wildcard atau filter.

use serde_json::Value;

/// Panjang maksimum jalur.
pub const MAX_PATH_LEN: usize = 200;
const MAX_SEGMENTS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    Key(String),
    Index(usize),
}

/// Mengurai jalur; None bila sintaksnya tidak valid.
pub fn parse(path: &str) -> Option<Vec<Seg>> {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return None;
    }
    let mut segs = Vec::new();
    for (i, part) in path.split('.').enumerate() {
        let (name, mut rest) = match part.find('[') {
            Some(p) => (&part[..p], &part[p..]),
            None => (part, ""),
        };
        if name.contains(']') || name.chars().any(|c| c.is_control()) {
            return None;
        }
        if name.is_empty() {
            // Hanya `[0]...` di awal jalur yang boleh tanpa nama.
            if i != 0 || rest.is_empty() {
                return None;
            }
        } else {
            segs.push(Seg::Key(name.to_string()));
        }
        while !rest.is_empty() {
            let inner = rest.strip_prefix('[')?;
            let end = inner.find(']')?;
            let digits = &inner[..end];
            if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            segs.push(Seg::Index(digits.parse().ok()?));
            rest = &inner[end + 1..];
        }
    }
    (!segs.is_empty() && segs.len() <= MAX_SEGMENTS).then_some(segs)
}

pub fn get<'a>(root: &'a Value, segs: &[Seg]) -> Option<&'a Value> {
    let mut cur = root;
    for s in segs {
        cur = match s {
            Seg::Key(k) => cur.as_object()?.get(k)?,
            Seg::Index(i) => cur.as_array()?.get(*i)?,
        };
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_and_reads() {
        let v = json!({"data":{"access_token":"T","items":[{"token":"A"},{"token":"B"}]},"list":[[1,2]]});
        let g = |p: &str| parse(p).and_then(|s| get(&v, &s).cloned());
        assert_eq!(g("data.access_token"), Some(json!("T")));
        assert_eq!(g("data.items[1].token"), Some(json!("B")));
        assert_eq!(g("list[0][1]"), Some(json!(2)));
        assert_eq!(g("data.nope"), None);
        assert_eq!(g("data.items[9].token"), None);
        let arr = json!([{"token":"X"}]);
        assert_eq!(
            parse("[0].token").and_then(|s| get(&arr, &s).cloned()),
            Some(json!("X"))
        );
    }

    #[test]
    fn rejects_invalid_syntax() {
        for bad in [
            "", ".", "a.", ".a", "a..b", "a[", "a[]", "a[x]", "a[-1]", "a[+1]", "a]b", "[0",
            "x.[0]", "a[1]b",
        ] {
            assert!(parse(bad).is_none(), "{bad}");
        }
        assert!(parse(&"a".repeat(201)).is_none());
    }
}
