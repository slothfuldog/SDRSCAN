//! Pengurai JSON kecil yang mencatat nomor baris tiap nilai dan kunci (untuk menunjuk entri lockfile).
//! Batas kedalaman mencegah stack overflow pada berkas jahat.

const MAX_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub enum Jv {
    Null,
    Bool(bool),
    Num,
    Str(String),
    Arr(Vec<Jn>),
    Obj(Vec<Member>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Jn {
    /// Baris (mulai 1) tempat nilai dimulai.
    pub line: u32,
    pub v: Jv,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub key: String,
    /// Baris tempat kunci ditulis.
    pub key_line: u32,
    pub value: Jn,
}

impl Jn {
    pub fn get(&self, key: &str) -> Option<&Member> {
        match &self.v {
            Jv::Obj(m) => m.iter().find(|m| m.key == key),
            _ => None,
        }
    }

    pub fn str(&self) -> Option<&str> {
        match &self.v {
            Jv::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn str_of(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|m| m.value.str())
    }

    pub fn bool_of(&self, key: &str) -> Option<bool> {
        match self.get(key).map(|m| &m.value.v) {
            Some(Jv::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    pub fn members(&self) -> &[Member] {
        match &self.v {
            Jv::Obj(m) => m,
            _ => &[],
        }
    }

    pub fn items(&self) -> &[Jn] {
        match &self.v {
            Jv::Arr(a) => a,
            _ => &[],
        }
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
    line: u32,
}

type R<T> = Result<T, String>;

impl P<'_> {
    fn err<T>(&self, m: &str) -> R<T> {
        Err(format!("JSON tidak valid di baris {}: {m}", self.line))
    }

    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.i) {
            match c {
                b'\n' => {
                    self.line += 1;
                    self.i += 1;
                }
                b' ' | b'\t' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn string(&mut self) -> R<String> {
        // posisi di tanda kutip pembuka
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(c) = self.peek() else {
                return self.err("string tidak ditutup");
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\n' => return self.err("baris baru di dalam string"),
                b'\\' => {
                    let Some(e) = self.peek() else {
                        return self.err("escape terpotong");
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi)
                                && self.b.get(self.i) == Some(&b'\\')
                                && self.b.get(self.i + 1) == Some(&b'u')
                            {
                                self.i += 2;
                                let lo = self.hex4()?;
                                char::from_u32(
                                    0x10000
                                        + ((hi - 0xD800) << 10)
                                        + (lo.wrapping_sub(0xDC00) & 0x3FF),
                                )
                            } else {
                                char::from_u32(hi)
                            };
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(
                                ch.unwrap_or('\u{FFFD}').encode_utf8(&mut buf).as_bytes(),
                            );
                        }
                        _ => return self.err("escape tidak dikenal"),
                    }
                }
                _ => out.push(c),
            }
        }
        String::from_utf8(out).or_else(|_| self.err("string bukan UTF-8"))
    }

    fn hex4(&mut self) -> R<u32> {
        let s = self
            .b
            .get(self.i..self.i + 4)
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| u32::from_str_radix(s, 16).ok());
        match s {
            Some(v) => {
                self.i += 4;
                Ok(v)
            }
            None => self.err("escape \\u tidak valid"),
        }
    }

    fn literal(&mut self, word: &str, v: Jv) -> R<Jv> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            self.err("token tidak dikenal")
        }
    }

    fn value(&mut self, depth: usize) -> R<Jn> {
        if depth > MAX_DEPTH {
            return self.err("terlalu dalam");
        }
        self.ws();
        let line = self.line;
        let Some(c) = self.peek() else {
            return self.err("nilai tidak ada");
        };
        let v = match c {
            b'{' => {
                self.i += 1;
                let mut members = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        if self.peek() != Some(b'"') {
                            return self.err("kunci objek harus string");
                        }
                        let key_line = self.line;
                        let key = self.string()?;
                        self.ws();
                        if self.peek() != Some(b':') {
                            return self.err("':' diharapkan");
                        }
                        self.i += 1;
                        let value = self.value(depth + 1)?;
                        members.push(Member {
                            key,
                            key_line,
                            value,
                        });
                        self.ws();
                        match self.peek() {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                break;
                            }
                            _ => return self.err("',' atau '}' diharapkan"),
                        }
                    }
                }
                Jv::Obj(members)
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                } else {
                    loop {
                        items.push(self.value(depth + 1)?);
                        self.ws();
                        match self.peek() {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            _ => return self.err("',' atau ']' diharapkan"),
                        }
                    }
                }
                Jv::Arr(items)
            }
            b'"' => Jv::Str(self.string()?),
            b't' => self.literal("true", Jv::Bool(true))?,
            b'f' => self.literal("false", Jv::Bool(false))?,
            b'n' => self.literal("null", Jv::Null)?,
            b'-' | b'0'..=b'9' => {
                while self
                    .peek()
                    .is_some_and(|c| matches!(c, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
                {
                    self.i += 1;
                }
                Jv::Num
            }
            _ => return self.err("karakter tak terduga"),
        };
        Ok(Jn { line, v })
    }
}

pub fn parse(text: &str) -> Result<Jn, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut p = P {
        b: text.as_bytes(),
        i: 0,
        line: 1,
    };
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return p.err("data tersisa setelah nilai akhir");
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_lines_of_keys_and_values() {
        let j = parse("{\n  \"a\": {\n    \"b\": \"x\"\n  },\n  \"c\": [1,\n 2]\n}\n").unwrap();
        let a = j.get("a").unwrap();
        assert_eq!(a.key_line, 2);
        assert_eq!(a.value.get("b").unwrap().key_line, 3);
        assert_eq!(a.value.str_of("b"), Some("x"));
        let c = j.get("c").unwrap();
        assert_eq!(c.key_line, 5);
        assert_eq!(c.value.items().len(), 2);
        assert_eq!(c.value.items()[1].line, 6);
    }

    #[test]
    fn decodes_escapes_and_surrogates() {
        let j = parse(r#"{"k":"a\"b\\c\né😀"}"#).unwrap();
        assert_eq!(j.str_of("k"), Some("a\"b\\c\n\u{e9}\u{1F600}"));
    }

    #[test]
    fn literals_numbers_and_empty_containers() {
        let j =
            parse("{\"t\":true,\"f\":false,\"n\":null,\"x\":-1.5e+3,\"o\":{},\"a\":[]}").unwrap();
        assert_eq!(j.bool_of("t"), Some(true));
        assert_eq!(j.bool_of("f"), Some(false));
        assert!(j.get("o").unwrap().value.members().is_empty());
        assert!(j.get("a").unwrap().value.items().is_empty());
    }

    #[test]
    fn rejects_broken_input() {
        for bad in [
            "",
            "{",
            "{\"a\"}",
            "{\"a\":1,}",
            "[1,2",
            "{\"a\":tru}",
            "{} x",
            "{\"a\":\"\n\"}",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn deep_nesting_is_rejected_not_crashing() {
        let deep = "[".repeat(10_000);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn bom_is_ignored() {
        assert!(parse("\u{feff}{\"a\":1}").is_ok());
    }
}
