//! Waktu UTC minimal (tanpa dependensi): format/parse RFC 3339 dan hitungan hari.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `2026-10-28T09:30:00Z`
pub fn format_rfc3339(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Format yang diminta API NVD untuk `lastModStartDate`: UTC dengan milidetik dan offset `+00:00`.
pub fn format_nvd(epoch: i64) -> String {
    let s = format_rfc3339(epoch);
    format!("{}.000+00:00", s.trim_end_matches('Z'))
}

pub fn now_rfc3339() -> String {
    format_rfc3339(now_epoch())
}

/// Menerima `YYYY-MM-DDTHH:MM:SS[.fff](Z|+HH:MM|-HH:MM)` dan `YYYY-MM-DDTHH:MM:SS` (dianggap UTC).
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b' ') {
        return None;
    }
    let num = |a: usize, z: usize| s.get(a..z)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, se) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        let digits = r.chars().take_while(|c| c.is_ascii_digit()).count();
        rest = &r[digits..];
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        r if r.len() == 6 && (r.starts_with('+') || r.starts_with('-')) => {
            let sign = if r.starts_with('-') { -1 } else { 1 };
            let oh: i64 = r.get(1..3)?.parse().ok()?;
            let om: i64 = r.get(4..6)?.parse().ok()?;
            sign * (oh * 3600 + om * 60)
        }
        _ => return None,
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset)
}

/// Umur dalam hari penuh dari stempel waktu `s` sampai `now`; None bila `s` tidak terbaca.
pub fn age_days(s: &str, now: i64) -> Option<i64> {
    parse_rfc3339(s).map(|t| (now - t).div_euclid(86_400))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_known_values() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        for t in [0, 951_782_400, 1_709_164_800, 1_793_000_000, 4_102_444_800] {
            assert_eq!(parse_rfc3339(&format_rfc3339(t)), Some(t));
        }
    }

    #[test]
    fn parses_offsets_and_fractions() {
        let utc = parse_rfc3339("2024-01-01T00:00:00Z").unwrap();
        assert_eq!(parse_rfc3339("2024-01-01T07:00:00+07:00"), Some(utc));
        assert_eq!(parse_rfc3339("2024-01-01T00:00:00.123Z"), Some(utc));
        assert_eq!(parse_rfc3339("2024-01-01T00:00:00"), Some(utc));
        assert_eq!(parse_rfc3339("kemarin"), None);
        assert_eq!(parse_rfc3339("2024-13-01T00:00:00Z"), None);
    }

    #[test]
    fn nvd_format() {
        assert_eq!(format_nvd(0), "1970-01-01T00:00:00.000+00:00");
    }

    #[test]
    fn age() {
        let now = parse_rfc3339("2024-01-10T12:00:00Z").unwrap();
        assert_eq!(age_days("2024-01-01T00:00:00Z", now), Some(9));
        assert_eq!(age_days("nonsense", now), None);
    }
}
