//! Skor CVSS v3.x (dihitung dari vektor, algoritma spesifikasi 3.1) dan pemetaan ke `Severity`.
//! Vektor CVSS v4 tidak dihitung (butuh tabel makrovektor); advisory seperti itu memakai severity
//! kualitatif dari sumbernya.

use sdrscan_core::Severity;

fn roundup(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

/// Skor dasar dari vektor `CVSS:3.0/...` atau `CVSS:3.1/...`; `None` bila bukan v3 atau tidak lengkap.
pub fn score_v3(vector: &str) -> Option<f32> {
    let mut parts = vector.trim().split('/');
    let head = parts.next()?;
    if head != "CVSS:3.1" && head != "CVSS:3.0" {
        return None;
    }
    let (mut av, mut ac, mut pr, mut ui, mut s, mut c, mut i, mut a) =
        (None, None, None, None, None, None, None, None);
    for p in parts {
        let (k, v) = p.split_once(':')?;
        match k {
            "AV" => av = Some(v),
            "AC" => ac = Some(v),
            "PR" => pr = Some(v),
            "UI" => ui = Some(v),
            "S" => s = Some(v),
            "C" => c = Some(v),
            "I" => i = Some(v),
            "A" => a = Some(v),
            _ => {} // metrik temporal/environmental diabaikan
        }
    }
    let changed = match s? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match av? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match ac? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (pr?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match ui? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |x: Option<&str>| -> Option<f64> {
        match x? {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let iss = 1.0 - (1.0 - cia(c)?) * (1.0 - cia(i)?) * (1.0 - cia(a)?);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if impact <= 0.0 {
        0.0
    } else if changed {
        roundup((1.08 * (impact + exploitability)).min(10.0))
    } else {
        roundup((impact + exploitability).min(10.0))
    };
    Some(base as f32)
}

/// critical >= 9,0; high >= 7,0; medium >= 4,0; low > 0; info lainnya.
pub fn severity_from_score(score: f32) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Info
    }
}

/// Severity kualitatif GitHub/NVD ("MODERATE", "high", ...) -> Severity.
pub fn severity_from_label(label: &str) -> Option<Severity> {
    match label.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" | "important" => Some(Severity::High),
        "moderate" | "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "none" | "info" | "informational" => Some(Severity::Info),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_scores() {
        // Contoh dari kalkulator CVSS 3.1 resmi.
        let cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ];
        for (v, want) in cases {
            assert_eq!(score_v3(v), Some(want), "{v}");
        }
    }

    #[test]
    fn rejects_other_versions_and_broken_vectors() {
        assert_eq!(
            score_v3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            None
        );
        assert_eq!(score_v3("AV:N/AC:L/Au:N/C:P/I:P/A:P"), None);
        assert_eq!(score_v3("CVSS:3.1/AV:N/AC:L"), None);
        assert_eq!(
            score_v3("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
        assert_eq!(score_v3(""), None);
    }

    #[test]
    fn severity_thresholds() {
        assert_eq!(severity_from_score(10.0), Severity::Critical);
        assert_eq!(severity_from_score(9.0), Severity::Critical);
        assert_eq!(severity_from_score(8.9), Severity::High);
        assert_eq!(severity_from_score(7.0), Severity::High);
        assert_eq!(severity_from_score(6.9), Severity::Medium);
        assert_eq!(severity_from_score(4.0), Severity::Medium);
        assert_eq!(severity_from_score(3.9), Severity::Low);
        assert_eq!(severity_from_score(0.1), Severity::Low);
        assert_eq!(severity_from_score(0.0), Severity::Info);
    }

    #[test]
    fn labels() {
        assert_eq!(severity_from_label("MODERATE"), Some(Severity::Medium));
        assert_eq!(severity_from_label("High"), Some(Severity::High));
        assert_eq!(severity_from_label("???"), None);
    }
}
