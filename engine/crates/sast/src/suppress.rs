//! Penekanan temuan lewat komentar `// sdrscan-ignore: <rule-id>[, <rule-id>...]`
//! di baris temuan atau baris sebelumnya.

const MARKER: &str = "sdrscan-ignore:";

fn ids_on_line(line: &str) -> Vec<&str> {
    let Some(pos) = line.find(MARKER) else {
        return Vec::new();
    };
    line[pos + MARKER.len()..]
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|s| s.trim_end_matches("*/").trim_end_matches("?>"))
        .filter(|s| !s.is_empty())
        .collect()
}

/// `line` dimulai dari 1. Mengembalikan true bila `rule_id` ditekan untuk baris itu.
pub fn is_suppressed(lines: &[&str], line: u32, rule_id: &str) -> bool {
    let idx = line as usize;
    [idx.checked_sub(1), idx.checked_sub(2)]
        .into_iter()
        .flatten()
        .filter_map(|i| lines.get(i))
        .any(|l| ids_on_line(l).contains(&rule_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_and_previous_line() {
        let lines = [
            "<?php",
            "// sdrscan-ignore: php-eval",
            "eval($x);",
            "eval($y); // sdrscan-ignore: php-eval, other",
        ];
        assert!(is_suppressed(&lines, 3, "php-eval"));
        assert!(is_suppressed(&lines, 4, "php-eval"));
        assert!(is_suppressed(&lines, 4, "other"));
        assert!(!is_suppressed(&lines, 3, "other"));
        assert!(!is_suppressed(&lines, 1, "php-eval"));
    }

    #[test]
    fn block_comment_terminator() {
        let lines = ["/* sdrscan-ignore: php-eval */", "eval($x);"];
        assert!(is_suppressed(&lines, 2, "php-eval"));
    }
}
