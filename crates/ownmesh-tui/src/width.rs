//! Display-width helpers for CJK / wide glyphs and truncation.

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Display columns occupied by `s` (East Asian Width aware).
#[must_use]
pub fn display_width(s: &str) -> usize {
    s.width()
}

/// Truncate `s` so its display width is at most `max_cols`, appending `…` when cut.
#[must_use]
pub fn truncate_to_width(s: &str, max_cols: usize) -> String {
    if max_cols == 0 {
        return String::new();
    }
    if display_width(s) <= max_cols {
        return s.to_owned();
    }
    if max_cols == 1 {
        return "…".to_owned();
    }
    let budget = max_cols.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0usize;
    for ch in s.chars() {
        let w = ch.width().unwrap_or(0);
        if used + w > budget {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

/// Pad (or truncate) to exactly `cols` display columns with spaces.
#[must_use]
#[allow(dead_code)]
pub fn pad_to_width(s: &str, cols: usize) -> String {
    let t = truncate_to_width(s, cols);
    let w = display_width(&t);
    if w >= cols {
        t
    } else {
        format!("{t}{pad}", pad = " ".repeat(cols - w))
    }
}

/// True when every character's width is either 1 or 2 (no zero-width surprises for UI labels).
#[must_use]
#[allow(dead_code)]
pub fn is_simple_label(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| matches!(c.width(), Some(1 | 2)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_width() {
        assert_eq!(display_width("Dashboard"), 9);
    }

    #[test]
    fn cjk_double_width() {
        // ダッシュボード = 7 CJK chars → 14 columns
        assert_eq!(display_width("ダッシュボード"), 14);
        assert_eq!(display_width("仪表盘"), 6);
        assert_eq!(display_width("Панель"), 6);
    }

    #[test]
    fn truncate_cjk_respects_columns() {
        let s = "ダッシュボード画面";
        let t = truncate_to_width(s, 8);
        assert!(display_width(&t) <= 8);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn pad_exact() {
        let p = pad_to_width("あ", 4);
        assert_eq!(display_width(&p), 4);
    }
}
