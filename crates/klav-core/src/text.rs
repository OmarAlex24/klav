//! Text that crosses a trust boundary and is shown to someone: what an
//! agent declares (a task, a reason, a claimed domain, its own name), shown
//! to the person.
//!
//! Control, format (bidi overrides, zero-width marks), line and paragraph
//! separator characters (Unicode `Cc`, `Cf`, `Zl`, `Zp`) can make a text
//! look like something else: a reason that reads backwards on the person's
//! screen, or a name that hides another one.

/// Whether `c` is a control, format, line or paragraph separator character
/// (`Cc`, `Cf`, `Zl`, `Zp`).
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            u32::from(c),
            0x00AD
                | 0x0600..=0x0605
                | 0x061C
                | 0x06DD
                | 0x070F
                | 0x0890..=0x0891
                | 0x08E2
                | 0x180E
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x206F
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x13430..=0x1343F
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0001
                | 0xE0020..=0xE007F
        )
}

/// `text` made safe to show: hidden characters dropped, runs of spaces
/// collapsed, and cut to `max` characters (with `…`).
pub fn shown(text: &str, max: usize) -> String {
    let clean: String = text
        .chars()
        .map(|c| if is_hidden(c) { ' ' } else { c })
        .collect();
    let clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.chars().count() <= max {
        return clean;
    }
    let mut cut: String = clean.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_characters_are_the_control_format_and_separator_ones() {
        for c in [
            '\n',
            '\u{202A}',
            '\u{202E}',
            '\u{2066}',
            '\u{2069}',
            '\u{200B}',
            '\u{2028}',
            '\u{2029}',
            '\u{FEFF}',
            '\u{E0041}',
        ] {
            assert!(is_hidden(c), "{c:?}");
        }
        for c in ['a', 'é', '✓', '日', ' '] {
            assert!(!is_hidden(c), "{c:?}");
        }
    }

    #[test]
    fn shown_text_is_clean_and_short() {
        assert_eq!(shown("bot\u{202E}gnp.exe", 64), "bot gnp.exe");
        assert_eq!(shown("a\n\n b", 64), "a b");
        let long = shown(&"x".repeat(100), 64);
        assert_eq!(long.chars().count(), 64);
        assert!(long.ends_with('…'));
    }
}
