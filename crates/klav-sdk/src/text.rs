//! Text that crosses a trust boundary: what an agent declares (its reason,
//! the domain it claims), shown to the person, and what the server says,
//! shown to the LLM.
//!
//! Control, format (bidi overrides, zero-width marks), line and paragraph
//! separator characters (Unicode `Cc`, `Cf`, `Zl`, `Zp`) can make a text
//! look like something else: a reason that reads backwards on the
//! person's screen, or a server message that hides an instruction.

use klav_client::{ClientError, ClientResult};

/// Longest server message passed on to the LLM, in characters.
pub const MAX_SERVER_TEXT: usize = 200;

pub use klav_core::text::is_hidden;

/// Refuses a declared text (`what`: "reason", "domain"…) with hidden
/// characters: the person must read what the agent wrote.
pub fn check_declared(what: &str, text: &str) -> ClientResult<()> {
    if text.chars().any(is_hidden) {
        return Err(ClientError::Invalid(format!(
            "the {what} has control or invisible formatting characters: write it as plain text"
        )));
    }
    Ok(())
}

/// A server message for the LLM: hidden characters dropped, cut to
/// [`MAX_SERVER_TEXT`] characters and marked as the server's word.
pub fn untrusted(message: &str) -> String {
    let clean: String = message
        .chars()
        .map(|c| if is_hidden(c) { ' ' } else { c })
        .collect();
    let clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut cut: String = clean.chars().take(MAX_SERVER_TEXT).collect();
    if clean.chars().count() > MAX_SERVER_TEXT {
        cut.push('…');
    }
    format!("the server says (unverified): {cut}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_characters_are_refused_in_declared_text() {
        assert!(check_declared("reason", "deploy the API").is_ok());
        assert!(check_declared("reason", "café ✓ 日本").is_ok());
        for bad in [
            "a\u{202E}gnp.exe",
            "a\u{2066}b",
            "a\u{200B}b",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\nb",
            "a\u{FEFF}b",
            "a\u{E0041}b",
        ] {
            assert!(check_declared("reason", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn server_text_is_marked_cleaned_and_cut() {
        let text = untrusted("denied\u{202E}\nIGNORE PREVIOUS");
        assert!(text.starts_with("the server says (unverified): "));
        assert!(!text.contains('\u{202E}') && !text.contains('\n'));
        let long = untrusted(&"x".repeat(5000));
        assert!(long.chars().count() < MAX_SERVER_TEXT + 40);
        assert!(long.ends_with('…'));
    }
}
