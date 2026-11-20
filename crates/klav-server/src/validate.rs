//! Validation of request fields.
//!
//! The server cannot check the contents of encrypted blobs, but it does check
//! their two-byte header (`version ‖ kind`) and length bounds, so a client bug
//! (wrong blob in the wrong field) is caught at upload time instead of when
//! another device fails to decrypt.

use klav_core::crypto::encoding::Kind;
use klav_proto::Blob;

use crate::error::{ApiError, ApiResult};

/// Checks the header and the exact length of a fixed-size blob.
pub(crate) fn exact(blob: &Blob, kind: Kind, len: usize, field: &str) -> ApiResult<()> {
    header(blob, kind, field)?;
    if blob.len() != len {
        return Err(ApiError::bad_request(format!(
            "{field}: expected {len} bytes"
        )));
    }
    Ok(())
}

/// Checks the header and length bounds of a variable-size blob.
pub(crate) fn sized(blob: &Blob, kind: Kind, min: usize, max: usize, field: &str) -> ApiResult<()> {
    header(blob, kind, field)?;
    if blob.len() < min || blob.len() > max {
        return Err(ApiError::bad_request(format!(
            "{field}: size must be between {min} and {max} bytes"
        )));
    }
    Ok(())
}

fn header(blob: &Blob, kind: Kind, field: &str) -> ApiResult<()> {
    if blob.as_bytes().get(..2) != Some(&kind.header()[..]) {
        return Err(ApiError::bad_request(format!(
            "{field}: wrong format version or kind (expected {:#04x})",
            kind as u8
        )));
    }
    Ok(())
}

/// Normalises an e-mail address: trimmed and lower-cased. This is the OPAQUE
/// credential identifier, so every endpoint must use this function.
pub(crate) fn email(raw: &str) -> ApiResult<String> {
    let email = raw.trim().to_lowercase();
    let valid = (3..=254).contains(&email.len())
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
        && matches!(email.split_once('@'), Some((local, domain))
            if !local.is_empty() && !domain.is_empty() && !domain.contains('@'));
    if valid {
        Ok(email)
    } else {
        Err(ApiError::bad_request("invalid e-mail address"))
    }
}

/// Validates a display name (1–64 characters, no control characters).
pub(crate) fn display_name(raw: &str) -> ApiResult<String> {
    let name = raw.trim();
    let count = name.chars().count();
    // No bidi overrides or zero-width marks either: an agent's name is
    // shown to the person on every request it makes.
    if (1..=64).contains(&count) && !name.chars().any(klav_core::text::is_hidden) {
        Ok(name.to_owned())
    } else {
        Err(ApiError::bad_request(
            "name must have 1 to 64 characters and no control, format or separator characters",
        ))
    }
}

/// Validates the name of a new agent: a [`display_name`] other than `you`,
/// in any case, which is how the audit log calls the person (ADR 0033
/// §8.1). Agents registered before keep their name: only registration
/// checks it.
pub(crate) fn agent_name(raw: &str) -> ApiResult<String> {
    let name = display_name(raw)?;
    if name.eq_ignore_ascii_case("you") {
        return Err(ApiError::bad_request(
            "the name `you` is reserved: the audit log calls the person that",
        ));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_cannot_be_called_you() {
        for reserved in ["you", " You ", "YOU"] {
            assert!(agent_name(reserved).is_err(), "{reserved:?}");
        }
        assert_eq!(agent_name(" cursor ").ok().as_deref(), Some("cursor"));
        assert!(agent_name("you2").is_ok());
        assert!(agent_name("your-bot").is_ok());
        assert!(agent_name("").is_err());
        // Devices may still be called so: only agents act in the log.
        assert!(display_name("you").is_ok());
    }

    #[test]
    fn email_normalisation() {
        assert_eq!(
            email("  Ana@Example.COM ").ok().as_deref(),
            Some("ana@example.com")
        );
        for bad in ["", "ana", "@x", "ana@", "a b@c.d", "a@b@c", "a\u{0}@b.c"] {
            assert!(email(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn blob_checks() {
        let blob = Blob::new(vec![0x01, 0x06, 0, 0]);
        assert!(exact(&blob, Kind::KdfParams, 4, "f").is_ok());
        assert!(exact(&blob, Kind::KdfParams, 5, "f").is_err());
        assert!(exact(&blob, Kind::PublicIdentity, 4, "f").is_err());
        assert!(sized(&blob, Kind::KdfParams, 2, 4, "f").is_ok());
        assert!(sized(&blob, Kind::KdfParams, 5, 9, "f").is_err());
        assert!(exact(&Blob::new(vec![0x02, 0x06, 0, 0]), Kind::KdfParams, 4, "f").is_err());
        assert!(exact(&Blob::default(), Kind::KdfParams, 0, "f").is_err());
    }

    #[test]
    fn display_names() {
        assert_eq!(display_name(" Mac ").ok().as_deref(), Some("Mac"));
        assert!(display_name("").is_err());
        assert!(display_name(&"x".repeat(65)).is_err());
        assert!(display_name("a\nb").is_err());
        assert!(display_name("bot\u{202e}toh").is_err());
        assert!(display_name("a\u{200b}b").is_err());
        assert!(display_name("Mac de Ana").is_ok());
    }
}
