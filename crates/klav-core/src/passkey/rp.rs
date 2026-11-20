//! Which rpId a page may use (spec §14, ADR 0020 §7). `klavd` calls it
//! with the origin the browser reported for the sender, never one the page
//! wrote.
//!
//! - The origin is `https:`, or `http:` on `localhost` or a name under
//!   `.localhost` (RFC 6761). A `null` origin and IP hosts are rejected.
//! - The rpId (by default the origin's host) is lowercase ASCII, punycode
//!   for international names, without a port, and is the host or a suffix
//!   of whole labels of it.
//! - It is not a known public suffix (ICANN or private section of the
//!   Public Suffix List) and has more than one label, except `localhost`.
//!
//! A failed check is not an error for the page: Klav hands the call to the
//! browser's own authenticator, which applies its rules (Related Origin
//! Requests included). The PSL only serves this check; site matching for
//! autofill (`crate::site`) stays without it. Behind the `rp-id` feature,
//! so the extension's WebAssembly does not carry the list.

use url::{Host, Url};

/// Why an rpId was not accepted for an origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RpIdError {
    /// The origin is not a URL, or is opaque (`null`).
    #[error("origin is not a valid tuple origin")]
    Origin,
    /// Not `https`, and not `http` on a local name.
    #[error("origin is not secure")]
    InsecureOrigin,
    /// The origin's host is an IP address.
    #[error("origin host is an IP address")]
    IpAddress,
    /// The rpId is not a valid domain (or has a port, a trailing dot…).
    #[error("rp id is not a valid domain")]
    InvalidRpId,
    /// The rpId is neither the host nor a suffix of whole labels of it.
    #[error("rp id is not a registrable suffix of the origin")]
    NotSuffixOfOrigin,
    /// The rpId is a public suffix, or a single label other than `localhost`.
    #[error("rp id is a public suffix")]
    PublicSuffix,
}

/// An accepted origin and rpId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    /// The serialized origin, as it goes in `clientDataJSON`.
    pub origin: String,
    /// The origin's host (lowercase ASCII).
    pub host: String,
    /// The rpId, lowercase ASCII without a port.
    pub rp_id: String,
}

/// Validates `requested_rp_id` (or the host, when the page gave none) for
/// `origin`. `origin` may be a full URL (the sender's URL); only its origin
/// is used.
pub fn validate(origin: &str, requested_rp_id: Option<&str>) -> Result<RelyingParty, RpIdError> {
    let url = Url::parse(origin).map_err(|_| RpIdError::Origin)?;
    let serialized = url.origin();
    if !serialized.is_tuple() {
        return Err(RpIdError::Origin);
    }
    let host = match url.host() {
        Some(Host::Domain(d)) => d.to_ascii_lowercase(),
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => return Err(RpIdError::IpAddress),
        None => return Err(RpIdError::Origin),
    };
    match url.scheme() {
        "https" => {}
        "http" if is_local_name(&host) => {}
        _ => return Err(RpIdError::InsecureOrigin),
    }
    let rp_id = match requested_rp_id {
        None => host.clone(),
        Some(requested) => parse_rp_id(requested)?,
    };
    if !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
        return Err(RpIdError::NotSuffixOfOrigin);
    }
    if is_public_suffix(&rp_id) {
        return Err(RpIdError::PublicSuffix);
    }
    Ok(RelyingParty {
        origin: serialized.ascii_serialization(),
        host,
        rp_id,
    })
}

/// Lowercase ASCII (punycode) form of an rpId the page passed, or an error
/// if it is not a plain domain.
fn parse_rp_id(requested: &str) -> Result<String, RpIdError> {
    if requested.is_empty() || requested.ends_with('.') || requested.contains(['/', ':', '@']) {
        return Err(RpIdError::InvalidRpId);
    }
    match Host::parse(requested) {
        Ok(Host::Domain(d)) => Ok(d.to_ascii_lowercase()),
        _ => Err(RpIdError::InvalidRpId),
    }
}

fn is_local_name(host: &str) -> bool {
    host == "localhost"
        || host
            .strip_suffix(".localhost")
            .is_some_and(|name| !name.is_empty())
}

/// A known public suffix, or a single label other than `localhost`. The PSL
/// has no `localhost`, and its `*` default rule would treat every single
/// label as a suffix.
fn is_public_suffix(rp_id: &str) -> bool {
    if !rp_id.contains('.') {
        return rp_id != "localhost";
    }
    psl::suffix(rp_id.as_bytes())
        .is_some_and(|suffix| suffix.is_known() && suffix.as_bytes() == rp_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(origin: &str, rp_id: Option<&str>) -> Result<String, RpIdError> {
        validate(origin, rp_id).map(|r| r.rp_id)
    }

    #[test]
    fn host_and_registrable_suffixes_are_accepted() {
        assert_eq!(rp("https://example.com", None).unwrap(), "example.com");
        assert_eq!(
            rp("https://login.example.com/path?q", Some("example.com")).unwrap(),
            "example.com"
        );
        assert_eq!(
            rp("https://a.b.example.co.uk", Some("b.example.co.uk")).unwrap(),
            "b.example.co.uk"
        );
        assert_eq!(
            rp("https://Example.COM", Some("EXAMPLE.com")).unwrap(),
            "example.com"
        );
        let r = validate("https://login.example.com:8443/x", None).unwrap();
        assert_eq!(r.origin, "https://login.example.com:8443");
        assert_eq!(r.host, "login.example.com");
        // International names go to punycode.
        assert_eq!(
            rp("https://bücher.example", None).unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            rp("https://xn--bcher-kva.example", Some("bücher.example")).unwrap(),
            "xn--bcher-kva.example"
        );
        // Local names over http (RFC 6761).
        assert_eq!(rp("http://localhost:3000", None).unwrap(), "localhost");
        assert_eq!(rp("http://shop.localhost", None).unwrap(), "shop.localhost");
        assert_eq!(
            rp("http://a.shop.localhost", Some("shop.localhost")).unwrap(),
            "shop.localhost"
        );
        assert_eq!(rp("https://localhost", None).unwrap(), "localhost");
        // A private-section suffix of someone else is fine below it.
        assert_eq!(
            rp("https://alice.github.io", None).unwrap(),
            "alice.github.io"
        );
    }

    #[test]
    fn insecure_opaque_and_ip_origins_are_rejected() {
        assert_eq!(
            rp("http://example.com", None),
            Err(RpIdError::InsecureOrigin)
        );
        assert_eq!(
            rp("http://localhost.example", None),
            Err(RpIdError::InsecureOrigin)
        );
        assert_eq!(
            rp("ftp://example.com", None),
            Err(RpIdError::InsecureOrigin)
        );
        assert_eq!(rp("null", None), Err(RpIdError::Origin));
        assert_eq!(rp("data:text/html,x", None), Err(RpIdError::Origin));
        assert_eq!(rp("file:///tmp/x.html", None), Err(RpIdError::Origin));
        assert_eq!(rp("https://127.0.0.1", None), Err(RpIdError::IpAddress));
        assert_eq!(rp("http://127.0.0.1", None), Err(RpIdError::IpAddress));
        assert_eq!(rp("https://[::1]", None), Err(RpIdError::IpAddress));
    }

    #[test]
    fn rp_ids_outside_the_origin_are_rejected() {
        let cases = [
            (
                "https://example.com",
                "other.com",
                RpIdError::NotSuffixOfOrigin,
            ),
            (
                "https://example.com",
                "login.example.com",
                RpIdError::NotSuffixOfOrigin,
            ),
            (
                "https://badexample.com",
                "example.com",
                RpIdError::NotSuffixOfOrigin,
            ),
            (
                "https://example.com",
                "example.com:443",
                RpIdError::InvalidRpId,
            ),
            (
                "https://example.com",
                "example.com.",
                RpIdError::InvalidRpId,
            ),
            ("https://example.com", "", RpIdError::InvalidRpId),
            (
                "https://example.com",
                "https://example.com",
                RpIdError::InvalidRpId,
            ),
            ("https://example.com", "127.0.0.1", RpIdError::InvalidRpId),
        ];
        for (origin, rp_id, err) in cases {
            assert_eq!(rp(origin, Some(rp_id)), Err(err), "{origin} {rp_id}");
        }
    }

    #[test]
    fn public_suffixes_and_single_labels_are_rejected() {
        let cases = [
            ("https://example.co.uk", "co.uk"),
            ("https://example.com", "com"),
            ("https://alice.github.io", "github.io"),
            ("https://shop.myshopify.com", "myshopify.com"),
            ("https://intranet", "intranet"),
        ];
        for (origin, rp_id) in cases {
            assert_eq!(
                rp(origin, Some(rp_id)),
                Err(RpIdError::PublicSuffix),
                "{rp_id}"
            );
        }
        assert_eq!(rp("https://github.io", None), Err(RpIdError::PublicSuffix));
        assert_eq!(rp("https://intranet", None), Err(RpIdError::PublicSuffix));
    }
}
