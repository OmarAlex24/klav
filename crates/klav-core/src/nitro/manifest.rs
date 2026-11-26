//! The Klav Enclave Transparency Manifest: which enclave images the release
//! authority accepts, signed with Ed25519 (spec §15.5, ADR 0051 §2.4).
//!
//! A device verifies the signature over the exact bytes it received, then
//! parses them; it keeps the highest `seq` it verified and refuses lower
//! ones, and refuses a manifest past `expires_at_ms`.

use std::net::IpAddr;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::NitroError;
use super::attestation::{Measurement, PCR_LEN, Pcr};
use crate::crypto::sign::signed_message;

/// Signature label of the manifest (spec §2.3).
pub const LABEL_ENCLAVE_MANIFEST: &str = "klav/v1/sig/enclave-manifest";
/// The manifest format this build reads.
pub const MANIFEST_VERSION: u32 = 1;
/// Longest a manifest may be valid: 30 days.
pub const MAX_MANIFEST_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// How far in the future `issued_at_ms` may be, for clock skew.
pub const MANIFEST_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
/// Largest manifest accepted, in bytes.
pub const MAX_MANIFEST_LEN: usize = 64 * 1024;
/// Most `egress` entries (ADR 0044's pin holds at most 16).
pub const MAX_EGRESS: usize = 16;

/// The release authority's Ed25519 public keys (ADR 0051 §11.5: the active
/// key and an offline backup). **Empty in this build:** the keys do not
/// exist yet, so every manifest is refused with
/// [`NitroError::NoReleaseKey`] until a later layer pins them.
pub const RELEASE_AUTHORITY_KEYS: &[[u8; 32]] = &[];

/// The status of an image in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageStatus {
    /// Accepted; new grants are wrapped for it.
    Current,
    /// Accepted, but no new grants once a newer `current` image is live.
    Draining,
    /// Refused.
    Revoked,
}

/// One enclave image of a verified manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestImage {
    version: (u32, u32, u32),
    version_text: String,
    commit: String,
    arch: String,
    measurement: Measurement,
    status: ImageStatus,
}

impl ManifestImage {
    /// The release, as `(major, minor, patch)`.
    pub fn version(&self) -> (u32, u32, u32) {
        self.version
    }

    /// The release as written, such as `0.12.0`.
    pub fn version_text(&self) -> &str {
        &self.version_text
    }

    /// The 40-hex-digit commit it was built from.
    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// `aarch64` or `x86_64`.
    pub fn arch(&self) -> &str {
        &self.arch
    }

    /// Its PCR0–2.
    pub fn measurement(&self) -> &Measurement {
        &self.measurement
    }

    /// `current`, `draining` or `revoked`.
    pub fn status(&self) -> ImageStatus {
        self.status
    }
}

/// A manifest whose signature, format, dates and `seq` verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    seq: u64,
    seed_epoch: u32,
    issued_at_ms: u64,
    expires_at_ms: u64,
    endpoint: String,
    server: String,
    images: Vec<ManifestImage>,
    parent_roles: Vec<Pcr>,
    egress: Vec<String>,
}

impl VerifiedManifest {
    /// Its sequence number: the device stores the highest one it verified.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Grows by one after a total loss of the enclaves' seed (§4.4).
    pub fn seed_epoch(&self) -> u32 {
        self.seed_epoch
    }

    /// When it was signed, Unix milliseconds.
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// When it stops being accepted, Unix milliseconds.
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// The hosted proxy's host, such as `proxy.klav.dev`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The Klav server the enclaves serve, such as `api.klav.dev`.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Every image, in the manifest's order.
    pub fn images(&self) -> &[ManifestImage] {
        &self.images
    }

    /// The PCR3 values of Klav's instance roles.
    pub fn parent_roles(&self) -> &[Pcr] {
        &self.parent_roles
    }

    /// The hosted proxy's egress addresses, as CIDR blocks.
    pub fn egress(&self) -> &[String] {
        &self.egress
    }

    /// The image with these PCRs, if it is `current` or `draining`.
    pub fn image_for(&self, measurement: &Measurement) -> Result<&ManifestImage, NitroError> {
        let image = self
            .images
            .iter()
            .find(|i| i.measurement == *measurement)
            .ok_or(NitroError::ImageNotListed)?;
        if image.status == ImageStatus::Revoked {
            return Err(NitroError::ImageRevoked);
        }
        Ok(image)
    }
}

/// The signed message: `tuple("klav/v1/sig/enclave-manifest", SHA-256(manifest))`.
pub fn manifest_message(manifest: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(manifest);
    signed_message(LABEL_ENCLAVE_MANIFEST, &[digest.as_slice()])
        .expect("the manifest label starts with klav/v1/sig/")
}

/// Verifies a manifest against the pinned release-authority keys.
///
/// `highest_seq` is the highest `seq` this device verified before, if any;
/// the same `seq` again is accepted, a lower one is a rollback.
pub fn verify_manifest(
    manifest: &[u8],
    signature: &[u8; 64],
    highest_seq: Option<u64>,
    now_ms: u64,
) -> Result<VerifiedManifest, NitroError> {
    verify_manifest_with_keys(
        manifest,
        signature,
        RELEASE_AUTHORITY_KEYS,
        highest_seq,
        now_ms,
    )
}

/// [`verify_manifest`] with other keys: only the tests use it.
pub(crate) fn verify_manifest_with_keys(
    manifest: &[u8],
    signature: &[u8; 64],
    keys: &[[u8; 32]],
    highest_seq: Option<u64>,
    now_ms: u64,
) -> Result<VerifiedManifest, NitroError> {
    if keys.is_empty() {
        return Err(NitroError::NoReleaseKey);
    }
    if manifest.len() > MAX_MANIFEST_LEN {
        return Err(NitroError::ManifestMalformed("too large"));
    }
    let message = manifest_message(manifest);
    let signature = Signature::from_bytes(signature);
    let signed = keys.iter().any(|key| {
        VerifyingKey::from_bytes(key)
            .is_ok_and(|key| key.verify_strict(&message, &signature).is_ok())
    });
    if !signed {
        return Err(NitroError::ManifestSignature);
    }

    let wire: Wire = serde_json::from_slice(manifest)
        .map_err(|_| NitroError::ManifestMalformed("not a version 1 manifest"))?;
    let verified = wire.validate()?;
    if verified.issued_at_ms > now_ms.saturating_add(MANIFEST_CLOCK_SKEW_MS) {
        return Err(NitroError::ManifestFuture);
    }
    if now_ms >= verified.expires_at_ms {
        return Err(NitroError::ManifestExpired);
    }
    if highest_seq.is_some_and(|seen| verified.seq < seen) {
        return Err(NitroError::ManifestRollback);
    }
    Ok(verified)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    v: u32,
    seq: u64,
    seed_epoch: u32,
    issued_at_ms: u64,
    expires_at_ms: u64,
    endpoint: String,
    server: String,
    images: Vec<WireImage>,
    parent_roles: Vec<String>,
    egress: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireImage {
    version: String,
    commit: String,
    arch: String,
    pcr0: String,
    pcr1: String,
    pcr2: String,
    status: ImageStatus,
}

impl Wire {
    fn validate(self) -> Result<VerifiedManifest, NitroError> {
        let bad = NitroError::ManifestMalformed;
        if self.v != MANIFEST_VERSION {
            return Err(bad("unsupported version"));
        }
        if self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_MANIFEST_LIFETIME_MS
        {
            return Err(bad("validity longer than 30 days or empty"));
        }
        if !is_host(&self.endpoint) || !is_host(&self.server) {
            return Err(bad("endpoint or server is not a host name"));
        }
        if self.images.is_empty() {
            return Err(bad("no images"));
        }
        let mut images: Vec<ManifestImage> = Vec::with_capacity(self.images.len());
        for image in self.images {
            let measurement = Measurement {
                pcr0: pcr_hex(&image.pcr0).ok_or(bad("image PCR"))?,
                pcr1: pcr_hex(&image.pcr1).ok_or(bad("image PCR"))?,
                pcr2: pcr_hex(&image.pcr2).ok_or(bad("image PCR"))?,
            };
            if [measurement.pcr0, measurement.pcr1, measurement.pcr2]
                .iter()
                .any(|p| p.iter().all(|b| *b == 0))
            {
                return Err(bad("image PCR is zero"));
            }
            if images.iter().any(|i| i.measurement == measurement) {
                return Err(bad("image listed twice"));
            }
            let version = semver(&image.version).ok_or(bad("image version"))?;
            if image.commit.len() != 40 || !is_lower_hex(&image.commit) {
                return Err(bad("image commit"));
            }
            if image.arch != "aarch64" && image.arch != "x86_64" {
                return Err(bad("image arch"));
            }
            images.push(ManifestImage {
                version,
                version_text: image.version,
                commit: image.commit,
                arch: image.arch,
                measurement,
                status: image.status,
            });
        }
        let parent_roles = self
            .parent_roles
            .iter()
            .map(|r| pcr_hex(r).filter(|p| p.iter().any(|b| *b != 0)))
            .collect::<Option<Vec<_>>>()
            .ok_or(bad("parent role"))?;
        if self.egress.len() > MAX_EGRESS || !self.egress.iter().all(|e| is_cidr(e)) {
            return Err(bad("egress"));
        }
        Ok(VerifiedManifest {
            seq: self.seq,
            seed_epoch: self.seed_epoch,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            endpoint: self.endpoint,
            server: self.server,
            images,
            parent_roles,
            egress: self.egress,
        })
    }
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 96 lowercase hex digits.
fn pcr_hex(s: &str) -> Option<Pcr> {
    if s.len() != PCR_LEN * 2 || !is_lower_hex(s) {
        return None;
    }
    let mut out = [0u8; PCR_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// `MAJOR.MINOR.PATCH`, digits only, no leading zeros.
fn semver(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.split('.').map(|p| {
        let canonical = !p.is_empty()
            && p.len() <= 9
            && p.bytes().all(|b| b.is_ascii_digit())
            && (p == "0" || !p.starts_with('0'));
        canonical.then(|| p.parse::<u32>().ok()).flatten()
    });
    let v = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(v)
}

/// A lowercase DNS name: labels of `a-z`, `0-9` and `-`, separated by dots.
fn is_host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// `address/prefix`, IPv4 or IPv6, with the address written canonically.
fn is_cidr(s: &str) -> bool {
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    ip.to_string() == addr
        && prefix
            .parse::<u8>()
            .is_ok_and(|p| p <= max && p.to_string() == prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_grammars() {
        assert_eq!(semver("0.12.0"), Some((0, 12, 0)));
        for bad in ["0.12", "0.12.0.1", "01.2.3", "1..3", "1.2.x", "+1.2.3", ""] {
            assert_eq!(semver(bad), None, "{bad}");
        }
        assert!(is_host("proxy.klav.dev"));
        for bad in [
            "",
            "Proxy.klav.dev",
            "proxy..dev",
            "-a.dev",
            "a_b.dev",
            "a.dev.",
        ] {
            assert!(!is_host(bad), "{bad}");
        }
        assert!(is_cidr("203.0.113.10/32") && is_cidr("2001:db8::/48"));
        for bad in [
            "203.0.113.10",
            "203.0.113.10/33",
            "203.0.113.010/32",
            "2001:DB8::/48",
            "1.2.3.4/032",
        ] {
            assert!(!is_cidr(bad), "{bad}");
        }
    }
}
