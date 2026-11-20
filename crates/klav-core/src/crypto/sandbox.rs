//! The sandbox package (`ksb1_…`, spec §13.10, ADR 0036 §4): what an issuer
//! hands to one sandbox so its forwarder can claim it at the credential
//! proxy, and the two digests around it.
//!
//! ```text
//! package = 0x01 ‖ sandbox_id(16) ‖ secret(32) ‖ u64_be(expires_at_ms)
//!                ‖ pin(32) ‖ lp(url)
//! text    = "ksb1_" ‖ BASE64URL-NO-PAD(package)
//! pin     = SHA-256(SPKI of the proxy's Ed25519 identity key)
//! digest  = SHA-256(tuple("klav/v1/sandbox/secret", sandbox_id, secret))
//! ```
//!
//! The package is **not a Klav key**: it decrypts nothing and signs nothing
//! before the server. Its secret is spent by the first claim (ADR 0036 §5);
//! the proxy keeps only its digest. Nothing here derives `Debug`: the
//! secret and the package never reach a log line.

use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::CryptoError;
use super::encoding::Tuple;
use super::identity::{IdentityKeyPair, PublicIdentity};
use super::random;
use super::sign::Signature;
use crate::ids::{AccountId, AgentId, SandboxId};

/// Prefix of the text form of a package.
pub const PACKAGE_PREFIX: &str = "ksb1_";
/// First byte of a package: its format version.
pub const PACKAGE_VERSION: u8 = 0x01;
/// Length of the one-time secret.
pub const SECRET_LEN: usize = 32;
/// Length of the proxy pin.
pub const PIN_LEN: usize = 32;
/// Longest proxy address in a package.
pub const MAX_URL: usize = 255;
/// The only scheme a package's address takes in this version: TLS 1.3 with
/// the pinned key, straight over TCP (ADR 0036 §6).
pub const URL_SCHEME: &str = "tls://";
/// Label of the digest the proxy keeps instead of the secret.
pub const LABEL_SECRET_DIGEST: &str = "klav/v1/sandbox/secret";
/// Bytes before the URL: version, ID, secret, expiry and pin.
const FIXED_LEN: usize = 1 + 16 + SECRET_LEN + 8 + PIN_LEN;
/// The DER `SubjectPublicKeyInfo` of an Ed25519 key (RFC 8410) up to the
/// key: `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused) }`.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// Length of an Ed25519 `SubjectPublicKeyInfo`.
pub const ED25519_SPKI_LEN: usize = 44;

/// The one-time secret of a sandbox. Zeroized on drop; never printed.
pub struct SandboxSecret(Zeroizing<[u8; SECRET_LEN]>);

impl SandboxSecret {
    /// A new random secret.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; SECRET_LEN]);
        random::fill(bytes.as_mut());
        Self(bytes)
    }

    /// A secret from its bytes (the proxy's answer, a test vector).
    pub fn from_bytes(bytes: &[u8; SECRET_LEN]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    /// The raw bytes.
    pub fn expose(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

/// What the proxy keeps instead of the secret:
/// `SHA-256(tuple("klav/v1/sandbox/secret", sandbox_id, secret))`. The ID
/// is inside so a digest of one sandbox never matches another's.
pub fn secret_digest(sandbox: SandboxId, secret: &SandboxSecret) -> [u8; 32] {
    let mut t = Tuple::new(LABEL_SECRET_DIGEST);
    t.push(sandbox.as_bytes()).push(secret.expose());
    // The tuple holds a copy of the secret.
    let bytes = Zeroizing::new(t.into_bytes());
    Sha256::digest(bytes.as_slice()).into()
}

/// Whether `secret` is the one behind `digest`, compared in constant time.
pub fn secret_matches(digest: &[u8; 32], sandbox: SandboxId, secret: &SandboxSecret) -> bool {
    secret_digest(sandbox, secret).ct_eq(digest).into()
}

/// The DER `SubjectPublicKeyInfo` of the identity's Ed25519 key, as a TLS
/// peer presents it (a raw public key, RFC 7250, or inside a certificate).
pub fn ed25519_spki(public: &PublicIdentity) -> [u8; ED25519_SPKI_LEN] {
    ed25519_spki_of(public.ed25519())
}

/// The DER `SubjectPublicKeyInfo` of an Ed25519 public key.
pub fn ed25519_spki_of(ed25519_public: &[u8; 32]) -> [u8; ED25519_SPKI_LEN] {
    let mut spki = [0u8; ED25519_SPKI_LEN];
    spki[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
    spki[ED25519_SPKI_PREFIX.len()..].copy_from_slice(ed25519_public);
    spki
}

/// The Ed25519 public key in a DER `SubjectPublicKeyInfo`, if it is exactly
/// one (RFC 8410: the fixed 12-byte prefix and 32 bytes of key).
pub fn ed25519_from_spki(spki: &[u8]) -> Option<[u8; 32]> {
    if spki.len() != ED25519_SPKI_LEN || spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return None;
    }
    spki[ED25519_SPKI_PREFIX.len()..].try_into().ok()
}

/// The pin of a proxy: `SHA-256(SPKI)` of its identity's Ed25519 key, the
/// key the person compared as six words when pairing it.
pub fn proxy_pin(public: &PublicIdentity) -> [u8; PIN_LEN] {
    Sha256::digest(ed25519_spki(public)).into()
}

/// What a `sandbox.claimed` says of the channel's key (ADR 0036 §5, E3.3):
/// `SHA-256(SPKI)` of the forwarder's Ed25519 channel key, the same
/// construction as the proxy pin, so both ends of the pinned channel are
/// named the same way.
pub fn channel_key_digest(ed25519_public: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(ed25519_spki_of(ed25519_public)).into()
}

/// Whether the SPKI a TLS peer presented is the pinned one:
/// `SHA-256(spki) == pin`, compared in constant time.
pub fn spki_matches_pin(spki: &[u8], pin: &[u8; PIN_LEN]) -> bool {
    let digest: [u8; 32] = Sha256::digest(spki).into();
    digest.ct_eq(pin).into()
}

/// Checks a proxy address: `tls://HOST:PORT`, at most [`MAX_URL`] bytes.
/// `HOST` is a lower-case DNS name (labels of `[a-z0-9-]`, 1–63 bytes, not
/// starting or ending with `-`), a dotted IPv4 address or a bracketed IPv6
/// address; `PORT` is 1–65535 in decimal without leading zeros.
pub fn check_proxy_url(url: &str) -> Result<(), CryptoError> {
    const BAD: CryptoError =
        CryptoError::Malformed("proxy address must be tls://host:port (at most 255 bytes)");
    if url.len() > MAX_URL {
        return Err(BAD);
    }
    let rest = url.strip_prefix(URL_SCHEME).ok_or(BAD)?;
    let (host, port) = rest.rsplit_once(':').ok_or(BAD)?;
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && !port.starts_with('0')
        && port.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p));
    if !port_ok || !host_ok(host) {
        return Err(BAD);
    }
    Ok(())
}

fn host_ok(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok()
            && inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
            && !inner.bytes().any(|b| b.is_ascii_uppercase());
    }
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let numeric = labels
        .last()
        .is_some_and(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()));
    if numeric {
        // A name whose last label is a number is an IPv4 address or
        // nothing: only the dotted form of four decimals counts.
        return host.parse::<std::net::Ipv4Addr>().is_ok();
    }
    labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// A sandbox package. No `Debug`: it holds the secret.
pub struct SandboxPackage {
    /// The sandbox.
    pub sandbox_id: SandboxId,
    /// The one-time secret its forwarder claims it with.
    pub secret: SandboxSecret,
    /// When it lapses (Unix ms).
    pub expires_at_ms: u64,
    /// `SHA-256(SPKI)` of the proxy's key ([`proxy_pin`]).
    pub proxy_pin: [u8; PIN_LEN],
    /// Where the forwarder reaches the proxy ([`check_proxy_url`]).
    pub url: String,
}

/// Encodes a package in its text form. Refuses an address that
/// [`check_proxy_url`] refuses and an expiry of `0`.
pub fn encode_package(package: &SandboxPackage) -> Result<Zeroizing<String>, CryptoError> {
    check_proxy_url(&package.url)?;
    if package.expires_at_ms == 0 {
        return Err(CryptoError::Malformed("sandbox package without an expiry"));
    }
    let url = package.url.as_bytes();
    let url_len = u32::try_from(url.len()).expect("checked above");
    let mut blob = Zeroizing::new(Vec::with_capacity(FIXED_LEN + 4 + url.len()));
    blob.push(PACKAGE_VERSION);
    blob.extend_from_slice(package.sandbox_id.as_bytes());
    blob.extend_from_slice(package.secret.expose());
    blob.extend_from_slice(&package.expires_at_ms.to_be_bytes());
    blob.extend_from_slice(&package.proxy_pin);
    blob.extend_from_slice(&url_len.to_be_bytes());
    blob.extend_from_slice(url);
    let mut text = Zeroizing::new(String::with_capacity(
        PACKAGE_PREFIX.len() + BASE64URL_NOPAD.encode_len(blob.len()),
    ));
    text.push_str(PACKAGE_PREFIX);
    BASE64URL_NOPAD.encode_append(&blob, &mut text);
    Ok(text)
}

/// Decodes [`encode_package`]. Surrounding whitespace is ignored. Rejects:
/// another prefix, invalid base64url, another version, a short package, an
/// expiry of `0`, a URL length that does not match what follows (no
/// trailing bytes) and an address [`check_proxy_url`] refuses.
pub fn decode_package(text: &str) -> Result<SandboxPackage, CryptoError> {
    let body = text
        .trim()
        .strip_prefix(PACKAGE_PREFIX)
        .ok_or(CryptoError::Malformed(
            "sandbox package must start with ksb1_",
        ))?;
    let blob = Zeroizing::new(
        BASE64URL_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| CryptoError::Malformed("sandbox package is not base64url"))?,
    );
    if blob.first() != Some(&PACKAGE_VERSION) {
        return Err(CryptoError::Malformed("unknown sandbox package version"));
    }
    if blob.len() < FIXED_LEN + 4 {
        return Err(CryptoError::Malformed("sandbox package is too short"));
    }
    let mut at = 1;
    let mut take = |n: usize| {
        let part = &blob[at..at + n];
        at += n;
        part
    };
    let sandbox_id = SandboxId::from_bytes(take(16).try_into().expect("16 bytes"));
    let secret = SandboxSecret::from_bytes(take(SECRET_LEN).try_into().expect("32 bytes"));
    let expires_at_ms = u64::from_be_bytes(take(8).try_into().expect("8 bytes"));
    let proxy_pin: [u8; PIN_LEN] = take(PIN_LEN).try_into().expect("32 bytes");
    let url_len = u32::from_be_bytes(take(4).try_into().expect("4 bytes"));
    let url = blob[at..].to_vec();
    if usize::try_from(url_len).ok() != Some(url.len()) {
        return Err(CryptoError::Malformed(
            "sandbox package address length does not match",
        ));
    }
    if expires_at_ms == 0 {
        return Err(CryptoError::Malformed("sandbox package without an expiry"));
    }
    let url = String::from_utf8(url)
        .map_err(|_| CryptoError::Malformed("sandbox package address is not text"))?;
    check_proxy_url(&url)?;
    Ok(SandboxPackage {
        sandbox_id,
        secret,
        expires_at_ms,
        proxy_pin,
        url,
    })
}

/// Label of the person's revocation of sandboxes, signed by the account
/// (spec §13.11, ADR 0036 E3.3).
pub const LABEL_SANDBOX_REVOKE: &str = "klav/v1/sig/sandbox-revoke";

/// What a person's revocation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeScope {
    /// Every sandbox of the proxy that the log issued before the
    /// revocation's `sandbox.revoke_requested`. The log's order decides,
    /// never `at_ms`.
    All,
    /// One sandbox.
    Sandbox(SandboxId),
}

impl RevokeScope {
    /// The signed `scope` field: the ASCII bytes `all`, or the sandbox's 16
    /// raw ID bytes. The lengths differ, so the two never collide.
    pub fn signed_bytes(&self) -> &[u8] {
        match self {
            RevokeScope::All => b"all",
            RevokeScope::Sandbox(sandbox) => sandbox.as_bytes(),
        }
    }
}

/// A person's revocation of sandboxes, as the account signs it (spec
/// §13.11): `tuple("klav/v1/sig/sandbox-revoke", account_id, proxy_id,
/// scope, u64_be(at_ms))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeToSign {
    /// The account.
    pub account: AccountId,
    /// The proxy whose sandboxes it revokes (an agent of the account).
    pub proxy: AgentId,
    /// One sandbox, or all of that proxy's.
    pub scope: RevokeScope,
    /// When the person revoked, Unix ms. Only against replays: each
    /// revocation of a scope must be later than the previous one.
    pub at_ms: u64,
}

impl RevokeToSign {
    fn fields(&self) -> [Vec<u8>; 4] {
        [
            self.account.as_bytes().to_vec(),
            self.proxy.as_bytes().to_vec(),
            self.scope.signed_bytes().to_vec(),
            self.at_ms.to_be_bytes().to_vec(),
        ]
    }

    /// The signed message (test vectors).
    pub fn message(&self) -> Vec<u8> {
        let fields = self.fields();
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        super::sign::signed_message(LABEL_SANDBOX_REVOKE, &refs).expect("valid label")
    }
}

/// Signs a revocation of sandboxes with the account identity.
pub fn sign_revoke(account: &IdentityKeyPair, revoke: &RevokeToSign) -> Signature {
    let fields = revoke.fields();
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    super::sign::sign(account, LABEL_SANDBOX_REVOKE, &refs).expect("valid label")
}

/// Verifies [`sign_revoke`].
pub fn verify_revoke(
    account: &PublicIdentity,
    revoke: &RevokeToSign,
    signature: &Signature,
) -> Result<(), CryptoError> {
    let fields = revoke.fields();
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    super::sign::verify(account, LABEL_SANDBOX_REVOKE, &refs, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::IdentityKeyPair;

    fn package(url: &str) -> SandboxPackage {
        SandboxPackage {
            sandbox_id: SandboxId::generate(),
            secret: SandboxSecret::generate(),
            expires_at_ms: 1_800_000_000_000,
            proxy_pin: proxy_pin(IdentityKeyPair::generate().public()),
            url: url.to_owned(),
        }
    }

    #[test]
    fn a_package_survives_its_text_form() {
        let p = package("tls://proxy.example.com:8443");
        let text = encode_package(&p).expect("encodes");
        assert!(text.starts_with("ksb1_"));
        let back = decode_package(&format!("  {}\n", text.as_str())).expect("decodes");
        assert_eq!(back.sandbox_id, p.sandbox_id);
        assert_eq!(back.secret.expose(), p.secret.expose());
        assert_eq!(back.expires_at_ms, p.expires_at_ms);
        assert_eq!(back.proxy_pin, p.proxy_pin);
        assert_eq!(back.url, p.url);
    }

    #[test]
    fn addresses_are_tls_host_and_port_only() {
        for good in [
            "tls://proxy.example.com:8443",
            "tls://a:1",
            "tls://100.64.1.2:8790",
            "tls://[fd7a:115c:a1e0::1]:443",
            "tls://my-proxy.up.railway.app:65535",
        ] {
            assert!(check_proxy_url(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "https://proxy.example.com:443",
            "tls://proxy.example.com",
            "tls://proxy.example.com:",
            "tls://proxy.example.com:0",
            "tls://proxy.example.com:65536",
            "tls://proxy.example.com:080",
            "tls://Proxy.example.com:443",
            "tls://proxy.example.com.:443",
            "tls://-proxy.example.com:443",
            "tls://proxy..example.com:443",
            "tls://user@proxy.example.com:443",
            "tls://proxy.example.com:443/path",
            "tls://10.1:443",
            "tls://[FD7A::1]:443",
            "tls://[not-ipv6]:443",
            "tls://:443",
        ] {
            assert!(check_proxy_url(bad).is_err(), "{bad}");
        }
        let long = format!("tls://{}.example.com:443", "a.".repeat(130));
        assert!(check_proxy_url(&long).is_err());
    }

    #[test]
    fn a_damaged_package_is_refused() {
        let p = package("tls://proxy.example.com:8443");
        let text = encode_package(&p).expect("encodes");
        let blob = BASE64URL_NOPAD
            .decode(
                text.strip_prefix(PACKAGE_PREFIX)
                    .expect("prefix")
                    .as_bytes(),
            )
            .expect("base64");
        let enc = |b: &[u8]| format!("{PACKAGE_PREFIX}{}", BASE64URL_NOPAD.encode(b));
        let mut other_version = blob.clone();
        other_version[0] = 0x02;
        let mut trailing = blob.clone();
        trailing.push(0);
        let short = blob[..blob.len() - 1].to_vec();
        let mut no_expiry = blob.clone();
        no_expiry[49..57].copy_from_slice(&[0; 8]);
        for bad in [
            format!("ksb2_{}", BASE64URL_NOPAD.encode(&blob)),
            format!("{PACKAGE_PREFIX}!!!"),
            enc(&other_version),
            enc(&trailing),
            enc(&short),
            enc(&blob[..20]),
            enc(&no_expiry),
        ] {
            assert!(decode_package(&bad).is_err());
        }
        assert!(encode_package(&package("https://proxy.example.com:443")).is_err());
    }

    #[test]
    fn the_digest_binds_the_sandbox() {
        let secret = SandboxSecret::generate();
        let one = SandboxId::generate();
        let digest = secret_digest(one, &secret);
        assert!(secret_matches(&digest, one, &secret));
        assert!(!secret_matches(&digest, SandboxId::generate(), &secret));
        assert!(!secret_matches(&digest, one, &SandboxSecret::generate()));
    }

    #[test]
    fn the_pin_is_the_hash_of_the_ed25519_spki() {
        let keys = IdentityKeyPair::generate();
        let spki = ed25519_spki(keys.public());
        assert_eq!(&spki[..12], &ED25519_SPKI_PREFIX);
        assert_eq!(&spki[12..], keys.public().ed25519());
        let pin: [u8; 32] = Sha256::digest(spki).into();
        assert_eq!(proxy_pin(keys.public()), pin);
    }

    #[test]
    fn a_revocation_verifies_only_for_what_was_signed() {
        let account = IdentityKeyPair::generate();
        let revoke = RevokeToSign {
            account: AccountId::generate(),
            proxy: AgentId::generate(),
            scope: RevokeScope::Sandbox(SandboxId::generate()),
            at_ms: 1_800_000_000_000,
        };
        let signature = sign_revoke(&account, &revoke);
        assert!(verify_revoke(account.public(), &revoke, &signature).is_ok());
        let other = IdentityKeyPair::generate();
        assert!(verify_revoke(other.public(), &revoke, &signature).is_err());
        for changed in [
            RevokeToSign {
                account: AccountId::generate(),
                ..revoke
            },
            RevokeToSign {
                proxy: AgentId::generate(),
                ..revoke
            },
            RevokeToSign {
                scope: RevokeScope::All,
                ..revoke
            },
            RevokeToSign {
                scope: RevokeScope::Sandbox(SandboxId::generate()),
                ..revoke
            },
            RevokeToSign {
                at_ms: revoke.at_ms + 1,
                ..revoke
            },
        ] {
            assert!(
                verify_revoke(account.public(), &changed, &signature).is_err(),
                "{changed:?}"
            );
        }
        // The message starts with its own label.
        let message = revoke.message();
        let label = LABEL_SANDBOX_REVOKE.as_bytes();
        let len = u32::try_from(label.len()).unwrap().to_be_bytes();
        assert_eq!(&message[..4], &len);
        assert_eq!(&message[4..4 + label.len()], label);
    }
}
