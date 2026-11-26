//! What the enclave trusts (ADR 0051 §2.1, §4.2).
//!
//! - [`Anchors`]: AWS's Nitro root and the release authority's keys,
//!   compiled into `klav-core`. Only a test build can swap them for a test
//!   chain and test keys; a release build has no way to.
//! - [`ManifestSource`]: where the public copy of every signed manifest is
//!   read before a seed moves: `deploy/nitro/manifests/<seq>.json` and its
//!   `<seq>.json.sig` (128 hex characters) on the repository's default
//!   branch ([`PublishedRepo`]). A manifest the release authority signed but
//!   did not publish never moves the seed.

use futures_util::future::BoxFuture;
use klav_core::nitro::{
    HandoffHolder, HandoffPeer, ManifestImage, NitroError, VerifiedDocument, VerifiedManifest,
};

/// The public copy of the manifests, on the repository's default branch.
pub const DEFAULT_PUBLISHED_BASE: &str =
    "https://raw.githubusercontent.com/OmarAlex24/klav/main/deploy/nitro/manifests/";

/// A manifest and its release-authority signature, as served and published.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedManifest {
    /// The exact bytes the signature covers.
    pub bytes: Vec<u8>,
    /// The Ed25519 signature.
    pub signature: [u8; 64],
}

impl std::fmt::Debug for SignedManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedManifest")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl SignedManifest {
    /// The `.sig` file's text: 128 lowercase hex characters.
    pub fn signature_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.signature)
    }

    /// Parses a `.sig` file's text (an optional trailing newline).
    pub fn parse_signature(text: &str) -> Option<[u8; 64]> {
        let text = text.strip_suffix('\n').unwrap_or(text);
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(text.as_bytes())
            .ok()?
            .try_into()
            .ok()
    }
}

/// AWS's root and the release keys; in a test build, possibly test ones.
#[derive(Default)]
pub struct Anchors {
    #[cfg(all(test, feature = "enclave-testkit"))]
    test: Option<(Vec<u8>, Vec<[u8; 32]>)>,
}

impl Anchors {
    /// What a release build trusts: [`klav_core::nitro::AWS_NITRO_ROOT_G1`]
    /// and [`klav_core::nitro::RELEASE_AUTHORITY_KEYS`].
    pub fn production() -> Self {
        Self::default()
    }

    /// Tests: a fake NSM's root and test release keys.
    #[cfg(all(test, feature = "enclave-testkit"))]
    pub(crate) fn test(root: &[u8], keys: &[[u8; 32]]) -> Self {
        Self {
            test: Some((root.to_vec(), keys.to_vec())),
        }
    }

    /// The document's chain and signature.
    pub fn document(&self, document: &[u8], now_ms: u64) -> Result<VerifiedDocument, NitroError> {
        #[cfg(all(test, feature = "enclave-testkit"))]
        if let Some((root, _)) = &self.test {
            return klav_core::nitro::fake::verify_document_with(document, root, now_ms);
        }
        klav_core::nitro::verify_document(document, now_ms)
    }

    /// A manifest's signature, format, dates and `seq` watermark.
    pub fn manifest(
        &self,
        manifest: &SignedManifest,
        highest_seq: Option<u64>,
        now_ms: u64,
    ) -> Result<VerifiedManifest, NitroError> {
        #[cfg(all(test, feature = "enclave-testkit"))]
        if let Some((_, keys)) = &self.test {
            return klav_core::nitro::fake::verify_manifest_with(
                &manifest.bytes,
                &manifest.signature,
                keys,
                highest_seq,
                now_ms,
            );
        }
        klav_core::nitro::verify_manifest(&manifest.bytes, &manifest.signature, highest_seq, now_ms)
    }

    /// The holder's check of a joiner (§4.2 step 2).
    pub fn peer<'m>(
        &self,
        document: &[u8],
        manifest: &'m VerifiedManifest,
        own: &ManifestImage,
        nonce: &[u8],
        now_ms: u64,
    ) -> Result<HandoffPeer<'m>, NitroError> {
        #[cfg(all(test, feature = "enclave-testkit"))]
        if let Some((root, _)) = &self.test {
            return klav_core::nitro::fake::verify_handoff_peer_with(
                document, root, manifest, own, nonce, now_ms,
            );
        }
        klav_core::nitro::verify_handoff_peer(document, manifest, own, nonce, now_ms)
    }

    /// The joiner's check of the holder (§4.2 step 3).
    pub fn holder<'m>(
        &self,
        document: &[u8],
        manifest: &'m VerifiedManifest,
        nonce: &[u8],
        now_ms: u64,
    ) -> Result<HandoffHolder<'m>, NitroError> {
        #[cfg(all(test, feature = "enclave-testkit"))]
        if let Some((root, _)) = &self.test {
            return klav_core::nitro::fake::verify_handoff_holder_with(
                document, root, manifest, nonce, now_ms,
            );
        }
        klav_core::nitro::verify_handoff_holder(document, manifest, nonce, now_ms)
    }
}

/// Where the published copy of manifest `seq` is read.
pub trait ManifestSource: Send + Sync + 'static {
    /// Manifest `seq` and its signature, as published.
    fn fetch(&self, seq: u64) -> BoxFuture<'_, Result<SignedManifest, String>>;
}

/// The repository's published manifests, over HTTPS (inside the enclave,
/// through the parent's egress; TLS is terminated in the enclave).
pub struct PublishedRepo {
    base: reqwest::Url,
    client: reqwest::Client,
}

impl PublishedRepo {
    /// The manifests under `base` (a URL ending in `/`).
    pub fn new(base: &str, client: reqwest::Client) -> Result<Self, String> {
        let base = reqwest::Url::parse(base).map_err(|e| format!("manifest base URL: {e}"))?;
        if !base.path().ends_with('/') {
            return Err("the manifest base URL must end in /".into());
        }
        Ok(Self { base, client })
    }

    async fn get(&self, name: &str, max: usize) -> Result<Vec<u8>, String> {
        let url = self
            .base
            .join(name)
            .map_err(|_| "manifest URL".to_owned())?;
        let res = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| format!("{name}: the repository did not answer"))?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(format!("{name}: not published ({})", res.status().as_u16()));
        }
        let body = res
            .bytes()
            .await
            .map_err(|_| format!("{name}: the answer broke"))?;
        if body.len() > max {
            return Err(format!("{name}: too large"));
        }
        Ok(body.to_vec())
    }
}

impl ManifestSource for PublishedRepo {
    fn fetch(&self, seq: u64) -> BoxFuture<'_, Result<SignedManifest, String>> {
        Box::pin(async move {
            let bytes = self
                .get(&format!("{seq}.json"), klav_core::nitro::MAX_MANIFEST_LEN)
                .await?;
            let sig = self.get(&format!("{seq}.json.sig"), 256).await?;
            let signature = std::str::from_utf8(&sig)
                .ok()
                .and_then(SignedManifest::parse_signature)
                .ok_or_else(|| format!("{seq}.json.sig is not 128 hex characters"))?;
            Ok(SignedManifest { bytes, signature })
        })
    }
}

/// Whether `manifest` is, byte for byte, the one published under its `seq`
/// (ADR 0051 §4.2 step 2).
pub async fn is_published(
    source: &dyn ManifestSource,
    seq: u64,
    manifest: &SignedManifest,
) -> Result<(), String> {
    let published = source.fetch(seq).await?;
    if published != *manifest {
        return Err(format!(
            "manifest {seq} differs from the copy published in the repository"
        ));
    }
    Ok(())
}
