//! The pinned channel between a sandbox's forwarder and the credential
//! proxy (ADR 0036 §6): TLS 1.3 only, through `rustls` with the `aws-lc-rs`
//! provider, with raw Ed25519 public keys on both ends (RFC 7250) instead
//! of certificates.
//!
//! Both configurations live here so the proxy and the forwarder share them
//! and their tests. Nothing here is cryptography of its own:
//!
//! - **Handshake signatures** are checked by rustls
//!   ([`rustls::crypto::verify_tls13_signature_with_raw_key`] with the
//!   provider's algorithms); the verifiers only decide *which* key is
//!   acceptable.
//! - **Our signatures** come from [`TlsSigner`] in `klav-core`, which signs
//!   a TLS 1.3 `CertificateVerify` and nothing else.
//!
//! What each verifier checks, and what it leaves to others:
//!
//! - [`PinnedProxy`] (the forwarder checks the proxy): the proxy presents
//!   exactly one raw public key, it is an Ed25519 SPKI, and its SHA-256 is
//!   the pin from the package (constant-time). It ignores the server name
//!   (the pin names the proxy, not DNS) and the time (a raw key has no
//!   validity period). It refuses TLS 1.2 and any scheme but Ed25519.
//! - [`AnyChannelKey`] (the proxy checks the forwarder): the forwarder
//!   presents exactly one raw public key and it is an Ed25519 SPKI. It
//!   does **not** decide whether that key may do anything: a fresh key is
//!   how every claim starts. The proxy's application layer decides, by the
//!   SHA-256 of the key ([`peer_key`]), which sandbox, if any, the
//!   connection speaks for. A client without a key fails the handshake.

use std::sync::Arc;

use klav_core::crypto::channel::{Side, TlsSigner};
use klav_core::crypto::sandbox::{PIN_LEN, ed25519_from_spki, spki_matches_pin};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error,
    PeerIncompatible, ServerConfig, SignatureAlgorithm, SignatureScheme,
};

/// The only signature scheme of the channel.
const SCHEME: SignatureScheme = SignatureScheme::ED25519;

/// The provider: aws-lc-rs, as every Klav client (ADR 0011).
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The proxy's side: TLS 1.3 only, its identity as a raw public key, and a
/// raw Ed25519 key required from every client.
pub fn server_config(signer: TlsSigner) -> Result<Arc<ServerConfig>, Error> {
    if signer.side() != Side::Server {
        return Err(Error::General(
            "a client key cannot serve the channel".into(),
        ));
    }
    let provider = provider();
    let key = certified(signer);
    let mut config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AnyChannelKey::with_algorithms(
            provider.signature_verification_algorithms,
        )))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(key)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // No resumption: every connection proves its key again.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

/// The forwarder's side: TLS 1.3 only, the proxy accepted only with the
/// pinned key, and the channel key as the client's raw public key.
pub fn client_config(signer: TlsSigner, pin: [u8; PIN_LEN]) -> Result<ClientConfig, Error> {
    if signer.side() != Side::Client {
        return Err(Error::General(
            "the proxy's key cannot be a channel key".into(),
        ));
    }
    let provider = provider();
    let key = certified(signer);
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedProxy::with_algorithms(
            pin,
            provider.signature_verification_algorithms,
        )))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(key)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// The SHA-256 of the client's raw public key on an established
/// connection: what a sandbox is bound to. `None` if the client presented
/// no key, or not exactly one Ed25519 key (the verifier refuses both, so
/// only a misconfigured server sees it).
pub fn peer_key(conn: &rustls::ServerConnection) -> Option<[u8; 32]> {
    let [spki] = conn.peer_certificates()? else {
        return None;
    };
    let key = ed25519_from_spki(spki.as_ref())?;
    Some(klav_core::crypto::sandbox::channel_key_digest(&key))
}

fn certified(signer: TlsSigner) -> Arc<CertifiedKey> {
    let spki = signer.spki();
    certified_with(spki, signer)
}

/// `signer` presented as the key `spki`: the same key in production; a
/// test gives another one to check that a wrong signature fails.
pub(crate) fn certified_with(
    spki: [u8; klav_core::crypto::sandbox::ED25519_SPKI_LEN],
    signer: TlsSigner,
) -> Arc<CertifiedKey> {
    Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(spki.to_vec())],
        Arc::new(ChannelKey {
            signer: Arc::new(signer),
            spki,
        }),
    ))
}

/// A [`TlsSigner`] as rustls's signing key.
struct ChannelKey {
    signer: Arc<TlsSigner>,
    spki: [u8; klav_core::crypto::sandbox::ED25519_SPKI_LEN],
}

impl std::fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelKey(Ed25519)")
    }
}

impl SigningKey for ChannelKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SCHEME)
            .then(|| Box::new(ChannelSigner(Arc::clone(&self.signer))) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(&self.spki[..]))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

struct ChannelSigner(Arc<TlsSigner>);

impl std::fmt::Debug for ChannelSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelSigner(Ed25519)")
    }
}

impl Signer for ChannelSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.0
            .sign_certificate_verify(message)
            .map(|s| s.to_vec())
            .map_err(|_| Error::General("refused to sign".into()))
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

/// One raw Ed25519 public key and nothing else.
fn one_ed25519_key(end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>]) -> bool {
    intermediates.is_empty() && ed25519_from_spki(end_entity.as_ref()).is_some()
}

/// rustls's own check of a TLS 1.3 handshake signature with a raw key,
/// for Ed25519 only.
fn check_signature(
    algorithms: &WebPkiSupportedAlgorithms,
    message: &[u8],
    key: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    if dss.scheme != SCHEME {
        return Err(PeerIncompatible::NoSignatureSchemesInCommon.into());
    }
    rustls::crypto::verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(key.as_ref()),
        dss,
        algorithms,
    )
}

/// The forwarder's check of the proxy: the pinned key, nothing else.
#[derive(Debug)]
pub struct PinnedProxy {
    pin: [u8; PIN_LEN],
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedProxy {
    /// The check for `pin`, with the provider's signature algorithms.
    pub fn with_algorithms(pin: [u8; PIN_LEN], algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self { pin, algorithms }
    }
}

impl ServerCertVerifier for PinnedProxy {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if one_ed25519_key(end_entity, intermediates)
            && spki_matches_pin(end_entity.as_ref(), &self.pin)
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("the channel is TLS 1.3 only".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        check_signature(&self.algorithms, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The proxy's check of a forwarder: any one raw Ed25519 key, required.
#[derive(Debug)]
pub struct AnyChannelKey {
    algorithms: WebPkiSupportedAlgorithms,
}

impl AnyChannelKey {
    /// The check, with the provider's signature algorithms.
    pub fn with_algorithms(algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self { algorithms }
    }
}

impl ClientCertVerifier for AnyChannelKey {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if one_ed25519_key(end_entity, intermediates) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(CertificateError::BadEncoding))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("the channel is TLS 1.3 only".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        check_signature(&self.algorithms, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
