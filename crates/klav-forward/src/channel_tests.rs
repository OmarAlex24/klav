//! The pinned channel against the cases ADR 0036 §6 must refuse, over real
//! TCP connections: a wrong proxy key, a right key with a wrong signature
//! (either side), TLS 1.2 (either side) and a client without a key. The
//! positive case and most negatives go through the production
//! constructors ([`server_config`], [`client_config`]).
//!
//! In TLS 1.3 the client's handshake ends before the server checks the
//! client's key: a refused client key shows on the server's `accept` and
//! on the first round trip, which every case runs.

use std::sync::Arc;

use klav_core::crypto::channel::TlsSigner;
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::crypto::sandbox::proxy_pin;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::channel::{
    AnyChannelKey, KeysByName, PinnedProxy, certified_with, client_config, peer_key, server_config,
    server_config_by_name,
};
use super::forward::{LEGACY_SERVER_NAME, server_name_for};

/// What each end saw: the server's peer key, or that it failed; and
/// whether the client's round trip worked.
struct Outcome {
    server: Result<Option<[u8; 32]>, String>,
    client_round_trip: bool,
}

async fn run(server: Arc<rustls::ServerConfig>, client: Arc<rustls::ClientConfig>) -> Outcome {
    run_named(
        server,
        client,
        ServerName::try_from("proxy.invalid").expect("name"),
    )
    .await
}

/// [`run`], with the client sending `name` (SNI).
async fn run_named(
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
) -> Outcome {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serve = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = TlsAcceptor::from(server)
            .accept(tcp)
            .await
            .map_err(|e| e.to_string())?;
        let key = peer_key(tls.get_ref().1);
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
        tls.write_all(b"pong").await.map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        Ok::<_, String>(key)
    });
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let client_round_trip = async {
        let mut tls = TlsConnector::from(client).connect(name, tcp).await.ok()?;
        tls.write_all(b"ping").await.ok()?;
        tls.flush().await.ok()?;
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.ok()?;
        (&buf == b"pong").then_some(())
    }
    .await
    .is_some();
    let server = serve.await.expect("server task");
    Outcome {
        server,
        client_round_trip,
    }
}

fn proxy() -> (IdentityKeyPair, [u8; 32]) {
    let identity = IdentityKeyPair::generate();
    let pin = proxy_pin(identity.public());
    (identity, pin)
}

fn assert_refused(outcome: &Outcome, what: &str) {
    assert!(outcome.server.is_err(), "{what}: the server accepted");
    assert!(!outcome.client_round_trip, "{what}: the round trip worked");
}

#[tokio::test]
async fn the_pinned_proxy_and_a_channel_key_talk_and_the_proxy_sees_the_key() {
    let (identity, pin) = proxy();
    let channel = TlsSigner::channel_key();
    let digest = channel.spki_sha256();
    let outcome = run(
        server_config(TlsSigner::server(&identity)).expect("server"),
        Arc::new(client_config(channel, pin).expect("client")),
    )
    .await;
    assert!(outcome.client_round_trip);
    assert_eq!(outcome.server, Ok(Some(digest)));
}

#[tokio::test]
async fn a_proxy_with_another_key_is_refused() {
    let (_, pin) = proxy();
    let (other, _) = proxy();
    let outcome = run(
        server_config(TlsSigner::server(&other)).expect("server"),
        Arc::new(client_config(TlsSigner::channel_key(), pin).expect("client")),
    )
    .await;
    assert_refused(&outcome, "wrong proxy key");
}

#[tokio::test]
async fn a_proxy_showing_the_pinned_key_without_holding_it_is_refused() {
    let (identity, pin) = proxy();
    let (impostor, _) = proxy();
    // The pinned SPKI, signed with another key.
    let key = certified_with(
        TlsSigner::server(&identity).spki(),
        TlsSigner::server(&impostor),
    );
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_client_cert_verifier(Arc::new(any_channel_key(&provider)))
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(key),
        ));
    let outcome = run(
        Arc::new(server),
        Arc::new(client_config(TlsSigner::channel_key(), pin).expect("client")),
    )
    .await;
    assert_refused(&outcome, "right proxy key, wrong signature");
}

#[tokio::test]
async fn a_client_showing_a_key_it_does_not_hold_is_refused() {
    let (identity, pin) = proxy();
    let shown = TlsSigner::channel_key();
    let key = certified_with(shown.spki(), TlsSigner::channel_key());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinned(&provider, pin)))
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(key),
        ));
    let outcome = run(
        server_config(TlsSigner::server(&identity)).expect("server"),
        Arc::new(client),
    )
    .await;
    assert_refused(&outcome, "right client key, wrong signature");
}

#[tokio::test]
async fn a_client_without_a_key_is_refused() {
    let (identity, pin) = proxy();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinned(&provider, pin)))
        .with_no_client_auth();
    let outcome = run(
        server_config(TlsSigner::server(&identity)).expect("server"),
        Arc::new(client),
    )
    .await;
    assert_refused(&outcome, "no client key");
}

#[tokio::test]
async fn tls_1_2_is_refused_on_either_side() {
    let (identity, pin) = proxy();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // A client that only speaks TLS 1.2, against the proxy.
    let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinned(&provider, pin)))
        .with_no_client_auth();
    let outcome = run(
        server_config(TlsSigner::server(&identity)).expect("server"),
        Arc::new(client),
    )
    .await;
    assert_refused(&outcome, "TLS 1.2 client");

    // A proxy that only speaks TLS 1.2 (with the pinned key in a
    // certificate's place), against the forwarder.
    let key = certified_with(
        TlsSigner::server(&identity).spki(),
        TlsSigner::server(&identity),
    );
    let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(key),
        ));
    let outcome = run(
        Arc::new(server),
        Arc::new(client_config(TlsSigner::channel_key(), pin).expect("client")),
    )
    .await;
    assert_refused(&outcome, "TLS 1.2 proxy");
}

#[test]
fn each_config_takes_only_its_own_side_of_key() {
    let (identity, pin) = proxy();
    assert!(server_config(TlsSigner::channel_key()).is_err());
    assert!(client_config(TlsSigner::server(&identity), pin).is_err());
}

fn any_channel_key(provider: &rustls::crypto::CryptoProvider) -> AnyChannelKey {
    AnyChannelKey::with_algorithms(provider.signature_verification_algorithms)
}

fn pinned(provider: &rustls::crypto::CryptoProvider, pin: [u8; 32]) -> PinnedProxy {
    PinnedProxy::with_algorithms(pin, provider.signature_verification_algorithms)
}

/// ADR 0051 §3.4: the forwarder sends the URL's host as SNI; an IP literal
/// sends none; a host that is not a name falls back to the old fixed one.
#[test]
fn the_server_name_is_the_urls_host() {
    let dns = |s: &str| ServerName::try_from(s.to_owned()).expect("name");
    for (address, expected) in [
        (
            "a0123abcd.proxy.klav.dev:443",
            dns("a0123abcd.proxy.klav.dev"),
        ),
        (
            "A0123ABCD.Proxy.Klav.Dev:443",
            dns("a0123abcd.proxy.klav.dev"),
        ),
        ("proxy.example.com:8443", dns("proxy.example.com")),
        ("127.0.0.1:4443", dns("127.0.0.1")),
        ("[::1]:4443", dns("::1")),
        ("[2001:db8::7]:443", dns("2001:db8::7")),
        ("under_score!:443", dns(LEGACY_SERVER_NAME)),
        (":443", dns(LEGACY_SERVER_NAME)),
        ("no-port", dns(LEGACY_SERVER_NAME)),
        ("[::1", dns(LEGACY_SERVER_NAME)),
    ] {
        assert_eq!(server_name_for(address), expected, "{address}");
    }
    assert!(matches!(
        server_name_for("[::1]:4443"),
        ServerName::IpAddress(_)
    ));
    assert!(matches!(
        server_name_for("10.0.0.7:443"),
        ServerName::IpAddress(_)
    ));
}

/// A hosted proxy (keys by name): the account's name gets the account's
/// key; the fixed name of an older forwarder, another account's name and
/// no name at all get nothing, and the handshake fails closed.
#[tokio::test]
async fn keys_by_name_serve_only_the_named_account() {
    let (a, pin_a) = proxy();
    let (b, pin_b) = proxy();
    let keys = Arc::new(KeysByName::default());
    keys.insert("a0a.proxy.klav.dev", TlsSigner::server(&a))
        .expect("insert");
    keys.insert("A0B.proxy.klav.dev", TlsSigner::server(&b))
        .expect("insert");
    assert!(keys.contains("a0b.PROXY.klav.dev"));
    assert!(
        keys.insert("a0c.proxy.klav.dev", TlsSigner::channel_key())
            .is_err()
    );
    let server = server_config_by_name(Arc::clone(&keys)).expect("server");
    let client = |pin| Arc::new(client_config(TlsSigner::channel_key(), pin).expect("client"));
    let name = |s: &str| server_name_for(&format!("{s}:443"));

    let ok = run_named(
        Arc::clone(&server),
        client(pin_a),
        name("a0a.proxy.klav.dev"),
    )
    .await;
    assert!(ok.server.is_ok() && ok.client_round_trip, "account A");
    let ok = run_named(
        Arc::clone(&server),
        client(pin_b),
        name("a0b.proxy.klav.dev"),
    )
    .await;
    assert!(ok.server.is_ok() && ok.client_round_trip, "account B");

    // A's pin with B's name: B's key is presented, and the pin refuses it.
    let crossed = run_named(
        Arc::clone(&server),
        client(pin_a),
        name("a0b.proxy.klav.dev"),
    )
    .await;
    assert_refused(&crossed, "A's pin at B's name");
    // An older forwarder: the fixed name matches no account.
    let legacy = run_named(
        Arc::clone(&server),
        client(pin_a),
        ServerName::try_from(LEGACY_SERVER_NAME).expect("name"),
    )
    .await;
    assert_refused(&legacy, "the fixed name");
    // An IP literal sends no SNI at all.
    let none = run_named(Arc::clone(&server), client(pin_a), name("127.0.0.1")).await;
    assert_refused(&none, "no SNI");
    // A removed account is gone at once.
    keys.remove("a0a.proxy.klav.dev");
    let removed = run_named(server, client(pin_a), name("a0a.proxy.klav.dev")).await;
    assert_refused(&removed, "a removed account");
}

/// A self-hosted proxy ignores SNI: the new forwarder (the URL's host) and
/// an older one (the fixed name) both reach it.
#[tokio::test]
async fn a_self_hosted_proxy_ignores_the_server_name() {
    let (identity, pin) = proxy();
    for name in [
        server_name_for("proxy.example.com:443"),
        server_name_for("127.0.0.1:443"),
        ServerName::try_from(LEGACY_SERVER_NAME).expect("name"),
    ] {
        let server = server_config(TlsSigner::server(&identity)).expect("server");
        let client = Arc::new(client_config(TlsSigner::channel_key(), pin).expect("client"));
        let outcome = run_named(server, client, name.clone()).await;
        assert!(
            outcome.server.is_ok() && outcome.client_round_trip,
            "{name:?}"
        );
    }
}
