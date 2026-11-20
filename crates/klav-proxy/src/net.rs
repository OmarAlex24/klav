//! The way out to the provider (ADR 0036 §7): HTTPS only, no redirects,
//! no proxy from the environment, no transparent decompression, and a
//! resolver that refuses the whole lookup when any address it returns is
//! not a public unicast address. The connector only ever sees addresses
//! this resolver returned, so the check is on the address actually
//! connected to, with no second lookup in between.
//!
//! A release build has one constructor, [`upstream_client`], with the
//! system resolver, no exemptions and the system's roots. Tests get
//! another one (`test_client`) that only test code can call: a fake
//! lookup, an exempt loopback address for the fake upstream, and a root
//! store that holds only the fixture CA. The classifier is the same.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// How long connecting to the provider may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether `ip` is a public unicast address the proxy may connect to.
///
/// Refused: unspecified, loopback, private (RFC 1918), shared (CGNAT,
/// `100.64.0.0/10`, where some clouds put their metadata service),
/// link-local (`169.254.0.0/16`, the usual metadata address), the IETF and
/// documentation ranges, benchmarking, multicast, reserved and broadcast;
/// for IPv6 everything outside global unicast `2000::/3`, unique local
/// (`fc00::/7`, where AWS's IPv6 metadata lives), the documentation,
/// discard, ORCHID and Teredo ranges. IPv4 inside IPv6 is unwrapped and
/// judged as IPv4: mapped (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`) and
/// 6to4 (`2002::/16`); compatible (`::a.b.c.d`) and local NAT64
/// (`64:ff9b:1::/48`) are refused.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let refused = a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (18..20).contains(&b))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224;
    !refused
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let embedded =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    // ::ffff:a.b.c.d
    if s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        return is_public_v4(embedded(s[6], s[7]));
    }
    // 64:ff9b::a.b.c.d (well-known NAT64 prefix)
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_v4(embedded(s[6], s[7]));
    }
    // 2002:AABB:CCDD::/48 (6to4)
    if s[0] == 0x2002 {
        return is_public_v4(embedded(s[1], s[2]));
    }
    // Only global unicast (2000::/3).
    if s[0] & 0xe000 != 0x2000 {
        return false;
    }
    let refused = (s[0] == 0x2001 && s[1] < 0x0200) // IETF protocol assignments (Teredo, ORCHID…)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || s[0] == 0x3fff; // documentation (RFC 9637)
    !refused
}

/// Looks a host name up. The release build uses the system resolver.
pub(crate) trait Lookup: Send + Sync {
    fn lookup(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>>;
}

struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>> {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    }
}

/// A lookup refused because of the addresses it returned.
#[derive(Debug)]
pub struct RefusedAddress;

impl std::fmt::Display for RefusedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the host resolves to an address the proxy does not connect to")
    }
}

impl std::error::Error for RefusedAddress {}

/// The resolver the upstream client uses.
pub(crate) struct GuardedResolver {
    lookup: Arc<dyn Lookup>,
    /// Addresses allowed although not public: always empty in a release
    /// build (only `test_client` sets it).
    exempt: Vec<IpAddr>,
}

impl GuardedResolver {
    /// The addresses `host` may be connected to: all of them public (or
    /// exempt), at least one, or an error. One refused address refuses the
    /// whole lookup, so the connector cannot fall back to it.
    pub(crate) async fn resolve_checked(&self, host: &str) -> Result<Vec<IpAddr>, RefusedAddress> {
        let addrs = self
            .lookup
            .lookup(host.to_owned())
            .await
            .map_err(|_| RefusedAddress)?;
        if addrs.is_empty()
            || addrs
                .iter()
                .any(|ip| !is_public(*ip) && !self.exempt.contains(ip))
        {
            return Err(RefusedAddress);
        }
        Ok(addrs)
    }
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let lookup = Arc::clone(&self.lookup);
        let exempt = self.exempt.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let this = GuardedResolver { lookup, exempt };
            let addrs = this.resolve_checked(&host).await?;
            let addrs: Addrs = Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

/// The settings every upstream client shares.
fn base(resolver: GuardedResolver) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .dns_resolver(resolver)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        // `HTTPS_PROXY` and friends would send the request somewhere the
        // resolver never sees.
        .no_proxy()
        // The body goes back redacted; reqwest must not decode it (another
        // crate turning a decompression feature on would make it).
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(concat!("klav-proxy/", env!("CARGO_PKG_VERSION")))
}

/// The roots the provider's certificate is checked against: the system's,
/// through the platform verifier that every Klav client uses (ADR 0011).
/// On Linux that is the CA bundle the image installs; [`check_roots`]
/// refuses to start without one. ADR 0036 §7 says "webpki roots": whether
/// that means the system's public roots, as here, or the `webpki-roots`
/// crate (a new lockfile entry) is an open decision for the owner, and
/// this is the one place to change.
fn with_roots(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
}

/// The client a release build uses to reach providers.
pub fn upstream_client() -> reqwest::Result<reqwest::Client> {
    with_roots(base(GuardedResolver {
        lookup: Arc::new(SystemLookup),
        exempt: Vec::new(),
    }))
    .build()
}

/// Fails, with a message for the person, when the system has no root
/// certificates: without them every provider would fail, and an empty
/// store is never a reason to trust anything else.
pub fn check_roots() -> Result<usize, String> {
    #[cfg(target_os = "linux")]
    {
        let found = rustls_native_certs::load_native_certs();
        if found.certs.is_empty() {
            return Err(
                "no root certificates found on this system: install the CA bundle (on Debian, the ca-certificates package) so the proxy can check the providers' certificates"
                    .into(),
            );
        }
        Ok(found.certs.len())
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS and Windows verify through the system's own trust store.
        Ok(0)
    }
}

/// A client for tests: `lookup` instead of the system resolver, `exempt`
/// addresses allowed (the fake upstream's loopback), and only `ca` as a
/// root. Never reachable from a release build.
#[cfg(test)]
pub(crate) fn test_client(
    lookup: Arc<dyn Lookup>,
    exempt: Vec<IpAddr>,
    ca_der: &[u8],
) -> reqwest::Result<reqwest::Client> {
    let ca = reqwest::Certificate::from_der(ca_der)?;
    base(GuardedResolver { lookup, exempt })
        .tls_certs_only([ca])
        .build()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A lookup with fixed answers that counts how often it is asked.
    pub(crate) struct FakeLookup {
        pub(crate) answers: HashMap<String, Vec<IpAddr>>,
        pub(crate) calls: AtomicUsize,
    }

    impl FakeLookup {
        pub(crate) fn new(answers: &[(&str, &[IpAddr])]) -> Arc<Self> {
            Arc::new(Self {
                answers: answers
                    .iter()
                    .map(|(h, a)| ((*h).to_owned(), a.to_vec()))
                    .collect(),
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl Lookup for FakeLookup {
        fn lookup(
            &self,
            host: String,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let found = self.answers.get(&host).cloned();
            Box::pin(async move {
                found.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "no such host")
                })
            })
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_public_unicast_addresses_pass() {
        for refused in [
            "0.0.0.0",
            "127.0.0.1",
            "127.255.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.100.100.200",
            "169.254.169.254",
            "169.254.170.2",
            "192.0.0.192",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "2002:a9fe:a9fe::1",
            "2002:0a00:0001::1",
            "fc00::1",
            "fd00:ec2::254",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "3fff::1",
            "100::1",
        ] {
            assert!(!is_public(ip(refused)), "{refused} must be refused");
        }
        for public in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "::ffff:1.1.1.1",
            "64:ff9b::808:808",
            "2002:0808:0808::1",
        ] {
            assert!(is_public(ip(public)), "{public} must pass");
        }
    }

    #[tokio::test]
    async fn the_release_resolver_refuses_the_whole_lookup_on_one_bad_address() {
        let lookup = FakeLookup::new(&[
            ("public.test", &[ip("1.1.1.1")]),
            ("mixed.test", &[ip("1.1.1.1"), ip("10.0.0.1")]),
            ("mapped.test", &[ip("::ffff:127.0.0.1")]),
            ("metadata.test", &[ip("169.254.169.254")]),
            ("cgnat.test", &[ip("100.64.1.1")]),
            ("linklocal.test", &[ip("fe80::1")]),
            ("loopback.test", &[ip("127.0.0.1")]),
            ("empty.test", &[]),
        ]);
        let resolver = GuardedResolver {
            lookup: lookup.clone(),
            exempt: Vec::new(),
        };
        assert_eq!(
            resolver.resolve_checked("public.test").await.unwrap(),
            vec![ip("1.1.1.1")]
        );
        for bad in [
            "mixed.test",
            "mapped.test",
            "metadata.test",
            "cgnat.test",
            "linklocal.test",
            "loopback.test",
            "empty.test",
            "unknown.test",
        ] {
            assert!(resolver.resolve_checked(bad).await.is_err(), "{bad}");
        }
    }

    /// The release constructor refuses `localhost` at connect time: the
    /// system lookup answers loopback and nothing is exempt.
    #[tokio::test]
    async fn the_release_client_never_connects_to_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .is_ok()
        });
        let client = upstream_client().unwrap();
        let err = client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .expect_err("loopback must be refused");
        assert!(
            std::error::Error::source(&err).is_some(),
            "a connect error, not a response"
        );
        assert!(!accepted.await.unwrap(), "nothing may reach the listener");
    }

    /// The connector uses exactly what the resolver returned, after one
    /// lookup: no second resolution between the check and the connection.
    #[tokio::test]
    async fn one_lookup_per_connection_and_its_addresses_are_used() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let lookup = FakeLookup::new(&[("upstream.test", &[ip("127.0.0.1")])]);
        let accepted = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .is_ok()
        });
        let client = test_client(
            lookup.clone(),
            vec![ip("127.0.0.1")],
            include_bytes!("../tests/fixtures/ca.der"),
        )
        .unwrap();
        // The TLS handshake fails (nobody answers it), but the connection
        // reached the address the resolver returned.
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            client.get(format!("https://upstream.test:{port}/")).send(),
        )
        .await;
        assert!(accepted.await.unwrap());
        assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
    }
}
