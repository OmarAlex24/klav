//! The only place that reads the grant's per-item format (ADR 0036 §2,
//! spec §13.4): its `profiles`, its `items` and the `proxy` rules of its
//! policy. Everything else in the proxy sees a [`Profile`] and a
//! [`ProxyCall`]: a change to the grant's shape is a change here.

use std::collections::HashMap;

use axum::http::{HeaderName, HeaderValue};
use klav_client::{ClientError, ClientResult};
use klav_core::ids::ItemId;
use klav_core::model::Item;
use klav_core::model::item::{FieldKind, ItemKind};
use klav_sdk::grant::OpenGrant;
use klav_sdk::{ProxyCall, Session};
use zeroize::Zeroizing;

/// Where a profile sends its requests: always HTTPS, never an IP literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// Host name, normalized (lower case, no trailing dot).
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Upstream {
    /// `https://host[:port]`, without a path.
    pub fn origin(&self) -> String {
        if self.port == 443 {
            format!("https://{}", self.host)
        } else {
            format!("https://{}:{}", self.host, self.port)
        }
    }
}

/// A profile the person signed, ready to use. It holds no value, only
/// where the value goes.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Its name: the first segment of the local URL in mode (a).
    pub name: String,
    /// The item whose value it uses.
    pub item: ItemId,
    pub(crate) field: Option<String>,
    /// The header the value goes in.
    pub header: HeaderName,
    pub(crate) prefix: String,
    /// Where requests go.
    pub upstream: Upstream,
    /// Most calls per minute.
    pub rate_per_minute: u32,
    /// An MCP profile's endpoint and fixed headers (ADR 0049 §2.1): the
    /// proxy forwards only that path and governs its JSON-RPC
    /// ([`crate::mcp`]).
    pub mcp: Option<McpEndpoint>,
}

/// What makes a [`Profile`] an MCP profile, ready to use.
#[derive(Debug, Clone)]
pub struct McpEndpoint {
    /// The upstream's MCP endpoint path, canonical.
    pub endpoint: String,
    /// The fixed, non-secret headers the person signed, sent on every
    /// request in place of any the caller sent with the same name.
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl McpEndpoint {
    /// From the grant's `mcp`, or `None` when an endpoint or a header does
    /// not parse (the grant was checked when it was opened; this fails
    /// closed on anything a newer format could mean differently).
    fn of(mcp: &klav_proto::agent::McpProfile) -> Option<Self> {
        if !klav_core::policy::is_canonical_path(&mcp.endpoint)
            || mcp.endpoint.len() > klav_proto::agent::MAX_MCP_ENDPOINT
        {
            return None;
        }
        let mut headers = Vec::new();
        for h in &mcp.headers {
            headers.push((
                HeaderName::from_bytes(h.name.as_bytes()).ok()?,
                HeaderValue::from_str(&h.value).ok()?,
            ));
        }
        Some(Self {
            endpoint: mcp.endpoint.clone(),
            headers,
        })
    }
}

/// The profiles of the grant in force, by name.
#[derive(Debug, Clone, Default)]
pub struct Profiles {
    by_name: HashMap<String, Profile>,
}

impl Profiles {
    /// Reads the profiles of `grant`. A profile whose item the grant does
    /// not carry, whose header does not parse or whose upstream is not a
    /// host name is left out (the grant was checked when it was opened; this
    /// fails closed on anything a newer format could mean differently).
    ///
    /// An MCP profile (`v: 4`, ADR 0049 §2.1) keeps its endpoint and
    /// headers, and is served only through [`crate::mcp`], which reads,
    /// checks and filters its JSON-RPC: one whose endpoint or headers do
    /// not parse is left out, never served as a plain profile, whose
    /// session rule would let every tool through.
    pub fn from_grant(grant: &OpenGrant) -> Self {
        let mut by_name = HashMap::new();
        for p in &grant.payload.profiles {
            if !grant.items.contains_key(&p.item_id) {
                continue;
            }
            let mcp = match &p.mcp {
                Some(m) => match McpEndpoint::of(m) {
                    Some(m) => Some(m),
                    None => continue,
                },
                None => None,
            };
            let Some((host, port)) = p.upstream_host() else {
                continue;
            };
            if klav_core::policy::is_ip_literal(&host) {
                continue;
            }
            let Ok(header) = HeaderName::from_bytes(p.header.as_bytes()) else {
                continue;
            };
            by_name.insert(
                p.name.clone(),
                Profile {
                    name: p.name.clone(),
                    item: p.item_id,
                    field: p.field.clone(),
                    header,
                    prefix: p.prefix.clone(),
                    upstream: Upstream { host, port },
                    rate_per_minute: p.rate(),
                    mcp,
                },
            );
        }
        Self { by_name }
    }

    /// The profile called `name`.
    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.by_name.get(name)
    }

    /// All of them, sorted by name.
    pub fn all(&self) -> Vec<&Profile> {
        let mut all: Vec<&Profile> = self.by_name.values().collect();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        all
    }

    /// How many there are.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

impl Profile {
    /// The call to ask the server for: this profile's item and host, with
    /// the method and path exactly as they will be sent.
    pub fn call<'a>(
        &'a self,
        method: &'a str,
        path: &'a str,
        tags: &'a [String],
        sandbox: Option<klav_core::ids::SandboxId>,
    ) -> ProxyCall<'a> {
        ProxyCall {
            item: self.item,
            host: &self.upstream.host,
            method,
            path,
            tags,
            reason: if sandbox.is_some() {
                "credential proxy call from a sandbox"
            } else {
                "credential proxy call"
            },
            sandbox,
            mcp_tool: None,
            mcp_args: None,
            local_client: None,
        }
    }

    /// The field whose value goes in the header: the profile's `field`, or
    /// the item's main secret, which is `password` for a login and
    /// `api_key` for an API key. Any other item type has no main secret
    /// and its profile must name a field (spec §13.4).
    fn field_name<'a>(&'a self, item: &Item) -> ClientResult<&'a str> {
        if let Some(field) = &self.field {
            return Ok(field);
        }
        match item.kind() {
            ItemKind::Login => Ok("password"),
            ItemKind::ApiKey => Ok("api_key"),
            _ => Err(ClientError::Denied(format!(
                "profile {}: the item has no main secret; the profile must name a field",
                self.name
            ))),
        }
    }

    /// The header value: the prefix and the value of the field, in a
    /// header marked sensitive, and the value alone for the response
    /// redactor. A one-time password seed is never sent, nor an empty
    /// value, nor one a header cannot carry. Errors never contain the
    /// value.
    pub fn credential(&self, item: &Item) -> ClientResult<(HeaderValue, Zeroizing<String>)> {
        let field = self.field_name(item)?;
        let (kind, value) = klav_sdk::session::field_value(item, field)?;
        if kind == FieldKind::Totp {
            return Err(ClientError::Denied(format!(
                "profile {}: a one-time password seed never goes in a header",
                self.name
            )));
        }
        if value.expose().is_empty() {
            return Err(ClientError::Denied(format!(
                "profile {}: the field {field:?} is empty",
                self.name
            )));
        }
        let mut header = shared_header(HeaderBytes::new(
            self.prefix.as_bytes(),
            value.expose().as_bytes(),
        ))
        .map_err(|_| {
            ClientError::Denied(format!(
                "profile {}: the value of {field:?} cannot go in an HTTP header",
                self.name
            ))
        })?;
        header.set_sensitive(true);
        Ok((header, Zeroizing::new(value.expose().to_owned())))
    }
}

/// The bytes of a header that carries a value (ADR 0044 §3.3): zeroed when
/// the last [`HeaderValue`] sharing them drops. No `Debug`, no `Display`.
struct HeaderBytes(Vec<u8>);

impl HeaderBytes {
    /// `prefix` then `value`, in a buffer sized once, so the value is never
    /// copied by a reallocation.
    fn new(prefix: &[u8], value: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(prefix.len() + value.len());
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(value);
        #[cfg(test)]
        header_bytes_seen::alive(1);
        Self(bytes)
    }
}

impl AsRef<[u8]> for HeaderBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for HeaderBytes {
    fn drop(&mut self) {
        // Every byte, in place, before the buffer is freed (volatile
        // writes: `zeroize`).
        zeroize::Zeroize::zeroize(self.0.as_mut_slice());
        #[cfg(test)]
        {
            header_bytes_seen::alive(-1);
            header_bytes_seen::dropped(
                self.0.len(),
                self.0.capacity(),
                self.0.iter().all(|b| *b == 0),
            );
        }
    }
}

/// What the tests see of [`HeaderBytes`] on this thread: how many are
/// alive, and each one's length, capacity and whether every byte was zero
/// when it dropped.
#[cfg(test)]
mod header_bytes_seen {
    use std::cell::{Cell, RefCell};

    thread_local! {
        static ALIVE: Cell<i64> = const { Cell::new(0) };
        static DROPPED: RefCell<Vec<(usize, usize, bool)>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn alive(delta: i64) {
        ALIVE.with(|a| a.set(a.get() + delta));
    }

    pub(super) fn dropped(len: usize, capacity: usize, zeroed: bool) {
        DROPPED.with(|d| d.borrow_mut().push((len, capacity, zeroed)));
    }

    pub(super) fn count() -> i64 {
        ALIVE.with(Cell::get)
    }

    pub(super) fn take() -> Vec<(usize, usize, bool)> {
        DROPPED.with(|d| std::mem::take(&mut *d.borrow_mut()))
    }
}

/// A header value over `owner`'s own buffer, without the copy
/// `HeaderValue::from_bytes` makes: `Bytes::from_owner` keeps `owner` alive
/// until the last clone of the header drops, and
/// `HeaderValue::from_maybe_shared` keeps that `Bytes` as it is when given
/// one (`http` 1.5.0, `HeaderValue::from_shared`). A value a header can't
/// carry drops `owner` here.
fn shared_header<T>(owner: T) -> Result<HeaderValue, axum::http::header::InvalidHeaderValue>
where
    T: AsRef<[u8]> + Send + 'static,
{
    HeaderValue::from_maybe_shared(bytes::Bytes::from_owner(owner))
}

/// The profiles of `session`'s grant.
pub fn of(session: &Session) -> Profiles {
    Profiles::from_grant(session.grant())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: ItemKind, field: &str, value: &str) -> Item {
        let mut item = Item::from_template(kind, "Provider").unwrap();
        item.field_mut(field).unwrap().set_value(value).unwrap();
        item
    }

    fn profile(field: Option<&str>) -> Profile {
        Profile {
            name: "p".into(),
            item: ItemId::generate(),
            field: field.map(str::to_owned),
            header: HeaderName::from_static("authorization"),
            prefix: "Bearer ".into(),
            upstream: Upstream {
                host: "api.example.com".into(),
                port: 443,
            },
            rate_per_minute: 60,
            mcp: None,
        }
    }

    #[test]
    fn the_main_secret_is_the_password_or_the_api_key() {
        let login = item(ItemKind::Login, "password", "pw-value");
        let (v, secret) = profile(None).credential(&login).unwrap();
        assert!(v.is_sensitive());
        assert_eq!(v.as_bytes(), b"Bearer pw-value");
        assert_eq!(secret.as_str(), "pw-value");
        let key = item(ItemKind::ApiKey, "api_key", "ak-value");
        assert_eq!(
            profile(None).credential(&key).unwrap().0.as_bytes(),
            b"Bearer ak-value"
        );
        // Another type has none: the profile must name a field.
        let card = item(ItemKind::Card, "number", "4111");
        assert!(profile(None).credential(&card).is_err());
        assert_eq!(
            profile(Some("number"))
                .credential(&card)
                .unwrap()
                .0
                .as_bytes(),
            b"Bearer 4111"
        );
    }

    /// ADR 0044 §3.3: the header is the buffer it was built from, not a
    /// copy, and that buffer goes when the last clone of the header does.
    #[test]
    fn the_header_shares_its_buffer_and_drops_it_with_the_last_clone() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Owner {
            bytes: Vec<u8>,
            dropped: Arc<AtomicBool>,
        }
        impl AsRef<[u8]> for Owner {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let bytes = b"Bearer value".to_vec();
        let at = bytes.as_ptr();
        let header = shared_header(Owner {
            bytes,
            dropped: Arc::clone(&dropped),
        })
        .unwrap();
        assert_eq!(header.as_bytes().as_ptr(), at, "no copy");
        let clone = header.clone();
        assert_eq!(clone.as_bytes().as_ptr(), at, "a clone shares it");
        drop(header);
        assert!(!dropped.load(Ordering::SeqCst), "the clone keeps it");
        drop(clone);
        assert!(dropped.load(Ordering::SeqCst), "gone with the last clone");
        // A value a header can't carry drops the buffer at once.
        let dropped = Arc::new(AtomicBool::new(false));
        assert!(
            shared_header(Owner {
                bytes: b"a\r\nb".to_vec(),
                dropped: Arc::clone(&dropped),
            })
            .is_err()
        );
        assert!(dropped.load(Ordering::SeqCst));
        // The credential's header is the buffer `HeaderBytes` owns: the same
        // bytes, marked sensitive.
        let login = item(ItemKind::Login, "password", "pw-value");
        let (v, _) = profile(None).credential(&login).unwrap();
        assert!(v.is_sensitive());
        assert_eq!(v.as_bytes(), b"Bearer pw-value");
    }

    /// ADR 0044 §3.3, through `credential` itself: the header lives on the
    /// self-zeroing buffer until its last clone drops (with
    /// `HeaderValue::from_bytes` the buffer would drop inside `credential`,
    /// and the header would be a plain copy), and every byte of that buffer
    /// is zero when it is freed.
    #[test]
    fn the_credential_header_is_the_buffer_that_zeroes_itself() {
        header_bytes_seen::take();
        let login = item(ItemKind::Login, "password", "pw-value");
        let (header, _redactor) = profile(None).credential(&login).unwrap();
        assert_eq!(header_bytes_seen::count(), 1, "the header holds the buffer");
        assert!(header_bytes_seen::take().is_empty(), "nothing freed yet");
        let clone = header.clone();
        drop(header);
        assert_eq!(header_bytes_seen::count(), 1, "the clone keeps it");
        drop(clone);
        assert_eq!(header_bytes_seen::count(), 0);
        let len = b"Bearer pw-value".len();
        assert_eq!(
            header_bytes_seen::take(),
            vec![(len, len, true)],
            "freed once, sized exactly, every byte zero"
        );
        // A value a header can't carry: freed, zeroed, inside `credential`.
        let bad = item(ItemKind::Login, "password", "a\nb");
        assert!(profile(None).credential(&bad).is_err());
        assert_eq!(header_bytes_seen::count(), 0);
        let dropped = header_bytes_seen::take();
        assert_eq!(dropped.len(), 1);
        assert!(dropped[0].2, "zeroed");
    }

    #[test]
    fn seeds_empty_values_and_line_breaks_never_go_in_a_header() {
        let login = item(ItemKind::Login, "totp", "JBSWY3DPEHPK3PXP");
        assert!(profile(Some("totp")).credential(&login).is_err());
        let empty = Item::from_template(ItemKind::Login, "x").unwrap();
        assert!(profile(None).credential(&empty).is_err());
        let split = item(ItemKind::Login, "password", "a\r\nX-Evil: 1");
        let err = profile(None).credential(&split).err().unwrap().to_string();
        assert!(
            !err.contains("X-Evil"),
            "the error must not carry the value"
        );
    }

    /// ADR 0049 layer 4: an MCP profile keeps its endpoint and headers,
    /// and one whose endpoint does not parse is left out, never served as
    /// a plain profile whose session rule would let every tool through.
    #[test]
    fn mcp_profiles_keep_their_endpoint_and_bad_ones_are_left_out() {
        use klav_core::crypto::context::ItemContext;
        use klav_core::crypto::keys::ItemKey;
        use klav_core::ids::{AccountId, AgentId, ProjectId, VaultId};
        use klav_proto::agent::{GrantPayload, McpProfile, ProxyProfile};
        use klav_sdk::grant::GrantedItemKey;

        let (plain, mcp) = (ItemId::generate(), ItemId::generate());
        let profile = |name: &str, item_id, mcp: Option<McpProfile>| ProxyProfile {
            name: name.into(),
            item_id,
            field: None,
            header: "authorization".into(),
            prefix: "Bearer ".into(),
            upstream: "https://api.example.com".into(),
            rate_per_minute: None,
            mcp,
        };
        let key = |item| GrantedItemKey {
            ctx: ItemContext {
                account: AccountId::generate(),
                vault: VaultId::generate(),
                project: ProjectId::generate(),
                item,
            },
            key: ItemKey::generate(),
        };
        let grant = OpenGrant {
            payload: GrantPayload {
                v: 4,
                account_id: AccountId::generate(),
                agent_id: AgentId::generate(),
                version: 1,
                issued_at: 0,
                policy: klav_core::policy::Policy::default(),
                projects: Vec::new(),
                items: Vec::new(),
                profiles: vec![
                    profile("rest", plain, None),
                    profile(
                        "maple",
                        mcp,
                        Some(McpProfile {
                            endpoint: "/mcp".into(),
                            headers: vec![klav_proto::agent::McpHeader {
                                name: "x-toolsets".into(),
                                value: "read".into(),
                            }],
                        }),
                    ),
                    profile(
                        "broken",
                        mcp,
                        Some(McpProfile {
                            endpoint: "/a/../mcp".into(),
                            headers: Vec::new(),
                        }),
                    ),
                ],
                issuers: Vec::new(),
                sandbox: None,
                local_clients: Vec::new(),
                released: Vec::new(),
            },
            keys: HashMap::new(),
            items: HashMap::from([(plain, key(plain)), (mcp, key(mcp))]),
        };
        let profiles = Profiles::from_grant(&grant);
        assert!(profiles.get("rest").is_some_and(|p| p.mcp.is_none()));
        let maple = profiles
            .get("maple")
            .and_then(|p| p.mcp.as_ref())
            .expect("mcp");
        assert_eq!(maple.endpoint, "/mcp");
        assert_eq!(maple.headers.len(), 1);
        assert!(profiles.get("broken").is_none());
        assert_eq!(profiles.len(), 2);
    }
}
