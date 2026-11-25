//! The MCP gateway's two digests and the local client token (ADR 0049
//! §3.2 and §5.4, spec §13.16).
//!
//! **Local client token.** A capability for one MCP client on the person's
//! Mac to use named profiles through the proxy's loopback listener. 32
//! random bytes, written versioned from the first byte:
//!
//! ```text
//! klc1_ ‖ BASE64URL-NOPAD(0x01 ‖ token(32))
//! ```
//!
//! A text with another prefix, another version byte, another length or
//! anything but canonical base64url without padding is refused. The proxy's
//! grant carries only `token_digest = SHA-256(tuple("klav/v1/proxy/local-client",
//! agent_id(16), token(32)))`, never the token. [`LocalClientToken`] wraps a
//! [`SecretString`]: its `Debug` is redacted and it has no `Display`.
//!
//! **Argument digest.** What a `tools/call` claims about its arguments, so
//! an approve-once decision binds them without the server ever seeing them:
//!
//! ```text
//! mcp_args = SHA-256(tuple("klav/v1/proxy/mcp-args", agent_id(16), item_id(16), tool, raw_arguments))
//! ```
//!
//! Every field of the tuple is length-prefixed (spec §2.3): `tool` is the
//! tool name's UTF-8 bytes and `raw_arguments` the exact bytes of
//! `params.arguments` as received (empty when absent). Its text form is
//! base64url without padding (43 characters).

use data_encoding::BASE64URL_NOPAD;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::encoding::Tuple;
use super::random;
use crate::ids::{AgentId, ItemId};

/// Label of the local client token digest.
pub const LABEL_LOCAL_CLIENT: &str = "klav/v1/proxy/local-client";
/// Label of the argument digest.
pub const LABEL_MCP_ARGS: &str = "klav/v1/proxy/mcp-args";
/// What every local client token starts with.
pub const LOCAL_CLIENT_PREFIX: &str = "klc1_";
/// Version byte of the token's blob.
pub const LOCAL_CLIENT_VERSION: u8 = 0x01;
/// Random bytes per token.
pub const LOCAL_CLIENT_TOKEN_BYTES: usize = 32;
/// Length of a digest.
pub const DIGEST_LEN: usize = 32;
/// Length of a digest's text form (base64url without padding).
pub const DIGEST_TEXT_LEN: usize = 43;

/// A text that is not a local client token. Carries no detail: the proxy
/// answers the same for every reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid local client token")]
pub struct InvalidLocalClientToken;

/// A local client token, as generated or as received in a bearer header.
/// `Debug` never prints it, and it has no `Display`.
#[derive(Clone)]
pub struct LocalClientToken(SecretString);

impl LocalClientToken {
    /// A fresh token from the CSPRNG.
    pub fn generate() -> Self {
        let bytes = Zeroizing::new(random::array::<LOCAL_CLIENT_TOKEN_BYTES>());
        Self::from_bytes(&bytes)
    }

    /// The text form of `bytes`.
    pub fn from_bytes(bytes: &[u8; LOCAL_CLIENT_TOKEN_BYTES]) -> Self {
        let mut blob = Zeroizing::new([0u8; 1 + LOCAL_CLIENT_TOKEN_BYTES]);
        blob[0] = LOCAL_CLIENT_VERSION;
        blob[1..].copy_from_slice(bytes);
        let mut text = String::with_capacity(
            LOCAL_CLIENT_PREFIX.len() + BASE64URL_NOPAD.encode_len(blob.len()),
        );
        text.push_str(LOCAL_CLIENT_PREFIX);
        BASE64URL_NOPAD.encode_append(blob.as_ref(), &mut text);
        Self(SecretString::from(text))
    }

    /// A token as received; nothing is checked until [`Self::bytes`].
    pub fn new(text: impl Into<String>) -> Self {
        Self(SecretString::from(text.into()))
    }

    /// The text, to write into a client's configuration.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// The 32 bytes, or [`InvalidLocalClientToken`] for anything but the
    /// exact form above.
    pub fn bytes(
        &self,
    ) -> Result<Zeroizing<[u8; LOCAL_CLIENT_TOKEN_BYTES]>, InvalidLocalClientToken> {
        let body = self
            .expose()
            .strip_prefix(LOCAL_CLIENT_PREFIX)
            .ok_or(InvalidLocalClientToken)?;
        if body.len() != BASE64URL_NOPAD.encode_len(1 + LOCAL_CLIENT_TOKEN_BYTES) {
            return Err(InvalidLocalClientToken);
        }
        let blob = Zeroizing::new(
            BASE64URL_NOPAD
                .decode(body.as_bytes())
                .map_err(|_| InvalidLocalClientToken)?,
        );
        // `data-encoding` refuses non-zero trailing bits, so each token has
        // one spelling; the round trip below says so for any decoder.
        if blob.len() != 1 + LOCAL_CLIENT_TOKEN_BYTES || blob[0] != LOCAL_CLIENT_VERSION {
            return Err(InvalidLocalClientToken);
        }
        if BASE64URL_NOPAD
            .encode(&blob)
            .as_bytes()
            .ct_eq(body.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(InvalidLocalClientToken);
        }
        let mut out = Zeroizing::new([0u8; LOCAL_CLIENT_TOKEN_BYTES]);
        out.copy_from_slice(&blob[1..]);
        Ok(out)
    }

    /// `SHA-256(tuple(LABEL_LOCAL_CLIENT, agent_id, token))`: what the
    /// proxy's grant carries for this client.
    pub fn digest(&self, proxy: AgentId) -> Result<[u8; DIGEST_LEN], InvalidLocalClientToken> {
        Ok(local_client_digest(proxy, &*self.bytes()?))
    }

    /// Whether this token's digest for `proxy` is `expected`, compared in
    /// constant time. A malformed token never matches.
    pub fn matches(&self, proxy: AgentId, expected: &[u8]) -> bool {
        self.digest(proxy)
            .is_ok_and(|d| expected.len() == DIGEST_LEN && bool::from(d.ct_eq(expected)))
    }
}

impl std::fmt::Debug for LocalClientToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalClientToken([redacted])")
    }
}

/// `SHA-256(tuple("klav/v1/proxy/local-client", agent_id(16), token(32)))`.
pub fn local_client_digest(
    proxy: AgentId,
    token: &[u8; LOCAL_CLIENT_TOKEN_BYTES],
) -> [u8; DIGEST_LEN] {
    let mut t = Tuple::new(LABEL_LOCAL_CLIENT);
    t.push(proxy.as_bytes()).push(token);
    let tuple = Zeroizing::new(t.into_bytes());
    Sha256::digest(tuple.as_slice()).into()
}

/// `SHA-256(tuple("klav/v1/proxy/mcp-args", agent_id(16), item_id(16), tool, raw_arguments))`.
pub fn mcp_args_digest(
    proxy: AgentId,
    item: ItemId,
    tool: &str,
    raw_arguments: &[u8],
) -> [u8; DIGEST_LEN] {
    let mut t = Tuple::new(LABEL_MCP_ARGS);
    t.push(proxy.as_bytes())
        .push(item.as_bytes())
        .push(tool.as_bytes())
        .push(raw_arguments);
    let tuple = Zeroizing::new(t.into_bytes());
    Sha256::digest(tuple.as_slice()).into()
}

/// Label of the proxy's in-memory digest of a tool's definition.
pub const LABEL_TOOL_DEFINITION: &str = "klav/v1/proxy/tool-definition";

/// `SHA-256(tuple("klav/v1/proxy/tool-definition", raw_element))`: what the
/// proxy keeps in memory of each tool `tools/list` showed, to log when the
/// definition behind a name changes (ADR 0049 §5.2, rug-pull detection).
/// Local only: it never leaves the proxy, is never signed and is no wire
/// format, so it has no vectors.
pub fn tool_definition_digest(raw_element: &[u8]) -> [u8; DIGEST_LEN] {
    let mut t = Tuple::new(LABEL_TOOL_DEFINITION);
    t.push(raw_element);
    Sha256::digest(t.into_bytes().as_slice()).into()
}

/// The text form of a digest: base64url without padding.
pub fn digest_text(digest: &[u8; DIGEST_LEN]) -> String {
    BASE64URL_NOPAD.encode(digest)
}

/// Whether `text` is the text form of some digest: exactly 43 characters
/// of canonical base64url without padding, decoding to 32 bytes. One
/// spelling per digest, so the same arguments always make the same key.
pub fn digest_text_ok(text: &str) -> bool {
    text.len() == DIGEST_TEXT_LEN
        && BASE64URL_NOPAD
            .decode(text.as_bytes())
            .is_ok_and(|d| d.len() == DIGEST_LEN && BASE64URL_NOPAD.encode(&d) == text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lp(out: &mut Vec<u8>, field: &[u8]) {
        out.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        out.extend_from_slice(field);
    }

    #[test]
    fn the_digests_by_hand() {
        let agent = AgentId::from_bytes([7; 16]);
        let item = ItemId::from_bytes([9; 16]);
        let mut manual = Vec::new();
        lp(&mut manual, LABEL_LOCAL_CLIENT.as_bytes());
        lp(&mut manual, &[7; 16]);
        lp(&mut manual, &[0xAB; 32]);
        let expected: [u8; 32] = Sha256::digest(&manual).into();
        assert_eq!(local_client_digest(agent, &[0xAB; 32]), expected);

        let args = br#"{"query":"error", "limit":10}"#;
        let mut manual = Vec::new();
        lp(&mut manual, LABEL_MCP_ARGS.as_bytes());
        lp(&mut manual, &[7; 16]);
        lp(&mut manual, &[9; 16]);
        lp(&mut manual, b"query_logs");
        lp(&mut manual, args);
        let expected: [u8; 32] = Sha256::digest(&manual).into();
        assert_eq!(mcp_args_digest(agent, item, "query_logs", args), expected);
        // The tool and the arguments are separate fields: moving bytes
        // from one to the other changes the digest.
        assert_ne!(
            mcp_args_digest(agent, item, "query_log", b"s{}"),
            mcp_args_digest(agent, item, "query_logs", b"{}")
        );
        // Absent arguments are the empty field, not `{}`.
        assert_ne!(
            mcp_args_digest(agent, item, "t", b""),
            mcp_args_digest(agent, item, "t", b"{}")
        );
    }

    #[test]
    fn a_token_round_trips_and_one_spelling_only() {
        let token = LocalClientToken::generate();
        let text = token.expose().to_owned();
        assert!(text.starts_with(LOCAL_CLIENT_PREFIX));
        assert_eq!(text.len(), LOCAL_CLIENT_PREFIX.len() + 44);
        let bytes = token.bytes().unwrap();
        assert_eq!(LocalClientToken::from_bytes(&bytes).expose(), text);
        let agent = AgentId::generate();
        let digest = token.digest(agent).unwrap();
        assert!(LocalClientToken::new(text.clone()).matches(agent, &digest));
        assert!(!LocalClientToken::new(text.clone()).matches(AgentId::generate(), &digest));
        assert!(!LocalClientToken::new(text.clone()).matches(agent, &digest[..31]));
        assert_ne!(LocalClientToken::generate().expose(), text);
    }

    #[test]
    fn what_is_not_a_token_is_refused() {
        let good = LocalClientToken::from_bytes(&[0x11; 32])
            .expose()
            .to_owned();
        let body = &good[LOCAL_CLIENT_PREFIX.len()..];
        let mut other_version = [0x11u8; 33];
        other_version[0] = 0x02;
        let short = [0x01u8; 32];
        let long = [0x01u8; 34];
        for bad in [
            String::new(),
            body.to_owned(),
            format!("klc2_{body}"),
            format!("KLC1_{body}"),
            format!("kag1_{body}"),
            format!(" {good}"),
            format!("{good} "),
            format!("{good}="),
            format!("klc1_{}", BASE64URL_NOPAD.encode(&other_version)),
            format!("klc1_{}", BASE64URL_NOPAD.encode(&short)),
            format!("klc1_{}", BASE64URL_NOPAD.encode(&long)),
            // Standard base64, not base64url.
            format!("{}+{}", &good[..8], &good[9..]),
        ] {
            assert_eq!(
                LocalClientToken::new(bad.clone()).bytes().map(|_| ()),
                Err(InvalidLocalClientToken),
                "{bad:?}"
            );
        }
        // 33 bytes are exactly 44 symbols: no padding bits, so no second
        // spelling of the same bytes.
        assert_eq!(body.len() * 6, 33 * 8);
    }

    #[test]
    fn debug_never_shows_the_token() {
        let token = LocalClientToken::from_bytes(&[0x5A; 32]);
        assert_eq!(format!("{token:?}"), "LocalClientToken([redacted])");
        assert!(!format!("{:?}", Some(&token)).contains("klc1_"));
    }

    #[test]
    fn digest_texts_have_one_spelling() {
        let d = [0xFF; 32];
        let text = digest_text(&d);
        assert_eq!(text.len(), DIGEST_TEXT_LEN);
        assert!(digest_text_ok(&text));
        // 32 bytes end with 4 bits of padding: `8` is not `_`'s spelling.
        assert_eq!(text.chars().last(), Some('8'));
        assert!(!digest_text_ok(&format!("{}9", &text[..42])));
        assert!(!digest_text_ok(&format!("{text}=")));
        assert!(!digest_text_ok(&text[..42]));
        assert!(!digest_text_ok(&text.replace('_', "/")));
        assert!(!digest_text_ok(""));
    }
}
