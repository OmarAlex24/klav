//! Passkeys in imports (ADR 0020, ADR 0024): Bitwarden's
//! `login.fido2Credentials`, the only export Klav reads that carries the
//! private key (1Password's `.1pux` and Google's CSV do not).
//!
//! Each one is checked while reading, so the preview says what will
//! happen: an ECDSA P-256 key in PKCS#8, a credential ID (`b64.` and
//! base64url, or a GUID, as Bitwarden stores it), an rpId that is a valid
//! registrable domain (`passkey::rp`, with the Public Suffix List), and a
//! user handle of 1 to 64 bytes. The key is parsed here by `klav-core` and
//! sealed with the vault key (`0x15`) by the client when it saves the
//! login: it is never stored in the clear.

use std::sync::Arc;

use data_encoding::BASE64URL_NOPAD;
use klav_core::crypto::passkey::{PasskeyBinding, PasskeyPrivateKey};
use klav_core::model::passkey::{MAX_PASSKEY_TEXT_LEN, PasskeyAccount};
use klav_core::passkey::rp;
use serde::Deserialize;
use zeroize::Zeroizing;

/// A passkey read from an export, before the client seals it. Not `Debug`:
/// it holds the private key.
#[derive(Clone)]
pub struct ImportedPasskey {
    credential_id: Vec<u8>,
    rp_id: String,
    rp_name: Option<String>,
    user_handle: Vec<u8>,
    user_name: String,
    user_display_name: Option<String>,
    created_at: i64,
    key: Arc<PasskeyPrivateKey>,
}

impl ImportedPasskey {
    /// Credential ID.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Relying party ID.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// What `Passkey::import` needs besides the key and the credential ID.
    pub fn account(&self) -> PasskeyAccount<'_> {
        PasskeyAccount {
            rp_id: &self.rp_id,
            rp_name: self.rp_name.as_deref(),
            user_handle: &self.user_handle,
            user_name: &self.user_name,
            user_display_name: self.user_display_name.as_deref(),
            created_at: self.created_at,
        }
    }

    /// The private key, for `Passkey::import` (which seals it).
    pub fn key(&self) -> &PasskeyPrivateKey {
        &self.key
    }
}

/// One of Bitwarden's `fido2Credentials` (`Fido2CredentialExport`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BwFido2 {
    #[serde(default)]
    credential_id: Option<String>,
    #[serde(default)]
    key_type: Option<String>,
    #[serde(default)]
    key_algorithm: Option<String>,
    #[serde(default)]
    key_curve: Option<String>,
    #[serde(default)]
    key_value: Option<Zeroizing<String>>,
    #[serde(default)]
    rp_id: Option<String>,
    #[serde(default)]
    rp_name: Option<String>,
    #[serde(default)]
    user_handle: Option<String>,
    #[serde(default)]
    user_name: Option<String>,
    #[serde(default)]
    user_display_name: Option<String>,
    /// A string in the export (`"0"`), a number in older ones.
    #[serde(default)]
    counter: Option<serde_json::Value>,
    #[serde(default)]
    creation_date: Option<String>,
}

/// Why a passkey of the export is not imported (no values in it).
pub(crate) const NOT_P256: &str = "a passkey whose key is not ECDSA P-256, not imported";
pub(crate) const BAD_CREDENTIAL_ID: &str = "a passkey without a valid credential ID, not imported";
pub(crate) const BAD_RP_ID: &str = "a passkey for a site Klav cannot sign for (rpId), not imported";
pub(crate) const BAD_USER_HANDLE: &str = "a passkey without a valid user handle, not imported";
pub(crate) const BAD_KEY: &str = "a passkey whose private key could not be read, not imported";
/// Klav keeps one passkey per login (ADR 0020 §2).
pub(crate) const ONE_PER_LOGIN: &str =
    "Klav keeps one passkey per login: another passkey of this entry was not imported";
/// A counter above 0 (ADR 0020: Klav always signs with 0).
pub(crate) const COUNTED: &str = "the passkey had a signature counter above 0, and Klav's passkeys always sign with 0: a site that checks the counter may refuse it. If it does, sign in another way and register a new passkey for that site in Klav";

/// `b64.<base64url>` or a GUID (16 bytes), as Bitwarden's
/// `parseCredentialId` reads it.
fn credential_id(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if let Some(b64) = text.strip_prefix("b64.") {
        return base64url(b64);
    }
    guid(text)
}

/// Base64url, with or without padding.
fn base64url(text: &str) -> Option<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(text.trim().trim_end_matches('=').as_bytes())
        .ok()
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` to its 16 bytes, in order.
fn guid(text: &str) -> Option<Vec<u8>> {
    let groups: Vec<&str> = text.split('-').collect();
    let lengths: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    if lengths != [8, 4, 4, 4, 12] {
        return None;
    }
    let hex: String = groups.concat();
    (0..16)
        .map(|i| u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

/// A display text Klav can store: no control characters, at most
/// [`MAX_PASSKEY_TEXT_LEN`] characters. Empty: `None`.
fn shown(text: Option<&str>) -> Option<String> {
    let clean: String = text?
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_PASSKEY_TEXT_LEN)
        .collect();
    let clean = clean.trim();
    (!clean.is_empty()).then(|| clean.to_owned())
}

fn counter(value: Option<&serde_json::Value>) -> u64 {
    match value {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// What reading one passkey gave: the passkey and whether its counter was
/// above 0, or why it is not imported.
pub(crate) fn read(
    c: &BwFido2,
    username: &str,
    created_ms: Option<i64>,
) -> Result<(ImportedPasskey, bool), &'static str> {
    let is = |v: &Option<String>, want: &str| {
        v.as_deref()
            .map(str::trim)
            .is_none_or(|v| v.is_empty() || v.eq_ignore_ascii_case(want))
    };
    if !is(&c.key_type, "public-key")
        || !is(&c.key_algorithm, "ECDSA")
        || !is(&c.key_curve, "P-256")
    {
        return Err(NOT_P256);
    }
    let credential_id = c
        .credential_id
        .as_deref()
        .and_then(credential_id)
        .ok_or(BAD_CREDENTIAL_ID)?;
    let rp_id = c
        .rp_id
        .as_deref()
        .map(|r| r.trim().to_ascii_lowercase())
        .filter(|r| {
            rp::validate(&format!("https://{r}"), Some(r)).is_ok_and(|valid| &valid.rp_id == r)
        })
        .ok_or(BAD_RP_ID)?;
    let user_handle = c
        .user_handle
        .as_deref()
        .and_then(base64url)
        .ok_or(BAD_USER_HANDLE)?;
    let binding = PasskeyBinding {
        credential_id: &credential_id,
        rp_id: &rp_id,
        user_handle: &user_handle,
    };
    if binding.validate().is_err() {
        // The rpId passed above: the lengths of the IDs are what failed.
        return Err(if user_handle.is_empty() || user_handle.len() > 64 {
            BAD_USER_HANDLE
        } else {
            BAD_CREDENTIAL_ID
        });
    }
    let der = c
        .key_value
        .as_deref()
        .and_then(|k| base64url(k))
        .map(Zeroizing::new)
        .ok_or(BAD_KEY)?;
    let key = PasskeyPrivateKey::from_pkcs8_der(&der).map_err(|_| BAD_KEY)?;
    let passkey = ImportedPasskey {
        credential_id,
        rp_id,
        rp_name: shown(c.rp_name.as_deref()),
        user_handle,
        user_name: shown(c.user_name.as_deref())
            .or_else(|| shown(Some(username)))
            .unwrap_or_default(),
        user_display_name: shown(c.user_display_name.as_deref()),
        created_at: c
            .creation_date
            .as_deref()
            .and_then(crate::date::rfc3339_ms)
            .or(created_ms)
            .unwrap_or(0),
        key: Arc::new(key),
    };
    Ok((passkey, counter(c.counter.as_ref()) > 0))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A synthetic P-256 key made for these tests with WebCrypto's
    /// `exportKey("pkcs8")`, as Bitwarden exports it (base64url). It
    /// belongs to no one and signs nothing real.
    pub(crate) const TEST_KEY: &str = crate::samples::SAMPLE_PASSKEY_KEY;

    /// A valid imported passkey for `shop.example.com` with `credential`
    /// (base64url) as its ID, for the planner's tests.
    pub(crate) fn imported(credential: &str) -> ImportedPasskey {
        let json = replace(
            &sample(),
            &format!(r#", "credentialId": "b64.{credential}""#),
        );
        read(&fido2(&json), "ana", None).unwrap().0
    }

    /// [`imported`], for another site.
    pub(crate) fn imported_for(credential: &str, rp_id: &str) -> ImportedPasskey {
        let json = replace(
            &sample(),
            &format!(r#", "credentialId": "b64.{credential}""#),
        );
        let json = replace(&json, &format!(r#", "rpId": "{rp_id}""#));
        read(&fido2(&json), "ana", None).unwrap().0
    }

    fn fido2(json: &str) -> BwFido2 {
        serde_json::from_str(json).unwrap()
    }

    fn sample() -> String {
        format!(
            r#"{{"credentialId": "b64.c2FtcGxlLWNyZWRlbnRpYWw", "keyType": "public-key",
                "keyAlgorithm": "ECDSA", "keyCurve": "P-256", "keyValue": "{TEST_KEY}",
                "rpId": "shop.example.com", "userHandle": "dXNlci0x", "userName": "ana",
                "counter": "0", "discoverable": "true", "creationDate": "2026-03-01T12:00:00.000Z"}}"#
        )
    }

    #[test]
    fn reads_bitwardens_passkey() {
        let (p, counted) = read(&fido2(&sample()), "fallback", None).unwrap();
        assert!(!counted);
        assert_eq!(p.credential_id(), b"sample-credential");
        assert_eq!(p.rp_id(), "shop.example.com");
        let a = p.account();
        assert_eq!(a.user_handle, b"user-1");
        assert_eq!(a.user_name, "ana");
        assert_eq!(a.created_at, 1_772_366_400_000);
        assert_eq!(p.key().public_key().len(), 65);
    }

    #[test]
    fn a_guid_credential_id_is_its_16_bytes() {
        assert_eq!(
            credential_id("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            (0u8..16).map(|i| i * 0x11).collect::<Vec<_>>()
        );
        assert_eq!(credential_id("0011223-34455-6677-8899-aabbccddeeff"), None);
        assert_eq!(credential_id("c2FtcGxl"), None);
        assert_eq!(credential_id("b64.!!"), None);
    }

    #[test]
    fn each_bad_part_has_its_reason() {
        let cases = [
            (r#", "keyCurve": "P-384""#, NOT_P256),
            (r#", "keyAlgorithm": "EdDSA""#, NOT_P256),
            (r#", "credentialId": "x""#, BAD_CREDENTIAL_ID),
            (r#", "rpId": "co.uk""#, BAD_RP_ID),
            (r#", "rpId": "github.io""#, BAD_RP_ID),
            (r#", "rpId": "shop.example.com:443""#, BAD_RP_ID),
            (r#", "rpId": "https://shop.example.com""#, BAD_RP_ID),
            (r#", "userHandle": """#, BAD_USER_HANDLE),
            (r#", "userHandle": "*""#, BAD_USER_HANDLE),
            (r#", "keyValue": "c2FtcGxlLWtleQ""#, BAD_KEY),
            (r#", "keyValue": null"#, BAD_KEY),
        ];
        for (extra, reason) in cases {
            let json = replace(&sample(), extra);
            assert_eq!(read(&fido2(&json), "", None).err(), Some(reason), "{extra}");
        }
        let long = format!(
            r#", "userHandle": "{}""#,
            BASE64URL_NOPAD.encode(&[7u8; 65])
        );
        assert_eq!(
            read(&fido2(&replace(&sample(), &long)), "", None).err(),
            Some(BAD_USER_HANDLE)
        );
    }

    /// `json` with the field in `extra` (`, "name": value`) replaced.
    fn replace(json: &str, extra: &str) -> String {
        let name = extra.split('"').nth(1).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
        let new: serde_json::Value = serde_json::from_str(&format!("{{{}}}", &extra[1..])).unwrap();
        v[name] = new[name].clone();
        v.to_string()
    }

    #[test]
    fn a_counter_above_zero_is_flagged_and_names_are_cleaned() {
        let json = replace(&sample(), r#", "counter": "41""#);
        let json = replace(&json, r#", "userName": null"#);
        let json = replace(&json, r#", "rpName": "Shop\u0007 Inc""#);
        let (p, counted) = read(&fido2(&json), "ana@example.com", Some(5)).unwrap();
        assert!(counted);
        assert_eq!(p.account().user_name, "ana@example.com");
        assert_eq!(p.account().rp_name, Some("Shop Inc"));
        let json = replace(&sample(), r#", "counter": 3"#);
        assert!(read(&fido2(&json), "", None).unwrap().1);
        let json = replace(&json, r#", "creationDate": null"#);
        assert_eq!(
            read(&fido2(&json), "", Some(5))
                .unwrap()
                .0
                .account()
                .created_at,
            5
        );
    }

    #[test]
    fn a_missing_key_type_is_not_a_reason_to_refuse() {
        let json = replace(&sample(), r#", "keyType": null"#);
        let json = replace(&json, r#", "keyAlgorithm": """#);
        assert!(read(&fido2(&json), "", None).is_ok());
    }
}
