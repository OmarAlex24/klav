//! The bytes Klav produces as a WebAuthn authenticator (spec §14.4–§14.6):
//! authenticator data, the COSE public key, the `none` attestation object,
//! `clientDataJSON` and assertion signatures.
//!
//! Only ES256 credentials, attestation `none`, a sign count of zero and the
//! backup flags of a synced passkey (BE = BS = 1). Klav's AAGUID is
//! [`crate::crypto::passkey::AAGUID`].

use sha2::{Digest, Sha256};

use super::cbor::Value;
use crate::crypto::CryptoError;
use crate::crypto::passkey::{AAGUID, MAX_CREDENTIAL_ID_LEN, PUBLIC_KEY_LEN, PasskeyPrivateKey};

/// COSE algorithm identifier of ES256.
pub const ALG_ES256: i64 = -7;

/// User present.
pub const FLAG_UP: u8 = 0x01;
/// User verified.
pub const FLAG_UV: u8 = 0x04;
/// Backup eligible.
pub const FLAG_BE: u8 = 0x08;
/// Backed up.
pub const FLAG_BS: u8 = 0x10;
/// Attested credential data included.
pub const FLAG_AT: u8 = 0x40;

/// Length of the authenticator data of an assertion.
pub const ASSERTION_AUTH_DATA_LEN: usize = 37;
/// Length of an ES256 COSE public key.
pub const COSE_KEY_LEN: usize = 77;

/// SHA-256 of the rpId, the first 32 bytes of the authenticator data.
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// SHA-256 of `clientDataJSON`, the second half of the signed message.
pub fn client_data_hash(client_data_json: &[u8]) -> [u8; 32] {
    Sha256::digest(client_data_json).into()
}

/// The ES256 public key as a COSE_Key: `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`
/// in CTAP2 canonical order (77 bytes).
pub fn cose_public_key(public_key: &[u8; PUBLIC_KEY_LEN]) -> Vec<u8> {
    let (x, y) = public_key[1..].split_at(32);
    Value::map(vec![
        (Value::int(1), Value::int(2)),
        (Value::int(3), Value::int(ALG_ES256)),
        (Value::int(-1), Value::int(1)),
        (Value::int(-2), Value::bytes(x)),
        (Value::int(-3), Value::bytes(y)),
    ])
    .into_bytes()
}

fn flags(user_verified: bool, attested: bool) -> u8 {
    let mut flags = FLAG_UP | FLAG_BE | FLAG_BS;
    if user_verified {
        flags |= FLAG_UV;
    }
    if attested {
        flags |= FLAG_AT;
    }
    flags
}

pub(crate) fn registration_auth_data_with(
    aaguid: &[u8; 16],
    flags: u8,
    rp_id: &str,
    credential_id: &[u8],
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(CryptoError::Malformed("passkey credential ID length"));
    }
    let id_len = u16::try_from(credential_id.len()).expect("bounded by MAX_CREDENTIAL_ID_LEN");
    let mut out = Vec::with_capacity(37 + 18 + credential_id.len() + COSE_KEY_LEN);
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(flags);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(aaguid);
    out.extend_from_slice(&id_len.to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(&cose_public_key(public_key));
    Ok(out)
}

/// Authenticator data of a registration: `rpIdHash ‖ flags ‖ signCount(0) ‖
/// aaguid ‖ len(credential_id) ‖ credential_id ‖ COSE key`. Flags are
/// UP·BE·BS·AT plus UV when `user_verified` (`0x5D`, or `0x59`).
pub fn registration_auth_data(
    rp_id: &str,
    credential_id: &[u8],
    public_key: &[u8; PUBLIC_KEY_LEN],
    user_verified: bool,
) -> Result<Vec<u8>, CryptoError> {
    registration_auth_data_with(
        &AAGUID,
        flags(user_verified, true),
        rp_id,
        credential_id,
        public_key,
    )
}

/// Authenticator data of an assertion: `rpIdHash ‖ flags ‖ signCount(0)`.
/// Flags are UP·BE·BS plus UV when `user_verified` (`0x1D`, or `0x19`).
pub fn assertion_auth_data(rp_id: &str, user_verified: bool) -> [u8; ASSERTION_AUTH_DATA_LEN] {
    assertion_auth_data_with(flags(user_verified, false), rp_id)
}

pub(crate) fn assertion_auth_data_with(flags: u8, rp_id: &str) -> [u8; ASSERTION_AUTH_DATA_LEN] {
    let mut out = [0u8; ASSERTION_AUTH_DATA_LEN];
    out[..32].copy_from_slice(&rp_id_hash(rp_id));
    out[32] = flags;
    out
}

/// `{"fmt": "none", "attStmt": {}, "authData": authData}`, in canonical
/// order. Klav never attests, even when the RP asks for `direct`.
pub fn attestation_object_none(auth_data: &[u8]) -> Vec<u8> {
    Value::map(vec![
        (Value::text("fmt"), Value::text("none")),
        (Value::text("attStmt"), Value::map(vec![])),
        (Value::text("authData"), Value::bytes(auth_data)),
    ])
    .into_bytes()
}

/// The ceremony a `clientDataJSON` belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    /// `navigator.credentials.create`.
    Create,
    /// `navigator.credentials.get`.
    Get,
}

impl Ceremony {
    fn type_str(self) -> &'static str {
        match self {
            Ceremony::Create => "webauthn.create",
            Ceremony::Get => "webauthn.get",
        }
    }
}

/// The JSON-compatible serialization of client data (WebAuthn L3 §5.8.1.1):
/// `{"type":…,"challenge":…,"origin":…,"crossOrigin":false}`, with each
/// string escaped by `CCDToString`. Klav never builds a cross-origin client
/// data (spec §14.6): `origin` is the one the browser reported.
pub fn client_data_json(ceremony: Ceremony, challenge: &[u8], origin: &str) -> String {
    let mut out = String::with_capacity(96 + challenge.len() * 2 + origin.len());
    out.push_str("{\"type\":");
    ccd_to_string(&mut out, ceremony.type_str());
    out.push_str(",\"challenge\":");
    ccd_to_string(&mut out, &data_encoding::BASE64URL_NOPAD.encode(challenge));
    out.push_str(",\"origin\":");
    ccd_to_string(&mut out, origin);
    out.push_str(",\"crossOrigin\":false}");
    out
}

fn ccd_to_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{20}'..='\u{10FFFF}' => out.push(c),
            _ => out.push_str(&format!("\\u{:04x}", c as u32)),
        }
    }
    out.push('"');
}

/// What a registration returns to the page. Nothing here is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// Authenticator data (with the attested credential).
    pub auth_data: Vec<u8>,
    /// CBOR attestation object, format `none`.
    pub attestation_object: Vec<u8>,
    /// COSE public key (inside `auth_data` too).
    pub public_key_cose: Vec<u8>,
    /// SubjectPublicKeyInfo DER, for `getPublicKey()`.
    pub public_key_spki: Vec<u8>,
}

/// Builds the response of a registration for `key`.
pub fn register(
    key: &PasskeyPrivateKey,
    rp_id: &str,
    credential_id: &[u8],
    user_verified: bool,
) -> Result<Registration, CryptoError> {
    let public = key.public_key();
    let auth_data = registration_auth_data(rp_id, credential_id, &public, user_verified)?;
    Ok(Registration {
        attestation_object: attestation_object_none(&auth_data),
        auth_data,
        public_key_cose: cose_public_key(&public),
        public_key_spki: key.public_key_spki_der(),
    })
}

/// What an assertion returns to the page. Nothing here is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// Authenticator data (37 bytes).
    pub authenticator_data: Vec<u8>,
    /// ES256 signature of `authenticator_data ‖ client_data_hash`, DER.
    pub signature: Vec<u8>,
}

/// Signs an assertion. `client_data_hash` is SHA-256 of the
/// `clientDataJSON` that `klavd` built (or that iOS hands over).
pub fn assert(
    key: &PasskeyPrivateKey,
    rp_id: &str,
    user_verified: bool,
    client_data_hash: &[u8; 32],
) -> Assertion {
    sign_assertion(
        key,
        assertion_auth_data(rp_id, user_verified).to_vec(),
        client_data_hash,
    )
}

pub(crate) fn sign_assertion(
    key: &PasskeyPrivateKey,
    authenticator_data: Vec<u8>,
    client_data_hash: &[u8; 32],
) -> Assertion {
    let mut message = authenticator_data.clone();
    message.extend_from_slice(client_data_hash);
    Assertion {
        signature: key.sign(&message),
        authenticator_data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::passkey::verify_es256;
    use ciborium::value::Value as Cbor;
    use serde_json::Value as Json;

    fn decode(bytes: &[u8]) -> Cbor {
        ciborium::de::from_reader(bytes).expect("valid CBOR")
    }

    fn map_get<'a>(map: &'a Cbor, key: &Cbor) -> &'a Cbor {
        map.as_map()
            .expect("map")
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .expect("key present")
    }

    #[test]
    fn registration_decodes_with_an_independent_cbor_reader() {
        let key = PasskeyPrivateKey::generate();
        let cred = [9u8; 16];
        let reg = register(&key, "example.com", &cred, true).unwrap();
        assert_eq!(reg.auth_data.len(), 148);
        assert_eq!(reg.public_key_cose.len(), COSE_KEY_LEN);
        let att = decode(&reg.attestation_object);
        let entries = att.as_map().unwrap();
        let keys: Vec<_> = entries.iter().map(|(k, _)| k.as_text().unwrap()).collect();
        assert_eq!(keys, ["fmt", "attStmt", "authData"]);
        assert_eq!(
            map_get(&att, &Cbor::Text("fmt".into())).as_text(),
            Some("none")
        );
        assert!(
            map_get(&att, &Cbor::Text("attStmt".into()))
                .as_map()
                .unwrap()
                .is_empty()
        );
        let auth = map_get(&att, &Cbor::Text("authData".into()))
            .as_bytes()
            .unwrap();
        assert_eq!(auth, &reg.auth_data);
        assert_eq!(&auth[..32], &rp_id_hash("example.com"));
        assert_eq!(auth[32], 0x5D);
        assert_eq!(&auth[33..37], &[0, 0, 0, 0]);
        assert_eq!(&auth[37..53], &AAGUID);
        assert_eq!(&auth[53..55], &[0, 16]);
        assert_eq!(&auth[55..71], &cred);
        // The COSE key decodes to the public key, keys in canonical order.
        let cose = decode(&auth[71..]);
        let ints: Vec<i128> = cose
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_integer().unwrap().into())
            .collect();
        assert_eq!(ints, [1, 3, -1, -2, -3]);
        let int = |k: i64| map_get(&cose, &Cbor::Integer(k.into())).clone();
        assert_eq!(int(1), Cbor::Integer(2.into()));
        assert_eq!(int(3), Cbor::Integer((-7).into()));
        assert_eq!(int(-1), Cbor::Integer(1.into()));
        let public = key.public_key();
        assert_eq!(int(-2).as_bytes().unwrap().as_slice(), &public[1..33]);
        assert_eq!(int(-3).as_bytes().unwrap().as_slice(), &public[33..]);
        assert_eq!(
            register(&key, "example.com", &cred, false)
                .unwrap()
                .auth_data[32],
            0x59
        );
    }

    #[test]
    fn assertions_verify_and_carry_the_flags() {
        let key = PasskeyPrivateKey::generate();
        let cdj = client_data_json(Ceremony::Get, b"challenge-bytes!", "https://example.com");
        let hash = client_data_hash(cdj.as_bytes());
        let a = assert(&key, "example.com", true, &hash);
        assert_eq!(a.authenticator_data.len(), 37);
        assert_eq!(a.authenticator_data[32], 0x1D);
        let mut message = a.authenticator_data.clone();
        message.extend_from_slice(&hash);
        verify_es256(&key.public_key(), &message, &a.signature).unwrap();
        assert_eq!(
            assert(&key, "example.com", false, &hash).authenticator_data[32],
            0x19
        );
    }

    #[test]
    fn client_data_json_is_valid_json_in_the_fixed_order() {
        let cdj = client_data_json(Ceremony::Create, &[0xfb, 0xff], "https://a.example");
        assert_eq!(
            cdj,
            r#"{"type":"webauthn.create","challenge":"-_8","origin":"https://a.example","crossOrigin":false}"#
        );
        // Escaping of CCDToString: quote, backslash and control characters.
        let odd = client_data_json(Ceremony::Get, b"", "https://x\"\\\u{1}\u{7f}é");
        let parsed: Json = serde_json::from_str(&odd).unwrap();
        assert_eq!(parsed["origin"], "https://x\"\\\u{1}\u{7f}é");
        assert!(odd.contains(r#""https://x\"\\\u0001"#));
        assert_eq!(parsed["crossOrigin"], false);
    }

    /// WebAuthn L3 §16, «ES256 Credential with No Attestation», transcribed
    /// in `docs/vectores/webauthn-l3.json`. With the same key, AAGUID,
    /// credential ID and flags, Klav must produce the same attestation
    /// object, authenticator data, `clientDataJSON` (of the assertion,
    /// which has no `extraData`) and, with RFC 6979, the same signature.
    #[test]
    fn webauthn_l3_es256_none_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/vectores/webauthn-l3.json");
        let file: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let h = |v: &Json| hex::decode(v.as_str().unwrap()).unwrap();
        let case = &file["cases"][0];
        let rp_id = case["rp_id"].as_str().unwrap();
        let origin = case["origin"].as_str().unwrap();
        let reg = &case["registration"];
        let scalar: [u8; 32] = h(&reg["credential_private_key"]).try_into().unwrap();
        let key = PasskeyPrivateKey::from_scalar(&scalar).unwrap();
        let aaguid: [u8; 16] = h(&reg["aaguid"]).try_into().unwrap();
        let flags = u8::from_str_radix(reg["flags"].as_str().unwrap(), 16).unwrap();
        let auth = registration_auth_data_with(
            &aaguid,
            flags,
            rp_id,
            &h(&reg["credential_id"]),
            &key.public_key(),
        )
        .unwrap();
        assert_eq!(
            attestation_object_none(&auth),
            h(&reg["attestation_object"])
        );

        let get = &case["authentication"];
        let cdj = client_data_json(Ceremony::Get, &h(&get["challenge"]), origin);
        assert_eq!(cdj.as_bytes(), h(&get["client_data_json"]));
        let flags = u8::from_str_radix(get["flags"].as_str().unwrap(), 16).unwrap();
        let a = sign_assertion(
            &key,
            assertion_auth_data_with(flags, rp_id).to_vec(),
            &client_data_hash(cdj.as_bytes()),
        );
        assert_eq!(a.authenticator_data, h(&get["authenticator_data"]));
        assert_eq!(a.signature, h(&get["signature"]));
        // The registration's clientDataJSON has `extraData`, which Klav
        // never adds; it still parses to the same leading fields.
        let reg_cdj: Json = serde_json::from_slice(&h(&reg["client_data_json"])).unwrap();
        assert_eq!(reg_cdj["type"], "webauthn.create");
        assert_eq!(
            reg_cdj["challenge"],
            data_encoding::BASE64URL_NOPAD.encode(&h(&reg["challenge"]))
        );
    }
}
