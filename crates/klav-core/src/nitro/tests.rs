//! Positive and negative tests of the Nitro checks. Every mutation of a
//! document is re-signed with the leaf key (or the chain rebuilt), so it
//! reaches the check it names; each test asserts that exact error.

use ed25519_dalek::Signer as _;

use super::attestation::{
    verify_document_with_root, verify_handoff_holder_with_root, verify_handoff_peer_with_root,
    verify_hosted_proxy_with_root,
};
use super::manifest::verify_manifest_with_keys;
use super::testkit::*;
use super::*;
use crate::ids::{AccountId, AgentId};

/// The captured document of a real debug-mode enclave (testdata/README.md).
pub(crate) const REAL_DEBUG_DOCUMENT: &[u8] =
    include_bytes!("testdata/evervault-2023-09-18-debug.cbor");
/// Its `timestamp`: 2023-09-18T15:03:30.860Z.
pub(crate) const REAL_DEBUG_TIMESTAMP_MS: u64 = 1_695_049_410_860;

/// The captured document of Klav's own enclave on real hardware
/// (testdata/README.md): `GET https://proxy.klav.dev/v1/attest` on a
/// `c7g.large` in `us-east-2a`, running an image of manifest 2 at
/// commit `23f82370`.
pub(crate) const REAL_KLAV_DOCUMENT: &[u8] =
    include_bytes!("testdata/klav-proxy-2026-11-27-us-east-2a.cbor");
/// Its `timestamp`: 2026-11-27T13:43:56.356Z.
pub(crate) const REAL_KLAV_TIMESTAMP_MS: u64 = 1_795_787_036_356;
/// The `nonce` query parameter of that capture. It was sent as these 64
/// characters, which the API reads as base64url: the document carries their
/// 48 decoded bytes, not the 32 bytes the hex spells.
pub(crate) const REAL_KLAV_NONCE_PARAM: &[u8] =
    b"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";

pub(crate) fn release_key(label: &str) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&det(&format!("release key {label}")))
}

pub(crate) fn pcr_hex(p: &[u8]) -> String {
    hex::encode(p)
}

/// One image line of a manifest: `(version, pcr0, pcr1, pcr2, status)`.
pub(crate) type ImageLine = (&'static str, Pcr, Pcr, Pcr, &'static str);

pub(crate) fn current_image() -> ImageLine {
    ("0.12.0", test_pcr(0), test_pcr(1), test_pcr(2), "current")
}

/// A manifest in the ADR's field order.
pub(crate) fn manifest_json(seq: u64, issued: u64, expires: u64, images: &[ImageLine]) -> String {
    let images: Vec<String> = images
        .iter()
        .map(|(version, p0, p1, p2, status)| {
            format!(
                r#"{{"version":"{version}","commit":"{}","arch":"aarch64","pcr0":"{}","pcr1":"{}","pcr2":"{}","status":"{status}"}}"#,
                hex::encode(det::<20>(version)),
                pcr_hex(p0),
                pcr_hex(p1),
                pcr_hex(p2),
            )
        })
        .collect();
    format!(
        r#"{{"v":1,"seq":{seq},"seed_epoch":0,"issued_at_ms":{issued},"expires_at_ms":{expires},"endpoint":"proxy.klav.dev","server":"api.klav.dev","images":[{}],"parent_roles":["{}"],"egress":["203.0.113.10/32","203.0.113.11/32"]}}"#,
        images.join(","),
        pcr_hex(&test_pcr(3)),
    )
}

pub(crate) fn sign_manifest(key: &ed25519_dalek::SigningKey, manifest: &[u8]) -> [u8; 64] {
    key.sign(&manifest_message(manifest)).to_bytes()
}

pub(crate) fn manifest_from(images: &[ImageLine]) -> VerifiedManifest {
    let key = release_key("active");
    let json = manifest_json(7, NOW_MS - DAY_MS, NOW_MS + 29 * DAY_MS, images);
    verify_manifest_with_keys(
        json.as_bytes(),
        &sign_manifest(&key, json.as_bytes()),
        &[key.verifying_key().to_bytes()],
        None,
        NOW_MS,
    )
    .expect("the test manifest verifies")
}

/// Everything a device knows when it checks the hosted proxy.
pub(crate) struct Fixture {
    pub(crate) chain: TestChain,
    pub(crate) nonce: [u8; 32],
    pub(crate) binding: [u8; 32],
    pub(crate) manifest: VerifiedManifest,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let seed = HostedSeed::from_bytes(&det("hosted seed"));
        let account = AccountId::from_bytes(det("account"));
        let agent = AgentId::from_bytes(det("agent"));
        let keys = derive_account_keys(&seed, account, 0);
        Self {
            chain: TestChain::new(),
            nonce: det("nonce"),
            binding: enclave_binding(account, agent, keys.public(), 0),
            manifest: manifest_from(&[current_image()]),
        }
    }

    pub(crate) fn spec(&self) -> DocSpec {
        DocSpec::new(&self.nonce, &self.binding)
    }

    pub(crate) fn expectation(&self) -> HostedProxyExpectation<'_> {
        HostedProxyExpectation {
            nonce: &self.nonce,
            binding: &self.binding,
            now_ms: NOW_MS,
        }
    }

    /// The device's whole check on `document`.
    pub(crate) fn check(&self, document: &[u8]) -> Result<&ManifestImage, NitroError> {
        verify_hosted_proxy_with_root(
            document,
            &self.chain.root,
            &self.manifest,
            &self.expectation(),
        )
    }
}

// --------------------------------------------------------------- positive --

#[test]
fn a_synthetic_document_verifies() {
    let f = Fixture::new();
    let document = f.spec().build(&f.chain);
    let image = f.check(&document).expect("verifies");
    assert_eq!(image.version(), (0, 12, 0));
    assert_eq!(image.status(), ImageStatus::Current);

    let doc = verify_document_with_root(&document, &f.chain.root, NOW_MS).expect("verifies");
    assert_eq!(doc.user_data(), Some(f.binding.as_slice()));
    assert_eq!(doc.pcr(3), Some(&test_pcr(3)));
}

#[test]
fn a_tagged_document_verifies_too() {
    let f = Fixture::new();
    let mut spec = f.spec();
    spec.tagged = true;
    assert!(f.check(&spec.build(&f.chain)).is_ok());
}

/// A real NSM writes the payload's top-level map with an indefinite length
/// (ADR 0051 §18, `a_real_document_of_klavs_enclave_matches_manifest_2`).
/// The reader accepts any array or map in that form: a document with every
/// array and map indefinite, the protected header too, verifies and reads as
/// its definite twin.
#[test]
fn a_document_with_indefinite_arrays_and_maps_verifies() {
    let f = Fixture::new();
    let mut spec = f.spec();
    spec.indefinite_containers = true;
    spec.protected = vec![0xbf, 0x01, 0x38, 0x22, 0xff];
    let document = spec.build(&f.chain);
    assert_eq!(document[0], 0x9f, "the COSE array is indefinite");
    assert_eq!(document.last(), Some(&0xff));

    let doc = verify_document_with_root(&document, &f.chain.root, NOW_MS).expect("verifies");
    let definite = f.spec().build(&f.chain);
    let twin = verify_document_with_root(&definite, &f.chain.root, NOW_MS).expect("verifies");
    assert_eq!(doc, twin);
    assert!(f.check(&document).is_ok());

    // Tagged, and with only the containers indefinite (definite protected).
    spec.tagged = true;
    assert!(f.check(&spec.build(&f.chain)).is_ok());
    let mut definite_protected = f.spec();
    definite_protected.indefinite_containers = true;
    assert!(f.check(&definite_protected.build(&f.chain)).is_ok());

    // The payload map's own checks hold when it is indefinite.
    let mut duplicate = f.spec();
    duplicate.indefinite_containers = true;
    duplicate.extra = vec![(Cbor::text("nonce"), Cbor::bytes(&f.nonce))];
    expect(&f, &duplicate, NitroError::Cbor(CborError::DuplicateKey));
    let mut unknown = f.spec();
    unknown.indefinite_containers = true;
    unknown.extra = vec![(Cbor::text("debug"), Cbor::uint(1))];
    expect(&f, &unknown, NitroError::UnknownField);

    // Changing a byte of the signed protected header breaks the signature:
    // the signature covers the bytes as sent, not their decoded value.
    // Here it is swapped for the definite `{1: -35}`, which is accepted on
    // its own, so only the signature can refuse it.
    let mut swapped = document.clone();
    let at = swapped
        .windows(6)
        .position(|w| w == [0x45, 0xbf, 0x01, 0x38, 0x22, 0xff])
        .expect("protected header");
    swapped.splice(at..at + 6, [0x44, 0xa1, 0x01, 0x38, 0x22]);
    assert_eq!(f.check(&swapped), Err(NitroError::Signature));
}

#[test]
fn a_draining_image_is_accepted() {
    let mut f = Fixture::new();
    let (v, p0, p1, p2, _) = current_image();
    f.manifest = manifest_from(&[(v, p0, p1, p2, "draining")]);
    let image = f.check(&f.spec().build(&f.chain)).expect("accepted");
    assert_eq!(image.status(), ImageStatus::Draining);
}

/// ADR 0051 §13: AWS's chain is ECDSA P-384 with SHA-384 end to end. A real
/// document from 2023 chains to the pinned root and its COSE signature
/// verifies; its PCRs are zero (debug mode), so the enclave is refused.
#[test]
fn a_real_document_verifies_and_its_debug_enclave_is_refused() {
    let doc = verify_document(REAL_DEBUG_DOCUMENT, REAL_DEBUG_TIMESTAMP_MS).expect("real chain");
    assert_eq!(doc.module_id(), "i-0918f6c55e3b61d89-enc018aa8b8e2285d13");
    assert_eq!(doc.timestamp_ms(), REAL_DEBUG_TIMESTAMP_MS);
    assert_eq!(doc.nonce().map(<[u8]>::len), Some(256));
    assert_eq!(doc.public_key(), None);
    assert!((0..16).all(|i| doc.pcr(i).is_some()));
    assert_eq!(doc.measurement(), Err(NitroError::DebugEnclave));

    // A day later the leaf (valid for three hours) has expired.
    assert_eq!(
        verify_document(REAL_DEBUG_DOCUMENT, REAL_DEBUG_TIMESTAMP_MS + DAY_MS),
        Err(NitroError::Validity { index: 3 })
    );
    // One bit of the payload changed (in module_id): the signature fails.
    let mut flipped = REAL_DEBUG_DOCUMENT.to_vec();
    let at = flipped
        .windows(12)
        .position(|w| w == b"i-0918f6c55e")
        .expect("module id");
    flipped[at + 5] ^= 0x01;
    assert_eq!(
        verify_document(&flipped, REAL_DEBUG_TIMESTAMP_MS),
        Err(NitroError::Signature)
    );
}

/// ADR 0051 §18: the first document of Klav's own enclave, captured live in
/// `us-east-2`. It chains to the pinned root, its PCR0–3 are the ones
/// published in manifest 2 and `deploy/nitro/manifests/2.json` accepts it.
/// Real NSM output writes only the payload's top-level map with an
/// indefinite length; the COSE array, the protected header, `pcrs` and
/// `cabundle` are definite.
#[test]
fn a_real_document_of_klavs_enclave_matches_manifest_2() {
    let doc = verify_document(REAL_KLAV_DOCUMENT, REAL_KLAV_TIMESTAMP_MS).expect("real chain");
    assert_eq!(doc.module_id(), "i-067f86b09762550c5-enc01a21af794a29886");
    assert_eq!(doc.timestamp_ms(), REAL_KLAV_TIMESTAMP_MS);
    assert_eq!(doc.public_key(), None);
    let pcr = |i: u8| hex::encode(doc.pcr(i).expect("pcr"));
    assert_eq!(
        pcr(0),
        "5fb787478bec5ce5177cd53fda493abbd540fd231ea4f8c521b4b3b82aa85a1319c0025cdb3e36ffac8d0a223a7faa23"
    );
    assert_eq!(
        pcr(1),
        "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03"
    );
    assert_eq!(
        pcr(2),
        "53c8a3bc595b73dcf8acd799649b39afc6c2468730306c05aa524427b39cf941fa0a4d9f169bb5b8fa34f2b78f73e00a"
    );
    assert_eq!(
        pcr(3),
        "c736eec14c71000823cc5b011f61cad2ef5e45605bdef47aed8494021b21d5f28011c2f7ebfc1723eb8d929504400eca"
    );

    // Where the indefinite length is: `84` (array of 4), the protected
    // header `44 a1 01 38 22`, `a0`, then a 4432-byte payload (`59 11 50`)
    // that opens with `bf` and closes with `ff`.
    assert_eq!(
        REAL_KLAV_DOCUMENT[..7],
        [0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0]
    );
    assert_eq!(REAL_KLAV_DOCUMENT[7..10], [0x59, 0x11, 0x50]);
    let payload = &REAL_KLAV_DOCUMENT[10..10 + 0x1150];
    assert_eq!((payload[0], payload[payload.len() - 1]), (0xbf, 0xff));
    let after = |key: &[u8]| {
        let at = payload
            .windows(key.len())
            .position(|w| w == key)
            .expect("key");
        payload[at + key.len()]
    };
    assert_eq!(after(b"\x64pcrs"), 0xb0, "pcrs: a definite map of 16");
    assert_eq!(
        after(b"\x68cabundle"),
        0x84,
        "cabundle: a definite array of 4"
    );

    // The published manifest 2 and its signature, as devices fetch them.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/nitro/manifests");
    let manifest_bytes = std::fs::read(dir.join("2.json")).expect("manifest 2");
    let sig = std::fs::read_to_string(dir.join("2.json.sig")).expect("its signature");
    let sig: [u8; 64] = hex::decode(sig.trim_end())
        .expect("hex")
        .try_into()
        .expect("64 bytes");
    let manifest =
        verify_manifest(&manifest_bytes, &sig, None, REAL_KLAV_TIMESTAMP_MS).expect("manifest 2");
    assert_eq!(manifest.seq(), 2);
    assert_eq!(
        manifest.parent_roles(),
        [*doc.pcr(3).expect("pcr3")].as_slice(),
        "PCR3 is the parent role manifest 2 lists"
    );

    // The device's whole check. The capture recorded only the account and
    // agent IDs, not the agent's public keys, so the binding is taken from
    // the document's `user_data` rather than recomputed with
    // `enclave_binding`: this checks the chain, the nonce, freshness and the
    // manifest, not who the agent is.
    let nonce = data_encoding::BASE64URL_NOPAD
        .decode(REAL_KLAV_NONCE_PARAM)
        .expect("base64url");
    assert_eq!(nonce.len(), 48);
    assert_eq!(doc.nonce(), Some(nonce.as_slice()));
    let binding: [u8; 32] = doc.user_data().expect("user_data").try_into().expect("32");
    let image = verify_hosted_proxy(
        REAL_KLAV_DOCUMENT,
        &manifest,
        &HostedProxyExpectation {
            nonce: &nonce,
            binding: &binding,
            now_ms: REAL_KLAV_TIMESTAMP_MS,
        },
    )
    .expect("the live enclave passes the device's check");
    assert_eq!(image.commit(), "23f82370520574eb91e78dd0d70c7031263d5866");
    assert_eq!(image.status(), ImageStatus::Current);
    assert_eq!(hex::encode(image.measurement().pcr0), pcr(0));

    // A day later a certificate of the chain (index 3, the last
    // intermediate) has expired; one bit of module_id breaks the signature.
    assert_eq!(
        verify_document(REAL_KLAV_DOCUMENT, REAL_KLAV_TIMESTAMP_MS + DAY_MS),
        Err(NitroError::Validity { index: 3 })
    );
    let mut flipped = REAL_KLAV_DOCUMENT.to_vec();
    let at = flipped
        .windows(12)
        .position(|w| w == b"i-067f86b097")
        .expect("module id");
    flipped[at + 5] ^= 0x01;
    assert_eq!(
        verify_document(&flipped, REAL_KLAV_TIMESTAMP_MS),
        Err(NitroError::Signature)
    );
}

/// A document captured by hand: `KLAV_NITRO_DOC=path [KLAV_NITRO_NOW_MS=ms]
/// cargo test -p klav-core --features nitro-attestation -- --ignored captured`.
/// Layer 6 runs it on the hosted proxy's test enclave.
#[test]
#[ignore = "needs a captured document in KLAV_NITRO_DOC"]
fn a_captured_document_chains_to_the_pinned_root() {
    let path = std::env::var("KLAV_NITRO_DOC").expect("KLAV_NITRO_DOC");
    let bytes = std::fs::read(path).expect("readable document");
    let now = std::env::var("KLAV_NITRO_NOW_MS")
        .ok()
        .and_then(|v| v.parse().ok());
    let doc = match now {
        Some(now) => verify_document(&bytes, now),
        None => {
            // At its own timestamp: read it first, unverified.
            let first = verify_document(&bytes, u64::MAX);
            let Err(NitroError::Validity { .. }) = first else {
                panic!("unexpected result {first:?}");
            };
            let ts = timestamp_of(&bytes);
            verify_document(&bytes, ts)
        }
    };
    let doc = doc.expect("chain and signature verify");
    assert!(!doc.module_id().is_empty());
}

fn timestamp_of(document: &[u8]) -> u64 {
    use super::cbor::{Value, decode};
    let Ok(Value::Array(parts)) = decode(document) else {
        panic!("not a COSE_Sign1")
    };
    let Value::Bytes(payload) = parts[2] else {
        panic!("no payload")
    };
    let Ok(Value::Map(entries)) = decode(payload) else {
        panic!("no map")
    };
    entries
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text("timestamp"), Value::Uint(t)) => Some(*t),
            _ => None,
        })
        .expect("timestamp")
}

// --------------------------------------------------- document negatives --

fn expect(f: &Fixture, spec: &DocSpec, error: NitroError) {
    assert_eq!(f.check(&spec.build(&f.chain)), Err(error));
}

#[test]
fn one_bit_in_the_payload_breaks_the_signature() {
    let f = Fixture::new();
    let mut document = f.spec().build(&f.chain);
    // Inside module_id: the CBOR stays valid.
    let at = document
        .windows(4)
        .position(|w| w == b"i-01")
        .expect("module id");
    document[at + 3] ^= 0x01;
    assert_eq!(f.check(&document), Err(NitroError::Signature));
}

#[test]
fn one_bit_in_the_signature_breaks_it() {
    let f = Fixture::new();
    let mut document = f.spec().build(&f.chain);
    let last = document.len() - 1;
    document[last] ^= 0x01;
    assert_eq!(f.check(&document), Err(NitroError::Signature));
}

#[test]
fn a_changed_pcr_is_not_in_the_manifest() {
    let f = Fixture::new();
    for index in 0..3 {
        let mut spec = f.spec();
        let mut pcr = test_pcr(index);
        pcr[0] ^= 0x01;
        spec.set_pcr(index, &pcr);
        expect(&f, &spec, NitroError::ImageNotListed);
    }
}

#[test]
fn zero_pcrs_are_a_debug_enclave() {
    let f = Fixture::new();
    for index in 0..3 {
        let mut spec = f.spec();
        spec.set_pcr(index, &[0; 48]);
        expect(&f, &spec, NitroError::DebugEnclave);
    }
}

#[test]
fn a_revoked_image_is_refused() {
    let mut f = Fixture::new();
    let (v, p0, p1, p2, _) = current_image();
    f.manifest = manifest_from(&[(v, p0, p1, p2, "revoked")]);
    expect(&f, &f.spec(), NitroError::ImageRevoked);
}

#[test]
fn freshness_nonce_and_binding() {
    let f = Fixture::new();

    let mut stale = f.spec();
    stale.timestamp_ms = NOW_MS - FRESHNESS_MS - 1;
    expect(&f, &stale, NitroError::Stale);
    let mut future = f.spec();
    future.timestamp_ms = NOW_MS + FRESHNESS_MS + 1;
    expect(&f, &future, NitroError::Stale);
    let mut edge = f.spec();
    edge.timestamp_ms = NOW_MS - FRESHNESS_MS;
    assert!(f.check(&edge.build(&f.chain)).is_ok());

    let mut nonce = f.spec();
    nonce.nonce = Some(det::<32>("another nonce").to_vec());
    expect(&f, &nonce, NitroError::Nonce);
    let mut no_nonce = f.spec();
    no_nonce.nonce = None;
    expect(&f, &no_nonce, NitroError::Nonce);

    let mut binding = f.spec();
    binding.user_data = Some(det::<32>("another binding").to_vec());
    expect(&f, &binding, NitroError::Binding);
    let mut no_binding = f.spec();
    no_binding.user_data = None;
    expect(&f, &no_binding, NitroError::Binding);
}

#[test]
fn the_payload_has_exactly_the_documented_fields() {
    let f = Fixture::new();

    let mut extra = f.spec();
    extra.extra = vec![(Cbor::text("debug"), Cbor::uint(1))];
    expect(&f, &extra, NitroError::UnknownField);
    let mut int_key = f.spec();
    int_key.extra = vec![(Cbor::uint(1), Cbor::uint(1))];
    expect(&f, &int_key, NitroError::UnknownField);

    let mut duplicate = f.spec();
    duplicate.extra = vec![(Cbor::text("nonce"), Cbor::bytes(&f.nonce))];
    expect(&f, &duplicate, NitroError::Cbor(CborError::DuplicateKey));

    // An indefinite payload map is read like the definite one.
    let mut indefinite = f.spec();
    indefinite.indefinite = true;
    assert!(f.check(&indefinite.build(&f.chain)).is_ok());

    let mut digest = f.spec();
    digest.digest = "SHA256".into();
    expect(&f, &digest, NitroError::Digest);

    let mut module = f.spec();
    module.module_id = String::new();
    expect(&f, &module, NitroError::ModuleId);

    let mut short_pcr = f.spec();
    short_pcr.set_pcr(5, &[1; 32]);
    expect(&f, &short_pcr, NitroError::Field("pcrs"));
    let mut missing_pcr = f.spec();
    missing_pcr.pcrs.retain(|(i, _)| *i != 2);
    expect(&f, &missing_pcr, NitroError::Field("pcrs"));
    let mut high_pcr = f.spec();
    high_pcr.pcrs.push((32, vec![1; 48]));
    expect(&f, &high_pcr, NitroError::Field("pcrs"));

    let mut big = f.spec();
    big.public_key = Some(vec![1; MAX_OPTIONAL_FIELD_LEN + 1]);
    expect(&f, &big, NitroError::Field("public_key"));
}

#[test]
fn the_cose_envelope_is_strict() {
    let f = Fixture::new();

    let mut es256 = f.spec();
    es256.protected = vec![0xa1, 0x01, 0x26];
    expect(&f, &es256, NitroError::ProtectedHeader);
    let mut extra_header = f.spec();
    extra_header.protected = vec![0xa2, 0x01, 0x38, 0x22, 0x04, 0x40];
    expect(&f, &extra_header, NitroError::ProtectedHeader);
    // The protected header decodes strictly to exactly {1: -35}: any other
    // map, a repeated or extra entry, a non-map, a long form, an indefinite
    // string or a break with no map is the same refusal.
    for protected in [
        vec![0xbf, 0x01, 0x26, 0xff],
        vec![0xbf, 0x01, 0x38, 0x22, 0x04, 0x40, 0xff],
        vec![0xbf, 0x01, 0x38, 0x22, 0x01, 0x38, 0x22, 0xff],
        vec![0xa2, 0x01, 0x38, 0x22, 0x01, 0x38, 0x22],
        vec![0xa1, 0x02, 0x38, 0x22],
        vec![0xa1, 0x61, b'1', 0x38, 0x22],
        vec![0xa1, 0x18, 0x01, 0x38, 0x22],
        vec![0xa1, 0x01, 0x39, 0x00, 0x22],
        vec![0xbf, 0x01, 0x38, 0x22],
        vec![0xa1, 0x01, 0x38, 0x22, 0x00],
        vec![0xa0],
        vec![0xbf, 0xff],
        vec![0x82, 0x01, 0x38, 0x22],
        vec![0x5f, 0x41, 0x01, 0xff],
        vec![0xff],
        vec![],
    ] {
        let mut spec = f.spec();
        spec.protected = protected.clone();
        assert_eq!(
            f.check(&spec.build(&f.chain)),
            Err(NitroError::ProtectedHeader),
            "{protected:02x?}"
        );
    }

    let spec = f.spec();
    let payload = spec.payload(&f.chain);
    let good = spec.build(&f.chain);
    let unprotected = Cbor::array(&[
        Cbor::bytes(&PROTECTED_ES384),
        Cbor::map(&[(Cbor::uint(4), Cbor::bytes(b"kid"))]),
        Cbor::bytes(&payload),
        Cbor::bytes(&[0; 96]),
    ]);
    assert_eq!(f.check(&unprotected.0), Err(NitroError::UnprotectedHeader));

    let mut trailing = good.clone();
    trailing.push(0x00);
    assert_eq!(
        f.check(&trailing),
        Err(NitroError::Cbor(CborError::TrailingBytes))
    );
    let other_tag = Cbor::tag(98, Cbor(good.clone())).0;
    assert_eq!(f.check(&other_tag), Err(NitroError::Cose("unexpected tag")));
    let short_sig = cose(&PROTECTED_ES384, &payload, &[0; 64], false);
    assert_eq!(
        f.check(&short_sig),
        Err(NitroError::Cose("signature is not 96 bytes"))
    );
    assert_eq!(
        f.check(&vec![0x40; MAX_DOCUMENT_LEN + 1]),
        Err(NitroError::TooLarge)
    );
}

// ---------------------------------------------------------- chain negatives --

#[test]
fn the_chain_must_start_at_the_root() {
    let f = Fixture::new();
    let document = f.spec().build(&f.chain);
    // Production pins AWS's root: a synthetic chain is refused.
    assert_eq!(
        verify_document(&document, NOW_MS),
        Err(NitroError::RootMismatch)
    );
    let mut no_root = f.spec();
    no_root.cabundle = Some(f.chain.intermediates.clone());
    expect(&f, &no_root, NitroError::RootMismatch);
    let mut empty = f.spec();
    empty.cabundle = Some(Vec::new());
    expect(&f, &empty, NitroError::ChainLength);
    let mut long = f.spec();
    let mut bundle = f.chain.cabundle();
    bundle.extend(std::iter::repeat_n(f.chain.intermediates[0].clone(), 6));
    long.cabundle = Some(bundle);
    expect(&f, &long, NitroError::ChainLength);
}

#[test]
fn the_chain_order_matters() {
    let f = Fixture::new();
    let mut swapped = f.spec();
    swapped.cabundle = Some(vec![
        f.chain.root.clone(),
        f.chain.intermediates[1].clone(),
        f.chain.intermediates[0].clone(),
    ]);
    expect(&f, &swapped, NitroError::IssuerMismatch { index: 1 });
}

/// A document from a chain built with changed specs, verified at `now`.
fn chain_case(
    change: impl FnOnce(&mut Vec<CertSpec>),
    now: u64,
) -> Result<VerifiedDocument, NitroError> {
    let mut specs = TestChain::specs();
    change(&mut specs);
    let chain = TestChain::from_specs(specs);
    let f = Fixture::new();
    let document = f.spec().build(&chain);
    verify_document_with_root(&document, &chain.root, now)
}

#[test]
fn every_certificate_is_checked() {
    // Expired and not yet valid.
    assert_eq!(
        chain_case(|s| s[2].not_after_ms = NOW_MS - 1, NOW_MS),
        Err(NitroError::Validity { index: 2 })
    );
    assert_eq!(
        chain_case(|s| s[3].not_before_ms = NOW_MS + 1_000, NOW_MS),
        Err(NitroError::Validity { index: 3 })
    );
    // The leaf is a CA, or can't sign.
    assert_eq!(
        chain_case(|s| s[3].basic = Some((true, None)), NOW_MS),
        Err(NitroError::LeafUsage)
    );
    assert_eq!(
        chain_case(|s| s[3].key_usage = Some(KU_CERT_SIGN), NOW_MS),
        Err(NitroError::LeafUsage)
    );
    // An intermediate is not a CA, or may not sign certificates.
    assert_eq!(
        chain_case(|s| s[1].basic = Some((false, None)), NOW_MS),
        Err(NitroError::NotCa { index: 1 })
    );
    assert_eq!(
        chain_case(|s| s[2].key_usage = Some(KU_DIGITAL_SIGNATURE), NOW_MS),
        Err(NitroError::NotCa { index: 2 })
    );
    assert_eq!(
        chain_case(|s| s[1].basic = None, NOW_MS),
        Err(NitroError::NotCa { index: 1 })
    );
    // pathLenConstraint 0 with an intermediate below.
    assert_eq!(
        chain_case(|s| s[1].basic = Some((true, Some(0))), NOW_MS),
        Err(NitroError::PathLength { index: 1 })
    );
    // A critical extension nobody processes.
    assert_eq!(
        chain_case(|s| s[2].unknown_critical = true, NOW_MS),
        Err(NitroError::Extension { index: 2 })
    );
    // ECDSA with SHA-256.
    assert_eq!(
        chain_case(|s| s[3].signature_oid = "1.2.840.10045.4.3.2", NOW_MS),
        Err(NitroError::Algorithm { index: 3 })
    );
    // The leaf names an issuer that is not the certificate before it.
    assert_eq!(
        chain_case(
            |s| s[3].issuer = "regional.klav-test.nitro-enclaves".into(),
            NOW_MS
        ),
        Err(NitroError::IssuerMismatch { index: 3 })
    );
}

#[test]
fn a_certificate_signed_by_another_key_is_refused() {
    let mut chain = TestChain::new();
    // The leaf, signed by the root's key while naming the last intermediate.
    chain.leaf = chain.specs[3].build(&chain.keys[3], &chain.keys[0]);
    let f = Fixture::new();
    let document = f.spec().build(&chain);
    assert_eq!(
        verify_document_with_root(&document, &chain.root, NOW_MS),
        Err(NitroError::ChainSignature { index: 3 })
    );
}

#[test]
fn a_flipped_bit_in_a_certificate_is_refused() {
    let f = Fixture::new();
    let mut leaf = f.chain.leaf.clone();
    let last = leaf.len() - 1;
    leaf[last] ^= 0x01;
    let mut spec = f.spec();
    spec.certificate = Some(leaf);
    assert!(matches!(
        f.check(&spec.build(&f.chain)),
        Err(NitroError::ChainSignature { index: 3 } | NitroError::Certificate { index: 3, .. })
    ));
}

// ------------------------------------------------------------------ hand-off --

#[test]
fn a_peer_is_handed_the_seed_only_when_it_qualifies() {
    let f = Fixture::new();
    let own = f.manifest.images()[0].clone();
    let peer_key = det::<32>("peer x25519");
    let mut spec = f.spec();
    spec.public_key = Some(peer_key.to_vec());
    let check = |spec: &DocSpec, manifest: &VerifiedManifest, own: &ManifestImage| {
        verify_handoff_peer_with_root(
            &spec.build(&f.chain),
            &f.chain.root,
            manifest,
            own,
            &f.nonce,
            NOW_MS,
        )
        .map(|p| (p.x25519, p.image.version()))
    };
    assert_eq!(check(&spec, &f.manifest, &own), Ok((peer_key, (0, 12, 0))));

    // PCR3 is not one of Klav's instance roles.
    let mut role = spec.clone();
    role.set_pcr(3, &det::<48>("someone else's role"));
    assert_eq!(check(&role, &f.manifest, &own), Err(NitroError::ParentRole));

    // No X25519 key to seal to.
    let mut no_key = spec.clone();
    no_key.public_key = None;
    assert_eq!(
        check(&no_key, &f.manifest, &own),
        Err(NitroError::PublicKey)
    );

    // The holder runs 0.13.0; the peer's 0.12.0 is older.
    let newer: ImageLine = (
        "0.13.0",
        det("newer 0"),
        det("newer 1"),
        det("newer 2"),
        "current",
    );
    let manifest = manifest_from(&[newer, current_image()]);
    let own_newer = manifest.images()[0].clone();
    assert_eq!(
        check(&spec, &manifest, &own_newer),
        Err(NitroError::Downgrade)
    );
}

/// ADR 0051 §4.2 step 3, in both directions of a rolling upgrade: a new
/// joiner takes the seed from an older holder (the holder refuses only an
/// older joiner, above), and the joiner refuses a holder on another role,
/// a revoked or unlisted image, or a document with another nonce.
#[test]
fn a_joiner_takes_the_seed_only_from_a_qualifying_holder() {
    let f = Fixture::new();
    let check = |spec: &DocSpec, manifest: &VerifiedManifest| {
        verify_handoff_holder_with_root(
            &spec.build(&f.chain),
            &f.chain.root,
            manifest,
            &f.nonce,
            NOW_MS,
        )
        .map(|h| h.image.version())
    };
    // The holder runs 0.12.0; the manifest also lists a newer 0.13.0,
    // which the joiner runs: an older holder is accepted.
    let newer: ImageLine = (
        "0.13.0",
        det("newer 0"),
        det("newer 1"),
        det("newer 2"),
        "current",
    );
    let manifest = manifest_from(&[newer, current_image()]);
    let spec = f.spec();
    assert_eq!(check(&spec, &manifest), Ok((0, 12, 0)));
    // No public key is needed from the holder.
    assert_eq!(spec.public_key, None);

    let mut role = spec.clone();
    role.set_pcr(3, &det::<48>("someone else's role"));
    assert_eq!(check(&role, &manifest), Err(NitroError::ParentRole));

    let mut unlisted = spec.clone();
    unlisted.set_pcr(0, &det::<48>("an image nobody listed"));
    assert_eq!(check(&unlisted, &manifest), Err(NitroError::ImageNotListed));

    let revoked = manifest_from(&[("0.12.0", test_pcr(0), test_pcr(1), test_pcr(2), "revoked")]);
    assert_eq!(check(&spec, &revoked), Err(NitroError::ImageRevoked));

    let mut other_nonce = spec.clone();
    other_nonce.nonce = Some(det::<32>("another nonce").to_vec());
    assert_eq!(check(&other_nonce, &manifest), Err(NitroError::Nonce));
}

// ---------------------------------------------------------------- manifest --

fn verify(
    json: &str,
    sig: &[u8; 64],
    keys: &[[u8; 32]],
    seen: Option<u64>,
    now: u64,
) -> Result<VerifiedManifest, NitroError> {
    verify_manifest_with_keys(json.as_bytes(), sig, keys, seen, now)
}

#[test]
fn manifest_checks() {
    let active = release_key("active");
    let backup = release_key("backup");
    let keys = [
        active.verifying_key().to_bytes(),
        backup.verifying_key().to_bytes(),
    ];
    let json = manifest_json(7, NOW_MS - DAY_MS, NOW_MS + 29 * DAY_MS, &[current_image()]);
    let sig = sign_manifest(&active, json.as_bytes());

    let m = verify(&json, &sig, &keys, None, NOW_MS).expect("verifies");
    assert_eq!(
        (m.seq(), m.seed_epoch(), m.endpoint(), m.server()),
        (7, 0, "proxy.klav.dev", "api.klav.dev")
    );
    assert_eq!(m.parent_roles(), &[test_pcr(3)]);
    assert_eq!(m.egress().len(), 2);

    // No key at all: nothing verifies.
    assert_eq!(
        verify(&json, &sig, &[], None, NOW_MS),
        Err(NitroError::NoReleaseKey)
    );
    // Production pins the real keys: a test key's signature is refused.
    assert_eq!(
        verify_manifest(json.as_bytes(), &sig, None, NOW_MS),
        Err(NitroError::ManifestSignature)
    );
    // The backup key signs too; a third key doesn't.
    let by_backup = sign_manifest(&backup, json.as_bytes());
    assert!(verify(&json, &by_backup, &keys, None, NOW_MS).is_ok());
    let stranger = sign_manifest(&release_key("stranger"), json.as_bytes());
    assert_eq!(
        verify(&json, &stranger, &keys, None, NOW_MS),
        Err(NitroError::ManifestSignature)
    );
    // One byte of the manifest changed.
    let tampered = json.replace("\"seq\":7", "\"seq\":8");
    assert_eq!(
        verify(&tampered, &sig, &keys, None, NOW_MS),
        Err(NitroError::ManifestSignature)
    );

    // Watermark: the same seq again is fine, a lower one is a rollback.
    assert!(verify(&json, &sig, &keys, Some(7), NOW_MS).is_ok());
    assert_eq!(
        verify(&json, &sig, &keys, Some(8), NOW_MS),
        Err(NitroError::ManifestRollback)
    );
    // Dates.
    assert_eq!(
        verify(&json, &sig, &keys, None, NOW_MS + 29 * DAY_MS),
        Err(NitroError::ManifestExpired)
    );
    assert_eq!(
        verify(
            &json,
            &sig,
            &keys,
            None,
            NOW_MS - DAY_MS - MANIFEST_CLOCK_SKEW_MS - 1
        ),
        Err(NitroError::ManifestFuture)
    );
}

#[test]
fn malformed_manifests_are_refused_after_the_signature() {
    let key = release_key("active");
    let keys = [key.verifying_key().to_bytes()];
    let base = manifest_json(7, NOW_MS - DAY_MS, NOW_MS + 29 * DAY_MS, &[current_image()]);
    let (v, p0, p1, p2, _) = current_image();
    let cases: Vec<(String, &str)> = vec![
        (base.replace("\"v\":1", "\"v\":2"), "unsupported version"),
        (
            base.replacen('{', "{\"debug\":true,", 1),
            "not a version 1 manifest",
        ),
        (
            base.replacen('{', "{\"seq\":6,", 1),
            "not a version 1 manifest",
        ),
        (
            base.replace("\"status\":\"current\"", "\"status\":\"active\""),
            "not a version 1 manifest",
        ),
        (
            manifest_json(7, NOW_MS - DAY_MS, NOW_MS + 30 * DAY_MS, &[current_image()]),
            "validity longer than 30 days or empty",
        ),
        (manifest_json(7, NOW_MS, NOW_MS + DAY_MS, &[]), "no images"),
        (
            manifest_json(
                7,
                NOW_MS,
                NOW_MS + DAY_MS,
                &[(v, [0; 48], p1, p2, "current")],
            ),
            "image PCR is zero",
        ),
        (
            manifest_json(
                7,
                NOW_MS,
                NOW_MS + DAY_MS,
                &[current_image(), (v, p0, p1, p2, "revoked")],
            ),
            "image listed twice",
        ),
        (
            base.replace(&pcr_hex(&p0), &pcr_hex(&p0).to_uppercase()),
            "image PCR",
        ),
        (base.replace("\"0.12.0\"", "\"0.12\""), "image version"),
        (base.replace("aarch64", "arm64"), "image arch"),
        (
            base.replace("proxy.klav.dev", "Proxy.klav.dev"),
            "endpoint or server is not a host name",
        ),
        (base.replace("203.0.113.10/32", "203.0.113.10"), "egress"),
    ];
    for (json, reason) in cases {
        let sig = sign_manifest(&key, json.as_bytes());
        assert_eq!(
            verify(&json, &sig, &keys, None, NOW_MS),
            Err(NitroError::ManifestMalformed(reason)),
            "{json}"
        );
    }
}

/// The production release-authority keys (ADR 0051 §11.5), `[active,
/// backup]`, as Omar generated them; each one is a valid Ed25519 point,
/// since `verify_manifest` skips a key that doesn't parse.
#[test]
fn release_authority_keys_are_pinned() {
    let expected = [
        "a8aa68a51a5d6cee7b2c2789cea049ac1c6a2f80d98d1416ddc49fcf074abc45",
        "b25c2385c2179b8fd404e12b513ab512aa2048ec14b4b03bfb62d08c0e189e88",
    ];
    assert_eq!(RELEASE_AUTHORITY_KEYS.len(), 2);
    for (key, hex_key) in RELEASE_AUTHORITY_KEYS.iter().zip(expected) {
        assert_eq!(hex::encode(key), hex_key);
        assert!(
            ed25519_dalek::VerifyingKey::from_bytes(key).is_ok(),
            "{hex_key}"
        );
    }
}
