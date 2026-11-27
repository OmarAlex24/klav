//! Test-only builders: DER certificates, CBOR and `COSE_Sign1` documents in
//! the AWS Nitro format, signed with deterministic P-384 keys. They make the
//! synthetic chains of the vectors (spec §15.7) and the mutations of the
//! negative tests, each re-signed so it reaches the check it names.
//!
//! With the feature `nitro-testkit` (and no test) only [`super::fake`]
//! uses it, so some builders are unused there.
#![cfg_attr(not(test), allow(dead_code))]

use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use super::attestation::{PROTECTED_ES384, Pcr, sig_structure};

// ------------------------------------------------------------------ bytes --

/// Deterministic test bytes: a SHA-256 chain of a label.
pub(crate) fn det<const N: usize>(label: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let mut block = Sha256::digest(format!("klav nitro test vector: {label}").as_bytes());
    for chunk in out.chunks_mut(32) {
        chunk.copy_from_slice(&block[..chunk.len()]);
        block = Sha256::digest(block);
    }
    out
}

/// A deterministic P-384 test key.
pub(crate) fn p384_key(label: &str) -> SigningKey {
    SigningKey::from_slice(&det::<48>(label)).expect("a test scalar below the group order")
}

// -------------------------------------------------------------------- DER --

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(dotted: &str) -> Vec<u8> {
    let oid = der::oid::ObjectIdentifier::new(dotted).expect("valid OID");
    tlv(0x06, oid.as_bytes())
}

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0u8][..], bytes].concat())
}

fn utc_time(ms: u64) -> Vec<u8> {
    use der::Encode;
    der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_millis(ms))
        .expect("a time before 2050")
        .to_der()
        .expect("encodes")
}

fn name(common_name: &str) -> Vec<u8> {
    seq(&[tlv(
        0x31,
        &seq(&[oid("2.5.4.3"), tlv(0x0c, common_name.as_bytes())]),
    )])
}

fn extension(id: &str, critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![oid(id)];
    if critical {
        parts.push(vec![0x01, 0x01, 0xff]);
    }
    parts.push(tlv(0x04, &value));
    seq(&parts)
}

/// What one test certificate says.
#[derive(Debug, Clone)]
pub(crate) struct CertSpec {
    pub(crate) subject: String,
    pub(crate) issuer: String,
    pub(crate) serial: u8,
    pub(crate) not_before_ms: u64,
    pub(crate) not_after_ms: u64,
    /// `None`: no basicConstraints; `Some((ca, path_len))` otherwise.
    pub(crate) basic: Option<(bool, Option<u8>)>,
    /// The keyUsage BIT STRING as `(unused_bits, byte)`, if any.
    pub(crate) key_usage: Option<(u8, u8)>,
    /// An extra critical extension with an OID nobody processes.
    pub(crate) unknown_critical: bool,
    /// Signature algorithm OID (ecdsa-with-SHA384 unless a test changes it).
    pub(crate) signature_oid: &'static str,
}

/// keyUsage: digitalSignature only.
pub(crate) const KU_DIGITAL_SIGNATURE: (u8, u8) = (7, 0x80);
/// keyUsage: keyCertSign and cRLSign.
pub(crate) const KU_CERT_SIGN: (u8, u8) = (1, 0x06);

impl CertSpec {
    pub(crate) fn ca(subject: &str, issuer: &str, serial: u8, path_len: Option<u8>) -> Self {
        Self {
            subject: subject.into(),
            issuer: issuer.into(),
            serial,
            not_before_ms: NOW_MS - 30 * DAY_MS,
            not_after_ms: NOW_MS + 30 * DAY_MS,
            basic: Some((true, path_len)),
            key_usage: Some(KU_CERT_SIGN),
            unknown_critical: false,
            signature_oid: "1.2.840.10045.4.3.3",
        }
    }

    pub(crate) fn leaf(subject: &str, issuer: &str, serial: u8) -> Self {
        Self {
            not_before_ms: NOW_MS - 60 * 60 * 1000,
            not_after_ms: NOW_MS + 3 * 60 * 60 * 1000,
            basic: Some((false, None)),
            key_usage: Some(KU_DIGITAL_SIGNATURE),
            ..Self::ca(subject, issuer, serial, None)
        }
    }

    /// The DER certificate for `subject_key`, signed by `issuer_key`.
    pub(crate) fn build(&self, subject_key: &SigningKey, issuer_key: &SigningKey) -> Vec<u8> {
        let alg = seq(&[oid(self.signature_oid)]);
        let point = subject_key.verifying_key().to_sec1_point(false);
        let spki = seq(&[
            seq(&[oid("1.2.840.10045.2.1"), oid("1.3.132.0.34")]),
            bit_string(point.as_bytes()),
        ]);
        let mut extensions = Vec::new();
        if let Some((ca, path_len)) = self.basic {
            let mut body = Vec::new();
            if ca {
                body.push(vec![0x01, 0x01, 0xff]);
            }
            if let Some(n) = path_len {
                body.push(tlv(0x02, &[n]));
            }
            extensions.push(extension("2.5.29.19", true, seq(&body)));
        }
        if let Some((unused, byte)) = self.key_usage {
            extensions.push(extension("2.5.29.15", true, tlv(0x03, &[unused, byte])));
        }
        if self.unknown_critical {
            extensions.push(extension("1.3.6.1.4.1.99999.1", true, vec![0x05, 0x00]));
        }
        let tbs = seq(&[
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[self.serial]),
            alg.clone(),
            name(&self.issuer),
            seq(&[utc_time(self.not_before_ms), utc_time(self.not_after_ms)]),
            name(&self.subject),
            spki,
            tlv(0xa3, &seq(&extensions)),
        ]);
        let signature: Signature = issuer_key.sign(&tbs);
        seq(&[tbs, alg, bit_string(signature.to_der().as_bytes())])
    }
}

/// The clock of every synthetic case: 2026-11-18T22:13:20Z.
pub(crate) const NOW_MS: u64 = 1_795_040_000_000;
pub(crate) const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// A synthetic AWS-shaped chain: root, two intermediates, leaf.
pub(crate) struct TestChain {
    pub(crate) root: Vec<u8>,
    pub(crate) intermediates: Vec<Vec<u8>>,
    pub(crate) leaf: Vec<u8>,
    pub(crate) leaf_key: SigningKey,
    pub(crate) specs: Vec<CertSpec>,
    pub(crate) keys: Vec<SigningKey>,
}

impl TestChain {
    /// The default chain, mirroring AWS's shape with one fewer intermediate.
    pub(crate) fn specs() -> Vec<CertSpec> {
        vec![
            CertSpec::ca(
                "klav-test.nitro-enclaves",
                "klav-test.nitro-enclaves",
                1,
                None,
            ),
            CertSpec::ca(
                "regional.klav-test.nitro-enclaves",
                "klav-test.nitro-enclaves",
                2,
                Some(1),
            ),
            CertSpec::ca(
                "instance.klav-test.nitro-enclaves",
                "regional.klav-test.nitro-enclaves",
                3,
                Some(0),
            ),
            CertSpec::leaf(
                "enclave.klav-test.nitro-enclaves",
                "instance.klav-test.nitro-enclaves",
                4,
            ),
        ]
    }

    pub(crate) fn new() -> Self {
        Self::from_specs(Self::specs())
    }

    pub(crate) fn from_specs(specs: Vec<CertSpec>) -> Self {
        let keys: Vec<SigningKey> = (0..specs.len())
            .map(|i| p384_key(&format!("chain key {i}")))
            .collect();
        let certs: Vec<Vec<u8>> = specs
            .iter()
            .enumerate()
            .map(|(i, spec)| spec.build(&keys[i], &keys[i.saturating_sub(1)]))
            .collect();
        let (leaf, cas) = certs.split_last().expect("at least a root and a leaf");
        Self {
            root: cas[0].clone(),
            intermediates: cas[1..].to_vec(),
            leaf: leaf.clone(),
            leaf_key: keys[keys.len() - 1].clone(),
            specs,
            keys,
        }
    }

    /// `cabundle`: the root, then each intermediate.
    pub(crate) fn cabundle(&self) -> Vec<Vec<u8>> {
        std::iter::once(self.root.clone())
            .chain(self.intermediates.iter().cloned())
            .collect()
    }
}

// ------------------------------------------------------------------- CBOR --

/// One encoded CBOR item. Unlike the passkey encoder, it keeps map entries
/// in the order given and can write what the strict reader must refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cbor(pub(crate) Vec<u8>);

fn head(major: u8, value: u64) -> Vec<u8> {
    let m = major << 5;
    match value {
        0..=23 => vec![m | value as u8],
        24..=0xff => vec![m | 24, value as u8],
        0x100..=0xffff => [&[m | 25][..], &(value as u16).to_be_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[m | 26][..], &(value as u32).to_be_bytes()].concat(),
        _ => [&[m | 27][..], &value.to_be_bytes()].concat(),
    }
}

impl Cbor {
    pub(crate) fn uint(v: u64) -> Self {
        Self(head(0, v))
    }
    pub(crate) fn bytes(v: &[u8]) -> Self {
        Self([head(2, v.len() as u64), v.to_vec()].concat())
    }
    pub(crate) fn text(v: &str) -> Self {
        Self([head(3, v.len() as u64), v.as_bytes().to_vec()].concat())
    }
    pub(crate) fn null() -> Self {
        Self(vec![0xf6])
    }
    pub(crate) fn array(items: &[Cbor]) -> Self {
        let mut out = head(4, items.len() as u64);
        items.iter().for_each(|i| out.extend_from_slice(&i.0));
        Self(out)
    }
    pub(crate) fn map(entries: &[(Cbor, Cbor)]) -> Self {
        let mut out = head(5, entries.len() as u64);
        for (k, v) in entries {
            out.extend_from_slice(&k.0);
            out.extend_from_slice(&v.0);
        }
        Self(out)
    }
    /// The same map with an indefinite length.
    pub(crate) fn indefinite_map(entries: &[(Cbor, Cbor)]) -> Self {
        let mut out = vec![0xbf];
        for (k, v) in entries {
            out.extend_from_slice(&k.0);
            out.extend_from_slice(&v.0);
        }
        out.push(0xff);
        Self(out)
    }
    /// The same array with an indefinite length.
    pub(crate) fn indefinite_array(items: &[Cbor]) -> Self {
        let mut out = vec![0x9f];
        items.iter().for_each(|i| out.extend_from_slice(&i.0));
        out.push(0xff);
        Self(out)
    }
    pub(crate) fn tag(tag: u64, inner: Cbor) -> Self {
        Self([head(6, tag), inner.0].concat())
    }
}

// --------------------------------------------------------------- document --

/// The fields of a synthetic attestation payload, in the NSM's order.
#[derive(Debug, Clone)]
pub(crate) struct DocSpec {
    pub(crate) module_id: String,
    pub(crate) digest: String,
    pub(crate) timestamp_ms: u64,
    pub(crate) pcrs: Vec<(u64, Vec<u8>)>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) user_data: Option<Vec<u8>>,
    pub(crate) nonce: Option<Vec<u8>>,
    /// Entries appended after `nonce`, such as an unknown or repeated key.
    pub(crate) extra: Vec<(Cbor, Cbor)>,
    /// Write the payload map with an indefinite length.
    pub(crate) indefinite: bool,
    /// Write every array and map of the document with an indefinite length:
    /// the `COSE_Sign1` array, its unprotected map, the payload map, `pcrs`
    /// and `cabundle` (the protected header is `protected`, as given).
    pub(crate) indefinite_containers: bool,
    /// Wrap the `COSE_Sign1` in tag 18.
    pub(crate) tagged: bool,
    /// Protected header bytes.
    pub(crate) protected: Vec<u8>,
    /// Certificates; `None` takes them from the chain.
    pub(crate) cabundle: Option<Vec<Vec<u8>>>,
    pub(crate) certificate: Option<Vec<u8>>,
}

/// PCR `i` of the synthetic image.
pub(crate) fn test_pcr(i: u64) -> Pcr {
    det(&format!("pcr {i}"))
}

impl DocSpec {
    pub(crate) fn new(nonce: &[u8], user_data: &[u8]) -> Self {
        Self {
            module_id: "i-0123456789abcdef0-enc0123456789abcdef".into(),
            digest: "SHA384".into(),
            timestamp_ms: NOW_MS - 1_000,
            pcrs: (0..16)
                .map(|i| {
                    let value = if i < 4 {
                        test_pcr(i).to_vec()
                    } else {
                        vec![0; 48]
                    };
                    (i, value)
                })
                .collect(),
            public_key: None,
            user_data: Some(user_data.to_vec()),
            nonce: Some(nonce.to_vec()),
            extra: Vec::new(),
            indefinite: false,
            indefinite_containers: false,
            tagged: false,
            protected: PROTECTED_ES384.to_vec(),
            cabundle: None,
            certificate: None,
        }
    }

    pub(crate) fn set_pcr(&mut self, index: u64, value: &[u8]) {
        if let Some(entry) = self.pcrs.iter_mut().find(|(i, _)| *i == index) {
            entry.1 = value.to_vec();
        }
    }

    pub(crate) fn payload(&self, chain: &TestChain) -> Vec<u8> {
        let opt = |v: &Option<Vec<u8>>| v.as_deref().map_or_else(Cbor::null, Cbor::bytes);
        let pcrs: Vec<(Cbor, Cbor)> = self
            .pcrs
            .iter()
            .map(|(i, v)| (Cbor::uint(*i), Cbor::bytes(v)))
            .collect();
        let cabundle: Vec<Cbor> = self
            .cabundle
            .clone()
            .unwrap_or_else(|| chain.cabundle())
            .iter()
            .map(|c| Cbor::bytes(c))
            .collect();
        let mut entries = vec![
            (Cbor::text("module_id"), Cbor::text(&self.module_id)),
            (Cbor::text("digest"), Cbor::text(&self.digest)),
            (Cbor::text("timestamp"), Cbor::uint(self.timestamp_ms)),
            (Cbor::text("pcrs"), self.map(&pcrs)),
            (
                Cbor::text("certificate"),
                Cbor::bytes(self.certificate.as_deref().unwrap_or(&chain.leaf)),
            ),
            (Cbor::text("cabundle"), self.array(&cabundle)),
            (Cbor::text("public_key"), opt(&self.public_key)),
            (Cbor::text("user_data"), opt(&self.user_data)),
            (Cbor::text("nonce"), opt(&self.nonce)),
        ];
        entries.extend(self.extra.iter().cloned());
        if self.indefinite {
            Cbor::indefinite_map(&entries).0
        } else {
            self.map(&entries).0
        }
    }

    fn map(&self, entries: &[(Cbor, Cbor)]) -> Cbor {
        if self.indefinite_containers {
            Cbor::indefinite_map(entries)
        } else {
            Cbor::map(entries)
        }
    }

    fn array(&self, items: &[Cbor]) -> Cbor {
        if self.indefinite_containers {
            Cbor::indefinite_array(items)
        } else {
            Cbor::array(items)
        }
    }

    /// The `COSE_Sign1` document, signed by the chain's leaf key.
    pub(crate) fn build(&self, chain: &TestChain) -> Vec<u8> {
        let payload = self.payload(chain);
        let signature: Signature = chain
            .leaf_key
            .sign(&sig_structure(&self.protected, &payload));
        let array = self.array(&[
            Cbor::bytes(&self.protected),
            self.map(&[]),
            Cbor::bytes(&payload),
            Cbor::bytes(&signature.to_bytes()),
        ]);
        if self.tagged {
            Cbor::tag(18, array).0
        } else {
            array.0
        }
    }
}

/// A `COSE_Sign1` from its parts.
pub(crate) fn cose(protected: &[u8], payload: &[u8], signature: &[u8], tagged: bool) -> Vec<u8> {
    let array = Cbor::array(&[
        Cbor::bytes(protected),
        Cbor::map(&[]),
        Cbor::bytes(payload),
        Cbor::bytes(signature),
    ]);
    if tagged {
        Cbor::tag(18, array).0
    } else {
        array.0
    }
}
