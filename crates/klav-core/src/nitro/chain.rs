//! The certificate chain of an attestation document, from AWS's pinned root
//! to the leaf that signs the document (spec §15.3, ADR 0051 §2.2 step 3).
//!
//! The chain is fixed in shape: `cabundle` gives the root and then each
//! intermediate, each issued by the one before; `certificate` is the leaf.
//! Every certificate is X.509 v3 in DER, ECDSA P-384 with SHA-384 end to end
//! (checked on documents of real enclaves in 2022 and 2023, ADR 0051 §13).
//! There is no path building, no name constraints, no policies and no CRL
//! (AWS says to disable it): a critical extension other than
//! `basicConstraints` and `keyUsage` is refused.

use der::{Decode, Encode, Reader, SliceReader};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

use super::NitroError;

/// The AWS Nitro Enclaves Root-G1 certificate, DER, from
/// `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`.
/// Subject `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`, valid from
/// 2019-10-28 to 2049-10-28, ECDSA P-384 with SHA-384.
pub const AWS_NITRO_ROOT_G1: &[u8] = include_bytes!("aws-nitro-enclaves-root-g1.der");

/// SHA-256 of [`AWS_NITRO_ROOT_G1`], as AWS publishes it
/// (`64:1A:03:21:…:79:BB:5B`).
pub const AWS_NITRO_ROOT_G1_SHA256: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31,
    0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
];

/// Most certificates in a chain, root and leaf included.
pub const MAX_CHAIN: usize = 8;
/// Largest certificate accepted, in bytes (AWS: 1 to 1024).
pub const MAX_CERTIFICATE_LEN: usize = 1024;

const ECDSA_WITH_SHA384: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ID_EC_PUBLIC_KEY: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP384R1: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.3.132.0.34");
const BASIC_CONSTRAINTS: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("2.5.29.19");
const KEY_USAGE: der::oid::ObjectIdentifier = der::oid::ObjectIdentifier::new_unwrap("2.5.29.15");

/// One parsed certificate and the bytes its issuer signed.
struct Parsed<'a> {
    cert: Certificate,
    tbs: &'a [u8],
    key: VerifyingKey,
    not_before_ms: u128,
    not_after_ms: u128,
    basic: Option<BasicConstraints>,
    usage: Option<KeyUsage>,
}

/// Verifies `[root, intermediates…, leaf]` at `now_ms` and returns the
/// leaf's public key. `cabundle[0]` must be byte-equal to `root`.
pub(crate) fn verify(
    root: &[u8],
    cabundle: &[&[u8]],
    leaf: &[u8],
    now_ms: u64,
) -> Result<VerifyingKey, NitroError> {
    if cabundle.is_empty() || cabundle.len() + 1 > MAX_CHAIN {
        return Err(NitroError::ChainLength);
    }
    if cabundle[0] != root {
        return Err(NitroError::RootMismatch);
    }
    let all: Vec<&[u8]> = cabundle.iter().copied().chain([leaf]).collect();
    let parsed = all
        .iter()
        .enumerate()
        .map(|(index, der)| parse(index, der))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf_index = parsed.len() - 1;
    let now = u128::from(now_ms);

    for (index, cert) in parsed.iter().enumerate() {
        // Issued by the certificate before it: the name, then the signature.
        if index > 0 {
            let issuer = &parsed[index - 1];
            let named = cert.cert.tbs_certificate().issuer().to_der();
            let subject = issuer.cert.tbs_certificate().subject().to_der();
            match (named, subject) {
                (Ok(a), Ok(b)) if a == b => {}
                _ => return Err(NitroError::IssuerMismatch { index }),
            }
            let signature = cert
                .cert
                .signature()
                .as_bytes()
                .and_then(|b| Signature::from_der(b).ok())
                .ok_or(NitroError::Certificate {
                    index,
                    reason: "signature is not a DER ECDSA signature",
                })?;
            issuer
                .key
                .verify(cert.tbs, &signature)
                .map_err(|_| NitroError::ChainSignature { index })?;
        }
        if now < cert.not_before_ms || now > cert.not_after_ms {
            return Err(NitroError::Validity { index });
        }
        if index == leaf_index {
            // Not a CA, and allowed to sign (the COSE document).
            if cert.basic.as_ref().is_some_and(|b| b.ca) {
                return Err(NitroError::LeafUsage);
            }
            if cert.usage.as_ref().is_some_and(|u| !u.digital_signature()) {
                return Err(NitroError::LeafUsage);
            }
        } else {
            let is_ca = cert.basic.as_ref().is_some_and(|b| b.ca);
            let signs = cert.usage.as_ref().is_some_and(|u| u.key_cert_sign());
            if !is_ca || !signs {
                return Err(NitroError::NotCa { index });
            }
            // Intermediates below this one, the leaf not counted (RFC 5280
            // §4.2.1.9). None of AWS's certificates is self-issued.
            let below = leaf_index - index - 1;
            if let Some(max) = cert.basic.as_ref().and_then(|b| b.path_len_constraint)
                && below > usize::from(max)
            {
                return Err(NitroError::PathLength { index });
            }
        }
    }
    Ok(parsed[leaf_index].key)
}

fn parse(index: usize, der: &[u8]) -> Result<Parsed<'_>, NitroError> {
    let malformed = |reason| NitroError::Certificate { index, reason };
    if der.is_empty() || der.len() > MAX_CERTIFICATE_LEN {
        return Err(malformed("length out of range"));
    }
    let cert = Certificate::from_der(der).map_err(|_| malformed("not a DER certificate"))?;
    // The signed bytes are the TBSCertificate exactly as received.
    let tbs = tbs_bytes(der).map_err(|_| malformed("not a DER certificate"))?;
    // And DER has a single encoding: a certificate that re-encodes to other
    // bytes was not DER.
    if cert.to_der().ok().as_deref() != Some(der) {
        return Err(malformed("not in DER"));
    }
    let tbs_cert = cert.tbs_certificate();
    if tbs_cert.version() != Version::V3 {
        return Err(malformed("not X.509 v3"));
    }
    let ecdsa_sha384 = |alg: &spki::AlgorithmIdentifierOwned| {
        alg.oid == ECDSA_WITH_SHA384 && alg.parameters.is_none()
    };
    if !ecdsa_sha384(cert.signature_algorithm()) || !ecdsa_sha384(tbs_cert.signature()) {
        return Err(NitroError::Algorithm { index });
    }
    let spki = tbs_cert.subject_public_key_info();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<der::oid::ObjectIdentifier>().ok());
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY || curve != Some(SECP384R1) {
        return Err(NitroError::Algorithm { index });
    }
    let key = spki
        .subject_public_key
        .as_bytes()
        .and_then(|b| VerifyingKey::from_sec1_bytes(b).ok())
        .ok_or(NitroError::Algorithm { index })?;

    let validity = tbs_cert.validity();
    let not_before_ms = validity.not_before.to_unix_duration().as_millis();
    let not_after_ms = validity.not_after.to_unix_duration().as_millis();

    let mut basic = None;
    let mut usage = None;
    let mut seen = Vec::new();
    for ext in tbs_cert.extensions().map(|e| e.as_slice()).unwrap_or(&[]) {
        if seen.contains(&ext.extn_id) {
            return Err(NitroError::Extension { index });
        }
        seen.push(ext.extn_id);
        let value = ext.extn_value.as_bytes();
        if ext.extn_id == BASIC_CONSTRAINTS {
            basic =
                Some(BasicConstraints::from_der(value).map_err(|_| malformed("basicConstraints"))?);
        } else if ext.extn_id == KEY_USAGE {
            usage = Some(KeyUsage::from_der(value).map_err(|_| malformed("keyUsage"))?);
        } else if ext.critical {
            return Err(NitroError::Extension { index });
        }
    }
    Ok(Parsed {
        cert,
        tbs,
        key,
        not_before_ms,
        not_after_ms,
        basic,
        usage,
    })
}

/// The TBSCertificate TLV of `der`, as received.
fn tbs_bytes(der: &[u8]) -> der::Result<&[u8]> {
    let mut reader = SliceReader::new(der)?;
    let tbs = reader.sequence(|r: &mut SliceReader<'_>| {
        let tbs = r.tlv_bytes()?;
        r.tlv_bytes()?;
        r.tlv_bytes()?;
        Ok::<_, der::Error>(tbs)
    })?;
    reader.finish()?;
    Ok(tbs)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn the_pinned_root_is_aws_root_g1() {
        assert_eq!(
            Sha256::digest(AWS_NITRO_ROOT_G1).as_slice(),
            AWS_NITRO_ROOT_G1_SHA256
        );
        let parsed = parse(0, AWS_NITRO_ROOT_G1).expect("the pinned root parses");
        assert!(parsed.basic.is_some_and(|b| b.ca));
        assert!(parsed.usage.is_some_and(|u| u.key_cert_sign()));
        // 2019-10-28T13:28:05Z to 2049-10-28T14:28:05Z.
        assert_eq!(parsed.not_before_ms, 1_572_269_285_000);
        assert_eq!(parsed.not_after_ms, 2_519_044_085_000);
        // Self-signed: its own key verifies it.
        let sig = parsed.cert.signature().as_bytes().expect("octets");
        let sig = Signature::from_der(sig).expect("DER signature");
        assert!(parsed.key.verify(parsed.tbs, &sig).is_ok());
    }
}
