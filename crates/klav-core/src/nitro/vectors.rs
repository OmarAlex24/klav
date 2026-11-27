//! `docs/vectores/nitro-attestation.json` and `docs/vectores/enclave-manifest.json`
//! (spec §15.7). Built only with the feature:
//! `cargo test -p klav-core --features nitro-attestation nitro_vectors`;
//! `KLAV_REGEN_VECTORS=1` rewrites them.
//!
//! Every value is recomputed from its inputs and compared with the file,
//! and every stored document and manifest goes through the verifier again,
//! which must give the stored result.

use std::path::PathBuf;

use serde_json::{Value, json};

use super::attestation::{verify_document_with_root, verify_hosted_proxy_with_root};
use super::hosted::{HandoffKey, seal_handoff_with_rng};
use super::manifest::verify_manifest_with_keys;
use super::testkit::*;
use super::tests::*;
use super::*;
use crate::crypto::identity::IdentityKeyPair;
use crate::crypto::sign::Signature as EdSignature;
use crate::crypto::vectors::FixedRng;
use crate::ids::{AccountId, AgentId};

const ENCODING: &str = "Los campos binarios van en hexadecimal; las cadenas de texto en UTF-8.";

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectores")
}

fn hx(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

fn result_code<T>(r: &Result<T, NitroError>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

// ------------------------------------------------------ nitro-attestation --

/// The release keys the vectors pin: `active` and `backup`.
fn release_keys() -> [[u8; 32]; 2] {
    [
        release_key("active").verifying_key().to_bytes(),
        release_key("backup").verifying_key().to_bytes(),
    ]
}

/// `(name, manifest JSON)` of the manifests the document cases use.
fn document_manifests() -> Vec<(&'static str, String)> {
    let (v, p0, p1, p2, _) = current_image();
    let window = (NOW_MS - DAY_MS, NOW_MS + 29 * DAY_MS);
    vec![
        (
            "current",
            manifest_json(7, window.0, window.1, &[current_image()]),
        ),
        (
            "revoked",
            manifest_json(8, window.0, window.1, &[(v, p0, p1, p2, "revoked")]),
        ),
    ]
}

/// `(name, document, now_ms, manifest, expected)`.
fn document_cases(f: &Fixture) -> Vec<(&'static str, Vec<u8>, u64, &'static str, &'static str)> {
    let chain = &f.chain;
    let base = f.spec();
    let good = base.build(chain);
    let with = |change: &dyn Fn(&mut DocSpec)| {
        let mut spec = base.clone();
        change(&mut spec);
        spec.build(chain)
    };

    let mut payload_flip = good.clone();
    let at = payload_flip
        .windows(4)
        .position(|w| w == b"i-01")
        .expect("module id");
    payload_flip[at + 3] ^= 0x01;
    let mut signature_flip = good.clone();
    let last = signature_flip.len() - 1;
    signature_flip[last] ^= 0x01;
    let mut pcr0 = test_pcr(0);
    pcr0[0] ^= 0x01;
    let other_nonce = det::<32>("another nonce");
    let other_binding = det::<32>("another binding");

    vec![
        ("valid", good.clone(), NOW_MS, "current", "ok"),
        (
            "valid-tagged",
            with(&|s| s.tagged = true),
            NOW_MS,
            "current",
            "ok",
        ),
        (
            "payload-bit-flipped",
            payload_flip,
            NOW_MS,
            "current",
            "signature",
        ),
        (
            "signature-bit-flipped",
            signature_flip,
            NOW_MS,
            "current",
            "signature",
        ),
        (
            "pcr0-changed",
            with(&|s| s.set_pcr(0, &pcr0)),
            NOW_MS,
            "current",
            "image_not_listed",
        ),
        (
            "chain-out-of-order",
            with(&|s| {
                s.cabundle = Some(vec![
                    chain.root.clone(),
                    chain.intermediates[1].clone(),
                    chain.intermediates[0].clone(),
                ])
            }),
            NOW_MS,
            "current",
            "issuer_mismatch",
        ),
        (
            "extra-map-key",
            with(&|s| s.extra = vec![(Cbor::text("debug"), Cbor::uint(1))]),
            NOW_MS,
            "current",
            "unknown_field",
        ),
        (
            "duplicate-map-key",
            with(&|s| s.extra = vec![(Cbor::text("nonce"), Cbor::bytes(&f.nonce))]),
            NOW_MS,
            "current",
            "cbor_duplicate_key",
        ),
        (
            "indefinite-length",
            with(&|s| s.indefinite = true),
            NOW_MS,
            "current",
            "ok",
        ),
        // Three hours later the leaf has expired (the timestamp is checked after).
        (
            "expired-certificate",
            good.clone(),
            NOW_MS + 4 * 60 * 60 * 1000,
            "current",
            "validity",
        ),
        (
            "wrong-root",
            with(&|s| {
                let mut bundle = chain.cabundle();
                bundle[0] = AWS_NITRO_ROOT_G1.to_vec();
                s.cabundle = Some(bundle);
            }),
            NOW_MS,
            "current",
            "root_mismatch",
        ),
        (
            "zero-pcrs",
            with(&|s| s.set_pcr(1, &[0; 48])),
            NOW_MS,
            "current",
            "debug_enclave",
        ),
        (
            "stale-timestamp",
            with(&|s| s.timestamp_ms = NOW_MS - FRESHNESS_MS - 1),
            NOW_MS,
            "current",
            "stale",
        ),
        (
            "other-nonce",
            with(&|s| s.nonce = Some(other_nonce.to_vec())),
            NOW_MS,
            "current",
            "nonce",
        ),
        (
            "other-user-data",
            with(&|s| s.user_data = Some(other_binding.to_vec())),
            NOW_MS,
            "current",
            "binding",
        ),
        ("revoked-image", good, NOW_MS, "revoked", "image_revoked"),
        // What a real NSM writes (ADR 0051 §18): every array and map
        // indefinite, the protected header too.
        (
            "indefinite-arrays-and-maps",
            with(&|s| {
                s.indefinite_containers = true;
                s.protected = vec![0xbf, 0x01, 0x38, 0x22, 0xff];
            }),
            NOW_MS,
            "current",
            "ok",
        ),
        // An indefinite-length string stays refused.
        (
            "indefinite-length-string",
            with(&|s| {
                s.indefinite_containers = true;
                s.extra = vec![(Cbor::text("debug"), Cbor(vec![0x5f, 0x41, 0x00, 0xff]))];
            }),
            NOW_MS,
            "current",
            "cbor_indefinite_length",
        ),
    ]
}

fn render_attestation() -> Value {
    let f = Fixture::new();
    let keys = release_keys();
    let manifests: Vec<Value> = document_manifests()
        .into_iter()
        .map(|(name, json)| {
            json!({
                "name": name,
                "manifest": json,
                "signature": hx(&sign_manifest(&release_key("active"), json.as_bytes())),
            })
        })
        .collect();
    let documents: Vec<Value> = document_cases(&f)
        .into_iter()
        .map(|(name, document, now, manifest, expect)| {
            json!({
                "name": name,
                "document": hx(&document),
                "now_ms": now,
                "manifest": manifest,
                "expect": expect,
            })
        })
        .collect();

    let seed = HostedSeed::from_bytes(&det("hosted seed"));
    let account = AccountId::from_bytes(det("account"));
    let agent = AgentId::from_bytes(det("agent"));
    let derived: Vec<Value> = [0u32, 1]
        .iter()
        .map(|&generation| {
            let keys = derive_account_keys(&seed, account, generation);
            json!({
                "generation": generation,
                "info": hx(&hosted_account_info(account, generation)),
                "x25519_public": hx(keys.public().x25519()),
                "ed25519_public": hx(keys.public().ed25519()),
                "binding": hx(&enclave_binding(account, agent, keys.public(), generation)),
            })
        })
        .collect();
    let identity = IdentityKeyPair::from_secret_bytes(
        &det("account identity x25519"),
        &det("account identity ed25519"),
    );
    let enroll_at = NOW_MS;
    let enroll = sign_enroll(&identity, account, 0, enroll_at);
    let holder_nonce = det::<32>("handoff nonce from joiner");
    let joiner_nonce = det::<32>("handoff nonce from holder");
    let holder_pcr0 = test_pcr(0);
    let joiner_pcr0 = det::<48>("joiner pcr0");
    let info = handoff_info(&holder_pcr0, &joiner_pcr0, &joiner_nonce, &holder_nonce);
    let mix_os = det::<32>("hosted seed os random");
    let mix_entropy = det::<32>("hosted seed nsm entropy");
    let mixed = HostedSeed::mix(&mix_os, &mix_entropy);
    let service = hosted_service_keys(&seed);
    let gen0 = derive_account_keys(&seed, account, 0);
    let registration = sign_hosted_registration(&service, account, agent, gen0.public(), 0);
    let joiner_secret = det::<32>("handoff joiner x25519");
    let joiner = HandoffKey::from_secret(&joiner_secret);
    let handoff_state = br#"{"v":1,"accounts":[]}"#;
    let ikm_e = det::<32>("handoff ikm_e");
    let sealed = seal_handoff_with_rng(
        &seed,
        handoff_state,
        &joiner.public(),
        &info,
        &mut FixedRng(ikm_e.to_vec()),
    )
    .expect("seals");

    json!({
        "description": "AWS Nitro Enclaves attestation (ADR 0051): the pinned Root-G1, a real document of a debug-mode enclave and one of Klav's own enclave, a synthetic AWS-format P-384 chain with a document that verifies and mutated documents (each re-signed) that must be refused, the per-account keys, the binding, the hand-off info, a sealed hand-off (kind 0x28), the seed mix, the service key with its registration mark and the enroll signature",
        "spec": "docs/especificacion-cripto.md §15",
        "format_version": 1,
        "encoding": ENCODING,
        "feature": "cargo test -p klav-core --features nitro-attestation nitro_vectors",
        "aws_root_g1": {
            "der": hx(AWS_NITRO_ROOT_G1),
            "sha256": hx(&AWS_NITRO_ROOT_G1_SHA256),
        },
        "real_documents": [{
            "name": "evervault-2023-09-18-debug",
            "source": "github.com/evervault/attestation-doc-validation, test-data/valid-attestation-doc-base64 at 6e477381464fbfefe1afa606052f9ad81b99120d, base64-decoded (Apache-2.0)",
            "document": hx(REAL_DEBUG_DOCUMENT),
            "now_ms": REAL_DEBUG_TIMESTAMP_MS,
            "expect_document": "ok",
            "module_id": "i-0918f6c55e3b61d89-enc018aa8b8e2285d13",
            "expect_measurement": "debug_enclave",
        }, {
            "name": "klav-proxy-2026-11-27-us-east-2a",
            "source": "GET https://proxy.klav.dev/v1/attest on 2026-11-27, Klav's own enclave on a c7g.large in us-east-2a, an image of deploy/nitro/manifests/2.json at commit 23f82370520574eb91e78dd0d70c7031263d5866",
            "document": hx(REAL_KLAV_DOCUMENT),
            "now_ms": REAL_KLAV_TIMESTAMP_MS,
            "expect_document": "ok",
            "module_id": "i-067f86b09762550c5-enc01a21af794a29886",
            "expect_measurement": "ok",
        }],
        "synthetic_chain": {
            "note": "Synthetic, not AWS: a test root, two intermediates and a leaf in AWS's shape (ECDSA P-384 with SHA-384, basicConstraints and keyUsage critical), with deterministic keys.",
            "root": hx(&f.chain.root),
            "intermediates": f.chain.intermediates.iter().map(|c| hx(c)).collect::<Vec<_>>(),
            "leaf": hx(&f.chain.leaf),
        },
        "release_keys": keys.iter().map(|k| hx(k)).collect::<Vec<_>>(),
        "manifests": manifests,
        "expectation": {
            "nonce": hx(&f.nonce),
            "binding": hx(&f.binding),
        },
        "documents": documents,
        "hosted": {
            "seed": hx(&det::<32>("hosted seed")),
            "account_id": hx(account.as_bytes()),
            "agent_id": hx(agent.as_bytes()),
            "derived": derived,
            "enroll": {
                "account_public": hx(&identity.public().encode()),
                "generation": 0,
                "at_ms": enroll_at,
                "signature": hx(&enroll.to_bytes()),
            },
            "handoff": {
                "holder_pcr0": hx(&holder_pcr0),
                "joiner_pcr0": hx(&joiner_pcr0),
                "holder_document_nonce": hx(&joiner_nonce),
                "joiner_document_nonce": hx(&holder_nonce),
                "info": hx(&info),
                "joiner_x25519_secret": hx(&joiner_secret),
                "joiner_x25519_public": hx(&joiner.public()),
                "state": hx(handoff_state),
                "ikm_e": hx(&ikm_e),
                "sealed": hx(&sealed),
            },
            "seed_mix": {
                "os_random": hx(&mix_os),
                "nsm_entropy": hx(&mix_entropy),
                "seed": hx(mixed.expose()),
            },
            "service": {
                "public_identity": hx(&service.public().encode()),
                "registration": {
                    "generation": 0,
                    "agent_public_identity": hx(&gen0.public().encode()),
                    "signature": hx(&registration.to_bytes()),
                },
            },
        },
    })
}

/// Runs the verifier on what the file stores.
fn check_attestation(stored: &Value) {
    let root = unhex(&stored["synthetic_chain"]["root"]);
    let keys: Vec<[u8; 32]> = stored["release_keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|k| unhex(k).try_into().expect("32 bytes"))
        .collect();
    let nonce = unhex(&stored["expectation"]["nonce"]);
    let binding: [u8; 32] = unhex(&stored["expectation"]["binding"])
        .try_into()
        .expect("32 bytes");

    for real in stored["real_documents"].as_array().expect("real") {
        let doc = verify_document(
            &unhex(&real["document"]),
            real["now_ms"].as_u64().expect("ms"),
        );
        assert_eq!(result_code(&doc), real["expect_document"]);
        let doc = doc.expect("verified");
        assert_eq!(doc.module_id(), real["module_id"]);
        assert_eq!(result_code(&doc.measurement()), real["expect_measurement"]);
    }

    for case in stored["documents"].as_array().expect("documents") {
        let manifest_name = case["manifest"].as_str().expect("manifest");
        let m = stored["manifests"]
            .as_array()
            .expect("manifests")
            .iter()
            .find(|m| m["name"] == manifest_name)
            .expect("named manifest");
        let manifest = verify_manifest_with_keys(
            m["manifest"].as_str().expect("text").as_bytes(),
            &unhex(&m["signature"]).try_into().expect("64 bytes"),
            &keys,
            None,
            NOW_MS,
        )
        .expect("the vector manifests verify");
        let now = case["now_ms"].as_u64().expect("ms");
        let result = verify_hosted_proxy_with_root(
            &unhex(&case["document"]),
            &root,
            &manifest,
            &HostedProxyExpectation {
                nonce: &nonce,
                binding: &binding,
                now_ms: now,
            },
        );
        assert_eq!(result_code(&result), case["expect"], "{}", case["name"]);
        if case["expect"] == "ok" {
            let doc =
                verify_document_with_root(&unhex(&case["document"]), &root, now).expect("verifies");
            assert_eq!(doc.user_data(), Some(binding.as_slice()));
        }
    }

    let hosted = &stored["hosted"];
    let handoff = &hosted["handoff"];
    let joiner = HandoffKey::from_secret(
        &unhex(&handoff["joiner_x25519_secret"])
            .try_into()
            .expect("32"),
    );
    let (opened, state) = open_handoff(
        &joiner,
        &unhex(&handoff["sealed"]),
        &unhex(&handoff["info"]),
    )
    .expect("the stored hand-off opens");
    assert_eq!(opened.expose().to_vec(), unhex(&hosted["seed"]));
    assert_eq!(state.to_vec(), unhex(&handoff["state"]));
    let service = &hosted["service"];
    let service_public =
        crate::crypto::identity::PublicIdentity::decode(&unhex(&service["public_identity"]))
            .expect("public identity");
    let reg = &service["registration"];
    let agent_public =
        crate::crypto::identity::PublicIdentity::decode(&unhex(&reg["agent_public_identity"]))
            .expect("public identity");
    assert_eq!(
        verify_hosted_registration(
            &service_public,
            AccountId::from_bytes(unhex(&hosted["account_id"]).try_into().expect("16")),
            AgentId::from_bytes(unhex(&hosted["agent_id"]).try_into().expect("16")),
            &agent_public,
            0,
            &EdSignature::from_bytes(unhex(&reg["signature"]).try_into().expect("64")),
        ),
        Ok(())
    );

    let enroll = &stored["hosted"]["enroll"];
    let public = crate::crypto::identity::PublicIdentity::decode(&unhex(&enroll["account_public"]))
        .expect("public identity");
    let signature = EdSignature::from_bytes(unhex(&enroll["signature"]).try_into().expect("64"));
    let account = AccountId::from_bytes(
        unhex(&stored["hosted"]["account_id"])
            .try_into()
            .expect("16"),
    );
    assert_eq!(
        verify_enroll(
            &public,
            account,
            0,
            enroll["at_ms"].as_u64().expect("ms"),
            &signature
        ),
        Ok(())
    );
}

// ------------------------------------------------------ enclave-manifest --

/// `(name, manifest, signer, highest_seq, now_ms, expected)`.
type ManifestCase = (
    &'static str,
    String,
    &'static str,
    Option<u64>,
    u64,
    &'static str,
);

fn manifest_cases() -> Vec<ManifestCase> {
    let (v, p0, p1, p2, _) = current_image();
    let issued = NOW_MS - DAY_MS;
    let expires = NOW_MS + 29 * DAY_MS;
    let base = manifest_json(7, issued, expires, &[current_image()]);
    let two = manifest_json(
        9,
        issued,
        expires,
        &[
            (
                "0.13.0",
                det("newer 0"),
                det("newer 1"),
                det("newer 2"),
                "current",
            ),
            (v, p0, p1, p2, "draining"),
        ],
    );
    vec![
        ("valid", base.clone(), "active", None, NOW_MS, "ok"),
        (
            "valid-backup-key",
            base.clone(),
            "backup",
            None,
            NOW_MS,
            "ok",
        ),
        (
            "valid-same-seq",
            base.clone(),
            "active",
            Some(7),
            NOW_MS,
            "ok",
        ),
        (
            "valid-current-and-draining",
            two,
            "active",
            Some(7),
            NOW_MS,
            "ok",
        ),
        (
            "unknown-key",
            base.clone(),
            "stranger",
            None,
            NOW_MS,
            "manifest_signature",
        ),
        (
            "rollback",
            base.clone(),
            "active",
            Some(8),
            NOW_MS,
            "manifest_rollback",
        ),
        (
            "expired",
            base.clone(),
            "active",
            None,
            expires,
            "manifest_expired",
        ),
        (
            "issued-in-the-future",
            base.clone(),
            "active",
            None,
            issued - MANIFEST_CLOCK_SKEW_MS - 1,
            "manifest_future",
        ),
        (
            "unknown-field",
            base.replacen('{', "{\"debug\":true,", 1),
            "active",
            None,
            NOW_MS,
            "manifest_malformed",
        ),
        (
            "duplicate-field",
            base.replacen('{', "{\"seq\":99,", 1),
            "active",
            None,
            NOW_MS,
            "manifest_malformed",
        ),
        (
            "longer-than-30-days",
            manifest_json(7, issued, issued + 30 * DAY_MS + 1, &[current_image()]),
            "active",
            None,
            NOW_MS,
            "manifest_malformed",
        ),
        (
            "zero-pcr",
            manifest_json(7, issued, expires, &[(v, p0, [0; 48], p2, "current")]),
            "active",
            None,
            NOW_MS,
            "manifest_malformed",
        ),
    ]
}

fn render_manifest() -> Value {
    let base = manifest_json(7, NOW_MS - DAY_MS, NOW_MS + 29 * DAY_MS, &[current_image()]);
    let cases: Vec<Value> = manifest_cases()
        .into_iter()
        .map(|(name, manifest, signer, seen, now, expect)| {
            json!({
                "name": name,
                "manifest": manifest,
                "signer": signer,
                "signature": hx(&sign_manifest(&release_key(signer), manifest.as_bytes())),
                "highest_seq": seen,
                "now_ms": now,
                "expect": expect,
            })
        })
        .collect();
    json!({
        "description": "Klav Enclave Transparency Manifest (ADR 0051 §2.4): the signed message, manifests a device accepts and manifests it refuses (unknown key, rollback, expired, issued in the future, unknown or repeated field, longer than 30 days, a zero PCR)",
        "spec": "docs/especificacion-cripto.md §15.5",
        "format_version": 1,
        "encoding": ENCODING,
        "feature": "cargo test -p klav-core --features nitro-attestation nitro_vectors",
        "note": "Test release keys only, not Klav's release-authority keys (RELEASE_AUTHORITY_KEYS).",
        "release_keys": {
            "active": hx(&release_key("active").verifying_key().to_bytes()),
            "backup": hx(&release_key("backup").verifying_key().to_bytes()),
            "stranger": hx(&release_key("stranger").verifying_key().to_bytes()),
        },
        "trusted": ["active", "backup"],
        "message": {
            "manifest": base,
            "label": LABEL_ENCLAVE_MANIFEST,
            "sha256": hx(&<sha2::Sha256 as sha2::Digest>::digest(base.as_bytes())),
            "signed_message": hx(&manifest_message(base.as_bytes())),
        },
        "cases": cases,
    })
}

fn check_manifest(stored: &Value) {
    let key = |name: &Value| -> [u8; 32] {
        unhex(&stored["release_keys"][name.as_str().expect("name")])
            .try_into()
            .expect("32 bytes")
    };
    let trusted: Vec<[u8; 32]> = stored["trusted"]
        .as_array()
        .expect("trusted")
        .iter()
        .map(key)
        .collect();
    for case in stored["cases"].as_array().expect("cases") {
        let result = verify_manifest_with_keys(
            case["manifest"].as_str().expect("text").as_bytes(),
            &unhex(&case["signature"]).try_into().expect("64 bytes"),
            &trusted,
            case["highest_seq"].as_u64(),
            case["now_ms"].as_u64().expect("ms"),
        );
        assert_eq!(result_code(&result), case["expect"], "{}", case["name"]);
    }
}

/// `(file name, render, check)`.
type VectorFile = (&'static str, fn() -> Value, fn(&Value));

#[test]
fn nitro_vectors_match_spec() {
    let regenerate = std::env::var_os("KLAV_REGEN_VECTORS").is_some();
    let files: [VectorFile; 2] = [
        ("nitro-attestation", render_attestation, check_attestation),
        ("enclave-manifest", render_manifest, check_manifest),
    ];
    for (name, render, check) in files {
        let path = dir().join(format!("{name}.json"));
        let computed = render();
        if regenerate {
            let mut text = serde_json::to_string_pretty(&computed).expect("serializes");
            text.push('\n');
            std::fs::write(&path, text).expect("writes vector file");
        }
        let stored: Value = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("missing {}", path.display())),
        )
        .expect("valid JSON");
        assert_eq!(
            stored, computed,
            "{name}: stored vectors differ from the code"
        );
        check(&stored);
    }
}
