# Captured Nitro attestation documents

Real documents signed by an AWS Nitro Secure Module, used by the tests of
`klav_core::nitro` and copied as hex into `docs/vectores/nitro-attestation.json`.

| File | Source | License | What it shows |
|---|---|---|---|
| `evervault-2023-09-18-debug.cbor` | `test-data/valid-attestation-doc-base64` of [evervault/attestation-doc-validation](https://github.com/evervault/attestation-doc-validation) at commit `6e477381464fbfefe1afa606052f9ad81b99120d`, base64-decoded | Apache-2.0 | An untagged `COSE_Sign1` from `us-east-1` on 2023-09-18, chained to the pinned AWS Nitro Enclaves Root-G1 through three intermediates, ECDSA P-384 with SHA-384 end to end. Its PCR0–2 are zero: a debug-mode enclave, which Klav refuses after the chain and the signature verify |

Klav has no document from its own enclave yet; ADR 0051's layer 6 adds one
captured from the hosted proxy's test enclave.
