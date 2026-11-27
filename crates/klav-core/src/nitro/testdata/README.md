# Captured Nitro attestation documents

Real documents signed by an AWS Nitro Secure Module, used by the tests of
`klav_core::nitro` and copied as hex into `docs/vectores/nitro-attestation.json`.

| File | Source | License | What it shows |
|---|---|---|---|
| `evervault-2023-09-18-debug.cbor` | `test-data/valid-attestation-doc-base64` of [evervault/attestation-doc-validation](https://github.com/evervault/attestation-doc-validation) at commit `6e477381464fbfefe1afa606052f9ad81b99120d`, base64-decoded | Apache-2.0 | An untagged `COSE_Sign1` from `us-east-1` on 2023-09-18, chained to the pinned AWS Nitro Enclaves Root-G1 through three intermediates, ECDSA P-384 with SHA-384 end to end. Its PCR0–2 are zero: a debug-mode enclave, which Klav refuses after the chain and the signature verify |
| `klav-proxy-2026-11-27-us-east-2a.cbor` | `GET https://proxy.klav.dev/v1/attest` on 2026-11-27 (`timestamp` 2026-11-27T13:43:56.356Z), base64url-decoded from the answer's `document` | Klav's own enclave (public data, no secret) | An untagged `COSE_Sign1` from Klav's hosted proxy on a Graviton `c7g.large` in `us-east-2a`, running an image of `deploy/nitro/manifests/2.json` at commit `23f82370520574eb91e78dd0d70c7031263d5866`. Chained to the pinned Root-G1 through three intermediates; PCR0–2 match that manifest entry (`current`) and PCR3 its `parent_roles`. The payload's top-level map is the only indefinite-length item (`bf` … `ff`); the COSE array, the protected header, `pcrs` (`b0`) and `cabundle` (`84`) are definite |

The 2026 document was captured with `GET /v1/attest?account=…&nonce=000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f`. The API reads `nonce` as base64url, so the document's `nonce` is the 48 bytes those 64 characters decode to, not the 32 bytes the hex spells. Its `user_data` is the binding of agent `52918dc2-0c7f-4d7d-9b83-b37e42e430bf` at generation 0; the agent's public keys weren't recorded, so the test takes the binding from the document instead of recomputing it.
