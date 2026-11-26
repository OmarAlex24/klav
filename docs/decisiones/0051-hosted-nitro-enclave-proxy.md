# 0051 · Klav Cloud's hosted credential proxy: `klav-proxy` in an AWS Nitro Enclave, verified by the person's devices before any credential is wrapped for it

- Status: accepted (2026-11-26). Omar asked for the hosted proxy in his own words that day («si, hagamos A», to "build the hosted proxy in an AWS Nitro Enclave now"), and then answered (a), the recommended option, to all of Q1–Q7 («si», to "¿todas (a)?"). His answers are under "Omar's answers" below. Layers 1, 2 and 4 are built; what layer 2 found is in §14, and what layer 4 found in §15.
- Date: 2026-11-26
- Amends:
  - [ADR 0045](0045-keyless-services.md) §5 and its decision 4 ("a proxy hosted by Klav: out of launch … the enclave holds only per-customer signers, never provider keys"). Q1 (a) overturned it for sandboxes and remote MCP profiles; a dated note there says so.
  - [ADR 0036](0036-sandboxes-de-agentes.md) §12, which this ADR designs in full, and its plan's layers 15 and 16.
  - [ADR 0049](0049-mcp-gateway.md) §1 ("no hosted gateway in this ADR") and §3.1 (a remote proxy can't serve the Mac's local agents), narrowly: MCP profiles run in the hosted proxy for sandboxes; by Q5 (a) the Mac keeps its own local proxy for its local agents.
- Builds on, unchanged: the per-item grants and the `0x23` item key (ADR 0036 §2, E10), the pinned channel (§6), the issuer and `ksb1_` (§4), the server as second barrier (E3), the memory and network measures of [ADR 0044](0044-proxy-key-at-rest.md), and the gateway of ADR 0049.
- Where the request comes from: the coordinator's brief of 2026-11-26 says Omar wants Klav Cloud to offer a hosted sandbox and MCP credential proxy backed by Nitro attestation, compatible with ADR 0045's federation later. That reached this ADR second-hand and contradicts decision 4 of ADR 0045 (2026-11-18), so Q1 asked him to confirm it in his own words; he did on 2026-11-26 (Q1 (a)). Kontext's D-86c244 ("the attested hosted proxy is a later, higher tier") agrees with the direction; P-47bc15 (pending) would market it as "coming soon".

## Context

### Why a hosted proxy at all
- **The case Klav was built for is the phone with the Mac asleep** (ADR 0036, answer 1). A sandbox started from T3 Code on the phone needs a proxy that is up when every device of the person is off.
- **Today that means running `klav-proxy` yourself** on Railway, Fly or a VPS (ADR 0036 §11), with ADR 0044's hardening and T151's rule that no token the proxy injects may reach its own host. That is a separate service, a volume, a key file, a network profile and a provider choice that most people get wrong (T151).
- **A one-click proxy is what turns the sandbox and MCP features into something a paying person uses.** It is the part of Klav Cloud that a self-hosted server alone doesn't give.
- **The constraint that stays:** Klav runs nothing that sees plaintext (ADR 0036, answer 10). The only hosted proxy allowed is one whose code the person's devices verify before they hand it a credential. This ADR is that design.

### What the code has today (`main` at `dc4e2e64`, read on 2026-11-26)
- **`ProxyMode::Klav` already exists** in the account's `preferences` item (`crates/klav-core/src/model/preferences.rs:38-46`), and every client refuses it with "Klav's hosted proxy does not exist yet" or "this version does not support yet" (`crates/klav-client/src/preferences.rs:122`, `proxy_admin.rs:597`, `:1095`). `ProxySetting` and `Preferences` reject unknown fields (`preferences.rs:24`, `:52`). Validation, which today requires `agent_id` only with `own`, runs only when a device writes the setting (`preferences.rs:120`), never when it reads it.
- **The proxy is an agent of one account** with its own grant, its per-call `POST /v1/agent/access`, its heartbeat and its sandbox store (ADR 0036 §2, §4, E3). Nothing in the server or the formats assumes the proxy runs on the person's machine.
- **The pinned channel** is TLS 1.3 with raw Ed25519 keys (RFC 7250) through `rustls` with `aws-lc-rs`, and Klav's signature comes from `klav_core::crypto::channel::TlsSigner` (AGENTS.md).
- **`klav-core` already has** `p256` 0.14, `ecdsa` 0.17 (`algorithm`, `der`), `elliptic-curve` 0.14.3, `sha2` 0.11 (SHA-384 included), `hpke`, `hkdf`, `ed25519-dalek`, and `ciborium` 0.2 as a dev-dependency only (`crates/klav-core/Cargo.toml`). `Cargo.lock` has `der` 0.8.3, `spki` 0.8.1, `const-oid` 0.10.2, `primeorder` 0.14.0, `crypto-bigint` 0.7.10, `half` 2.7.1 and `nix` 0.31.3. It has no `p384`, `x509-cert`, `coset`, NSM or vsock crate.
- **The toolchain is 1.98.1** (`rust-toolchain.toml`) and the workspace declares `rust-version = "1.89"` (`Cargo.toml:8`).

### What AWS documents (opened on 2026-11-26)
- **Enclaves** ([What is Nitro Enclaves?](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)): no persistent storage, no interactive access, no external networking; a vsock to the parent only. Up to four enclaves per parent instance. No extra charge beyond the instance.
- **Instance types:** the same page lists, among others, `c6a.large`, `c6i.large`, `m6i.large`, `m6a.large`, `c7i.large` and `m7i.large` as **excluded**. On Graviton only the `.medium` and `.metal` sizes are excluded, so `c7g.large`, `m7g.large` and `c6g.large` are allowed. The brief's x86 `.large` sizes therefore don't work; an x86 parent starts at `.xlarge`.
- **The attestation document** ([Verifying the root of trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)): a tagged `COSE_Sign1` (CBOR tag 18) whose protected header is `{1: -35}` (ES384), unprotected header empty, payload a CBOR map `{module_id, timestamp (ms), digest: "SHA384", pcrs: {index => 32/48/64 bytes}, certificate, cabundle: [root, interm_1 … interm_N], ? public_key, ? user_data, ? nonce}`, with `public_key`, `user_data` and `nonce` up to 1024 bytes each and each certificate 1 to 1024 bytes of DER. The root is `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`, valid 30 years, with SHA-256 fingerprint `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`. Validation: rebuild the chain `[certificate, interm_N … interm_1, root]`, check every certificate's validity period, check the chain, check the signature. AWS says CRLs must be disabled.
- **KMS** ([attestation support](https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html), [`RecipientInfo`](https://docs.aws.amazon.com/kms/latest/APIReference/API_RecipientInfo.html)): `Decrypt`, `DeriveSharedSecret`, `GenerateDataKey`, `GenerateDataKeyPair` and `GenerateRandom` accept a `Recipient` with an attestation document and return `CiphertextForRecipient`. The only `KeyEncryptionAlgorithm` is `RSAES_OAEP_SHA_256`, so the enclave's attested key must be RSA. AWS doesn't document the envelope; third-party write-ups (the [Trail of Bits notes](https://blog.trailofbits.com/2026/08/05/a-few-notes-on-aws-nitro-enclaves-kms-integration/) ADR 0036 cites, and posts found by search) say it is CMS `EnvelopedData`, BER with indefinite lengths, with AES-CBC content encryption. **Not confirmed by AWS.** The condition-key page returned only its introduction; the key names come from ADR 0036's sources and are re-checked at the layer that would use them.
- **Trail of Bits (2026-08-05), on KMS sealing:** authorize by `PCR0` (PCRs 1–2 as defense in depth), never with a `:root` statement that lets IAM bypass the PCR condition; deny `PutKeyPolicy` to everyone with the lockout bypass; and yet "key owners can always contact AWS support to restore default key policies", so true immutability "is likely not possible". AWS says the same in its own pages: a key whose policy no principal can manage "becomes unmanageable and you must contact AWS Support to regain access" ([Default key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html)), and Support authorizes that with the root user ([AWS account root user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html)). Whether Support also overrides an explicit `Deny` of `PutKeyPolicy` is not stated (community answers say escalation to the KMS team). The parent can tamper with credentials, region and key ARN, so the enclave must talk to KMS over TLS it terminates itself, pin the key ARN and check the caller identity. The article says to avoid `aws-nitro-enclaves-sdk-c` and to use `aws-nitro-enclaves-nsm-api`.
- **AWS bulletin 2026-157-AWS** (2026-10-30, ADR 0045 §5): two flaws in the Nitro Enclaves SDK for C up to v0.4.5, one through `kmstool-enclave` or code derived from it. This design uses no C SDK and no `kmstool` (§9).

## Decision

### 1. What runs where
```
 sandbox (Boat)                AWS, Klav's account                                   provider / MCP server
 ┌─────────────┐   TLS 1.3    ┌──────────────── EC2 parent (c7g.large) ───────────┐
 │ klav-forward│──(pinned,───▶│ NLB:443 ─▶ klav-nitro-parent ──vsock──▶ ┌────────┐ │   TLS 1.3 (webpki)
 └─────────────┘  RFC 7250)   │            (bytes only)                 │ enclave│─┼──────────────────────▶ api.northflank.com
                              │            ◀─vsock── egress: host:port ─│klav-   │ │   (terminated inside)  api.maple.dev/mcp
 person's devices ──HTTPS────▶│ /attest, /manifest (self-authenticating)│proxy   │ │
 (CLI, Mac, iOS via klav-ffi) │                                         │--enclave │
                              │            ◀─vsock── to api.klav.dev ───└────────┘ │──▶ api.klav.dev (signed agent calls)
                              └────────────────────────────────────────────────────┘
```
- **Inside the enclave:** `klav-proxy --enclave`, the same program as the self-hosted proxy (ADR 0036 §1) built with the `enclave` feature. It generates or receives its master seed in enclave memory (§4), derives each account's keys (§3), terminates the pinned channel from `klav-forward`, terminates TLS to every upstream and to `api.klav.dev`, and decrypts items per call through `klav-core`, as today.
- **On the parent:** `klav-nitro-parent`, a small Linux binary with no Klav keys and no `klav-core` cryptography. It moves bytes: inbound TCP from the load balancer to the enclave's vsock port; outbound, on the enclave's request, a TCP connection to a `host:port` (§1.2). It also allocates the enclave (`nitro-cli run-enclave`) and serves a health check.
- **Nothing else:** no database, no disk state of value, no secret in the instance's user data, environment or IAM role (§4 keeps KMS out of v1).

#### 1.1 What the parent host sees and can't see

| The parent (and anyone with root on it, or AWS staff short of the hypervisor) | Sees | Never sees |
|---|---|---|
| Inbound | Source IPs, timing, sizes; the SNI of the channel's ClientHello (which names the account, §3.4) | The sandbox credential, request and response bodies, headers, MCP JSON-RPC, the channel key |
| Outbound | DNS names it resolves for the enclave, destination IPs and ports, timing, sizes, upstream SNI | Provider tokens, MCP bodies, anything inside TLS |
| To `api.klav.dev` | That the enclave talks to the server, and how often | Signed request bodies, sealed items, grants |
| Enclave memory | Nothing (Nitro hypervisor isolation) | Master seed, account keys, decrypted values |

DNS is the parent's, so it can lie: a wrong address fails TLS hostname verification inside the enclave and costs availability, not secrecy.

#### 1.2 Egress and SSRF
- The enclave asks the parent for `CONNECT host:port` over vsock; the parent resolves the name and **refuses** loopback, private, link-local (including `169.254.169.254`, the instance metadata service), CGNAT and multicast ranges, then connects. The proxy keeps its own checks (ADR 0049 §2.4: no redirects, `webpki` roots, `identity` encoding); it can't resolve DNS itself any more, so the parent's refusal list is the SSRF barrier, and the enclave refuses any IP literal from a profile that is in those ranges.
- The parent connects only to port 443 by default; another port (80 included) must be listed in the parent's configuration, which is Klav-wide, not per account.

### 2. Trust model and the verification the devices do

#### 2.1 Who must be trusted, said plainly
- **AWS**, as maker of the Nitro hypervisor and holder of the attestation PKI. A compromised hypervisor or root CA defeats this design. Nitro was not in scope of the 2025 physical attacks on SGX, TDX and SEV-SNP (ADR 0036 §12); that does not prove immunity.
- **The release authority** (§2.4), which decides which enclave images are acceptable. Today that is Omar.
- **The open source code at the attested commit**, which anyone can rebuild to the same `PCR0` (§7.3).
- **Not** Klav's operators of the AWS account, the parent's root user, Klav's sync server, the CDN or the network.

#### 2.2 What the person's device checks before it wraps anything for the hosted proxy
All of it lives in `klav-core` behind a new feature, `nitro-attestation`, and reaches the Mac and iOS apps through `klav-ffi` like every other check. **No Swift verifier.** `klav-wasm` doesn't compile the feature (the extension never wraps for a proxy).

1. **Fetch** `GET https://proxy.klav.dev/v1/attest?account=<id>&nonce=<32 random bytes, base64url>` and the current manifest (§2.4). Both are self-authenticating; the transport is ordinary TLS and is not trusted.
2. **Decode strictly:** `COSE_Sign1`, under tag 18 or untagged (the NSM omits the tag, §14), protected header exactly `{1: -35}`, unprotected header empty, no duplicate map keys, no indefinite lengths, no trailing bytes, total size ≤ 16 KiB. Payload map with exactly the documented keys; `digest == "SHA384"`; PCR values 48 bytes.
3. **Chain:** `cabundle[0]` must be byte-equal to the pinned AWS Nitro Enclaves Root-G1 certificate compiled into `klav-core` (its SHA-256 equals the fingerprint above, checked by a unit test). Each next certificate is signed by the previous one with ECDSA P-384/SHA-384; every certificate is within its validity period at the device's clock; intermediates have `basicConstraints CA:TRUE` and respect `pathLenConstraint`; the leaf (`certificate`) is not a CA. At most 8 certificates. No CRL (AWS says to disable it).
4. **Signature:** the COSE `Sig_structure` `["Signature1", protected, h'', payload]` (RFC 9052 §4.4) verified with the leaf's P-384 key; the signature is 96 bytes `r ‖ s`.
5. **Freshness and binding:** `nonce` equals the one sent; `timestamp` within 5 minutes of the device's clock; `user_data` equals `binding = SHA-256(tuple("klav/v1/proxy/enclave-binding", account_id(16), agent_id(16), agent_ed25519_pub(32), agent_x25519_pub(32), u32_be(generation)))`, where the keys are those the server shows for the account's hosted proxy agent (§3). `public_key` is ignored in v1.
6. **Measurement:** `pcrs[0]`, `pcrs[1]` and `pcrs[2]` equal one image entry of a valid manifest whose status is `current` or `draining`; all three nonzero (a debug-mode enclave reports zeros and is refused); `module_id` non-empty.
7. **Only then** may the device sign the hosted proxy's grant (wrapping `0x23` item keys to `agent_x25519_pub`), approve its registration, or set `proxy.mode = "klav"`.

The device repeats steps 1–6 with a fresh nonce whenever it is about to wrap for the hosted proxy, when the Sandboxes or MCP servers section opens, and in the background at most daily. A failure never blocks reading; it blocks wrapping, and shows a red row with "Stop using it" (§6.3).

#### 2.3 What this proves and what it doesn't
- It proves that **some** enclave running an image the release authority listed holds the private keys bound in `user_data`, now.
- It doesn't prove that the image is bug-free, that AWS is honest, or that the same enclave answers the next TCP connection. The latter is covered by the channel: `klav-forward` and the person's devices pin the per-account key (`ksb1_` carries its SPKI hash, ADR 0036 §4), and only approved enclaves ever hold it (§4).

#### 2.4 The Klav Enclave Transparency Manifest
- **Format, versioned:** `manifest.json`, UTF-8 JSON, `deny_unknown_fields`:
  ```json
  { "v": 1, "seq": 7, "seed_epoch": 0, "issued_at_ms": 1795000000000, "expires_at_ms": 1797592000000,
    "endpoint": "proxy.klav.dev", "server": "api.klav.dev",
    "images": [ { "version": "0.12.0", "commit": "<40 hex>", "arch": "aarch64",
                  "pcr0": "<96 hex>", "pcr1": "<96 hex>", "pcr2": "<96 hex>",
                  "status": "current" } ],
    "parent_roles": ["<96 hex: PCR3 of Klav's instance role>"],
    "egress": ["203.0.113.10/32", "203.0.113.11/32"] }
  ```
  `status` is `current`, `draining` (accepted, but no new grants are wrapped once a `current` newer image is live) or `revoked`. `seed_epoch` grows by one after a total loss (§4.4), so a device can tell a proxy that lost its keys from a broken endpoint.
- **Signature:** Ed25519 over `tuple("klav/v1/sig/enclave-manifest", SHA-256(manifest_bytes))`, by a release-authority key whose public half is compiled into `klav-core` (two keys pinned: the active one and an offline backup, §11). A new label in spec §2.3 with vectors (`docs/vectores/enclave-manifest.json`).
- **Anti-rollback:** a device keeps the highest `seq` it verified and refuses lower ones, like the audit watermarks (T7); it refuses a manifest past `expires_at_ms` (30 days), so a replayed manifest that still lists a later-revoked image ages out.
- **Publication:** every signed manifest is committed to the public repository under `deploy/nitro/manifests/<seq>.json` with its `.sig` before `proxy.klav.dev` serves it. Git history is the v1 transparency log: public, mirrored, and hard to rewrite unnoticed now that the repository is open. A verifiable log (Rekor or similar) is later work (§12).
- **`egress`** lets a device sign ADR 0044's strict network profile for the hosted proxy automatically, with Klav's own addresses (§3.5).

#### 2.5 2026-157-AWS, side channels and the honest residue
- **No C SDK, no `kmstool`:** the NSM is reached through `/dev/nsm` from Rust (§5.2), and v1 calls KMS not at all (§4). If KMS comes later (Q3 (b)), the client is Rust over TLS terminated in the enclave, with the key ARN and role pinned in the image, per Trail of Bits.
- **Cache side channels from the parent with root:** a 2026 paper on this was seen only as a search snippet (ADR 0045 §5), not confirmed. Klav's primitives are constant-time (RustCrypto, `aws-lc-rs`), but header insertion and the redactor's search over responses (ADR 0036 §8) are ordinary string code over the token. A working cache side channel could leak tokens while they are used. Residual risk, stated in the threat model.
- **Metadata to the parent** (§1.1). Residual risk.
- **AWS hardware and firmware trust** (§2.1). Residual risk.

### 3. Many accounts, one enclave

#### 3.1 The two models

| | (a) A derived identity per account | (b) One enclave identity, per-account grants |
|---|---|---|
| Keys | One 32-byte master seed; each account's agent keys = `klav-core` derivation of `HKDF-SHA-256(seed, info = tuple("klav/v1/proxy/hosted-account", account_id(16), u32_be(generation)))` | One Ed25519 + X25519 pair for every account |
| What the server sees | An ordinary proxy agent per account, as today; pause, revocation, ADR 0044's alarm, the heartbeat and E3 work per account untouched | The same public key registered in N accounts (whether the server allows a key in two accounts is not checked) |
| Cross-account isolation | Cryptographic against routing bugs: account A's request path holds only A's keys, so a confused-deputy bug can't open B's items | Only code: every grant is wrapped to the same key, so any routing bug reaches every account |
| Attestation | On demand per account: `user_data` binds that account's keys (§2.2) | One document, cacheable for everyone |
| Rotating one account's key (reset, suspected leak) | Bump that account's `generation`; nobody else is touched | Every account re-wraps every credential |
| What a seed leak costs | Every account (same as (b)) | Every account |
| Memory | Derivation is per request or cached per active account (~200 bytes each) | Same |
| Server or format changes | None for keys; `generation` lives in the enclave's request to register and in the binding | A rule for shared agent keys across accounts |
| Routing a sandbox's channel | The enclave must know the account **before** it presents a key, so the forwarder must name it in the ClientHello (§3.4): **a new `klav-forward`**, because today's sends the fixed SNI `klav-proxy` (`crates/klav-forward/src/forward.rs:178`) | Nothing changes: one key for every connection, the account learned after the handshake |

**Recommendation: (a)** (Q2). It reuses the whole per-agent machinery, isolates accounts at the key level, and lets one account reset without touching the others. A seed leak is total in both models; (a) doesn't make that worse. Its price is the forwarder change of §3.4: sandbox templates need a `klav-forward` from layer 3 or later to use the hosted proxy.

#### 3.2 `generation`
- Starts at 0. The person's device asks for `generation + 1` with "Reset Klav Cloud proxy" (a new pairing), after which the old agent is revoked and its item keys change (ADR 0036 §18). The enclave keeps no per-account state that must survive (§4.3), so `generation` arrives in the device-signed enroll request (§6.1) and in the server's record of the agent; a malicious server that asks for an old generation gets an old, revoked agent that the server itself refuses and whose item keys were already rotated.

#### 3.3 Per-account quotas, enforced inside the enclave
The parent can't attribute traffic to an account (it sees only SNI and bytes), so the enclave enforces. Defaults, all per account, configurable per plan in the enclave's signed configuration (§7.4):

| Quota | Default | On excess |
|---|---|---|
| Live sandboxes | 10 | `klav_rate_limited` on `klav sandbox start` |
| Requests per minute | 120 (60 per sandbox stays, ADR 0036 §8) | `429 klav_rate_limited` with `retry_after` |
| Request body | 32 MiB | `413`, `klav_upstream_blocked` |
| Egress bytes per day | 2 GiB up + down | `429` until the window rolls |
| Concurrent SSE streams | 8, each ≤ 1 hour | the oldest stream closes |
| Concurrent upstream connections | 32 | queue, then `503 klav_proxy_backlog` |
| Memory for buffers | 64 MiB | new connections refused for that account |

Fairness: one tokio task budget and a byte-based scheduler per account, so a stream-heavy tenant can't starve others. The signed host lists already stop it being an open proxy; quotas bound the bill and Klav's egress reputation. A global ceiling per instance protects the instance itself; the NLB and parent apply per-IP connection limits before any byte reaches the enclave.

#### 3.4 Routing an inbound channel to its account
- Each account's channel endpoint is `a<agent_id hex>.proxy.klav.dev` (one wildcard DNS name). The enclave reads the TLS SNI, picks that account's derived key and presents it. `ksb1_` already carries the URL and SPKI hash (spec §13.10), so the format doesn't change.
- **The forwarder changes:** today `klav-forward` sends the fixed SNI `klav-proxy` whatever the URL (`forward.rs:178`; the pin, not the name, authenticates). From layer 3 it sends the URL's host as SNI. A self-hosted proxy ignores SNI, so nothing changes for it. An older forwarder with a hosted package reaches the enclave with `klav-proxy`, gets no account's key, fails the pin and reports `klav_proxy_unreachable`: it fails closed, and `klav sandbox start`'s `next` says to update `klav-forward` in the template, as the note of 2026-11-15 did for `down --if-other-package` (ADR 0036 §14).
- The SNI reveals which account a connection is for to the parent (§1.1). Without it, the enclave would have to accept a connection under one key and switch, which raw-key TLS doesn't do. Stated as residual risk.

#### 3.5 Pause, revocation, account deletion and entitlement
- **Pause and per-sandbox revocation** already reach the hosted proxy the way they reach any proxy: the server refuses its next `POST /v1/agent/access` and its `sandbox.claimed`, and the proxy polls revocations every 30 s (ADR 0036 E3.3). Nothing new.
- **Revoking the hosted proxy** or switching away from it is the existing switch (ADR 0036 §3): the device revokes the agent and changes every item key it had.
- **Account deletion:** the server deletes the agent; the enclave's next signed call gets `401`, and it drops that account's state (store, cached grant, connections) at once. It also checks `GET /v1/agent/me` for every account with live state every 5 minutes.
- **Entitlement:** `GET /v1/agent/me` gains an optional `hosted_proxy: {entitled: bool, plan}` (`AgentMe` has no `deny_unknown_fields`). Not entitled → the enclave serves nothing for that account and says so with a new `klav_hosted_not_entitled` (`402`). A malicious server can only deny service this way.
- **ADR 0044 for the hosted proxy:** its egress addresses are in the manifest (§2.4), so the sheet that turns the hosted proxy on offers the **strict** network profile with exactly those addresses, on by default. Turning strict on is the first pin, which is narrowing and needs no presence (ADR 0044 §2.2, §2.5); it needs `agent_addresses` on at `api.klav.dev` (ADR 0044 decision 8) and carries that ADR's "every device updated" confirmation. A copy of an account key, which shouldn't exist outside approved enclaves, is then refused from anywhere else.
  - **The cost:** Klav's egress addresses must stay fixed. Adding an address later is widening for every account, which needs each person's Touch ID or Face ID (ADR 0044 §2.2). So a new address is listed in the manifest first, the apps ask each person to let it in, and the enclave uses it only for accounts whose pin already has it. The pin holds at most 16 entries; the instances need 2. Entries never lapse while the proxy runs (ADR 0044 §2.6).

### 4. Keys across restarts and upgrades

#### 4.1 The three options against one question: who can change who unseals?

| | (a) RAM-only, replicated between enclaves, attested hand-off | (b) KMS-sealed seed, key policy written and locked by the enclave | (c) KMS policy that Klav edits to add each new `PCR0` |
|---|---|---|---|
| How a restart recovers | A live peer enclave hands the seed over (§4.2) | The new enclave asks KMS to decrypt with its attestation | Same as (b) |
| How an upgrade recovers | The old enclave hands the seed to the new one after checking its attestation against the manifest | Same hand-off, then the new image creates and locks its own new KMS key | Klav adds the new `PCR0` to the policy, then removes the old |
| Who can get the seed into an image the devices wouldn't accept | Only the release authority, by signing a manifest that lists it, **and** publishing that manifest in the public repository first (§4.2, step 2) | The release authority, the same way; **and** Klav's AWS root user through AWS Support resetting the locked policy ([AWS](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html)), which the enclave sees only afterwards and which needs no publication | Anyone with `kms:PutKeyPolicy` in Klav's account, at any time, silently. **Breaks the trust model** |
| Total loss (every enclave down at once) | The seed is gone: every account sets the hosted proxy up again on a device (§4.4) | Recovers alone | Recovers alone |
| New dependencies | None beyond §5 | `rsa` 0.10, `aes` 0.9, `cbc` 0.2, a CMS parser (`cms` 0.3 is only `rc.2`) and SigV4 in `klav-core`, all for the enclave only | Same as (b) |
| Instances | At least 2, in 2 AZs | 1 is enough; 2 for availability | 1 |

**Recommendation: (a) for the beta, with (b) as a later decision once there is operating data** (Q3). Under (a) the only way to the seed is the release authority, and only in public; there is no AWS-account path. It needs no RSA or CMS, and a proxy that must stay up needs two instances anyway. Its cost is real: if both enclaves die together (a region event, an operator mistake during a deploy), every person must set the hosted proxy up again (§4.4), and their sandboxes fail with `klav_proxy_unreachable` until they do. (c) is rejected outright.

**What none of the options removes:** the release authority (§2.1) can sign a manifest listing an image that leaks the seed. Under (a) it must publish that manifest in the public repository before any enclave hands the seed over (§4.2), so the act is visible; it is not prevented.

#### 4.2 The attested hand-off (peer and upgrade)
1. The joining enclave J sends its attestation with `public_key` = a fresh X25519 key and a nonce from the holder H. H sends its own attestation with J's nonce. Both go through the parents and the network; nothing in between is trusted.
2. H verifies J exactly as a device would (§2.2 steps 2–4, 6) against its compiled-in release keys and the newest manifest it has, plus:
   - J's `PCR3` is in `parent_roles` (an approved image running on someone else's instance gets nothing; Trail of Bits' advice);
   - J's image is `current` or `draining` and **not older** than H's own entry in the manifest (no downgrade);
   - **the manifest is public:** H fetches `deploy/nitro/manifests/<seq>.json` and its `.sig` from the repository's default branch at `raw.githubusercontent.com`, over TLS it terminates itself, and requires them byte-equal to the manifest J relies on. A manifest the release authority signed but didn't publish never moves the seed. This trusts GitHub to serve the branch as it is, not to keep anything secret.
3. J verifies H the same way, so J never accepts a seed from an unapproved image.
4. H seals the seed to J's attested X25519 key with HPKE (`klav-core`'s `hpke_seal`, label `klav/v1/proxy/enclave-handoff`, `info` binding both attestations' `PCR0` and nonces) and sends it. J opens it, derives the account keys and starts serving.
5. Every hand-off is logged by both enclaves to the parent's operational log with the two image versions, never key material.

The same steps keep two or three replicas in sync after a restart of one of them.

#### 4.3 State that isn't the seed
- **Sandbox stores, `seq` and `store_epoch`** (ADR 0036 E3.3) live in enclave memory and replicate to peers over the hand-off channel (HPKE to the peer's attested key, sealed per batch).
- **On total loss** the new seed means new account keys, so every sandbox ends anyway. When only one replica restarts, it takes the store from its peer.
- **Nothing is written to the parent's disk.** (b) would allow a sealed store on disk; it would be open to rollback by the parent, bounded by the server's barrier (revocations live there).

#### 4.4 Setting it up again after total loss
What actually happens, step by step:
1. The first enclave to start with no live peer generates a new seed. It knows no account (§3.2: it keeps no per-account state), and it can't register anyone on its own: enrolling needs the account's signature (§6.1).
2. Every account's hosted proxy agent now has keys nobody holds. Its channel fails the pin, so sandboxes get `klav_proxy_unreachable`; `GET /v1/attest` for it answers `404 klav_hosted_not_enrolled`; the server still lists the old agent.
3. A device of the person, on its next check (§2.2, at most daily, or when the Sandboxes section opens), sees the `404` together with the manifest's `seed_epoch` (a counter the release authority bumps in a new manifest after a total loss, so a device can tell "lost its keys" from "a broken endpoint"). It shows: "Klav Cloud's proxy lost its keys. Set it up again to keep using your credentials from sandboxes."
4. The person opens one sheet, which:
   - enrolls again (§6.1): the enclave registers a **new agent**, with a new `agent_id` and so a new `a<agent_id>.proxy.klav.dev`;
   - verifies the attestation and approves the agent (presence);
   - signs a new grant with the same items and profiles (wrapping each item key to the new keys);
   - signs new grants for the account's issuers, which pin the proxy's address and key (ADR 0036 §3);
   - writes `preferences` with the new `agent_id` and signs the strict network profile again;
   - revokes the old agent, which changes the item keys it had (ADR 0036 §18).
   Whether one Touch ID or Face ID can cover all of those signatures on each platform is **not verified**; at worst it is one per kind of signature in the same sheet.
5. Every sandbox that was running ended in step 1. Issuers get their new grant on their next fetch, and new sandboxes work from then on.

A person with no device awake stays down until they open one. That is the availability price of (a), and the reason for two zones.

### 5. Dependencies (each needs Omar's approval, AGENTS.md; Q4)
Checked on 2026-11-26 by resolving throwaway manifests outside the repository against the crates.io index and running `cargo deny check advisories bans licenses` with the repository's `deny.toml`.

#### 5.1 In `klav-core`, behind the non-default feature `nitro-attestation` (clients and the enclave; never `klav-wasm`)

| Crate | Version | License | New to `Cargo.lock`? | Notes |
|---|---|---|---|---|
| `p384` | 0.14.0, features `ecdsa` (and `sha384` if ES384 verification needs it; layer 2 picks, from the crate's list `digest`, `pem`, `pkcs8`, `sha384`, `ecdsa`) | Apache-2.0 OR MIT | **Yes** | Rust 1.85. The probe resolved and passed `cargo deny`; it compiled nothing. Same generation as `p256` 0.14 / `ecdsa` 0.17 / `elliptic-curve` ≥ 0.14.3 already pinned; pulls `primeorder` 0.14 and `fiat-crypto` 0.3, both already present. Resolves `crypto-bigint` 0.7.10+ (≥ 0.7.9, the ban stays satisfied). Verify only; no secret scalar ever touches it |
| `x509-cert` | 0.3.1, no default features | Apache-2.0 OR MIT | **Yes** | Rust 1.87. Parsing only (`TbsCertificate`, validity, extensions, SPKI); brings `der_derive` 0.8.0 and `flagset` 0.4.7 (Apache-2.0), new |
| `der` | 0.8 (`alloc`, `oid`) | Apache-2.0 OR MIT | No (0.8.3) | Becomes direct |
| `spki` | 0.8 | Apache-2.0 OR MIT | No (0.8.1) | Becomes direct |
| `ciborium` | 0.2.2 | Apache-2.0 | No (dev-dependency today) | **Becomes a normal dependency behind the feature**, which AGENTS.md today allows only as a dev-dependency. *Layer 2: not needed; it stays a dev-dependency (§14)* |
| `sha2` | 0.11 | — | No | SHA-384 for PCR comparisons and the COSE signature |
| COSE_Sign1 | — | — | — | Written in `klav-core` (~80 lines): the 4-element array, the protected header check and the RFC 9052 `Sig_structure`. **`coset` 0.4.2 is not proposed:** it would only add a crate (Apache-2.0, depends only on `ciborium`) for one fixed structure |

`cargo deny`: **advisories ok, bans ok, licenses ok.** No `ring`, `openssl` or `serde_cbor` in the graph (`cargo tree -i`). WASM: not compiled; `no_std`: not relevant (`klav-core` is `std`). Binary size added to the Mac DMG (25 MB cap, ADR 0027 §5) and to the iOS app: **not measured**; layer 2 measures it and stops past 1 MB.

#### 5.2 In `klav-proxy`, behind the feature `enclave` (Linux only, `cfg(target_os = "linux")`)

| Crate | Version | License | New? | Notes |
|---|---|---|---|---|
| `aws-nitro-enclaves-nsm-api` | 0.5.2, default features (its only feature, `nix`, which the `/dev/nsm` driver is expected to need; layer 3 confirms) | Apache-2.0 | **Yes** | AWS's Rust NSM client (`/dev/nsm` ioctl). `nix` 0.31 is already in the tree. Its own `unsafe` sits in the dependency, not in Klav's code. **Pulls `serde_cbor` 0.11.2, unmaintained (RUSTSEC-2021-0127): `cargo deny` fails** until `deny.toml` ignores that ID with a reason. Declares Rust 1.92, above the workspace's 1.89 (the pinned 1.98.1 builds it); the `enclave` feature's real MSRV becomes 1.92. Also brings `serde_bytes` 0.11.19 and `half` 1.8.3 |
| `tokio-vsock` | 0.7.3 | Apache-2.0 | **Yes** | Async vsock listener and stream; brings `vsock` 0.5.5 (Apache-2.0, on `nix` 0.31, already present) |
| `vsock` | 0.5.5 | Apache-2.0 | **Yes** | — |

`cargo deny` for `tokio-vsock` + `vsock`: ok. Non-cryptographic: transport and the hypervisor device. The alternatives to the NSM crate are a hand-written ioctl, which needs a new `unsafe` exception like `klav-ffi`'s, or `nix`'s ioctl macros, which are still `unsafe` to call (Q4 (b)).

#### 5.3 The parent binary (`klav-nitro-parent`, in `klav-proxy` behind `nitro-parent`)
`tokio-vsock` and the existing `tokio`; no cryptography and no `klav-core` feature.

#### 5.4 Looked at and not proposed
- **`aws-nitro-enclaves-cose`** 0.6.1: depends on `openssl` (banned) through an optional feature and on `serde_with`; not needed with §5.1's 80 lines.
- **`aws-sdk-kms`** 1.134: pulls `ring` through `rustls` 0.21 by default (`cargo tree -i ring`), and ~50 crates. If Q3 (b) is chosen later, KMS goes through `reqwest` with SigV4 computed in `klav-core` from `hmac` and `sha2`.
- **`rsa` 0.10.0, `aes` 0.9.4, `cbc` 0.2.1, `cms` 0.3.0-rc.2:** only for Q3 (b). They resolve cleanly (`cargo deny` ok; `rsa` 0.10 is past RUSTSEC-2023-0071), but `cms` is a release candidate and KMS's BER envelope needs checking against it.
- **`rustls-webpki`** for the chain: already in the tree, but its signature algorithms come from `ring` or `aws-lc-rs` (banned in `klav-core`) and it applies Web PKI rules (EKU, names) that don't fit Nitro's chain. A custom `SignatureVerificationAlgorithm` on `p384` would work; not proposed, because it adds a transport crate to `klav-core` to validate a fixed 3–5 certificate chain.

### 6. UX, protocol and infrastructure

#### 6.1 Turning it on
- **CLI:** `klav proxy use klav`. **Mac:** "Use Klav Cloud Proxy" in Development › Sandboxes (the header row, ADR 0036 E4) and in Development › MCP servers. **iOS:** Settings › Credential proxy.
- **The steps, on the person's device:**
  1. Fetch and verify the manifest (§2.4).
  2. Sign `tuple("klav/v1/sig/hosted-proxy-enroll", account_id(16), u32_be(generation), u64_be(at_ms))` with the account identity and `POST https://proxy.klav.dev/v1/enroll` with the account's e-mail, its identity public key and the signature. The enclave checks the signature with that key and `at_ms` (±5 min), derives the keys and registers them with the server as a pending agent, the call `klav-proxy init --email` makes today (`POST /v1/agents/register` with `email` and `public_identity`, `crates/klav-server/src/routes/agents.rs:54`, `:137-160`). It keeps the identity key it was given and refuses any later grant not signed by it, as every agent pins its account (ADR 0014, point 4). Someone who enrolls a victim's e-mail with their own key only creates a pending agent the victim never approves, as `klav-proxy init` already allows; the enclave rate-limits enrolls per account and per IP. The server says whether the account is entitled when the agent first calls `GET /v1/agent/me` (§3.5). It answers `agent_id`.
  3. Attest for that account with a fresh nonce and verify (§2.2), comparing the bound keys with the pending agent the server shows.
  4. **No six words:** the person compares six words today so that the pending agent's keys are the ones they meant (ADR 0014 §1). Here the device checks that itself: the keys the server shows for the pending agent must be the ones the attestation binds (§2.2, step 5), which proves an approved image holds them. The sheet shows "Klav Cloud proxy · version 0.12.0 · commit abc1234 · verified just now", what Klav can and can't see (§1.1), and asks Touch ID or Face ID.
  5. Write `proxy: {mode: "klav", agent_id}` and sign the strict network profile with the manifest's `egress` (§3.5).
- **Then everything is ADR 0036 and ADR 0049:** `klav proxy grant ITEM --preset northflank` or `--mcp-url …` wraps to the hosted agent after a fresh attestation; `klav sandbox start` works with the issuer's grant pointing at `a<agent_id>.proxy.klav.dev`; approvals, heartbeat, revocation, Activity and `klav log verify` are unchanged.

#### 6.2 `preferences`
- `{mode: "klav", agent_id}`: `agent_id` now comes with `own` **and** `klav`. The change is in `ProxySetting::validate` only (`preferences.rs:76-80`); no new field, so `deny_unknown_fields` doesn't bite older devices (§9).

#### 6.3 What the person sees later
- A row "Credential proxy: Klav Cloud (attested, v0.12.0, checked 2 h ago)". Tapping it shows the commit, the three PCRs, the manifest `seq`, and a link to the manifest in the public repository.
- **When verification fails** (a PCR not in the manifest, a revoked image, a bad chain, an expired manifest): a red row, "Klav Cloud's proxy couldn't be verified. Klav won't share new credentials with it", with "Stop using it" (switch to `none`, revoke the agent, change the item keys, and recommend rotating the provider tokens, ADR 0036 §18). Existing credentials stay shared until the person acts, because an unverifiable proxy is more likely a stale manifest than an attack; the copy says which.

#### 6.4 Endpoints of the enclave (served through the parent)

| Path | Who | What |
|---|---|---|
| `GET /v1/manifest` | anyone | The current signed manifest (also at `deploy/nitro/manifests/`) |
| `GET /v1/attest?account&nonce` | anyone (rate-limited per IP) | Attestation with that account's binding; `404` for an account not enrolled |
| `POST /v1/enroll` | the account, signed (§6.1) | Registers the per-account agent |
| `a<agent_id>.proxy.klav.dev:443` | sandboxes, issuers | The pinned channel, as for any proxy |
| `GET /healthz` (parent only, vsock) | the parent | Liveness; no account data |

#### 6.5 Mac local agents
ADR 0049 §3.1 connects local MCP clients to the Mac's own proxy on loopback; a remote proxy can't serve them. With `mode: "klav"`, the account's proxy is the hosted one. Q5 decides between keeping the Mac's LaunchAgent proxy as a second, local-only proxy that the Mac knows by itself (no new preference field; `klav proxy grant --local` wraps for it), a local forwarder to the hosted proxy, or hosted for sandboxes only.

### 7. Build, release and infrastructure

#### 7.1 The image
- `deploy/nitro/Dockerfile.enclave`: multi-stage, every base image pinned by digest; stage 1 builds `klav-proxy --features enclave` for `aarch64-unknown-linux-gnu` (or `-musl`, chosen at layer 6 for reproducibility) with the toolchain of `rust-toolchain.toml`, `--locked`, `SOURCE_DATE_EPOCH` from the commit, `-C link-arg=-Wl,--build-id=none`, `--remap-path-prefix`; stage 2 is a minimal root filesystem with only the binary, the CA bundle of the pinned base image's `ca-certificates` package (the proxy reads system roots through `rustls-native-certs`, `crates/klav-proxy/Cargo.toml:39`, so no new crate) and no shell. The bundle is part of PCR2, so a roots update is a new image.
- `nitro-cli build-enclave --docker-uri … --output-file klav-proxy.eif` prints PCR0/1/2. `nitro-cli`'s version is pinned; its kernel and init blobs are part of PCR1 and come from that version.

#### 7.2 CI
- A separate workflow, `.github/workflows/eif.yml`, on release tags and on demand, **not** a ninth task of the Boat `ci` job (its cost model is per start, ADR 0034). It builds the EIF **twice on two independent runners** and fails unless PCR0, PCR1 and PCR2 match. aarch64 runners: GitHub's hosted Arm runners for public repositories, not verified for this repository. Its output is a draft `manifests/<seq>.json` and the EIF as a release asset.
- Signing the manifest is **not** in CI: the release authority signs on a device (§11).

#### 7.3 Anyone can check
`scripts/nitro/verify-release.sh <tag>` rebuilds the EIF from the tag and prints PCR0/1/2 next to the manifest's. The docs site explains it.

#### 7.4 Infrastructure (`deploy/nitro/`)
```
deploy/nitro/
  Dockerfile.enclave        build-eif.sh          manifests/<seq>.json(.sig)
  parent/  klav-nitro-parent.service  allocator.yaml (1 vCPU, 2048 MiB)  enclave.service
  terraform/  main.tf  network.tf (VPC, 2 public subnets in 2 AZs, EIPs for fixed egress)
              nlb.tf (TCP 443 passthrough, health on the parent)  instances.tf (2× c7g.large, AL2023, IMDSv2 only)
              iam.tf (no KMS in v1; SSM for the operator)  dns.tf (proxy.klav.dev, *.proxy.klav.dev)
  runbook.md (rolling upgrade, total loss, revoking an image)
```
- **Rolling upgrade:** start the new image on instance 2 → hand-off from instance 1 (§4.2) → move instance 1 to the new image → hand-off from instance 2. Never stop the last live enclave of the current seed.
- **Sizing:** `c7g.large` is Graviton (2 vCPU, 4 GiB): 1 vCPU and 2 GiB to the enclave, the rest to the parent. Whether a 1-vCPU enclave handles the beta's load is not measured; layer 6 load-tests it.
- **Cost (us-east-1, Linux, from third-party price aggregators, not AWS's page):** `c7g.large` $0.0725/h ≈ **$52.9/month** on demand; 1-year EC2 Instance Savings Plan ≈ $0.0478/h ≈ **$34.9/month**. Two instances: ≈ $106/month on demand, ≈ $70/month with the plan. Plus an NLB (fixed hourly plus capacity units), two public IPv4 addresses, and data transfer out, which is the cost that grows with use and the reason for §3.3's egress cap. x86 would start at `c6a.xlarge`, roughly twice the price (not verified).

### 8. Approvals, audit and the server
- **No new audit action.** The hosted proxy is an agent; its accesses, sandbox events and heartbeat are those of ADR 0036.
- **The server gains:** the `hosted_proxy` entitlement in `AgentMe` and an admin path to set it; recognizing the enroll registration (the enclave signs it with a seed-derived service key whose public half `klav-server` is configured with, so the server can mark the agent `hosted`; not a security boundary); and nothing else.
- **What the server learns that it didn't:** that an account uses Klav Cloud's proxy.

### 9. Safe with older clients
- **`{mode: "klav", agent_id}` in `preferences`:** an older device parses it (the field exists, validation runs only on write), and every proxy command refuses with "the account uses Klav's hosted proxy, which this version does not support yet" (`proxy_admin.rs:597`, `:1095`). It fails closed and says why. An older device that runs `klav proxy use own` replaces the setting, which is the person's choice.
- **Older devices never wrap for the hosted proxy**, because they refuse the mode. The sheet that turns it on asks to update every device first, as grant `v: 2`–`v: 4` did.
- **Issuers and `klav-forward`:** unchanged formats; the URL and pin are in the issuer's signed grant and `ksb1_`. A `klav-forward` older than layer 3 sends the fixed SNI and fails closed against the hosted proxy with `klav_proxy_unreachable` (§3.4); with a self-hosted proxy it keeps working.
- **The server:** `hosted_proxy` in `AgentMe` is optional and ignorable; the enroll marker is server-side only. Reviewed as "safe with older clients" before merge (`main` deploys production).

### 10. What this ADR does not stop
- A compromised AWS hypervisor or Nitro PKI (§2.1).
- A bug in an approved image: the image is what's attested, not its correctness. The open source and reproducible build let others look; revoking the image in the manifest stops new wraps, and the person must still revoke and rotate (ADR 0036 §18).
- **A release authority that signs a malicious image.** Whoever holds the release key can list an image that leaks the seed, and a live enclave will hand the seed to it. The hand-off requires the manifest to be in the public repository first (§4.2), so the act is visible, not prevented. Today the release authority is Omar, so "no one at Klav can get your credentials" is true of everyone at Klav except him, and only through a public act. The same holds for devices: they accept what the release key signs.
- Side channels against string handling of tokens (§2.5).
- Metadata to the parent and to Klav: account SNI, upstream hosts, timing and volume (§1.1).
- A deliberate total loss (someone at Klav stopping every enclave): it costs every account a new setup (§4.4), never a key.
- Everything ADR 0036 §18 already says the proxy doesn't stop: the agent can do whatever its profiles allow.

### 11. What this ADR chose on its own (Omar can overturn each)
1. The per-account endpoint by SNI, `a<agent_id>.proxy.klav.dev` (§3.4).
2. `user_data` as the binding, `public_key` unused in v1 (§2.2).
3. The manifest as JSON with an Ed25519 signature over its hash, 30-day expiry, `seq` watermark, `draining` status (§2.4).
4. Git history in the public repository as the v1 transparency log (§2.4).
5. **The release authority's key:** an Ed25519 key kept as a Klav vault item on Omar's Mac, signing with Touch ID through `klav release sign-manifest`, plus an offline backup key; both public halves pinned in `klav-core`.
6. The strict network profile offered on by default with the manifest's egress addresses, and new addresses let in per account before use (§3.5).
7. The quota defaults (§3.3), to be measured during the beta.
8. Hand-written COSE_Sign1 instead of `coset` (§5.1).
9. No six words when an attestation proves the keys (§6.1).
10. The parent's refusal list as the SSRF barrier, ports other than 443 off by default (§1.2).
11. Existing credentials kept when verification fails, with the red row (§6.3).
12. A separate EIF workflow outside the Boat `ci` job (§7.2).
13. Accounts on `api.klav.dev` only: the enclave pins that server and serves no self-hosted server (Q6).
14. `klav-forward` sends the URL's host as SNI from layer 3 (§3.4).
15. Hand-offs gated on the manifest being byte-equal to the one in the public repository (§4.2), and `seed_epoch` in the manifest (§4.4).

### 12. Left for later, not designed here
- KMS sealing (Q3 (b)) and its dependencies.
- A verifiable transparency log for manifests (Rekor or a Klav-run log with witnesses).
- Multi-region and splitting the seed across vendors (Signal's SVR3 idea, ADR 0036 §12).
- ADR 0045's federation signers in the hosted proxy: they are vault items granted to the proxy (0045 §1.3.1), so they work here unchanged once ADR 0045's layers exist.
- Copy detection for sandboxes (ADR 0045 Q8) in the hosted proxy: it arrives with ADR 0038's ratchet, as for any proxy.
- OAuth MCP servers (ADR 0049 §4).

### 13. Not verified (each checked at its layer, which stops if it is false)
- ~~The exact algorithms of AWS's intermediate and leaf certificates~~ **Checked at layer 2:** ECDSA P-384/SHA-384 end to end in two real documents (§14).
- ~~Whether `ciborium` can be made strict~~ **Checked at layer 2:** it can't; `klav-core` has its own strict reader (§14).
- ~~The size added to the Mac and iOS apps (§5.1)~~ **Measured at layer 2** (§14); the DMG cap is the tighter limit.
- NSM attestation latency and rate, for per-account documents on demand; layer 3.
- The enclave's entropy source at boot and its clock; layer 3.
- Whether a 1-vCPU, 2-GiB enclave on `c7g.large` carries the beta; layer 6.
- Reproducibility of the EIF across two runners, and aarch64 runner availability; layer 6.
- The KMS condition-key names and `CiphertextForRecipient`'s envelope (only for Q3 (b)).
- EC2 prices (third-party aggregators).
- Whether one Touch ID or Face ID can cover all the signatures of the set-up-again sheet (§4.4).
- That `raw.githubusercontent.com` serves the default branch reliably enough to gate hand-offs (§4.2); layer 3 adds a fallback mirror only if the hand test shows it is needed.
- ~~Whether ES384 needs `p384`'s `sha384` feature~~ **Checked at layer 2:** `p384`'s `ecdsa` feature turns `sha384` on.
- Whether the server allows one agent public key in two accounts (only for model (b) of §3.1).

### 14. What layer 2 found (2026-11-26)
- **Real documents.** Two attestation documents captured from real enclaves in `us-east-1`, from the test suites of open-source verifiers, were checked against `klav_core::nitro`: one from 2022 (`tkhq/qos`, AGPL-3.0, checked locally and not committed) and one from 2023 (`evervault/attestation-doc-validation`, Apache-2.0, committed under `crates/klav-core/src/nitro/testdata/` and in `docs/vectores/nitro-attestation.json`). Both chain to the pinned Root-G1 and their COSE signatures verify. The 2023 one is a debug-mode enclave (PCR0–2 zero) and is refused as such.
- **What they show that AWS's page doesn't:**
  - the `COSE_Sign1` is **untagged**: §2.2 step 2 now accepts tag 18 or no tag, and no other tag;
  - the absent optional fields are present as CBOR `null`, not missing: both are accepted;
  - 16 PCRs, each 48 bytes;
  - the chain is the root, three intermediates and the leaf, each ECDSA P-384 with SHA-384; the intermediates have `pathLenConstraint` 2, 1 and 0, and `basicConstraints` and `keyUsage` are the only critical extensions; the leaf's `keyUsage` is not critical. The verifier refuses any other critical extension.
- **`ciborium` couldn't be made strict.** Its `Value` decodes indefinite lengths and long-form integers without a trace a caller could refuse (a test shows it). `klav-core` reads the document with its own strict reader of about 150 lines (spec §15.2), so the feature adds only `p384`, `x509-cert`, `der` and `spki`, and `ciborium` stays a dev-dependency. `Cargo.lock` gains `p384` 0.14.0, `x509-cert` 0.3.1, `der_derive` 0.8.0 and `flagset` 0.4.7; `cargo deny check` passes, and `cargo tree -i` finds no `ring`, `openssl` or `serde_cbor`.
- **The release-authority keys are not pinned.** They don't exist yet (§11.5), so `RELEASE_AUTHORITY_KEYS` is empty and every manifest is refused with `no_release_key`. The layer that creates the keys pins them; the tests and vectors use test keys.
- **The derivation's split** (§3.1 says only "HKDF-SHA-256"): 64 bytes of output, X25519 secret first, Ed25519 seed second, the order of `kag1_` (spec §13.2).
- **The hand-off's `info`** is fixed (spec §15.6); the sealed blob, with its version and kind byte, comes with layer 3, and no kind byte is allocated yet.
- **Size.** A release binary that calls the attestation, hand-off and manifest checks and the derivation, built like the Mac app (`lto = "fat"`, symbols stripped), grows by **161 KiB** on `aarch64-apple-darwin` and **160 KiB** on `aarch64-apple-ios`; compressed, by about **85 KiB** (zlib -9) or 65 KiB (xz). That is well under this ADR's 1 MB stop rule. It is **not** under the DMG's headroom: `Klav-0.10.0.dmg` is 24.94 MB of the 25 MB cap (ADR 0027 §5), about 60 KB left, and each binary of the app that turns the feature on adds about 85 KB. Layer 2 turns it on in no binary, so nothing ships bigger today; layer 5 must make room or ask Omar to raise the cap before it turns the feature on in the Mac app.
- **CI.** The workspace build doesn't turn the feature on, so the `test` and `clippy` tasks of `ci.yml` run `klav-core` with `--features nitro-attestation` on their own line.

### 15. What layer 4 found (2026-11-26)
- **The registration mark is layer 3's contract.** Layer 3 derives the service key from the seed (`klav/v1/proxy/hosted-service`, an identity split like the account keys) and marks the registration with `klav/v1/sig/hosted-proxy-registration` over `account_id(16)`, `agent_id(16)`, the agent's Ed25519 and X25519 public keys and `u32_be(generation)`; that label is apart from `klav/v1/sig/hosted-proxy-enroll` (§6.1), which the account signs over other fields. Layer 4 checks the same bytes: `klav_core::crypto::hosted` verifies with the service key's Ed25519 public key, has no feature gate so `klav-server` doesn't compile the attestation crates, and accepts the mark in layer 3's `nitro-attestation.json` (checked by hand on 2026-11-26). The e-mail isn't signed; the server requires it to be the e-mail of `account_id`. When the two layers meet, `nitro::verify_hosted_registration` can call this module, so one verifier remains.
- **`RegisterAgent` is unchanged.** It is built field by field in `klav-sdk` and in `klav-ffi`'s tests, and an added field would break them. The route reads `RegisterHostedAgent`, the same fields plus an optional `hosted: {account_id, generation, signature}`, under `deny_unknown_fields`. Today's bodies parse as before; an older server refuses `hosted` with `400` instead of storing an unmarked agent.
- **One refusal, checked in order.** The signature is checked against `KLAV_HOSTED_PROXY_SERVICE_KEY` before any database read. Then: the e-mail's account must exist, be `account_id`, not be being deleted and be entitled, read under the account row's lock. Every failure, including a server with no key and too many pending requests, is the same `403 forbidden`. No new error code: an older client can't get one it doesn't know. What remains visible is that an e-mail belongs to an entitled account, and only to the holder of the service key: the enclave, which already rate-limits enrolls (§6.1).
- **`AgentMe.hosted_proxy` is `{entitled}`, only for hosted agents.** Every other agent, including the own proxy of an entitled account, gets the answer it got before, byte for byte. `plan` (§3.5) isn't sent until there is a plan to name; the type has no `deny_unknown_fields`, so adding it later breaks nobody. The person's devices read `GET /v1/account/hosted-proxy` (`{entitled}`; an older server answers `404`, as for the MCP gateway's switch) for the sheet of §6.1. `AgentInfo` doesn't show the mark (§9).
- **Migration `0024`** adds `accounts.hosted_proxy` (0/1, default 0) and `hosted_proxy_at`, and `agents.hosted` (0/1, default 0) and `hosted_generation`, which keeps the generation §3.2 puts "in the server's record of the agent".
- **The switch** is `klav-server hosted-proxy enable|disable|ls <email>`, like `klav-server invite`: no HTTP admin API, no migration, no log line, no audit event (§8). Turning it off doesn't revoke the hosted agent; the enclave stops serving the account when it reads `entitled: false`.
- **Operations:** a total loss (§4.4) means a new seed, so a new service key, and `KLAV_HOSTED_PROXY_SERVICE_KEY` on `api.klav.dev` has to change with it before re-enrolled agents can register.

## Omar's answers (2026-11-26)
On 2026-11-26 Omar asked for the hosted proxy himself («si, hagamos A»: build it now in an AWS Nitro Enclave rather than wait or host it without an enclave), and then answered (a) to every question below («si», to "¿todas (a)?"):

- **Q1 (a).** Klav Cloud runs a hosted proxy that holds provider keys inside an attested enclave, for sandboxes and remote MCP profiles, as a later, higher tier, with ADR 0045's signers added when they exist. This overturns ADR 0045's decision 4 (a note there says so).
- **Q2 (a).** A key pair per account, derived from one seed inside the enclave, each registered as that account's ordinary proxy agent.
- **Q3 (a).** The seed only in memory, in two enclaves in two AWS zones that hand it to each other and to a new version after attestation, and only with a manifest already published in the repository. No KMS.
- **Q4 (a).** The dependencies of §5: in `klav-core` behind `nitro-attestation` (never in the extension), and in `klav-proxy` behind `enclave` (Linux only), with a `deny.toml` ignore for `serde_cbor` (RUSTSEC-2021-0127) added when layer 3 adds the NSM crate.
- **Q5 (a).** The Mac keeps its own local proxy for local agents, known only to that Mac; the hosted proxy serves sandboxes.
- **Q6 (a).** Invited beta accounts on `api.klav.dev` first, behind a per-account switch, free during the beta with §3.3's quotas; the price of the higher tier later.
- **Q7 (a).** Two Graviton `c7g.large` instances in two zones of one region near `api.klav.dev`, behind a load balancer.

## Threats
Threat model §5.28. The IDs were assigned at acceptance and follow ADR 0050's T272:

| ID | Threat | Mitigation |
|---|---|---|
| T273 | An image Klav didn't release runs as "the hosted proxy" (a malicious operator, a stolen AWS account) | Devices wrap only after §2.2; the manifest is signed by a key pinned in `klav-core`; peers hand the seed only to approved images on approved roles (§4.2) |
| T274 | A replayed or rolled-back manifest that still lists a revoked image | `seq` watermark and 30-day expiry (§2.4) |
| T275 | A debug-mode enclave (PCRs zero) or an approved image on someone else's instance | Zero PCRs refused; `PCR3` checked against `parent_roles` for hand-offs |
| T276 | The parent reads, alters or replays traffic | TLS terminated inside the enclave for the channel, upstreams and the server; attestation nonces |
| T277 | The parent lies in DNS or routes to internal addresses (SSRF to instance metadata) | Hostname-verified TLS; the parent refuses private and link-local ranges; IMDSv2 only, no KMS rights in v1 |
| T278 | A routing bug lets one account's sandbox reach another's credentials | Per-account derived keys (§3.1); grants wrapped per account |
| T279 | A noisy or abusive tenant exhausts the instance or Klav's egress budget | Per-account quotas inside the enclave, per-IP limits on the parent (§3.3) |
| T280 | Downgrade during a hand-off to an older image with a known bug | No hand-off to an image older than the holder's (§4.2) |
| T281 | Total loss of all enclaves | Two AZs; re-wrap flow (§4.4) |
| T282 | The release authority's key is stolen or misused, and lists an image that leaks the seed | Kept on a device with presence; backup key; enclaves hand the seed over only for a manifest already public in the repository (§4.2), so the rogue entry is visible before it works; devices refuse revoked images in later manifests. Not prevented (residual) |
| T283 | Side channels from the parent with root against token handling | Constant-time primitives; residual |
| T284 | Account-level metadata to the parent (SNI) and to Klav (that the account uses the hosted proxy) | Stated; residual |

**Residual risks** (threat model §7): 109, AWS as root of trust (T273, T283); 110, metadata to the parent (T284); 111, total loss costs a re-wrap and an outage (T281, under Q3 (a)); 112, a released image with a bug (§10); 113, the release authority as a single signer (T282).

## Plan in layers
One branch per layer, stacked with `gh stack`. Omar accepted this ADR on 2026-11-26. Layer 1 is docs only; layers 1 and 2 go in one PR.

| Layer | What | Tests |
|---|---|---|
| 1 | This ADR accepted with Omar's answers; threat model rows and residual risks with real IDs; AGENTS.md's approved dependencies (§5, as answered); glossary (attested proxy, enclave manifest, release authority, PCR, attestation binding, hand-off); README index; roadmap; `docs/features.md` and the "On the way" page | Links and leak grep |
| 2 | `klav-core` `nitro-attestation`: strict COSE_Sign1/CBOR decoding, the chain against the pinned root, ES384, PCR/nonce/timestamp/`user_data` checks, the binding, the manifest and its signature, the per-account derivation, the hand-off seal labels; spec sections and `docs/vectores/nitro-attestation.json` and `enclave-manifest.json` (real documents captured from a test enclave, plus mutated negatives); size measured in the Mac and iOS builds | A real document verifies; each mutation (one bit in payload, signature, a PCR, the chain order, an extra map key, a duplicate key, an indefinite length, an expired certificate, a wrong root, zero PCRs, a stale timestamp, another nonce) is refused; manifest rollback refused; `klav-wasm` builds without the feature |
| 3 | `klav-forward` sending the URL's host as SNI; `klav-proxy --features enclave` and `klav-nitro-parent`: NSM attestation on demand, vsock in and out, the parent's egress refusal list, SNI routing to per-account keys, multi-account state, quotas, the in-RAM store with replication, peer hand-off and upgrade; enroll endpoint | Linux CI with a fake NSM (test CA) and two enclave processes: hand-off works only between approved images, never downgrades and never uses an unpublished manifest; an older `klav-forward` fails closed against the hosted proxy and still works with a self-hosted one; account A's channel never reaches B's grant; each quota trips; the parent refuses `169.254.169.254` and private ranges; nothing secret in any log |
| 4 | `klav-server`: `hosted_proxy` entitlement in `AgentMe`, the enroll marker, the admin switch; "safe with older clients" review | Older proxy and clients unaffected; a non-entitled account gets nothing from the enclave |
| 5 | `klav-client`, `klav-cli`, `klav-ffi`, Mac and iOS: `klav proxy use klav`, the verification before every wrap, `ProxySetting` accepting `klav` with `agent_id`, the status row, the red row and "Stop using it", the re-wrap flow, Q5's local choice, `apps/docs` | A forged manifest, a stale one and a revoked image each block wrapping; an older client refuses the mode with its message |
| 6 | `deploy/nitro/`: reproducible EIF, `eif.yml` with the double build, `verify-release.sh`, Terraform for two `c7g.large` in two AZs behind an NLB, the runbook; then a hand test: a Boat sandbox with `northflank` and Maple's MCP through the hosted proxy, a rolling upgrade with no failed call, and a forced total loss followed by re-wrap | Two runners give the same PCRs; the hand test's evidence in the PR |

## Consequences
- **Klav Cloud gets a 24/7 proxy** that the person enables in one step, whose trust rests on AWS and on published, reproducible code, not on Klav's staff.
- **New formats:** the manifest and its signature label, the binding label, the enroll signature label, the hand-off label, the per-account derivation label; with spec sections and vectors. `ksb1_`, `0x23` and the grants don't change.
- **New dependencies:** §5, behind features that the extension never builds.
- **A new piece of Klav infrastructure on AWS**, separate from Railway, with its own on-call reality: a total loss under Q3 (a) asks every person to re-wrap.
- **New metadata:** which accounts use the hosted proxy (server), and account SNI plus upstream hosts (parent).

## Questions for Omar
Each lists the options; (a) is the recommendation. **All answered (a) on 2026-11-26** (above).

- **Q1. Should Klav Cloud run a hosted proxy that holds people's provider keys (bearer API keys and MCP keys) inside an attested enclave?** On 2026-11-18 you decided the opposite for any hosted proxy: "only per-customer signers, never provider keys" (ADR 0045, decision 4). The brief for this ADR says you now want the hosted sandbox and MCP proxy. What changes if you say yes: with signers only, a breach of the enclave yields tokens that expire in minutes and that each customer cuts off at their provider without Klav (ADR 0045 §1.9). With provider keys, the same breach yields long-lived keys that keep working until each customer rotates them at each provider, and nobody at Klav can rotate them for them.
  - (a) **Yes, for sandboxes and remote MCP profiles, as a later and higher tier (D-86c244), with ADR 0045's signers added when they exist.** *Recommended:* only an enclave the devices verify ever gets a key, so ADR 0036's answer 10 still holds, and signers alone would cover only Anthropic today (ADR 0045 §1.2). The breach cost above is the price.
  - (b) Signers only, as decided on 2026-11-18: the hosted proxy waits for ADR 0045 and serves almost no provider.
  - (c) Keep it on the waitlist; no hosted proxy work now.
- **Q2. How does one enclave serve many accounts?**
  - (a) **A key pair per account, derived from one seed inside the enclave, each registered as that account's ordinary proxy agent.** *Recommended:* pause, revocation, the network alarm and the audit work per account as today, and a bug that mixes up accounts still can't open another account's credentials.
  - (b) One key pair for every account, with separate grants. Simpler attestation, but every account depends on routing code being right, and one reset re-shares everyone's credentials.
- **Q3. How does the enclave keep its keys across restarts and new versions?**
  - (a) **Only in memory, on two enclaves in two AWS zones that hand the keys to each other, and to a new version, after checking it is a release you signed and published in the repository.** *Recommended:* the only way to the keys is your release key, and only by publishing a manifest everyone can see first; there is no AWS-account or AWS Support path. The cost: if both enclaves die at once, every person must set Klav Cloud's proxy up again on a device (one sheet that re-shares their credentials and re-signs their sandbox issuers), and their sandboxes fail until they do.
  - (b) Also sealed with AWS KMS under a key whose policy the enclave writes and locks. Restarts recover alone, but the AWS account owner can ask AWS Support to unlock the policy, which the enclave notices only afterwards, and it adds RSA, AES-CBC and a CMS parser to `klav-core`.
  - (c) A KMS policy that Klav edits to add each new version. Simplest, but anyone with admin rights in Klav's AWS account could unseal silently. Not recommended.
- **Q4. Do you approve these dependencies?** (§5)
  - (a) **In `klav-core`, behind `nitro-attestation` (never in the extension): `p384` 0.14.0, `x509-cert` 0.3.1, `der` and `spki` 0.8 as direct dependencies, and `ciborium` 0.2 moved from dev-only to normal. In `klav-proxy`, behind `enclave` (Linux only): `aws-nitro-enclaves-nsm-api` 0.5.2 with a `deny.toml` ignore for its unmaintained `serde_cbor` (RUSTSEC-2021-0127), and `tokio-vsock` 0.7.3 with `vsock` 0.5.5.** *Recommended:* all permissive, no `ring` or `openssl`, `cargo deny` clean apart from that one notice; AWS maintains the NSM crate.
  - (b) The same, but talk to `/dev/nsm` with Klav's own few lines of `unsafe` under a new exception like `klav-ffi`'s, avoiding `serde_cbor`.
  - (c) Only the `klav-core` part now; the enclave's crates come back with layer 3.
- **Q5. With Klav Cloud's proxy on, how do the coding agents on your Mac reach MCP servers?** ADR 0049 sends them to a proxy on the Mac itself.
  - (a) **The Mac keeps its own local proxy for local agents, known only to that Mac (no new account setting); the hosted proxy serves sandboxes. "Use Klav Cloud Proxy" in MCP servers offers both.** *Recommended:* local agents keep the fastest path with no third party in the middle, and no format changes.
  - (b) A forwarder on the Mac sends local agents' MCP calls to the hosted proxy. One proxy, but your Mac's calls go through AWS, and it needs a new design.
  - (c) The hosted proxy is for sandboxes only; Mac agents stay as they are and the MCP servers button doesn't offer it.
- **Q6. Who can use it first?**
  - (a) **Invited beta accounts on `api.klav.dev`, behind a per-account switch on the server, free during the beta with the quotas of §3.3; the price of the higher tier decided later.** *Recommended:* real use sizes the quotas and the instances before anyone pays.
  - (b) Only paid accounts, from the day it opens.
  - (c) Also accounts on self-hosted servers. More reach, but the enclave would have to trust servers it doesn't know.
- **Q7. Where does it run at the start?**
  - (a) **Two Graviton `c7g.large` instances in two zones of one AWS region near `api.klav.dev`, behind a load balancer, about $106 a month on demand or about $70 with a one-year plan, plus traffic.** *Recommended:* the cheapest instances AWS allows enclaves on, and two zones are what Q3 (a) needs. The x86 sizes in the brief (`c6a.large`, `c6i.large`, `m6i.large`) are not allowed for enclaves.
  - (b) One instance (about $53, or $35 with a plan). Only coherent with Q3 (b): under (a), every restart would ask everyone to re-share.
  - (c) x86 `c6a.xlarge` instances, about twice the price, if an x86 build matters more than cost.

## Stop rules
- **Layer 2 stops** if AWS's chain uses anything but ECDSA P-384, if `ciborium` can't be made strict, or if the feature adds more than 1 MB to the Mac or iOS app; each comes back here.
  - *2026-11-26, layer 2:* the chain is ECDSA P-384 end to end and the feature adds 160–161 KiB (§14), so those two didn't stop it. `ciborium` couldn't be made strict; layer 2 went on with a strict reader of its own in `klav-core`, the alternative §13 named, and it is Omar's to confirm (§14). The 1 MB rule passes, but the DMG's cap does not leave room for it (§14, layer 5).
- **Layer 3 stops** if the NSM crate can't be used without features beyond §5.2, or if the enclave can't seed its RNG from the NSM at boot.
- **Layer 6 stops** if two independent builds disagree on any PCR; nothing is listed in a manifest before they agree.
- **No layer merges before Omar accepts this ADR and approves §5's dependencies.**
