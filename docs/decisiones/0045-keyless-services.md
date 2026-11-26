# 0045 · Deployed services without a provider key where the provider allows it: the proxy signs a workload identity, and a key with limits elsewhere

- Status: Accepted (2026-11-18), not built. Omar decided the direction on 2026-11-18 («si, vamos con tus recomendados», to a list the coordinator wrote) and the same day answered Q1–Q11 (the owner's decisions, below). He took the recommended option in each except Q8, where he chose to give sandboxes the services' copy detection. No question is left open; §12 lists what this ADR chose on its own so he can overturn it. Accepting it doesn't schedule ADR 0038: deployed services are not launch work, and when its work starts is Omar's call. Q8's sandbox work is built with them, not before
- Date: 2026-11-18
- Amends: [ADR 0038](0038-deployed-services.md) (a dated note there: the definition, the enrollment token, the lease and the pause carve-out). Adds dated notes to [ADR 0036](0036-sandboxes-de-agentes.md) §5 and §12. Builds on [ADR 0044](0044-proxy-key-at-rest.md) (accepted, not built), whose §12 left three points to this ADR (§10 here)
- Does not touch: ADR 0043 (PR #445, sandbox mode (b)), which the roadmap now names as the first work after launch (decision 8)

## Context

### What Omar wants, in his words (2026-11-18, translated)
- "that my proxy is dumb: it never has anything stored in plain text";
- "that I'm not the leak point now";
- "that you could rotate your envs without redeploying and without shutting down your services";
- and, on why services at all: "the fact that your services keep running".

### Two limits that no design here removes
1. **A provider that authenticates with a bearer key receives that key whole.** Whatever Klav does, some machine assembles the bytes that go in the `Authorization` or `x-api-key` header, and whoever controls that machine while it does so can copy them. Today that machine is the person's proxy (ADR 0036 §2; ADR 0038 §7.2). Splitting the key across machines so that none of them holds it whole needs multi-party TLS, which is rejected below (§11).
2. **No home-made cryptography** (`CLAUDE.md`). The only way to stop handing out a long-lived secret is a mechanism the provider already offers. Where one exists, it is workload identity federation: the provider trusts a signer, and the signer's assertion buys a short-lived token.

So the design has two paths. **The federation path** removes the long-lived provider key from the proxy for providers that accept a signed identity. **The bearer path** keeps ADR 0038 as it is for the others and sets every limit the provider offers on the key.

### What ADR 0038 does today, read at `fee28baa`
- **The proxy holds the provider key,** decrypted in its memory while the service's leases keep renewing (`docs/decisiones/0038-deployed-services.md:410`), and reads it again when the item's `version` moves (0038:409).
- **A provider key already rotates without a redeploy:** the person saves the new value in Klav and the proxy reads it within one renewal (0038:409, 0038:464).
- **The enrollment token does not:** `klav service token rotate` signs a new definition, but "only new enrollments need the new token", and the PaaS brings the new variable "with a redeploy" (0038:116, 0038:188).
- **The `kse1_` token pins a hash of the proxy's key** (0038:110). No ADR says how a change or loss of that key reaches running instances.
- **Approvals exist for** signing the service definition (0038:100), rotating the enrollment token (0038:116), each enrollment during incident mode (0038:440–457) and resuming (0038:484–487). There is no approval per deploy, and a service's profiles have no `ask` (0038:377–382).
- **A global pause leaves a service's item reads open** (`POST /v1/agent/access` for a service, 0038:610).

### What the providers offer, checked on 2026-11-18
I opened each page below on 2026-11-18. Where only a summary of the page came back, the citation says so.

**Anthropic, workload identity federation.** Pages: [WIF reference](https://platform.claude.com/docs/en/manage-claude/wif-reference), [Workload Identity Federation](https://platform.claude.com/docs/en/manage-claude/workload-identity-federation), [Manage WIF with the Admin API](https://platform.claude.com/docs/en/manage-claude/wif-admin-api).
- **The exchange:** `POST /v1/oauth/token` with the RFC 7523 `jwt-bearer` grant, the `assertion`, `federation_rule_id`, `organization_id`, and `workspace_id` when the rule covers more than one workspace. The answer is a bearer `sk-ant-oat01-…` for `Authorization: Bearer`.
- **The assertion:** "only asymmetric algorithms (RSA and ECDSA families: ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512)". EdDSA is not in the list, and Klav's device and agent keys are Ed25519. The header needs a `kid` in the issuer's JWKS; `sub`, `iat` and `exp` are required; "An assertion that carries a `jti` claim can be exchanged only once for each issuer" (`check_jti`, on by default); `exp − iat` may not exceed the issuer's maximum, "1 hour by default"; 30 s of clock leeway; at most 16 KiB.
- **The issuer's keys:** `discovery`, `explicit_url` or `inline`. With `inline`, "Anthropic makes no outbound request" and compares `issuer_url` with `iss` as a string, so it "may reference an internal hostname". "In `inline` mode there is no automatic key refresh."
- **The rule:** must match on at least one of `subject_prefix` (exact, or a prefix with a trailing `*`), `claims` or a CEL `condition`, and may also require an exact `audience`. A rule binds the issuer to one service account, an `oauth_scope` and a workspace. `workspace:inference` covers Messages, Models and the OpenAI-compatible chat endpoint.
- **The minted token's lifetime:** the rule's `token_lifetime_seconds` is 60 to 86,400, default 3,600; the minted lifetime is "the lesser of (a) the rule's `token_lifetime_seconds` … and (b) twice the remaining lifetime of the IdP JWT you presented", "never less than 60 seconds".
- **Automation:** the federation endpoints of the Admin API need "an OAuth bearer token that carries the `org:admin` scope" and "do not accept Admin API keys". The bootstrap rule for an automated admin "must" be created in the Console.
- **Stopping it:** a rule, an issuer or a service account can be archived. What happens to tokens already minted when one is archived is **not stated**. No endpoint to revoke a minted token is described.
- **Status:** the federation pages carry no beta mark that I saw; not stated either way.

**Anthropic, IP allowlist** ([page](https://platform.claude.com/docs/en/manage-claude/ip-allowlist)): beta; one list "covers your entire organization"; up to 1,000 entries, no broader than `/8` (IPv4) or `/32` (IPv6); covers Messages, Batches, Token Counting, Models, Files and Skills "with an API key or a Workload Identity Federation token"; "Changes can take up to 15 minutes"; and "If you add a shared proxy address, note that an attacker with a leaked key … could potentially use it through the proxy". `POST /v1/oauth/token` is not among the listed endpoints, so whether the exchange itself is covered is **not stated**.

**Anthropic, key expiration** ([Authentication](https://platform.claude.com/docs/en/manage-claude/authentication)): a key gets "a preset (3 hours, 1 day, 7 days, or 30 days), a custom duration, or **Never**" when it is created in the Console, and "cannot be changed afterward". Service account keys stop working when the service account is archived.

**OpenAI, workload identity federation** ([guide](https://developers.openai.com/api/docs/guides/workload-identity-federation), opened 2026-11-18, page summary only): OIDC JWTs, SPIFFE JWT-SVIDs, and X.509 for the API; an uploaded JWKS is supported. OpenAI then does no discovery. **Not stated** on that page: the accepted algorithms, the exchange endpoint and grant, the token's lifetime range, and revocation. So whether ES256 is accepted is not confirmed, and OpenAI stays on the bearer path until it is.

**OpenAI, IP allowlist** ([guide](https://developers.openai.com/api/docs/guides/ip-allowlist), page summary only): per project or per organization, the project's list taking precedence; "up to 50 individual IP addresses or CIDR ranges"; up to 15 minutes; refused requests get `401` `ip_not_authorized`. Whether it covers federation tokens is not stated.

**OpenRouter** ([provisioning API keys](https://openrouter.ai/docs/features/provisioning-api-keys), page summary only): keys created by API (`POST /api/v1/keys`) with a Management API key, with an optional credit `limit` and a `limit_reset` (daily, weekly, monthly). The page says neither "USD" nor an expiry for those keys.

**Not confirmed, so not used:** federation at Google Vertex, AWS Bedrock and Azure; the absence of federation at Mistral, Groq, Stripe, GitHub, Cloudflare, Supabase and Neon; OpenAI's spend limits; Stripe's restricted keys with IP policies; Cloudflare tokens with `request.ip` and expiry; which platforms give a running service an OIDC token (ADR 0038 already cites Fly's, 0038:53). They came from search snippets that I did not open.

## The owner's decisions (2026-11-18)

### The direction
Omar answered «si, vamos con tus recomendados» to a list the coordinator wrote. The ADR records the items as given, translated:

- **Decision 2. Owner's decision (2026-11-18).** "Direction for services: a signed identity where the provider accepts it, a key with limits where it doesn't." (§1, §2.)
- **Decision 3. Owner's decision (2026-11-18).** "Who signs: the proxy, for services." He was told that a person's device signing instead is a dial: the proxy then holds no signer, but with the phone off for longer than a token's life the service goes down. **A device signing for sandboxes was mentioned only as "could come later". It is not decided** (§10).
- **Decision 4. Owner's decision (2026-11-18).** "A proxy hosted by Klav: out of launch, it stays on the waitlist." He was told that if it is ever built, the enclave should hold only a per-customer signer, never provider keys (§5). *(Overturned for sandboxes and MCP on 2026-11-26 by ADR 0051, Q1 (a); note in §5.)*
- **Decision 5. Owner's decision (2026-11-18).** "Approval per deploy: configurable per service, off by default." (§4.)
- **Roadmap only, no design here:**
  - decision 6: "secrets that aren't HTTP in sandboxes: out of launch; afterwards, databases through the proxy";
  - decision 7: a session hook and an offered block for `AGENTS.md` and `CLAUDE.md`, which belongs to the environments work (ADR 0032);
  - decision 8: "`HTTPS_PROXY` mode: the first thing after launch", which is ADR 0043 (PR #445).

### The answers to Q1–Q11
Omar answered each question with the options the ADR gave. The questions as they were asked are at the end. The answers are keyed by question, so the numbered decisions above keep their numbers.

- **Q1. Owner's decision (2026-11-18). `klav-core` signs the services' identity assertions with ECDSA P-256 (ES256), with the `p256` and `ecdsa` crates already approved for passkeys** (Q1 (a)). It is a new approved use of approved crates: the same versions and features, with its own vectors. `CLAUDE.md`'s list of approved dependencies gains the entry, written as ADR 0020's (§1.3).
- **Q2. Owner's decision (2026-11-18). A service's signing key is a vault item granted to the proxy, never on its disk** (Q2 (a)). It is made on the person's device and read by the proxy through the Klav server (§1.3.1).
- **Q3. Owner's decision (2026-11-18). The provider key and the signing key both stay decrypted in the proxy's memory while the service's leases renew** (Q3 (a)) (§1.3.2).
- **Q4. Owner's decision (2026-11-18). The person pastes the signer's public key into the provider ("inline")** (Q4 (a)). Klav prints it; no server Klav runs and no host the proxy runs on can add a key the provider trusts (§1.5).
- **Q5. Owner's decision (2026-11-18). The enrollment token pins the account's identity, and the person's devices sign which key is the proxy's current one** (Q5 (a)). A new proxy key needs the person's signature, not a redeploy. He was told the limit: a freshly started instance can't tell an older signed key from the newest. §3.1 designs it, and §7 says what bounds the limit. On 2026-11-18 he was told the corrected limit (the window lasts until the service's PaaS variable holds a token rotated after the key change, not until the token is rotated in Klav) and confirmed (a), declining again (b) of a token that pins a hash of the proxy's key, which has no window but leaves every service unable to enroll after each proxy key change until its variable is updated.
- **Q6. Owner's decision (2026-11-18). After a rotation of the enrollment token, the old one is also accepted for 24 hours, except after an incident** (Q6 (a)) (§3.2). Q11 adds a second exception.
- **Q7. Owner's decision (2026-11-18). With approval per deploy on, one card per service lists every instance waiting, and "Approve all" approves them with one Face ID or Touch ID** (Q7 (a)). No new signed message (§4.3).
- **Q8. Owner's decision (2026-11-18). Sandboxes get the copy detection that deployed services get, in the same work as the services** (Q8 (b)). This is the one answer where he didn't take the recommendation, which was "not for launch". It is not launch work either: it is built when ADR 0038's ratchet is built, reusing it. Until then, ADR 0036 §5's acceptance of a copied sandbox stands (§10.1, and a dated note in ADR 0036).
- **Q9. Owner's decision (2026-11-18). During "Pause agents", a deployed service's proxy keeps reading its keys,** the signing key included, as decided on 2026-11-09 (Q9 (a)). The new-network alarm and the strict profile of ADR 0044 still apply to the proxy (§10).
- **Q10. Owner's decision (2026-11-18). A minted token lives 10 minutes by default** (Q10 (a)). The person can change it per service, from 1 minute to 1 hour (§1.6).
- **Q11. Owner's decision (2026-11-18). A rotation of the enrollment token asks "did the old token leak?", and with yes the old token stops at once,** as after an incident (Q11 (a)). He was told it lets him cut a known leak without turning on incident mode, and that it needs no new signed message (§3.2).

Everything below that isn't one of these sentences is design.

## Decision

### 1. The federation path: the proxy is an OIDC issuer for the person's own provider organization

#### 1.1 What changes, in one line
The proxy no longer holds the service's provider key. It holds a **signer**: a P-256 key whose public half the person registered at the provider. For each enrolled instance, the proxy signs a short **assertion**, trades it at the provider for a **minted token**, and injects that token. The provider decides what the token can do (its rule), and the person can stop it there without Klav.

#### 1.2 Which providers the first version covers
**Anthropic only,** because it is the only one whose accepted algorithms, exchange and lifetimes I confirmed on its pages (§Context). A provider joins when a page states that it accepts ES256 with keys the person uploads, and its exchange. Every other provider stays on the bearer path (§2).

#### 1.3 The signer
- **One signer per service, not per proxy.** Any key of an issuer can sign any `sub`, so a per-proxy signer would let a copy of it mint for every service. With one signer and one issuer per service, a copy reaches one service.
- **ES256 (ECDSA P-256 with SHA-256),** because Anthropic accepts no EdDSA (Q1). `klav-core` already has `p256` 0.14 and `ecdsa` 0.17 for passkeys (`crates/klav-core/Cargo.toml:30`, `:39`; `crates/klav-core/src/crypto/passkey.rs:21-23`). No new crate.
- **The signing function** lives in `klav-core` (`crypto::federation::sign_assertion`), so no other crate implements it. It returns a JWS compact serialization with the raw 64-byte `r ‖ s` signature that JWS asks for, not DER. Whether `p256`'s current features give the JWK's `x` and `y` without another feature is not checked; layer 2 checks it and stops if one is needed (Q1 approved the same features as passkeys).

#### 1.3.1 Where it lives: a vault item granted to the proxy (Q2)
Checked in the code at this ADR's base:
- **The item type: an API key, `ItemKind::ApiKey`** (`crates/klav-core/src/model/item.rs:89`). No new item type, so no new format comes back to Omar. Its default fields (`item.rs:496-501`) carry what the signer needs:
  - `api_key`, concealed: the private key, as the base64url of its PKCS#8 DER. `p256` is built with `pkcs8` (`crates/klav-core/Cargo.toml:39`), and `klav-core` already reads PKCS#8 DER for passkeys (`passkey.rs:23`, `:127-128`);
  - `key_id`, text: the `kid`, the RFC 7638 thumbprint of the public JWK.

  The exact encoding of the field's value goes in layer 2's spec section, with vectors.
- **The grant carries it unchanged.** A granted item has no type in the grant (`GrantedItem`, `crates/klav-proto/src/agent.rs:246-257`): the item key is sealed for the proxy like any other (`0x23`).
- **It is made on the person's device.** `klav service federation setup` (§1.5) generates the key in `klav-core`, saves the item in the service's project, and grants it to the proxy in the same signed definition. The proxy never generates one, and nothing writes it to the proxy's disk.

**What Q2 forces that ADR 0038 didn't write:**
1. **The signer is an item with no profile.** Today every item in a proxy grant comes with a profile that puts it in a header (`crates/klav-client/src/proxy_admin.rs:597-640` builds them together). The service's definition gains `federation.signer_item`, which names one of the grant's `items`. **No profile may use that item:** the proxy refuses a definition where one does, so the private key can never go out in a header.
2. **The read has no host, method or path.** The proxy reads the signer with `POST /v1/agent/access`, `permission: proxy` and the `service` field ADR 0038 adds (0038:409), with empty `claims`. The server admits a read without claims only for the item the service's signed definition names as `federation.signer_item`, and logs it as an `agent.access` with the service, like a provider key's read.
3. **The lease answer and the pause cover it.** ADR 0038's lease answer brings the `version` of "each item the service's profiles use" (0038:405), and the pause carve-out lets through reads of "the items that its services' profiles use" (0038:609-610). Both now include the signer item, so a rotated signer reaches the proxy within one renewal, and a proxy that restarts during a pause can read it (Q9).
4. **It never leaves the proxy's memory.** Not in the store, not in an event, not in `klav-proxy status`, not in an error.

#### 1.3.2 How long it stays in memory (Q3)
- **The signer and the provider key both live decrypted while the service's leases keep renewing,** each in a `SecretBox`, as ADR 0038 already does for the provider key (0038:410).
- **They are zeroed** when the lease ends without renewal, when the grant changes, when a newer version replaces them, when the service is stopped, or, for the signer, when the definition names another one.
- **Read once:** the first time the service needs it and again when the lease shows a newer `version`: one logged read each time, never one per signature.
- **The memory is protected by ADR 0044 §3** (no swap where the host allows the lock, no core dumps, not dumpable on Linux), which therefore ships first. Whether `p256`'s signing key zeroes itself on drop is not checked; layer 4 checks it and wraps it if not.

#### 1.4 The assertion
A JWT, made by the proxy for one enrolled instance identity (ADR 0038 §5.1):

| Field | Value |
|---|---|
| header `alg` | `ES256` |
| header `kid` | the RFC 7638 thumbprint of the signer's public JWK |
| `iss` | `https://klav-issuer.invalid/s/<service_id hex>`: fixed per service, never fetched (§1.5) |
| `sub` | `klav:service:<service_id hex>:instance:<identity_id hex>` |
| `aud` | the provider's audience string, which the rule requires exactly (`https://api.anthropic.com` for Anthropic) |
| `iat` | now |
| `exp` | `iat` plus half the minted token's configured lifetime (§1.6) |
| `jti` | 16 random bytes, base64url |

- **`sub` names the service and the instance,** so the provider's history of exchanges says which instance asked. The rule matches the prefix `klav:service:<service_id hex>:instance:*`.
- **`aud`** keeps an assertion meant for one provider from being exchanged at another that trusts the same key.
- **`jti`** makes each assertion single-use at Anthropic (`check_jti`, which the person leaves on).
- **The format carries a version** in its own field: `"klav_v": 1`, a private claim the rule ignores. The spec section and vectors (`docs/vectores/federation-assertion.json`) come with layer 2.
- **The `.invalid` issuer** relies on Anthropic's statement that in inline mode it compares `issuer_url` as a string. Registering one is not checked: layer 2 stops if a test registration on a throwaway organization refuses it, and comes back here.

#### 1.5 How the person registers the issuer and the rule
- **Klav can't do it for them.** The Admin API's federation endpoints need an `org:admin` OAuth token and refuse Admin API keys (§Context). The proxy must never hold an organization admin token: it would be a key worth more than the one it replaces.
- **`klav service federation setup <service>`** on the person's device makes the signer (§1.3.1) and prints, with no secret in it:
  - the issuer: `issuer_url` and the public JWK, as `inline` keys (Q4);
  - the rule: `subject_prefix`, `audience`, `oauth_scope: workspace:inference` and `token_lifetime_seconds` (§1.6);
  - the equivalent `ant organization:federation:issuers create` and `…:rules create` commands, for a person who runs them in their own shell with their own admin login.
- **The person creates them in the Console or with `ant`,** then gives Klav four IDs: organization, rule, workspace and service account. They go into the service's signed definition, next to `federation.signer_item`. The server sees them in clear, like the rest of the definition (0038:104, residual risk 68).
- **Inline keys (Q4):** nobody but the person can add a key the provider trusts. The cost: changing the signer means pasting the new key, in two steps (§3), which the app walks through.

#### 1.6 The minted token's lifetime: a setting
- **`token_lifetime`** in the service's federation settings, signed in the definition: from 60 s to 1 hour, **10 minutes by default** (Q10), the value Anthropic's own wizard prefills.
- **Klav enforces it from its side** through `exp`: Anthropic mints for the lesser of the rule's lifetime and twice the assertion's remaining life, so an assertion that lives exactly half the setting, exchanged at once, caps the token at the setting whatever the rule says. At the 60 s minimum the assertion lives 30 s, within Anthropic's 30 s leeway. Klav still prints the same value for the rule.
- **The trade-off:**

  | Shorter | Longer |
  |---|---|
  | A stolen minted token works for less time (no revocation is documented, §1.9) | Fewer exchanges, so fewer round trips and fewer entries in the provider's history |
  | An outage of the provider's token endpoint hurts sooner | The service rides out a longer outage of the token endpoint |

  At the default, the proxy renews about 7 times an hour per instance (§1.7).

#### 1.7 Where the minted token lives, and for how long
- **Only in the proxy's memory,** in a `SecretBox`, one per enrolled identity. Never in the store, never on disk, never in an event.
- **Refreshed at 80 % of its life,** with a fresh assertion and a fresh `jti`. A failed refresh retries with backoff until the token has 30 s left, then the identity's calls get `503` with `Klav-Error: klav_provider_token_unavailable` and the provider's error (never the token) in the message.
- **Dropped at once** when its identity is frozen, retires or expires, when the service is stopped, when the lease lapses (0038:408), or when the signer changes. Dropping it at the proxy does not end it at the provider (§1.9).
- **Injected as `Authorization: Bearer`.** The `anthropic` preset of ADR 0038 injects `x-api-key` (0038:355); a federated service's profile injects the bearer instead, and removes any `Authorization` or `x-api-key` the app sent, as profiles already do for their header.

#### 1.8 What a copy of the proxy's disk yields
The proxy's agent key stays plaintext at rest (ADR 0044 §10). Its copy is the starting point of every row. The signer is not on the disk (Q2).

| With | What the copy yields |
|---|---|
| ADR 0044's measures off, or the alert profile | The agent key, which reads the signer through the server. Each read is logged as the proxy's own `agent.access` (ADR 0044, Context: a value comes only from a logged call), and under the alert profile a read from a new network raises the alarm |
| ADR 0044's strict profile | The read is refused from any network the person didn't sign, and the person is told at once |
| Plus the provider's IP allowlist on the proxy's egress | Minted tokens are refused from outside the list on the covered endpoints. Whether the exchange itself is refused is not stated |

Compared with today's bearer key, the signer is worth less to a thief: its tokens are limited by the rule (one workspace, `workspace:inference`), they expire, and the person cuts it at the provider without Klav. Kept in the vault, it also keeps "nothing stored in plain text" true for the signer. It doesn't for the agent key, which ADR 0044 §10 leaves plaintext.

#### 1.9 Revocation, at the provider, without Klav
- **Stop new tokens:** archive the rule, or update the inline issuer without the signer's key. Both are the person's action in the Console or with `ant`; neither needs Klav or the proxy.
- **Tokens already minted:** what archiving does to them is not stated, and no revocation endpoint is described. Klav assumes the worst: a minted token lives out its lifetime, at most the `token_lifetime` of §1.6. That is why the default is 10 minutes (Q10).
- **The allowlist** limits where a stolen minted token works, on the covered endpoints.
- **Inside Klav,** freezing an identity, stopping the service or incident mode drop the proxy's tokens (§1.7) and stop new mints; they don't reach a token already copied.

#### 1.10 What the federation path does not change
- **The minted token is still a bearer that the proxy assembles.** Whoever controls the proxy while it runs uses it, as today with the provider key (limit 1). What changes is that it expires in minutes and is scoped by the provider.
- **The proxy still sees prompts and responses** (0038 §12, limit 6).
- **The enrollment, the ratchet, the lease, incident mode and the usage record** of ADR 0038 stay as they are, except for the enrollment token's two changes in §3.

### 2. The bearer path: providers with no federation
- **What ADR 0038 already does stays:** the key lives in the vault, the proxy reads it through the lease, keeps it in memory while leases renew (Q3), and a new version reaches the proxy without a redeploy (0038:409).
- **What this ADR adds: the limits the provider offers, set on the key.** `klav service add` shows a checklist per provider, only from confirmed pages, and the service's page in the apps keeps it:

  | Provider | Limit | Source (opened 2026-11-18) |
  |---|---|---|
  | Anthropic | IP allowlist with the proxy's egress, for the whole organization; up to 15 minutes to apply | [IP allowlisting](https://platform.claude.com/docs/en/manage-claude/ip-allowlist) |
  | Anthropic | An expiry set when the key is created, and a service account key rather than a workspace key | [Authentication](https://platform.claude.com/docs/en/manage-claude/authentication) |
  | OpenAI | A project IP allowlist (up to 50 entries) on the project the key belongs to | [IP allowlist](https://developers.openai.com/api/docs/guides/ip-allowlist) (summary) |
  | OpenRouter | A credit `limit` with a `limit_reset`, on a key created for that service | [Provisioning API keys](https://openrouter.ai/docs/features/provisioning-api-keys) (summary) |

- **An allowlist only works with a fixed egress.** ADR 0044 §2.4 says when a proxy has one: a VPS with a fixed address, not a PaaS with shared egress. The checklist says so, and Anthropic's own warning about a shared proxy address applies.
- **Child keys made by API** (OpenRouter's management key, for example) would let the proxy mint a key per service, but the proxy would then hold the management key, which is worth more than the key it replaces. Not in this design; it would need its own decision.
- **Not confirmed, so not in the checklist:** OpenAI's spend limits, Stripe, Cloudflare, Google, AWS and Azure. Each joins with its page.

### 3. Rotation without a redeploy, key by key

| Key | Without a redeploy? | How |
|---|---|---|
| A provider key (bearer path) | Yes, today | Saved in Klav; the next lease shows the new `version` (0038:409, 0038:464) |
| A minted token | Yes, by itself | Every `token_lifetime` (§1.7) |
| The signer | Yes, in two steps | The person makes a new signer on a device; Klav prints its JWK; the person adds it to the inline issuer **next to** the old one; then a newly signed definition names the new item, and the proxy reads it through the next lease (§1.3.1); then the person removes the old key from the issuer. The app's card walks through the steps and doesn't sign the new definition before the person confirms the first |
| The provider's rule or service account | Yes | At the provider; the four IDs in the definition change with a newly signed definition |
| The enrollment token `kse1_` | Enrolled identities: never affected. New instances: they need the new variable, which the PaaS brings with a redeploy, but for 24 hours the old one still works (§3.2, Q6), unless the rotation came after an incident or the person said the old token leaked (Q11) | §3.2 |
| The proxy's own key | **Yes** (Q5) | The person signs the new key on a device; running and new instances accept it (§3.1) |

#### 3.1 The proxy's own key: the account signs which one is current (Q5)
ADR 0038's token pinned a hash of the proxy's key (0038:110). Nothing of ADR 0038 is built, so the token changes before it exists:

```
kse1_ = "kse1_" ‖ base64url(0x01 ‖ service_id(16) ‖ secret(32) ‖ account_identity_pub(32) ‖ u64_be(floor_at_ms) ‖ len ‖ url)
```

- **`account_identity_pub`** replaces `SHA-256(proxy SPKI)`: the account's Ed25519 identity public key, the one that signs grants and pauses. Agents already pin it and refuse a change (ADR 0014, point 4). Whether any flow changes an account's identity key is not checked here; if one does, every service needs a new token, as every agent needs pairing again.
- **`floor_at_ms`** is the `at_ms` of the proxy-key statement in force when the token was made or rotated. An instance never accepts an older statement (§7 says why).

**The proxy-key statement:**

```
message = tuple("klav/v1/sig/service-proxy-key", account_id(16), proxy_agent_id(16), u64_be(at_ms), SHA-256(proxy SPKI)(32))
```

- Signed by the account identity on a person's device, **with Touch ID or Face ID** (on Linux, the master password): it gives a key the right to serve every service, which is widening.
- Signed when the account's first service is added, for the proxy in use, and again whenever the proxy's key changes (pairing a new proxy, or a new key for the same one). An account without services never signs one.
- The server keeps the newest per proxy and hands it out in the lease answer; it goes in the audit chain with ADR 0038's other account-signed service states (0038 §9.3), so no older verifier meets it on an account without services.
- **The proxy presents its newest statement** when an instance opens the channel. `klav-forward` checks:
  1. the signature, by the `account_identity_pub` of its token;
  2. that the SPKI hash is the key the TLS handshake presented;
  3. that `at_ms` is not older than the token's `floor_at_ms`;
  4. that `at_ms` is not older than the newest statement this process has seen. A running instance keeps that in memory, so an older statement presented later is refused. A process that restarts starts again from its token's floor.
- **The spec section and vectors** (`docs/vectores/service-proxy-key.json`) come with layer 2, in `klav-core` (`sign_proxy_key`/`verify_proxy_key`). No new primitive: the Ed25519 signature the pause already uses.

**What Q5 forces that ADR 0038 didn't write:**
- **When the old key was stolen, not just lost,** "without a redeploy" holds for availability, not for cutting the old key off new instances (§7). So the app's flow for a new proxy key asks "was the old key copied or stolen?". With yes, it offers rotating every service's enrollment token, which raises `floor_at_ms`, and says that only instances started with the new variable refuse the old key, so the person must update each PaaS variable.
- **That rotation keeps Q6's grace, and doesn't ask Q11's "did the old token leak?".** Dropping the grace would not help here: the floor an instance trusts comes from its own variable, so an instance started from the old variable trusts the old floor whether or not the real proxy still accepts the old token. Refusing the old token would only stop such an instance from reaching the real proxy, which costs the availability Q5 was chosen for. A person who also knows a token leaked rotates that service's token on its own and answers yes (§3.2); this ADR chose that on its own (§12).

#### 3.2 The enrollment token's grace period (Q6, Q11)
- **The definition gains `previous_token_hash` and `previous_until_ms`** (the rotation's time plus 24 hours), signed with the rest. Until then, the proxy accepts an enrollment made with either token; each still needs the domain proof.
- **No grace after an incident or a leak.** The device writes no previous token when incident mode covers the service (for it or for `all`) when the rotation is signed, or when the person answers yes to "did the old token leak?", which every rotation outside incident mode asks (Q11). The answer is not signed or stored: the definition simply has no previous token, so the yes needs no new message. And while incident mode covers the service, the proxy ignores a previous token, from incident mode's own signed state (0038 §8.6), with no new message. So an incident that starts during a grace period stops the previous token at once, a definition signed in a race with the incident is not refused (that would reject the whole grant), and the grace doesn't come back when the incident ends.
- **At most one previous token.** A second rotation within 24 hours keeps only the token it replaces as the previous one; the one before stops at once. A second rotation answered with yes stops both.
- **What a yes does, by the path that already exists:** with no previous token, the narrower purge drops at once the pending entries made with the old token, `klav-forward` with the old token is told its token was rotated and stops asking, and enrolled identities keep working. An identity that must enroll again (it expired after a missed rotation, or the proxy lost its store, 0038 §5.3–5.4) needs the new variable, as after an incident. Nothing here is a new choice.
- **What changes in ADR 0038 §3.5** (dated note there):
  - "rotating the token purges the queue" now drops only the pending entries made with a token the proxy no longer accepts. Entries made with the previous token stay until the grace ends, and are dropped then;
  - `klav-forward` is told that its token was rotated only when the proxy no longer accepts it, so an instance started with the previous token during the grace enrolls normally.
- **The floor is the instance's, not the proxy's** (§3.1): an instance started with the previous token trusts that token's older floor, during the grace or after it (§7).
- **The cost Omar accepted:** a token rotated because of a leak nobody knows about keeps working for 24 hours, since the person answers no. It still can't enroll without the domain proof. A known leak is cut at once with yes, without incident mode (Q11).

### 4. Approval per deploy (decision 5)

#### 4.1 The setting
- **`approve_enrollments`** in the service's definition, signed by the account: **off by default.** Turning it on is narrowing and asks for nothing; turning it off is widening and asks for Touch ID or Face ID, like any change to a definition (0038:100).

#### 4.2 What "a deploy" is to the proxy
- **An enrollment:** a new instance identity that passed the domain proof (0038 §3.2).
- **The proxy can't tell a deploy from a crash restart or a scale-out:** each is a new process with a new key (0038 §4.3). So with the setting on, all three wait. A reconnect of an identity already enrolled is not an enrollment, and doesn't wait.

#### 4.3 What happens, reusing incident mode's approval (Q7)
With the setting on, every enrollment of the service goes as during incident mode (0038:440–457), and nothing else of incident mode applies:
- the identity passes the domain proof, the proxy records `service.enrollment_pending` and the person gets the card;
- the decision is the account-signed `klav/v1/sig/service-enrollment` that already exists (0038:449), per identity;
- a waiting entry is never evicted, and after 15 minutes without a decision it lapses as `not_approved` (0038:457); the instance then makes a new key and asks again, so a new card appears.

**What the person sees:** one card per service with every identity waiting, its hints "according to the instance", its source address and when its domain proof passed. "Approve all" signs one decision per identity behind one Face ID or Touch ID. An identity that starts waiting while the card is open joins it; once the person decides, the card closes, and identities that start waiting later open a new card. No new signed message.

#### 4.4 The availability cost, in ADR 0038's own numbers
- **A new instance's calls fail** with `klav_not_enrolled` after 30 seconds (0038:203) until the person decides.
- **Health checks pass through** to the app (0038:201), so the platform routes traffic to an instance whose AI calls fail.
- **On Railway the old replica is killed at once** by default (0038:205): after a deploy, no instance of the service can call the AI until the person approves.
- **A single replica that crashes** stays without AI calls until the person approves its restart.
- **Pushes are capped** at 10 `service_alarm` an hour per account (0038:584); the card doesn't depend on the push (0038:454), but a person asleep sees it in the morning.

That is why it is off by default, and why `klav service edit` says this before turning it on.

### 5. The proxy hosted by Klav: out of launch (decision 4)
> Note of 2026-11-26: Omar overturned the condition below for the hosted proxy of [ADR 0051](0051-hosted-nitro-enclave-proxy.md) (accepted that day, Q1 (a)): it holds provider keys for sandboxes and remote MCP profiles, inside an enclave the person's devices verify before they wrap anything for it, as a later, higher tier, with this ADR's signers added when they exist. The breach cost this section describes is the price ADR 0051 Q1 states. Deployed services still don't use a hosted proxy.

- **Not built for launch;** the plan keeps its place on the waitlist (roadmap, Hito C).
- **The condition for a future one:** the enclave holds **only per-customer signers** for the federation path, **never provider keys**. A customer cuts it at their provider without Klav (§1.9), and a breach of the enclave yields tokens limited by each customer's rule.
- **What changed since ADR 0036 §12 was written** (dated note there):
  - AWS bulletin 2026-157-AWS, of 2026-10-30 ([page](https://aws.amazon.com/security/security-bulletins/2026-157-aws/), opened 2026-11-18, summary): two flaws in the AWS Nitro Enclaves SDK for C up to v0.4.5, fixed in v0.4.6. One lets an application on the parent instance corrupt the enclave's heap and run code in it, through the `kmstool-enclave` example or code derived from it; the other lets a crafted region string impersonate KMS to the enclave. "There are no workarounds."
  - **Not confirmed:** a 2026 paper on a cache side channel against an enclave from its parent instance with root (seen only as a search snippet); whether any attestation verifier exists in Swift; whether the Rust one from Evervault still depends on `openssl`. ADR 0036 §12 already expected these verifiers to need their own ADR.

### 6. How the server, the proxy and the provider split the work

| What | Lives in | Decides | Signs | What the Klav server sees |
|---|---|---|---|---|
| The signer | The vault, as an API key item granted to the proxy; decrypted only in the proxy's memory (Q2, Q3) | The person | — | Ciphertext, and each logged read |
| The issuer and the rule | The provider | The person, at the provider | — | Nothing |
| Organization, rule, workspace and service account IDs; `federation.signer_item`; `token_lifetime`; `approve_enrollments`; `previous_token_hash` | The service's definition | The person | The account | In clear (residual risk 68) |
| Which key is the proxy's (§3.1) | The server, the proxy and each running instance's memory | The person | The account | The statement, in clear |
| Assertions | The proxy's memory, for one exchange | The proxy | The signer | Nothing |
| Minted tokens | The proxy's memory | The provider | — | Nothing |
| Enrollment decisions with `approve_enrollments` | The server and the proxy | The person | The account | As during incident mode (0038 §9.1) |

The Klav server stays out of the federation: it never sees an assertion or a minted token, and can't add a key the provider trusts (Q4).

### 7. What this does not stop
- **Someone who controls the proxy while it runs** uses the minted tokens and, with the signer in memory, mints more. As ADR 0036 §11 and residual risk 53 say, unchanged.
- **A copy of the proxy's agent key** reads the signer through the server, logged, until the person revokes the proxy; ADR 0044's alarm and strict profile are what watch it (§1.8).
- **A minted token copied before it is dropped** works until it expires (§1.9).
- **A rule the person writes too wide** (a `subject_prefix` of `*`, a broader scope, every workspace) widens what a signer can do. Klav prints a narrow one; it can't check what the person registered.
- **Providers without federation:** the bearer key is as exposed as in ADR 0038, minus what its limits cut.
- **Code inside the app's container** (0038 §12, limit 1): unchanged; it uses the proxy, not the token.
- **An old proxy key posing as the proxy to an instance that starts fresh** (Q5, the limit Omar was told). A freshly started instance knows only its token, so it can't tell an older signed proxy key from the newest. Someone who holds an old proxy key that the account once signed, **and** controls where the token's proxy URL leads (its DNS or the network path), can pose as the proxy to such an instance. What bounds it:
  - **The statement's timestamp against the token's floor.** An instance refuses a statement older than its token's `floor_at_ms`, so an instance started with a token made or rotated after the key change refuses the old key. The window therefore lasts until the PaaS variable holds such a token, not until the person rotates it in Klav: an instance started from the old variable trusts the old floor, whatever the real proxy accepts (§3.1).
  - **A running instance, as opposed to a fresh one,** refuses any statement older than the newest it has seen. But that is in its memory, lost on every restart, and on Railway every deploy is a fresh start.
  - **What the impostor gets:** the instance's outbound AI calls, so prompts and request bodies, and the chance to answer them; and the token's secret, which enrollment sends (0038 §3.2, step 2). With that secret it can ask the real proxy to enroll keys of its own, which fail the domain proof and fill the queue, as with a leaked token (T174, residual risk 65). No provider key and no minted token: the real proxy holds those, and the impostor has neither.
  - **A key that was only lost,** not copied, gives nobody this, which is why the app asks (§3.1).

### 8. Audit events
- **No new action in the closed table** for minting: an exchange is not a Klav action, and one per instance every few minutes would flood the chain. The proxy counts mints and failed exchanges in the sealed `service.usage` window (0038:422), so the person sees them per identity.
- **Changing the signer** is a newly signed definition (`agent.granted`), as any definition change.
- **Each read of the signer** is an `agent.access` with the `service` (0038:409, 0038:525), as a provider key's.
- **The proxy-key statement** goes in the chain with ADR 0038's account-signed service states (§3.1).

### 9. Safe with older clients
- **Services:** nothing of ADR 0038 is built, so no running program reads a service definition or a `kse1_` token today. The fields of §1, §3 and §4 and the token's new shape ship with ADR 0038's layer 2, not after it.
- **Sandboxes (Q8):** these do exist, with `klav-forward` already shipped inside sandboxes and their templates. Copy detection for sandboxes changes what the proxy and the forwarder say to each other, so its layer must keep today's forwarders working or say exactly what stops (§10.1).

### 10. What ADR 0044 §12 left here
- **What the proxy keeps in memory, and for how long:** the provider key and the signer while leases renew (Q3, §1.3.2), and the minted token for `token_lifetime`, 10 minutes by default (Q10, §1.7). ADR 0044 §3 protects that memory; it doesn't shorten its life.
- **The pause carve-out** (0038:610): it stays (Q9), and it covers the signer's read (§1.3.1). The new-network alarm and the strict profile still apply to the proxy during a pause.
- **Whether the alarm and the strict profile cover a service:** they cover the proxy, which is the only principal of a service that holds a Klav key and talks to the Klav server. Instances never talk to it (0038 §1). An instance's own egress changes are already a signal (`egress_change`, 0038:477). At the provider, the IP allowlist plays the role of the strict profile for a minted or bearer token.
- **Detecting a copied sandbox:** yes, with the services (Q8, §10.1).
- **A person's device signing for sandboxes** instead of the proxy: decision 3 left it for later; not designed here.

#### 10.1 Copy detection for sandboxes (Q8)
**The scope, said plainly.** Omar chose to give sandboxes the copy detection services get, in the same work as the services. It is not launch work: it is designed and built when ADR 0038's ratchet (0038 §5) is built, as a layer of this ADR that reuses it. Nothing of it is built before launch, and until it is, ADR 0036 §5's line stands: whoever copies the whole disk and memory of a sandbox gets what the agent already had, the proxy with those profiles, while the sandbox lives.

**What carries over from ADR 0038 §5.2:**
- **The ratchet:** the forwarder's channel key rotates every period, each successor signed by the old key and the new one, and the proxy keeps the history of keys per sandbox. Two successors of one key, or a key from the history that isn't the last, give a copy away (signal 1).
- **Two live channels at once,** with the ping to the first (signal 2).

**What doesn't carry over, and what that changes:**
- **The domain proof** (signals 3 and 4). A sandbox has no domain, so the case where the original stops and the copy carries on alone gives no signal from the ratchet. Detection needs both copies to keep running, as ADR 0038 §5.2 says of services without the proof.
- **Coming back after a freeze.** A frozen service's original re-enrolls through the domain (0038 §5.5). A sandbox can't. The outline here, which that layer's design confirms or changes, is that a detected copy ends the sandbox, revoked as `theft` with the same push as a second claim (ADR 0036 §5, E5), and the agent starts a new one.

**What its design brings back to Omar before it is built** (stop rule):
- what happens when a sandbox misses a rotation: ADR 0038 expires an identity after 15 minutes (0038 §5.3), while ADR 0036 lets a sandbox live 1 hour without a connection;
- today's forwarders, which know no ratchet (§9): refused, so that every template must be rebuilt, or let through without detection and marked as such in "Active sandboxes";
- the ratchet's state per sandbox in the proxy's store, and what a lost store does to it (0038 §5.4).

### 11. Rejected alternatives
- **Multi-party TLS** (TLSNotary and the like), so no machine holds the whole key: research-grade, TLS 1.2 only, seconds and tens of megabytes per small request in the reports the research found (not confirmed by me), no audit found, and a new cryptographic dependency.
- **Threshold signing (FROST)** of the assertion: no provider in §Context accepts Schnorr signatures, and it is a new dependency.
- **The person's device signs every assertion** (decision 3 chose the proxy for services): a service would go down when the phone is off longer than a token's life.
- **The signer as a file in the proxy's store** (Q2 (b)): it works while the Klav server is down, but a copy of the disk mints tokens from anywhere and Klav never sees it.
- **The proxy or the Klav server publishes the issuer's keys** (Q4 (b), (c)): whoever controls that host, or a malicious or breached Klav server, could add a key and mint tokens for the person's organization.
- **The proxy holds an `org:admin` token to register issuers itself:** a key worth more than the one it replaces (§1.5).
- **A per-proxy signer for every service:** one copy would mint for every service (§1.3).
- **RSA (RS256) instead of ES256:** no approved crate signs RSA (0038:213), so it would need a new dependency and its ADR.
- **A token that pins two proxy keys, the current one and a spare** (Q5 (b)): one change without a redeploy, and losing both still needs one.
- **One approval that opens a window for later instances** (Q7 (b)): it needs a new signed message, and a crash restart inside the window passes unasked.
- **The hosted proxy now:** decision 4.

### 12. What this ADR chose on its own (Omar can overturn each)
- **One signer and one issuer per service** (§1.3).
- **`sub`, `aud`, `jti` and the `.invalid` issuer** as in §1.4.
- **`token_lifetime` from 60 s to 1 hour, enforced through the assertion's `exp`** (§1.6).
- **A token per instance identity,** refreshed at 80 % of its life (§1.7).
- **Anthropic only in the first version** (§1.2).
- **No audit action per mint;** counts in the sealed usage record (§8).
- **The bearer path's checklist only lists confirmed limits** (§2).
- **With `approve_enrollments` on, crash restarts and scale-outs wait too,** because the proxy can't tell them from a deploy (§4.2).
- **The signer's item and its rules** (§1.3.1): an API key item with the PKCS#8 DER in base64url and the `kid` in `key_id`; named by `federation.signer_item`; never usable by a profile; read without claims only as the signer; covered by the lease and the pause.
- **How Q5 binds the proxy's key** (§3.1): the account's identity key and a floor in `kse1_`, the statement's label and fields, presence to sign it, the forwarder's four checks, and the stolen-key flow that offers rotating every token, with Q6's grace and without asking Q11's question. The other option: ask "did the old tokens leak too?" once for all of them, and with yes, rotate them with no grace. A fresh instance started from an old variable then can't reach the real proxy, the availability Q5 was chosen for, with no gain against T224 (§3.1).
- **How Q6's grace works** (§3.2): two fields in the definition, at most one previous token, no grace when incident mode covers the service at signing or when the person says the old token leaked (an answer that is not stored), a previous token ignored while incident mode covers the service, and ADR 0038 §3.5's purge limited to tokens no longer accepted.
- **A card that stays open while it fills** (§4.3).
- **Q8's outline** (§10.1): what carries over from ADR 0038 and what doesn't, and a detected copy ending the sandbox as a theft. All of it waits for that layer's design.

## Threats
New rows go in the threat model's §5.22, marked «aceptado, pendiente de implementar (ADR 0045)». The numbering continues after ADR 0044 (T216, risk 86):
- **T217:** a copy of the proxy's disk yields the agent key that reads the signer;
- **T218:** a minted token copied from the proxy's memory or its outbound traffic;
- **T219:** a key the person didn't make added to the issuer (by a server that serves the keys, or by whoever controls a URL the provider fetches);
- **T220:** an assertion replayed, or exchanged at another provider;
- **T221:** a rule registered too wide at the provider;
- **T222:** per-deploy approval as an outage or as approval fatigue;
- **T223:** a future hosted proxy attacked from its parent instance;
- **T224:** an old proxy key poses as the proxy to an instance that starts fresh (Q5);
- **residual risks 87–92:** 91 is T224's window, and 92 is the enrollment token's 24-hour grace (Q6), which a person who knows of the leak drops (Q11).

T147 and residual risk 51 (a copied sandbox) gain a dated note for Q8.

## Plan in layers
One branch per layer, stacked with `gh stack`. **No layer is launch work, and none starts before Omar starts ADR 0038's work;** layers 3 to 7 also wait for ADR 0038's own layers.

| Layer | What | Waits for | Tests |
|---|---|---|---|
| 1 | This ADR, the threat model (§5.22), the roadmap, the glossary, `CLAUDE.md`'s approved use of `p256` and `ecdsa`, and the dated notes in ADR 0036 and ADR 0038 | — | Links and leak grep |
| 2 | `klav-core`: `sign_assertion` (ES256 JWS), the JWK and its thumbprint, the signer item's encoding, and `sign_proxy_key`/`verify_proxy_key`, with their spec sections and `docs/vectores/federation-assertion.json` and `service-proxy-key.json`; the throwaway-organization check of the `.invalid` issuer (§1.4) | Omar starting ADR 0038's work | Vectors checked by a verifier independent of the signer (a dev-dependency or a fixed JWS from another library); `r ‖ s`, not DER; a header without `kid` and a payload without `jti` are never produced; a proxy-key statement with another account, another SPKI or a lower `at_ms` is refused |
| 3 | The service definition's `federation` settings with `signer_item`, `approve_enrollments`, `previous_token_hash` and `previous_until_ms`; `kse1_` with the account's identity key and `floor_at_ms` | ADR 0038 layer 2 | Definition round trips; an old proxy refuses a definition with fields it doesn't know (fails closed); a definition where a profile uses the signer item is refused; while incident mode covers the service, a previous token in the definition is ignored, and it doesn't come back when the incident ends; a rotation answered "leaked" writes no previous token |
| 4 | `klav-proxy` and `klav-forward`: the signer read without claims and kept while leases renew, minting per identity, refresh, drop, the bearer header, `klav_provider_token_unavailable`; mint counts in `service.usage`; the proxy-key statement in the channel and the forwarder's four checks; the grace period and the narrower purge; the server's read rule for the signer | ADR 0038 layers 4–6, ADR 0044 layer 1 | Against a fake token endpoint in the test harness that checks ES256, `aud`, `jti` single use and the lifetime rule: tokens refresh at 80 %, are dropped on freeze, stop and lease lapse, and never appear in a log, an event or the store. The server refuses a read without claims for an item that isn't the service's signer. A running forwarder refuses an older statement than the newest it saw, and a fresh one refuses one older than its token's floor. During the grace both tokens enroll, after it only the new one; incident mode during the grace stops the old one at once; with no previous token, the old token's pending entries are dropped and its `klav-forward` is told at once |
| 5 | `klav service federation setup` and the signer rotation card; the token rotation's "did the old token leak?" (Q11); the new proxy key flow with "was it stolen?"; the bearer path's checklist; the per-deploy approval card and "Approve all"; `apps/docs` | ADR 0038 layers 7–8 | CLI output carries no secret; rotation refuses to switch before the person confirms the first step; with `approve_enrollments` on, a new identity waits and lapses as `not_approved` after 15 minutes; the stolen-key flow offers rotating every token and says the PaaS variables must change; a token rotation outside incident mode asks whether the old token leaked, and with yes signs no previous token |
| 6 | End-to-end: ADR 0038's three-replica test (0038:718–724) with one service on the federation path and a proxy whose key changes without a redeploy; Omar's manual test against a real Anthropic organization | Layers 2–5 | As listed |
| 7 | Copy detection for sandboxes (Q8, §10.1), reusing the ratchet of ADR 0038's layers; T147 and risk 51 updated | ADR 0038's ratchet layers, and Omar's answers to the points of §10.1 | Two copies of a running sandbox's forwarder: the second rotation is a fork and ends the sandbox as `theft` with the push; a reconnect after a blip is not a copy; today's forwarders behave as the answer to §10.1 says |

## Consequences
- **With the federation path,** the proxy keeps no long-lived provider key for that service: a signer read from the vault, and tokens that expire in minutes.
- **With the bearer path,** nothing changes in Klav; the provider's limits cut what a copied key is worth.
- **New formats:** the assertion (a JWT with `klav_v: 1`), the proxy-key statement and the signer item's encoding, with their spec sections and vectors; `kse1_` changes before it exists.
- **New use of `p256` and `ecdsa`** in `klav-core` (Q1). `CLAUDE.md`'s list gains it with this ADR, as it did with ADR 0020 §6.
- **New metadata on the server:** the provider IDs and the signer's item ID in the definition (risk 68 grows), and the proxy-key statement.
- **Setting up federation is a manual step at the provider,** once per service (§1.5).
- **A new proxy key needs no redeploy** (Q5), but cutting a stolen old key off new instances still needs the PaaS variable updated (§7).
- **Sandboxes gain copy detection** when the services' ratchet is built (Q8); until then, nothing changes for them.

## The questions as asked (answered 2026-11-18)
Each listed two to four options; the first one was the recommendation. Omar's answer is under each, and the owner's decisions at the top record them.

- **Q1. May `klav-core` sign the services' identity assertions with ECDSA P-256 (ES256), using the `p256` and `ecdsa` crates already approved for passkeys?** Anthropic accepts ES256 or RSA, not Ed25519 (the curve every other Klav key uses), and approving a crate for one use doesn't cover another.
  - (a) **Yes, the same crates, versions and features as passkeys, with its own vectors.** *Recommended:* no new crate, and it is the only way to the federation path without RSA.
  - (b) No: services stay on the provider key (the bearer path) until another decision.
  - **Answered: (a).**
- **Q2. Where does the proxy keep a service's signing key?** It lets the proxy get short-lived provider tokens; whoever copies it can get them too, until you remove it at the provider.
  - (a) **As a vault item granted to the proxy, like a provider key:** made on your device, read by the proxy through the Klav server, never written to the proxy's disk. (Which existing item type holds the key is not checked yet; if none fits, a new type is a new format and comes back to you.) *Recommended:* a copy of the proxy's disk then gets only the proxy's Klav key, whose use the new-network alarm and the strict profile watch, and every read is logged; it keeps "nothing stored in plain text" true for the signer.
  - (b) As a file in the proxy's store, made on the proxy's host. It works while the Klav server is down, but a copy of the disk mints tokens from anywhere and Klav never sees it.
  - **Answered: (a).** The item type was checked afterwards: an API key item fits (§1.3.1), so no new type comes back.
- **Q3. How long do a service's secrets stay decrypted in the proxy's memory: the provider key (where the provider has no federation) and the signing key?** Before services, the proxy decrypted a key for each call and dropped it; the accepted design for services keeps it while the service runs.
  - (a) **Both while the service's leases keep renewing.** *Recommended:* one logged read when a secret is first needed and when it changes; the memory is protected by the measures already decided for the proxy (no swap, no core dumps); a call never waits for the Klav server.
  - (b) The provider key while leases renew, the signing key only for each signature: read, sign, wipe. Each signature is one logged read: with 20 instances, 10-minute tokens and a refresh at 80 % of their life, about 150 reads an hour per service.
  - (c) Both only for each use. For a provider key that is one read per call, which is what the accepted lease design was made to avoid (a round trip and an audit event per call).
  - **Answered: (a).**
- **Q4. How does the provider get the proxy's public key for a service?**
  - (a) **You paste it into the provider once ("inline"); Klav prints it.** *Recommended:* nobody else can add a key the provider trusts. The cost: changing the signer means pasting the new key, in two steps, which the app walks you through.
  - (b) The proxy publishes it at an HTTPS address the provider fetches. The provider refreshes keys by itself, but the proxy needs a public address on port 443, and whoever controls that host can add a key.
  - (c) The Klav server publishes it. Simplest to set up, but a malicious or breached Klav server could add its own key and mint tokens for your organization.
  - **Answered: (a).**
- **Q5. How does a change or loss of the proxy's own key reach services that are already running, without a redeploy?** Today each service's enrollment token pins a hash of the proxy's key, so a new proxy key would leave every instance unable to reconnect until you redeploy with a new token.
  - (a) **The token pins your account's identity instead, and you sign, on a device, which key is the proxy's current one.** Instances accept any proxy key that your account signed, so a new proxy key needs your signature, not a redeploy. Each signature carries a time; a running instance keeps the newest it has seen and refuses older ones, but a freshly started instance can't tell, so a stolen old proxy key, together with control of the proxy's address, could pose as the proxy to new instances (seeing prompts, with no provider key) until you rotate the token. *Recommended:* nothing of the services is built yet, so this costs no migration, and it is the same kind of signature as pausing.
  - (b) The token pins two hashes: the current key and a spare the proxy made in advance. One change without a redeploy; losing both still needs one.
  - (c) Accept it: a new proxy key means redeploying every service with a new token.
  - **Answered: (a), told the limit.** "Until you rotate the token" was too short: the window lasts until the PaaS variable holds a token rotated after the change (§7). Told that correction on 2026-11-18, he confirmed (a) and declined again the alternative of a token that pins a hash of the proxy's key: no window, but every proxy key change leaves every service unable to enroll until its variable is updated.
- **Q6. When you rotate a service's enrollment token, what happens to instances that start before the platform has the new variable?** Running instances are never affected; this is about new ones.
  - (a) **The proxy accepts the old token too for 24 hours after a rotation, unless the rotation came from incident mode.** *Recommended:* a deploy during the switch keeps working, and an incident still cuts the old token at once. The cost: a token is often rotated because it leaked, and outside incident mode the leaked one keeps working for those 24 hours (it still can't enroll without the domain proof).
  - (b) Only the new token: an instance that starts with the old one stays out until the platform redeploys it with the new variable.
  - **Answered: (a).**
- **Q7. With "approve each deploy" on for a service, how far does one approval reach?**
  - (a) **One card lists every instance waiting for that service, and "Approve all" approves them with one Face ID or Touch ID;** later instances need a new card. *Recommended:* it reuses the incident-mode approval exactly, with no new signed message.
  - (b) One approval opens a 15-minute window in which instances up to the service's replica limit enroll without asking, still with the domain proof. Fewer cards in a rolling deploy, but it needs a new signed message, and a crash restart inside the window passes unasked.
  - **Answered: (a).**
- **Q8. Should sandboxes get the copy detection that deployed services get (a key that changes every few minutes, so two copies give themselves away)?** Today a copy of a sandbox's disk and memory can use the proxy as the sandbox could, until the sandbox ends.
  - (a) **Not for launch: sandboxes live hours, end on their own, and the second-claim theft signal stays.** *Recommended:* the design exists for services and can be reused later with little new.
  - (b) Yes, in the same work as the services.
  - **Answered: (b),** not the recommendation. Built with the services, not before launch (§10.1).
- **Q9. During "Pause agents", may a deployed service's proxy keep reading its keys (and, with the federation path, its signing key)?** Today's decision is that the global pause leaves services running.
  - (a) **Yes, as decided on 2026-11-09:** reads that declare a service stay open, and the new-network alarm and strict profile still apply to the proxy. *Recommended:* it keeps "your services keep running".
  - (b) Only what the proxy already holds in memory: no new reads during a pause. A rotated key waits until the pause ends, and a proxy that restarts during a pause stops its services.
  - **Answered: (a).**
- **Q10. How long does a token the provider mints for a service live, by default?** The proxy keeps it only in memory and renews it by itself; the provider documents no way to revoke one early, so a copied token works until it expires. You can change it per service, from 1 minute to 1 hour.
  - (a) **10 minutes.** *Recommended:* the value the provider's own setup suggests; a copied token is worth at most 10 minutes, and the proxy renews about 7 times an hour per instance.
  - (b) 1 hour. Fewer renewals, and the service rides out a longer outage of the provider's token endpoint, but a copied token works up to an hour.
  - (c) 2 minutes. A copied token is nearly worthless, at about 40 renewals an hour per instance.
  - **Answered: (a).**
- **Q11. When you rotate a service's enrollment token, the old one keeps working 24 hours so services don't go down; today only incident mode removes that grace. Do you want to be able to remove it in a normal rotation too?** Its stated cost is that a token rotated because it leaked keeps working for those hours, and today the only way around it is turning on incident mode, which also asks for an approval for every new instance of the service.
  - (a) **Yes: the rotation asks "did the old token leak?", and with yes it carries no grace,** as after an incident. *Recommended:* it costs no new signed message (the definition simply has no previous token), and it lets a person who knows of a leak cut the old token at once without paying for incident mode.
  - (b) No: only incident mode drops the grace. Simpler, and the person who knows of a leak turns incident mode on, rotates, and turns it off.
  - **Answered: (a).** He was told it lets him cut a known leak without turning on incident mode, and that it needs no new signed message.

## Stop rules
- **Layer 2 stops** if the throwaway-organization check refuses the `.invalid` issuer in inline mode, or if `p256`'s current features can't give the JWK without another feature; both come back here.
- **Layer 4 stops** if an API key item can't hold the signer as §1.3.1 says (for example, a limit on a field's length found in the clients): a new item type is a new format, and it comes back here.
- **Layer 7 stops** before it is built and brings the points of §10.1 back to Omar as questions.
- **No layer of this ADR merges before the ADR 0038 layer it waits for.**
