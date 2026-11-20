# 0038 · Deployed services: enrollment with a domain challenge, a key ratchet with clone detection, policies with a sealed usage record, and incident mode

- Status: accepted (Omar accepted it on 2026-11-09 with option (a) for each of Q1–Q8, then answered the design review's Q-A, Q-B and Q-E, and took the list of allowed models out; Q-A replaces Q5. See "Omar's answers"). Note of 2026-11-18: [ADR 0045](0045-keyless-services.md) (accepted on 2026-11-18, not built; Q1–Q11 answered) amends this ADR, which Omar had said waits for that debate. Where the provider accepts a signed workload identity (Anthropic, in its first version), the proxy holds a per-service signer, an API key item of the vault granted to it, instead of the provider key, and injects a token that expires in minutes (10 by default); elsewhere the provider key stays, with the limits the provider offers. It also changes, before they are built: the definition (`federation` with `signer_item`, `approve_enrollments`, `previous_token_hash`); the `kse1_` token (§2.2), which pins the account's identity key and a floor instead of the proxy key's hash; the token rotation (§2.2, §3.5), with a 24-hour grace except after an incident or when the person says the old token leaked; and the lease answer (§7.2) and the pause carve-out (§10.3), which cover the signer's read. Accepting it doesn't schedule this ADR: deployed services are not launch work, and when its work starts is Omar's call.
- Date: 2026-11-09

## Context

### What happened in October 2026
- **Railway.** On 2026-10-21 at 21:59 UTC, Railway published a security notice that told all users to revoke the environment variables, API keys and registry credentials stored on the platform. Its preliminary report (2026-10-23) says an intruder reached the systems that store environment variables and, for some of them, their decrypted values, in at most 1.85% of workspaces, and that the attack seemed aimed at AI inference keys. Railway worked with Anthropic, OpenAI, OpenRouter, Stripe, GitHub and others to revoke keys. Deployments were paused during the investigation. These facts come from third-party reports of Railway's notice: [The Hacker News](https://thehackernews.com/2026/10/railway-says-intruder-may-have-accessed.html), [TechCrunch](https://techcrunch.com/2026/10/22/developer-platform-railway-urges-all-users-to-revoke-secret-keys-after-cyberattack/) and [GitGuardian](https://blog.gitguardian.com/railway-october-2026-incident-environment-variables/).
- **Northflank.** Its incident page (<https://status.northflank.com/cmvv0rn5a092f14rutwccodpp>) says:
  - "The first known decryption of secrets occurred between 02:39 UTC and 03:08 UTC on 30 October";
  - "Assume all environment variables have been decrypted. Disable/rotate all keys.";
  - "Users have reported unauthorised use of AI API keys supplied to the Northflank platform";
  - and recommends to "enable IP restrictions and budget limits wherever available".

Both incidents leaked the same thing: every service's variables, decrypted. Each team then had to rotate every key by hand, one by one, and AI keys were abused before that was done. Northflank's own advice, budget limits, stays for a later version (Q-A, [Later](#later)). This one makes sure there is no key in the variables to abuse, and records each service's usage so the person can see it and stop it.

### What Omar asked for
- **On 2026-11-06** ([roadmap](../roadmap.md), «Siguiente fase · Servicios desplegados»): the app's variables hold only the service ID and a low-value enrollment token. The real keys live in the proxy and rotate there, without redeploying the app. Each instance proves with a challenge, like ACME's HTTP-01, that it runs behind the service's public domain. The key changes every few minutes, signed by the previous one, and two successors of the same key reveal a clone. Policies and spend caps per service. An incident mode. (On 2026-11-09 Omar moved the spend caps to a later version: Q-A.)
- **On 2026-11-09,** Omar said enrollment matters more than personal cloud agents, because whether a company can install Klav depends on the company.

### What this ADR covers, and what it does not
- **In:** the enrollment token, enrollment with a domain challenge, the replica limit, the key ratchet and clone detection, policies and a sealed usage record, incident mode, the service as a principal, who decides and who signs each part, and the honest limits.
- **Separate ADRs, mentioned only where they touch this one:** the single source of truth with `klav rotate` (pushing values to the PaaS and rotating keys at the provider), and the canaries.
- **Out of the first version:**
  - serverless (the roadmap already says so);
  - workers and cron jobs with no public domain, because they can't answer the challenge (§3.8);
  - databases: AI APIs first, as the roadmap says;
  - a proxy hosted by Klav. ADR [0036](0036-sandboxes-de-agentes.md) §12 allows one only as an attested proxy in an enclave, and the roadmap adds "here with more reason", because this proxy sees the prompts of the app's users;
  - a proxy with more than one replica (§11);
  - spend caps (Q-A): [Later](#later) keeps what a future ADR has to solve first.

### What already exists: ADR 0036
- **`klav-proxy`** is the person's own credential proxy, on their server or their Mac. It pairs as an agent (six words), holds a **per-item grant** (blob `0x23`, `GrantPayload` `v: 2`; ADR 0036 E10 moved it off `0x22`, which ADR 0029 owns), uses the `proxy` permission, and applies **profiles** signed by the account: hosts, methods, path prefixes, rate, SSRF defense and response redaction.
- **`klav-forward`** runs next to the code and reaches the proxy over **TLS 1.3 with the proxy's key pinned**, authenticated with a client key that lives only in memory.
- **The sandbox package `ksb1_`** carries a version byte, the sandbox ID, a one-time secret, the hash of the proxy's key and its URL. A second claim is the theft signal.
- **Per-call access:** the proxy makes a signed `POST /v1/agent/access` for every request it injects. "If that weighs too much, another ADR can group them; the authorization is never cached" (ADR 0036 §2).
- **ADR 0036's amendment of 2026-11-09 (PR #252, accepted)** adds an account-signed revocation that the server enforces on that per-call access, proxy-signed lifecycle events in the audit chain, and a push without text that the app checks against the chain before showing it. This ADR reuses those three patterns.

**The difference.** A sandbox lives for hours and starts from a package that the issuer creates for each start. A deployed service lives for months, restarts on its own, scales up and down, and its variables sit in a PaaS store that has already leaked. Nobody is there to hand each instance a fresh package. That is the gap this ADR fills.

### What the platforms do (checked on 2026-11-09)

| | How traffic reaches replicas | Reaching one replica | Instance ID | Deploys and restarts | Scaling |
|---|---|---|---|---|---|
| **Railway** | "route public traffic to the nearest region and then randomly distribute requests to the replicas within that region"; "Railway does not support sticky sessions" ([scaling](https://docs.railway.com/reference/scaling)) | Not documented | `RAILWAY_REPLICA_ID`, `RAILWAY_REPLICA_REGION`, `RAILWAY_DEPLOYMENT_ID` ([variables](https://docs.railway.com/reference/variables)) | A deployment is `Active` after its healthcheck succeeds (that public traffic follows is an inference). "Once the new deployment is online, the old deployment is sent a SIGTERM signal", with 0 seconds before `SIGKILL` by default: `RAILWAY_DEPLOYMENT_DRAINING_SECONDS` defaults to 0. `RAILWAY_DEPLOYMENT_OVERLAP_SECONDS` sets how long both run; the docs give no default for it ([deployments](https://docs.railway.com/reference/deployments)) | "manually increasing the number of replicas"; only vertical scaling is automatic |
| **Render** | "load-balances that traffic evenly across all running instances" ([scaling](https://render.com/docs/scaling)) | Not documented. `RENDER_DISCOVERY_SERVICE` is "A DNS name for finding all instances of a scaled service" | `RENDER_INSTANCE_ID` ([environment variables](https://render.com/docs/environment-variables)) | The original instance "continues to receive all incoming traffic while the new instance is spinning up", until it is healthy; the old one gets `SIGTERM` after 60 seconds and `SIGKILL` after a shutdown delay (30 s by default); one instance at a time; a new instance that never becomes healthy cancels the whole deploy ([deploys](https://render.com/docs/deploys)) | Autoscaling between a minimum and a maximum on CPU and memory targets |
| **Northflank** | "The Northflank load-balancer will evenly distribute incoming traffic between different instances" ([autoscaling](https://northflank.com/docs/v1/application/scale/autoscale-deployments)) | Not documented | Not checked | Not checked | Autoscaling between a minimum and a maximum, "to limit your spend" |
| **Fly** | Through Fly Proxy | `fly-force-instance-id` "Forces routing to a specific Machine", with "No fallback if Machine is ultimately unavailable"; `fly-replay: instance=…` ([dynamic request routing](https://docs.fly.io/networking/dynamic-request-routing)) | The Machine ID, also in its OIDC token | Suspend saves memory; "Snapshots aren't guaranteed to persist", a deploy discards them, and "the clock can lag a few seconds until NTP syncs" on resume ([suspend and resume](https://docs.fly.io/reference/suspend-resume)) | Not used here |

**Workload identity:**

- **Fly OIDC** ([openid-connect](https://docs.fly.io/security/openid-connect)): a Machine gets a token with `POST http://localhost/v1/tokens/oidc` over the `/.fly/api` socket. It carries `machine_id`, `app_name`, `org_name`, `image_digest` and `region`, and its issuer is `https://oidc.fly.io/<org>`. The page does not state the signing algorithm.
- **GitHub Actions OIDC** ([reference](https://docs.github.com/en/actions/reference/security/oidc), [concepts](https://docs.github.com/en/actions/concepts/security/openid-connect)): the job needs `permissions: id-token: write` and asks `ACTIONS_ID_TOKEN_REQUEST_URL` with the bearer `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and an `audience` parameter. The issuer is `https://token.actions.githubusercontent.com`, with its discovery document at `/.well-known/openid-configuration`. The example token is signed `RS256` and carries `repository_id`, `ref`, `sha`, `environment`, `run_id` and `job_workflow_ref`. No lifetime is stated.

**ACME HTTP-01** (RFC 8555, <https://www.rfc-editor.org/rfc/rfc8555>):

- The answer is the key authorization, `token || '.' || base64url(Thumbprint(accountKey))` (§8.1), served at `http://{domain}/.well-known/acme-challenge/{token}` on port 80 (§8.3).
- §10.2: "Validation responses need to be bound to an account key pair", so a replayed response "can only be used with the account key for which it was generated". Making HTTP connections "from multiple points in the network" is RECOMMENDED.
- Let's Encrypt follows up to 10 redirects and checks "potentially multiple times from multiple vantage points" ([challenge types](https://letsencrypt.org/docs/challenge-types/)).

**The lesson Klav takes from ACME:** the answer to the challenge must be bound to the key being authorized, not to a shared secret. That is the whole of §3.

## Decision

### 1. A service is a principal of the proxy, not an agent
**Options:**

- **(a) Each service is an agent (ADR [0002](0002-agentes-con-identidad-propia.md)) of a new kind.** An agent has a Klav key that decrypts its grant. That key would live in every instance, and a variables dump or a memory dump would take it. Every new instance would also need six words and an approval. Rejected: it is the problem of ADR 0036 (no Klav key where others can copy it), made worse.
- **(b) Each instance is an agent with its own short grant,** issued automatically. It still puts a Klav key in the instance, and it fills the server with short-lived agents. Rejected.
- **(c) The service is a principal of the person's proxy, like a sandbox** (ADR 0036 §4). **Chosen.**
  - The account defines the service in the proxy's grant (§2).
  - Instances get **instance identities**: Ed25519 key pairs that live only in the memory of `klav-forward` and that only the proxy knows. They are not Klav keys: they decrypt nothing and sign nothing the Klav server accepts.
  - The provider keys stay where ADR 0036 put them: in the proxy, behind a per-item grant.

**What follows from (c):**

- **The audit chain:** each service event is an action of the proxy, signed by the proxy (§9), with the service and the instance identity as data "according to the proxy", as T136 and T157 ask for agent and issuer labels.
- **In the apps:** a "Services" row under Development on the Mac (ADR [0033](0033-agentes-desde-la-app-de-mac.md) E1), below Sandboxes (⌘7, ADR 0036 E4), with ⌘8, and a section in the Agents sheet on iOS (§10).
- **In `klav log verify`:** new actions in the closed table of ADR [0030](0030-ronda-de-seguridad-2026-11.md) §4 (§9.3).
- **Pausing:** "Pause agents" pauses the proxy, because the proxy is an agent. Q3 decided that the global pause leaves services running and that pausing the proxy itself stops them; §10.3 lists the routes that stay open.
- **Teams:** a service belongs to one Klav account, the one that owns the proxy. Klav has no sharing between people yet (design §8), so a company with several admins has to wait for sharing. Some can live with one account per team for now.

### 2. The service definition, and the enrollment token
#### 2.1 The definition
**What it is:** a list of `services` in the proxy's grant, signed by the account like the rest of the grant (ADR [0014](0014-agentes-fase-4.md) §2). The grant goes up one version after ADR 0036's `v: 2`. `Scope` and the grant reject unknown fields, so an old proxy fails closed.

**What each service carries:**

- `service_id`: 16 random bytes;
- `name`: as the person wrote it;
- `domains`: the public domains the service answers on, for example `api.acme.com` or `acme.up.railway.app`;
- `regions`: optional; one region in the first version (§3.6);
- `max_replicas`, `surge` and `surge_window` (§4);
- `ratchet_period`: 5 minutes by default, from 1 to 15 (§5);
- `items` and `profiles`: what ADR 0036 already defines, with the AI presets of §6;
- `token_hash`: the SHA-256 of the enrollment token's secret (§2.2);
- `strict`: the optional CI window (§3.7), off by default.

**Who writes it:** the person, with `klav service add` or in the apps, with Touch ID or Face ID, because it gives access. The command asks for the domain and the replica limit, and fills the rest from a preset.

**Where the replica limit comes from:** the person declares it. Klav can't read it from the PaaS: the proxy holds no PaaS token, because of T151 ("no token the proxy injects may reach the service where the proxy runs"). The ADR for the single source of truth may later read it with the PaaS API from one of the person's devices and offer it.

**What the server sees:** the definition in clear, like the profiles of ADR 0036 (domains and limits). Policy domains in grants are already in clear today, because the server evaluates them. This is new metadata (residual risk 68).

#### 2.2 The enrollment token: `kse1_`
`KLAV_SERVICE=kse1_…` goes in the app's PaaS variables, next to the service ID:

```
"kse1_" ‖ base64url(0x01 ‖ service_id(16) ‖ secret(32) ‖ SHA-256(proxy SPKI)(32) ‖ len ‖ url)
```

- **Shape:** the same as `ksb1_`. It carries a version byte from the first byte, and its exact encoding, its section of the spec and its vector in `docs/vectores/` come with the code.
- **The secret is generated on the person's device.** It is shown once (or written to a new 0600 file with `--token-file`) and never stored. The definition only carries its hash. Neither the proxy nor the server can produce it.
- **It is not used up.** Unlike `ksb1_`, every restart of every instance uses it. That is why it is worth so little on its own (§2.3).
- **`klav service token rotate`** makes a new one and signs a new definition with Touch ID or Face ID. Instances that are already enrolled keep working; only new enrollments need the new token. Updating the PaaS variable is up to the person, or to the source-of-truth ADR later. (Note of 2026-11-18: [ADR 0045](0045-keyless-services.md) §3.1, accepted and not built, replaces `SHA-256(proxy SPKI)` with the account's identity key and a floor, `floor_at_ms`, so a new proxy key needs the account's signature, not a redeploy; §3.2 keeps the old token working for 24 hours after a rotation, except after an incident or when the person, asked at the rotation, says the old token leaked.)
- **`klav-forward` removes it** from the app's environment before starting the app.

#### 2.3 What the token is worth if it leaks
The threat is a dump of the PaaS variables, as in October. The attacker gets `KLAV_SERVICE`, the service ID and anything else in the variables.

**What the attacker can do with the token:**

- open a channel to the proxy (they have its URL and the hash of its key) and ask to enroll a key of their own. Every attempt fails at the domain challenge (§3), and every failure raises the alarm "the enrollment token was used from outside the domain";
- slow down real enrollments by filling the pending queue until the person rotates the token (§3.5, residual risk 65);
- learn the proxy's address.

**What the attacker can't do:**

- decrypt anything: the token is not a Klav key;
- call a provider: the proxy only serves enrolled identities;
- enroll without answering through the domain with their own key, which means running code behind that domain;
- take over a running instance: identities live in memory and change every five minutes (§5);
- read the provider keys: they were never in the variables.

**What stays out of reach of this ADR:** the other variables in the same dump that can't go through the proxy, such as a `DATABASE_URL`. Those belong to the single-source ADR. Until then, the incident of October still applies to them.

### 3. Enrollment: a domain challenge bound to the instance's key
#### 3.1 The hard case
- The proxy reaches the service through its public domain, and the platform's load balancer picks the replica: at random on Railway, "evenly" on Render and Northflank (§Context).
- So the replica that answers the challenge is often not the one enrolling.
- **An answer any replica can give is broken.** Take a MAC of the challenge with the enrollment token: every real replica can compute it. An attacker outside the domain, with the token from the dump, asks to enroll their own key. The proxy sends a challenge, a real replica answers it, and the attacker's key is in. **This fails open.**

#### 3.2 The rule
**Each instance can only prove its own key.** It never vouches for another one.

1. **The instance makes its key.** `klav-forward service run` generates the instance key `K_0` (Ed25519) in memory and opens the pinned channel of ADR 0036 §6, presenting `K_0` as its client key. That proves it holds the private key it wants to enroll, so nobody can enroll the public key of another instance, which is not secret.
2. **It asks to enroll** with `{service_id, secret, pub_0, hints}`. The **hints** are what the platform says about the instance (`RAILWAY_REPLICA_ID` and `RAILWAY_REPLICA_REGION`, `RENDER_INSTANCE_ID`, Fly's Machine ID). They are only for display and for routing (§3.4), never proof. The proxy checks the secret against `token_hash`, stores a **pending identity** with `pub_0`, and answers nothing more.
3. **The probe.** The proxy sends `GET https://<domain>/.well-known/klav/service-proof?s=<service_id>&n=<nonce>`, with a fresh 32-byte nonce for each probe. A header carries its signature over `tuple("klav/v1/sig/service-probe", service_id, domain, nonce)` with the proxy's key, which every instance pinned from the token. The probe follows the outbound rules of ADR 0036 §7:
   - HTTPS with the domain's certificate checked against the `webpki` roots;
   - no redirects;
   - DNS resolved by the proxy, and private, loopback and cloud-metadata addresses refused when connecting;
   - **a new connection for each probe,** because one kept-alive connection could stay on one replica.
4. **Whichever instance gets the probe answers with its own key only.** Its `klav-forward` checks the proxy's signature, so an unsigned probe gets a plain `404`, like any unknown path, and the endpoint is not a signing oracle. It answers `{v: 1, pub, sig}` with `sig = Sign_K(tuple("klav/v1/sig/service-domain-proof", service_id, domain, nonce, pub))`, where `K` is its current key: pending or enrolled, it makes no difference.
5. **The proxy marks whichever identity answered.** A pending identity becomes **enrolled** once its own key has answered a probe with a nonce from this proxy, through the domain. The proxy records `service.enrolled` (§9).

**Why this binds:** the only things that can sign with `pub_A` are processes that hold `A`. An attacker outside the domain holds `A`, but nothing behind the domain does, so no probe ever comes back signed by `A`. Their enrollment stays pending and fails. **This fails closed.**

**Why HTTPS and a checked certificate matter:** someone on the network path between the proxy and the domain does hold `A`, and could answer a plain-HTTP probe with it. ACME uses port 80 and several vantage points for this. Klav uses TLS to the domain's own certificate instead. The limit that remains is the domain itself (§12).

#### 3.3 Finding the right replica: the campaign
- **One campaign per service** runs while any identity of that service is pending. All pending identities share it, and every answer marks whichever identity answered.
- **Cost with random routing over `r` replicas:** the chance of missing one replica after `k` probes is `(1 − 1/r)^k`. Below one in a million, `k ≈ 14·r`:

  | Replicas | Probes (one in a million) | Time at 5 probes/s | Expected time for one replica |
  |---|---|---|---|
  | 1 | 1 | under 1 s | under 1 s |
  | 3 | 42 | 9 s | 0.6 s |
  | 10 | 140 | 28 s | 2 s |
  | 20 | 280 | 56 s | 4 s |

- **Load on the app:** none. The answer comes from `klav-forward`, which fronts the app (§3.9). Each probe is a TLS handshake and a signature.
- **Rate:** 5 probes per second per service by default, at most 20, signed in the definition.

#### 3.4 Fly: one probe
- On Fly, the proxy probes with `fly-force-instance-id: <Machine ID from the hints>`, and gets the Machine that claims to be enrolling in one probe, in any region.
- The hint only routes; the signature is still what proves. A false hint costs one probe, and the proxy falls back to the campaign.
- Fly's OIDC token would be stronger: an attestation that Fly runs that Machine, with its `image_digest`. Verifying it needs a JWT library or its own verifier. It stays for later, in its own ADR (§3.7).

#### 3.5 Pending enrollments and the alarm
- **Time:** a pending identity waits up to 15 minutes. The probes go at the campaign's rate for the first 2 minutes, and with backoff after that. Waiting that long is not a sign of attack: Render keeps all traffic on the old instance until the new one is healthy (§3.6).
- **Queue:** at most `16 × (max_replicas + surge)` pending identities per service. An entry is a public key and two times, so the queue costs little memory. The size is a default the implementation may tune ([decided on 2026-11-09](#four-more-decisions-2026-11-09)).
  - **A full queue evicts its oldest entry** instead of refusing the newest. Refusing the newest let a token holder keep the queue full, 15 minutes at a time, so that real instances were turned away at once and indefinitely (residual risk 65).
  - **During an incident, an entry that passed the domain proof and waits for the person's decision is never evicted** (§8.2). Only code behind the domain can make one. Such entries count against `max_replicas + surge` together with the connected identities, and one that would go above it is refused with `klav_over_limit` (§4.2), so they never hold more than a sixteenth of the queue.
  - **The bound that remains:** a real instance's entry survives until `16 × (max_replicas + surge)` newer ones arrive (at least 15 times that during an incident), and the campaign finds it at one in a million within `14 × r` probes (§3.3). With the default `surge`, a token holder has to send more than about 10 enrollments per second, without pause, to push a real instance out before the campaign finds it.
  - **Per source address,** at most two pending, but only where the proxy sees real client addresses (§8.3). Behind an edge every request shares the edge's address, and Railway's replicas share outbound addresses, so the limit would cap the whole service.
  - **Rotating the token purges the queue:** when a new definition changes `token_hash`, the proxy drops every pending entry made with the old token. (Note of 2026-11-18: with [ADR 0045](0045-keyless-services.md) §3.2, accepted and not built, it drops only entries made with a token the proxy no longer accepts. Entries made with the previous token stay during its 24-hour grace and are dropped when it ends, and `klav-forward` is told its token was rotated only once the proxy no longer accepts it.)
- **What `klav-forward` does after a refusal or an eviction:** it keeps the same key and asks again, with exponential backoff from 1 second up to 60, with jitter, until it enrolls. The exception is a `deny` or a `not_approved` during an incident (§8.2): then it makes a new key before it asks again. If the token was rotated, the refusal says so, and `klav-forward` stops asking and logs why: the instance needs the new variable, which the PaaS brings with a redeploy. Outbound calls meanwhile get `klav_not_enrolled` (§3.6).
- **On failure:** after 15 minutes with no answer, or when an entry that never answered is evicted, the proxy records `service.enrollment_failed` and raises the alarm "the enrollment token was used from outside the domain", at most once per service per hour. An entry that passed the proof but got no decision during an incident fails differently, as `not_approved` and without this alarm (§8.2). It sends a push the same way the theft signal does in ADR 0036 E5: no text, checked against the chain.
- **What the alarm does not do:** close enrollments. An attacker who could close them with a leaked token could take the service down. The alarm tells the person to rotate the token, and incident mode can close enrollments by hand (§8).
- **The cost of a leaked token is bounded:** at most one campaign per service, at the signed rate, whatever the attacker does.

#### 3.6 Lifecycle: enrollment happens after the platform routes to the instance
A new instance can't answer through the domain until the platform sends it traffic:

- **Render** keeps all traffic on the old instance until the new one passes its health check, and cancels the whole deploy if a new instance never does.
- **Railway** marks a deployment `Active` after its healthcheck.

So:

1. **`klav-forward` never holds up the app's start or its health check** because of enrollment. Health checks pass straight through to the app.
2. **Enrollment finishes after cutover:** seconds after the platform starts routing to the instance (§3.3).
3. **Outbound calls before enrollment wait up to 30 seconds,** then fail with `503` and `Klav-Error: klav_not_enrolled`, with a `message` and a `next` as in ADR 0036 §10. A health check that calls an AI API would never pass. `klav service add` says so, and the docs ask for health checks that don't depend on outside APIs.
4. **On Render,** instances enroll one by one, as the platform rolls them.
5. **On Railway,** old replicas get `SIGKILL` right after `SIGTERM` by default, with no time to retire (§4). Setting `RAILWAY_DEPLOYMENT_DRAINING_SECONDS` to a few seconds lets them retire cleanly.

**Several regions:** Railway routes "to the nearest region" first. The proxy probes from one place, so a replica in another region never gets its probes and never enrolls. The first version accepts **one region per service**, except on Fly, where §3.4 reaches any Machine. A pending identity whose region hint differs from the signed `regions` is refused at once with a clear message. A lie in the hint gains nothing, because the proof still binds. A replica in another region gets `klav_not_enrolled`: it fails closed, at a cost in availability (residual risk 67). Omar chose this in Q1; probes from several regions, like ACME's vantage points, are in [Later](#later).

#### 3.7 The CI window: an optional strict mode, later
- **How it works:** a deploy job in GitHub Actions asks for an OIDC token (`id-token: write`) and sends it to the proxy. The proxy checks the issuer, the audience and the claims the definition signs (`repository_id`, `ref`, `environment`), and opens a window of 15 minutes for up to `max_replicas` enrollments. Each enrollment in the window still needs the domain proof.
- **What it adds:** an attacker who runs code behind the domain but can't run the deploy workflow can't add instances outside a deploy.
- **What it costs:**
  - **A dependency.** The example token is `RS256`, and none of the approved crates verifies RSA. It needs its own ADR, as CLAUDE.md asks.
  - **It fails closed on restarts outside a deploy:** a crash, an autoscale-out or a host migration has no CI run. A single-replica app that restarts itself would stay out until the next deploy. The roadmap foresaw this, and it is why strict mode is optional.
  - **The softer rule this ADR proposes for later:** outside a window, an enrollment that **replaces** a lost instance is allowed (connected identities below the count when the window closed), with the domain proof. Growth needs a window. That keeps crash restarts working, and makes strict mode a poor fit for autoscaling.
- **Decision:** not in the first version. It goes in [Later](#later), with its own dependency ADR (Q6).

#### 3.8 What has no domain
Workers and cron jobs (Render `worker` and `cron`, and Railway services with no public domain) can't answer the probe. Two ways in, both later:

- the CI window with replacements of §3.7;
- or approving each enrollment by hand (§8.2).

They are out of the first version.

#### 3.9 How the probe reaches `klav-forward`: it fronts the app
The roadmap's sketch puts `klav-forward` beside the app for outbound calls and doesn't say how the challenge comes in.

- **The choice:** `klav-forward service run -- <command>` listens on the platform's `$PORT` and passes the app another port in `PORT`.
  - It answers `/.well-known/klav/` itself and passes everything else to the app unchanged: streaming, WebSockets and headers.
  - It never logs bodies.
- **What it costs:** one more hop for every incoming request, and a reverse proxy that has to be solid.
- **The alternative:** a handler in the app that passes the probe to `klav-forward` over a local socket. It changes the app's code, so it comes with the SDKs later. Omar chose fronting the app in Q7.

### 4. The replica limit, and how deploys avoid false alarms
#### 4.1 What counts
- **The proxy counts connected identities:** enrolled, not frozen, with an open channel. A channel sends a keepalive every 15 seconds, and one with no sign of life for 45 seconds counts as closed.
- **Why not every unexpired identity:** on Railway, an old replica gets `SIGKILL` with no time to say goodbye (draining is 0 seconds by default). Its key would stay valid until it misses a rotation (15 minutes, §5), so every deploy would look like a doubling. A killed process has no open channel, so counting channels sees the truth within 45 seconds.
- **A clone has to connect to be any use,** so it counts too.

#### 4.2 The three numbers, signed in the definition
| Field | Default | What it is |
|---|---|---|
| `max_replicas` | what the person sets: the PaaS replica count, or its autoscaling maximum | How many instances should be connected in normal operation |
| `surge` | equal to `max_replicas` | Extra slots while a deploy overlaps old and new instances. Equal to `max_replicas` so that a deploy that brings up the new replicas before stopping the old ones never looks like an attack |
| `surge_window` | 30 minutes, or 2 minutes per declared replica when that is longer | How much time, added up over the last `2 × surge_window`, more than `max_replicas` may stay connected before it is an alarm |

The `surge_window` default, like the queue size of §3.5, is a default the implementation may tune ([decided on 2026-11-09](#four-more-decisions-2026-11-09)).

**The rules:**

- **Enrolling beyond `max_replicas + surge` is refused** (`klav_over_limit`), and raises an alarm. This fails closed: an extra instance comes up, but its calls fail, and the person sees why.
- **Time above `max_replicas` adds up.** When the time spent above it over the last `2 × surge_window` passes `surge_window`, the proxy raises an alarm ("more instances than declared"), without cutting anyone, because it can't tell which one is extra.
  - **Why a sum and not a stretch:** a timer that measured continuous time above the limit restarted whenever the count dropped. Code inside the domain could drop its extra instance for 46 seconds every 29 minutes and never trip it. With a sum over a rolling window, an extra instance can be connected at most half the time without the alarm.

**Checking that the numbers agree:**

- **On Railway,** the surplus lasts the deploy's overlap plus at most 45 seconds, about a minute per deploy. A default window takes some 30 deploys an hour.
- **On Render,** it is one instance at a time, for about 90 seconds each (60 seconds before `SIGTERM`, plus the shutdown delay), so a deploy spends about 1.5 minutes above the limit per replica. That is why the default grows to 2 minutes per replica: a deploy of 20 replicas spends about 30 of its 40 minutes.
- **In both,** the surplus fits within `surge`.
- **What still raises the alarm:** on Render, a deploy followed at once by another, such as a rollback, adds up to about 3 minutes per replica within the window. The alarm cuts no one, and a person who deploys like that raises `surge_window` in the definition.
- Expiry plays no part, because the count uses channels (§4.1).

#### 4.3 The cases that must not raise alarms
| Case | What happens |
|---|---|
| **Autoscaling** (Render, Northflank) | `max_replicas` is the autoscaling maximum. Scaling out enrolls new instances through the domain; scaling in closes their channels |
| **Rolling deploy** | Covered by `surge` and `surge_window` (§4.2) |
| **A single replica that restarts itself** (a crash, or the platform restarting it) | The dead process's channel closes. The new process makes a new key and enrolls once the platform routes to it (§3.6). For at most 45 seconds both count, which `surge = 1` covers. A crash loop never adds up, because dead processes have no channel |
| **A clean stop** | On `SIGTERM`, `klav-forward` sends a retirement signed with its current key (`klav/v1/sig/service-retire`), and the proxy records `service.retired` (`stop`) and frees the slot at once. Then it passes `SIGTERM` on to the app |
| **Fly suspend and resume** | A resumed Machine still has its memory and its key, but a suspension longer than the expiry (15 min) leaves the key dead: `klav-forward` gets `unknown_identity` and enrolls a new key, in one probe (§3.4). A short suspension resumes the same identity. If the same snapshot were ever resumed twice, the two copies would fork at the next rotation: that is a real clone, and the alarm is right |
| **The proxy restarts** | §5.4 |
| **The person lowers `max_replicas`** below what is connected | Nobody is cut off; the surplus alarm starts its window, and a new enrollment above the limit is refused |

### 5. The key ratchet
#### 5.1 Rotation
Every `ratchet_period` (5 minutes by default), the instance at epoch `i`, holding `K_i`, rotates:

1. it generates `K_{i+1}` **once for that epoch** and keeps it until the proxy acknowledges;
2. it sends `rotate {identity, epoch: i+1, pub_{i+1}, sig_old, sig_new}`, where both signatures cover `tuple("klav/v1/sig/service-ratchet", service_id, identity_id, u64_be(i+1), pub_{i+1})`. `sig_old` is made with `K_i` (the chain of custody) and `sig_new` with `K_{i+1}` (proof that it holds the new key);
3. the proxy checks both signatures, **writes the successor to its store durably**, and only then acknowledges;
4. the instance erases `K_i`. New channels authenticate with `K_{i+1}`. The open channel stays up, because it belongs to the identity and not to the key.

**The `identity_id`** is the first 16 bytes of `SHA-256(pub_0)`. The apps show it next to the platform's hints, which are "according to the instance".

#### 5.2 Clones: what gives one away
A **clone** is a copy of a running instance's memory, and so of its current key: a memory dump, a copied snapshot, or a checkpoint restored twice. The proxy treats these as clone signals:

1. **A fork:** two different successors of the same key, `pub_{i+1} ≠ pub'_{i+1}`, both with valid signatures by `K_i`. This is the roadmap's signal. Any later attempt to rotate from a key that already has another successor is also a fork, so a late clone gives itself away by trying.
   - **This needs every key an identity has had,** not only its last successor. The store keeps the SHA-256 of each `pub_i` of each identity, 32 bytes per rotation (about 9 KB a day), while the identity lives and for 24 hours after it retires, expires or freezes.
   - A channel or a rotation with a key from that history that isn't the identity's last one is a clone: the proxy freezes the identity if it is alive, and raises the alarm either way.
   - A channel with the last key of an identity that expired gets `unknown_identity` and enrolls again, as on a Fly resume (§4.3). A key the proxy has never seen gets the same.
2. **Two live channels at once** as the same identity.
   - `klav-forward` closes its channel before it opens another, so a second channel is either a reconnect after the network dropped the first, or a second process. Either way, the identity owes a domain proof (signal 3).
   - When a second channel opens, the proxy sends a ping with a fresh nonce on the first. The answer is a signature by the identity's current key over `tuple("klav/v1/sig/service-ping", service_id, identity_id, nonce)`.
   - **No answer within 5 seconds:** the first channel was dead, and the proxy closes it, with no alarm. A network blip used to look like a clone and froze the instance's calls for up to 30 seconds.
   - **An answer:** two processes hold the key, and it is a clone.
3. **A domain proof the identity owes** (Q-E). When an enrolled identity opens another channel (a reconnect after a blip, a proxy restart, a Fly resume, or a resumed TLS session, which is a new channel too), the identity owes a new domain proof. **The debt belongs to the identity, not to the channel:**
   - **One clock per debt.** The identity's 2-minute clock starts at the first channel that owes the proof. Closing that channel and opening another doesn't restart it, and neither does any later reconnect. Only once the debt is cleared can a later channel start a new clock.
   - **Only a probe signed by the identity's current key clears it** (§3.2, step 4), answered through the domain to a nonce sent after the clock started.
   - **The proxy doesn't hold the calls** meanwhile. It adds the identity to the service's campaign (§3.3). At the deadline, if the debt is still open, it freezes the identity, whether or not a channel is open then.
   - **This covers the case the ratchet alone misses:** the original stops and a clone outside the domain carries on alone, with no fork. On Railway that is every deploy, which kills the old process with `SIGKILL`. To use the proxy the clone has to open a channel, and nothing behind the domain answers for its key. Until the freeze, it can call for up to 2 minutes from its first channel, and reconnecting buys no time (residual risk 66).
   - **The cost:** one campaign per reconnect, shared by every identity that owes a proof. After a proxy restart they all reconnect at once, and reaching every one of `r` identities, at one in a million of missing one, takes about `r × (ln r + 14)` probes. At the default 5 probes per second, 2 minutes cover about 30 identities; at the maximum of 20, about 120. `klav service add` picks the rate from `max_replicas + surge`. On Fly, each identity takes one probe with its Machine ID (§3.4).
   - **A definition must fit in the 2 minutes.** The 2 minutes are Omar's (Q-E), so the number of identities gives way, not the deadline: `klav service add` and `edit` refuse a definition whose `max_replicas + surge` is above what 20 probes per second cover in 2 minutes, about 120 identities, and the proxy refuses an older definition above it, so it fails closed. On Fly, where each identity takes one probe, the bound is 2,400. The bound follows the campaign's rate, so it moves if an implementation tunes that rate.
4. **A liveness failure,** as a backstop: a sweep every 30 minutes uses the campaign of §3.3, and an identity that doesn't answer through the domain in two sweeps in a row, whatever its channels, is cut off: the proxy freezes it (`no_domain_proof`). Sweeps follow the regions rule of §3.6. On Fly, each identity gets one probe with its Machine ID.

**What doesn't count as a clone:** an instance that lost the proxy's acknowledgment reconnects with `K_i` and resends **the same** rotation. The proxy recognizes `pub_{i+1}`, acknowledges again and does nothing else (§5.3).

**A channel opened with a key that already has a successor** (`K_i`, after the proxy stored `pub_{i+1}`) may only resend that identical rotation. The proxy acknowledges it and closes the channel, and the instance reconnects with `K_{i+1}`. Anything else on that channel is refused, and a different successor is a fork. That keeps the retry working without letting a superseded key serve calls.

**A copy taken in the middle of a rotation** holds both `K_i` and the pending `K_{i+1}`. It sends the same successor, so the proxy can't tell it apart at that step. At the next rotation, the two copies make different `K_{i+2}`: a fork. **Detection takes at most one period after the clone starts using the identity, as long as both copies keep running.** When only the clone runs, the domain proof its identity owes from the clone's first channel catches it within 2 minutes (signal 3), if it is outside the domain.

#### 5.3 Crash, retry, clock skew
- **A crash during rotation:** the process loses its memory, so its identity is gone with it. Its channel closes, the new process enrolls a new key, and the proxy expires the old identity at the end of its period.
- **A retried rotation is idempotent:**
  - same identity, same epoch and same `pub_{i+1}`: the proxy acknowledges again and changes nothing;
  - `klav-forward` never makes a second `K_{i+1}` for an epoch, because a new key would look like a fork.
- **Clock skew can't break anything:** the signed messages carry epochs, not times.
  - The proxy measures every deadline with its own monotonic clock: expiry 15 minutes after the last rotation (`ratchet_period` plus a grace of two periods), pending identities, keepalives, the surge window.
  - The instance's clock only decides when to rotate. A Fly Machine whose clock lags a few seconds after resuming rotates a few seconds late, which nobody notices.
  - The channel uses raw public keys or self-signed certificates with no expiry check (ADR 0036 §6).
- **Expiry:** an identity that misses its rotation for 15 minutes expires (`service.retired`, `expired`). Its key no longer opens a channel. If its process is alive, it gets `unknown_identity` and enrolls again through the domain.

#### 5.4 When the proxy restarts
- **The identities, their epochs and their key histories (§5.2) live in the proxy's store** (ADR 0036 §4), in its volume. A successor is written there before it is acknowledged (§5.1), so a restart never forgets one. A fork across the restart is still a fork.
- **On startup, every identity gets a new expiry deadline,** so the proxy's own downtime doesn't count against the instances. Instances reconnect with their current keys, and each identity owes a domain proof, with its clock started at its first channel after the restart (§5.2, signal 3): the restart costs one campaign per service, which is why a definition has to fit in 2 minutes.
- **If the store is lost** (a new volume), the proxy knows nothing. Every instance gets `unknown_identity` and enrolls again through the domain. Fork detection starts over: a clone made before the loss isn't seen by the ratchet, only by the domain proof of its new enrollment and by liveness. The proxy records `service.store_reset` so the person sees it.
- **The usage of the current 5-minute window lives in the same store** (§7.3), so a restart doesn't lose it.

#### 5.5 What happens to the clone and to the original
The proxy can't tell which copy is the original: both hold `K_i`.

1. **It freezes the identity:** both branches are refused, all their channels close, and their calls fail with `klav_identity_frozen`. It records `service.frozen` with the reason and its evidence (`clone`: the two successors, or the ping answered on two channels, and the addresses they came from; `no_domain_proof`: the identity, when its debt started, and the channels it opened meanwhile with their addresses, or, after a liveness failure, the two sweeps it didn't answer) and sends an alarm push. **A frozen identity frees its slot.**
2. **Each copy's `klav-forward` drops its key and tries to enroll a new one through the domain:**
   - **the original,** behind the domain, comes back in seconds, and its app waits at most 30 seconds (§3.6);
   - **a clone outside the domain** stays out, and its failed enrollment raises the alarm of §3.5;
   - **a clone inside the domain** (code running on the platform) comes back. That is the honest limit of §12 (residual risk 66), and the replica limit is the signal that remains.

Omar decided this in Q4: freeze the identity, keep enrollment through the domain open so the original comes back, and alarm, with incident mode one tap away. Klav never closes enrollments or starts incident mode on its own.

### 6. Policies and usage
> Omar's answer Q-A (2026-11-09): no spend caps in the first version. The caps, the signed price table, reservations and settlement, and the body edits that only served them (forcing `include_usage`, capping output tokens, refusing `n`) are gone. [Later](#later) keeps what a future ADR has to solve first. The proxy touches headers only, as in ADR 0036 §7, and reads the usage that responses already carry.

#### 6.1 Policies per service
Each service carries its own policy, signed in its definition and applied by the proxy:

- **What ADR 0036 already gives:** items, profiles with hosts, methods and path prefixes, a rate per service and per identity, a maximum body size and request time, SSRF defense and redaction.
- **Rate:** by default, 60 calls per minute per identity, as for a sandbox (ADR 0036 §8), and `60 × max_replicas` per minute per service, both signed in the definition. A busy app raises them. They are defaults the implementation may tune.
- **No `ask` in a service's profiles** (§6.3).
- **AI presets:**

  | Preset | Host | Paths (`POST`) | Credential |
  |---|---|---|---|
  | `openai` | `api.openai.com` | `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings` | `Authorization: Bearer` |
  | `anthropic` | `api.anthropic.com` | `/v1/messages` | `x-api-key` |

  Anything else (batch jobs, files, admin endpoints, `GET /v1/responses/{id}`) is outside the profile and gets `klav_not_allowed`, unless the person adds it.
- **No list of allowed models** in the first version (Omar, 2026-11-09). It is a spend control, and enforcing it means reading `model` from the request body. For a service's calls, the proxy never parses a request body: it counts its bytes against the maximum size and passes it on unchanged. The list is in [Later](#allowed-models), next to the caps.
- **Concurrency:** at most 16 calls in flight per service by default, so one service can't take the whole proxy. Like the rate, it bounds the number of calls, not what each call costs (§12, limit 4).

#### 6.2 Usage in each response
The proxy reads usage from the response, never from the app, and only when the response carries it. It never edits a request or a response to get it.

- **OpenAI Chat Completions** ([reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)):
  - `usage.prompt_tokens`, `completion_tokens` and `total_tokens`, with `prompt_tokens_details.cached_tokens` ("Cached tokens present in the prompt") and `completion_tokens_details.reasoning_tokens`.
  - **When streaming,** usage only arrives if the request sets `stream_options.include_usage`: then "an additional chunk will be streamed before the `data: [DONE]` message", whose `usage` covers "the entire request". The proxy doesn't add it. A streamed call without it counts as a call with no tokens.
- **OpenAI Responses:**
  - `usage.input_tokens`, `input_tokens_details.cached_tokens`, `output_tokens`, `output_tokens_details.reasoning_tokens` and `total_tokens`. Reasoning tokens are billed as output tokens and are already counted in `output_tokens` ([reasoning guide](https://developers.openai.com/api/docs/guides/reasoning)).
  - **When streaming,** `response.completed` ("Emitted when the model response is complete") carries the whole `response`, and so does `response.incomplete`; `usage` is "optional ResponseUsage or null" ([streaming events](https://developers.openai.com/api/reference/resources/responses/streaming-events)).
  - With `background: true` and no `stream`, the usage only arrives through `GET /v1/responses/{id}`, which the preset leaves out: the call counts with no tokens.
- **Anthropic Messages:**
  - **Without streaming,** the response's `usage` carries `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens` and, when server tools ran, `server_tool_use` (for example `web_search_requests`).
  - **When streaming** ([streaming](https://platform.claude.com/docs/en/build-with-claude/streaming)), `message_start` carries the input counts and `message_delta` the rest. "The token counts shown in the `usage` field of the `message_delta` event are *cumulative*", so the proxy keeps the last values and never adds them up.

**What it is for:** the usage record of §7.3 and the incident report of §8.2: calls, tokens where the response reports them, and addresses, per model as the response names it. The proxy never takes the model from the request. No dollars and no prices: what a call cost depends on pricing tiers the proxy can't see (see [Later](#later)).

#### 6.3 No approvals in a service's profiles
A profile of ADR 0036 can put a call in `ask`, and an approval comes from the per-call access of ADR 0036 §9 with a person at the card. A service has neither: its calls go through the lease (§7), and nobody is there to approve a production app's calls one by one.

- **Decision:** a service's profiles have no `ask`. `klav service add` and `edit` refuse one, and the proxy refuses a definition that carries one, so an old definition fails closed.
- **What a dangerous call gets instead:** it stays out of the profile (`klav_not_allowed`). The AI presets only allow `POST` to the paths of §6.1.
- **The person's approval does exist in one place:** enrollments during incident mode (§8.2), which is an account-signed decision, not a call.

### 7. How the server takes part: a lease per service
#### 7.1 Why not per call
ADR 0036 §2 has the proxy make a signed `POST /v1/agent/access` for each request it injects, and "the authorization is never cached". For a deployed service that makes thousands of calls a day, that means:

- **latency:** one round trip to the Klav server before every AI call;
- **availability:** the app can't call the AI while the Klav server is down;
- **volume:** one audit event per call, so tens of thousands a day for a single service;
- **metadata:** the server learns the timing and volume of every call the app makes.

ADR 0036 §2 already says that another ADR may group these. This is that ADR. With the lease, the chain gets an `agent.access` when the proxy reads an item (§7.2), a few per item and day, not one per call.

#### 7.2 The lease
- **The proxy renews a lease per service** every 30 seconds with a signed `POST /v1/agent/services/lease {service_id}`, so a slow renewal never leaves a gap. The server answers `200` if:
  - the proxy is not revoked, and not paused by its own ID (the global pause leaves services running, Q3, §10.3);
  - the account has no pending deletion (Q-B, §10.4);
  - the service is in the proxy's current grant;
  - the service is not stopped (§8.4). The lease of a stopped service gets `403 service_stopped`, and the service's calls `423 klav_service_stopped`, as a pending deletion pairs `403 account_deleting` with `423 klav_account_deleting` (§10.4).

  The answer also brings:
  - the newest account-signed states for the service and for `all` (§8.6);
  - the newest enrollment decisions and freezes for the service, signed by the account (§8.2);
  - the `version` of each item the service's profiles use.

  The server keeps only the latest lease of each service, outside the chain, like the latest-only heartbeat of ADR 0036 E3.3.
- **The proxy injects only while it holds a lease less than 60 seconds old.** Without one, calls fail with `503 klav_server_unreachable`, as in ADR 0036 §10.
- **The proxy reads an item's value** with `POST /v1/agent/access`, `permission: proxy` and a new `service` field declared instead of a sandbox: the first time a service needs the item, and again whenever the lease answer shows a newer `version`. So a key the person rotates and saves in Klav reaches the proxy within one renewal, without redeploying (§8.2, step 3). `GET /v1/agent/items` lists items without their values (`api.md` §8.3), so it isn't the read.
- **The decrypted item lives in the proxy's memory while its leases keep renewing,** in a `SecretBox`, and is zeroed when the lease ends without renewal, when the grant changes, or when a newer version replaces it. ADR 0036 decrypted it per call.

**This is a cached authorization, bounded to 60 seconds:** exactly what ADR 0036 §2 forbids, and this ADR says so. In exchange:

- a pause, a stop or an incident reaches the service within 60 seconds, not on the next call;
- a server outage of under a minute doesn't stop the app;
- the server sees two renewals a minute per service, not each call.

Per-call access stays for sandboxes. Omar chose the 60-second lease in Q2 (residual risk 69). ADR 0036 §2 points here.

#### 7.3 What goes into the audit chain
- **Lifecycle events,** at once: `service.enrolled`, `service.enrollment_pending` (during an incident, §8.2), `service.enrollment_failed`, `service.retired`, `service.frozen`, `service.alarm` and `service.store_reset` (§9.3).
- **Usage, once per window:** a `service.usage` event per service for each 5-minute window with any calls, so at most 288 a day per service, and none for a quiet service. It covers each identity, item and model (as the response names it, §6.2): calls, tokens where the response reported them (§6.2) and how many calls had none, refusals, and the source addresses the proxy saw (§8.3). No dollars (Q-A).
- **Its body is sealed for the account** with HPKE to the account's X25519 identity, the primitive Klav already uses to share keys, and signed by the proxy. The server stores and chains it without reading it: it sees that the event exists, its size and its time. The person's devices open it to show usage and to build the incident report. A company's AI usage, and where it comes from, is business data the server doesn't need. Omar chose this in Q8.

### 8. Incident mode
#### 8.1 Who turns it on
- **The person,** from any device: the Mac, the iPhone, or `klav service incident start [--service NAME | --all]`.
  - **It asks for no Touch ID or Face ID,** like "Pause agents" (ADR 0033 §7.3) and the sandbox revocation of ADR 0036 E2.3: it only takes access away. With `klavd` locked, it works like the pause: the Mac asks to unlock, and the iPhone is the fast path.
  - **It is signed by the account:**

    ```
    tuple("klav/v1/sig/service-state", account_id, proxy_id, scope, state, u64_be(at_ms))
    ```

    `scope` is a `service_id` or `"all"`; `state` is `incident`, `incident_end`, `stop` or `resume` (§8.4). `stop` and `resume` are one switch, and `incident` and `incident_end` another. The server checks the signature, an `at_ms` within ±5 minutes, and that it is later than the last one for the same scope and switch, as with the pause. The proxy keeps the same order on its own (§8.6). The exact encoding and its vector come with the code.
- **Not the proxy.** On a clone it freezes the identity and raises the alarm (Q4, §5.5); incident mode stays one tap away.
- **Not the Klav server.** It can't sign as the account, so it can't start an incident or end one.

#### 8.2 What it does, for one service or for all
1. **It closes enrollments.** Each new enrollment still needs the domain proof, and now **also the person's approval** with Touch ID or Face ID. The card shows:
   - the service;
   - the platform hints "according to the instance";
   - the source address;
   - when the domain proof passed.

   The decision is signed by the account and names the identity it decides on, so a server can't reuse an approval for another pending identity:

   ```
   tuple("klav/v1/sig/service-enrollment", account_id, proxy_id, service_id, identity_id, pub_0, decision, u64_be(at_ms))
   ```

   `decision` is `approve` or `deny`, and the chain gets `service.enrollment_decided`. That keeps a service usable during an incident: a crashed instance comes back when the person says so.

   - **How the card reaches the person:** when an identity passes the domain proof during an incident, the proxy records `service.enrollment_pending`, signed by the proxy, with a body sealed for the account: `identity_id`, `pub_0`, the hints, the source address and when the proof passed. The `service_alarm` push announces it (§10.1). The card doesn't depend on the push, whose budget may be spent: the service's page lists every enrollment waiting for a decision, from the chain.
   - **How the decision reaches the proxy:** the device sends it to the server, which chains `service.enrollment_decided`. The lease answer and `GET /v1/agent/services/state` carry the newest decisions, and both routes stay open during a global pause (§10.3). The proxy checks the account's signature and that the decision names an identity it holds waiting, with that `pub_0`.
   - **Each key is decided once.** The proxy keeps in its store, for the incident, the identities it has decided on. A decision for one already decided, or for one that isn't waiting, changes nothing, so a server that replays an old decision gains nothing.
   - **A waiting entry is never evicted** (§3.5) and counts against `max_replicas + surge`. After 15 minutes without a decision, a default the implementation may tune, the proxy drops it and records `service.enrollment_failed` with the reason `not_approved`, without the alarm of §3.5, because the domain proof passed. After `deny` or `not_approved`, `klav-forward` makes a new key and asks again with backoff (§3.5), so each new card is a new identity.
2. **It freezes the identities.** The set of identities connected at the start is fixed:
   - they keep working and keep rotating, and a fork still freezes one (§5.5);
   - one that leaves is not replaced, except through an approved enrollment;
   - from the report or the list of instances, the person can freeze any one ("Freeze this instance", or `klav service instances --freeze ID`), without biometry, because it only takes access away. It is signed by the account, `tuple("klav/v1/sig/service-freeze", account_id, proxy_id, service_id, identity_id, u64_be(at_ms))`; the chain gets `service.freeze_requested`. It reaches the proxy like a decision, in the lease answer or `GET /v1/agent/services/state`, and the proxy records `service.frozen` with the reason `person`. A freeze for an identity already frozen or gone changes nothing. A frozen identity frees its slot. It works outside an incident too.
3. **It rotates what can be rotated:**
   - **The enrollment token:** incident mode offers `klav service token rotate` at once. It is in Klav's hands, because the person's device makes it.
   - **The provider keys behind the service:** rotating them at the provider belongs to `klav rotate`, in the single-source ADR. Until that exists, incident mode lists each item with its provider's key page. When the person saves the new value in Klav, the item's `version` moves, and the proxy reads the new value at its next lease renewal, within 30 seconds (§7.2), **without redeploying**, because the app never had the key. When `klav rotate` exists, this step runs it for every item with an API.
   - **Why rotate at all,** if the variables leaked nothing? Because whoever had the identities may have used the proxy, and because the incident may not be the PaaS's.
4. **It reports which identity used which key, from where, and how much,** in calls and tokens. The person's device builds the report from the chain, opening the sealed events (§7.3). For each identity, it shows:
   - when and how it enrolled: the domain proof, its hints "according to the instance", the source address and whether it was approved;
   - its rotations and alarms;
   - for each item and model: calls, tokens where the responses reported them, refusals, and the source addresses as the proxy saw them.

   The report exports to JSON and CSV (`klav service incident report`). It shows what the proxy recorded: a compromised proxy can lie (§9.4).

#### 8.3 "From where": what the source address is worth
- **What the proxy records:** the source address of each channel when it enrolls, rotates and reconnects.
- **When it is real:** only where the proxy's own host passes the client's address, as on a VPS that terminates the channel itself. Behind an edge or a layer-4 proxy that doesn't pass it, the address is the edge's, and the report says so.
- **Checked later:** whether each platform's layer-4 proxy keeps the client's address, per platform, when the proxy's hosting docs are written. This ADR doesn't claim it.
- **A signal, not a quarantine:** an identity whose source network changes between rotations raises `service.alarm` (`egress_change`) and nothing else, as the roadmap says, because an attacker also runs in AWS or GCP, and a PaaS's outbound addresses may change.

#### 8.4 "Stop service": the switch that cuts everything
- **What it does:** all of a service's calls get `423` with `Klav-Error: klav_service_stopped`, within one lease (at most 60 seconds, §7.2). Incident mode keeps the service running and contains it; stopping cuts it off. A stop of `all` stops every service of the proxy, and a stop wins over incident mode (§8.6).
- **Two barriers:**
  - the server refuses the lease of a stopped service (`403 service_stopped`), so an honest proxy stops even if it never learned why;
  - the proxy stops as soon as it learns.
- **Costs:** stopping asks for nothing, and resuming asks for Touch ID or Face ID, like pausing and resuming agents. It uses the same signature, with `state` set to `stop` or `resume`.

#### 8.5 How it ends
- **Only the person ends it,** with Touch ID or Face ID (or the master password where there is neither), signing `incident_end`, like resuming the agents.
- **What changes:** enrollments open again. An entry still waiting for a decision enrolls at once, because its domain proof already passed, and the proxy forgets which identities it decided on during the incident.
- **What doesn't:**
  - frozen identities stay frozen, and their instances enroll again through the domain;
  - definitions;
  - the report, which is still in the chain.
- **The closing card** lists the items that are still not rotated.
- **An incident never ends on its own,** and has no duration.

#### 8.6 How the proxy finds out, and in what order
- **Two ways in:**
  - the lease answer, every 30 seconds;
  - `GET /v1/agent/services/state?since=` on startup and on waking, before serving.

  Both also carry the enrollment decisions and freezes of §8.2.
- **Signatures:** the proxy checks the account's signature with the identity it pinned when it paired, so a server can't make up an incident, a stop or an end.
- **The proxy keeps the order itself.** A signed state belongs to a scope (one service or `all`) and a switch (`stop`/`resume`, or `incident`/`incident_end`).
  - For each scope and switch, the proxy writes the newest `at_ms` it applied to its store before it applies the state, and refuses any state with an `at_ms` older than or equal to it, whatever the server sends.
  - So a server that replays an older, validly signed `resume` after a proxy restart can't undo a stop.
  - If the store is lost, the proxy can't tell. The chain can (below).
- **Precedence:**
  - **`all` and one service are separate switches, and the stricter wins.** A service is stopped while its own switch or the `all` switch says `stop`. Resuming `all` doesn't resume a service stopped on its own, and resuming that service doesn't lift a stop of `all`. Incident mode works the same way.
  - **A stop wins over incident mode.** While a service is stopped, nothing runs. When it resumes and incident mode is still on, incident mode applies.
- **The confirmation:** the proxy records each state it applies, with that state's `at_ms`: `service.stop_applied`, `service.resume_applied`, `service.incident_applied` and `service.incident_end_applied`. As with the sandbox revocation of ADR 0036 E3.3, the app shows "Starting…" or "Resuming…" until it sees the event, and "The proxy hasn't confirmed" after 2 minutes.
- **What the chain checks:** each applied event names a `service.state` earlier in the chain with the same scope, state and `at_ms`, and for each proxy, scope and switch the applied `at_ms` only grow (§9.3). A proxy that applied an older state, after a lost store or through a bug, shows up in `klav log verify`, and the app says "The proxy applied an older state".

### 9. Where everything lives, and who signs it
#### 9.1 The table
| What | Lives in | Decides | Signs | In the chain | What the server sees |
|---|---|---|---|---|---|
| Service definition: domains, limits, ratchet period, items, profiles, token hash | The proxy's grant | The person | The account | `agent.granted` | Everything in it, in clear (residual risk 68) |
| Enrollment token | The PaaS variables, and nowhere else | Made on the person's device | — | No | Only the hash of its secret |
| Instance identities, epochs, key histories | The proxy's store | The proxy | Each instance's key | Lifecycle events | Opaque identity IDs and times |
| Domain proof | The proxy | The proxy | The instance (answer) and the proxy (probe) | `service.enrolled`; during an incident, `service.enrollment_pending` first, sealed | That it happened, and when |
| Replica limit, clones, liveness, source changes | The proxy | The proxy | The proxy | `service.alarm`, `service.frozen` | The kind and the time; details sealed |
| Policies: profiles, rates, concurrency | The service definition, in the proxy's grant | The person | The account | `agent.granted` | Everything in it, in clear (residual risk 68) |
| Usage counters | The proxy's store | The proxy | The proxy | `service.usage`, sealed | That there was usage in a window, and the event's size |
| Lease | The server, the latest only | The server | The proxy's request | No | Two renewals a minute per service |
| Reading an item for a service | The proxy's memory, while the leases renew | The server, on the grant and the lease | The proxy's request | `agent.access`, with the `service` | Which item, for which service, and when |
| Stop, resume, incident start and end, enrollment decisions during an incident, freezes by the person | The server and the proxy | The person | The account | Yes | Scope, state and time, in clear |
| The order of the stops and incidents applied | The proxy's store | The proxy | — | The `*_applied` events | Which states the proxy applied, and when |
| Provider keys | The vault, decrypted only in the proxy's memory | The person | — | — | Ciphertext only |

**The Klav server stays zero-knowledge:** it never sees a provider key, a prompt, a usage figure or a source address.

#### 9.2 A malicious Klav server
**It can:**

- refuse leases, which stops every service: the same denial of service as refusing sync;
- learn the metadata of the table: definitions, when events happen, how big they are, and the lease cadence;
- leave out the events after the last signed head (residual risk 10);
- hold back a stop or an incident from the proxy. The app sees no `service.stop_applied` or `service.incident_applied` and says so, and the proxy polls;
- send false alarms. The app checks the chain before showing one, as with the theft signal of ADR 0036 E5 (T173).

**It can't:**

- enroll an identity;
- change a definition;
- start or end an incident, stop or resume a service, freeze an identity, or approve an enrollment;
- undo a stop or an incident by replaying an older signed state: the proxy keeps the order (§8.6);
- read usage or addresses;
- see a key or a prompt.

#### 9.3 `klav log verify`
- **New actions in the closed table** (ADR 0030 §4):
  - **signed by the proxy, with a body:** `service.enrolled`, `service.enrollment_pending`, `service.enrollment_failed`, `service.retired`, `service.frozen`, `service.alarm`, `service.usage`, `service.store_reset`, `service.stop_applied`, `service.resume_applied`, `service.incident_applied` and `service.incident_end_applied`;
  - **signed by the account:** `service.state` (stop, resume, incident, end of incident), `service.enrollment_decided` and `service.freeze_requested`.
- **Errors:**
  - a service event from a proxy whose identity isn't vouched for by an earlier `agent.granted`;
  - a service that is not in that grant;
  - an identity's event before its `service.enrolled`;
  - an applied event with no `service.state` before it with the same scope, state and `at_ms`, or with an `at_ms` lower than one the same proxy already applied for that scope and switch (§8.6);
  - a `service.frozen` with the reason `person` and no `service.freeze_requested` before it.
- **Warnings,** like the pause check of ADR 0033 §7.6:
  - a `service.enrolled` during an incident with no `service.enrollment_decided` that approves that `identity_id`;
  - a `service.enrollment_decided` with no `service.enrollment_pending` for that `identity_id` before it;
  - a `service.usage` for a window that starts more than 60 seconds after a `stop`;
  - during a global pause, an `agent.access` of the proxy that declares no service: the pause check of ADR 0033 §7.6 now skips the routes of §10.3, and only those.
- **Sealed bodies:** `verify` checks the signature over the ciphertext. The person's device opens them to show them and to check that what is inside matches the event, such as the service and the identity.
- **Old verifiers:** one from before these actions fails on a chain that has them, as happened with the pause. The CLI, `klavd` and the Mac and iOS apps ship together.

#### 9.4 A compromised proxy, and a compromised instance
- **A compromised proxy** holds every value granted to it and sees every prompt that goes through it. It can lie in every event (enrollments, usage, alarms), ignore policies, freezes, stops and incidents, and enroll anything. The lease only stops an honest proxy. The incident report can't be trusted for that proxy.
  - **What limits it:** per-item grants, so it holds only what was granted.
  - **What helps:** revoking the proxy and rotating the keys at the provider (ADR 0036 §18, residual risk 52).
- **A compromised instance** (code running in the container): §12.

### 10. A service in the apps, in the CLI and in the pause
#### 10.1 The apps
- **Mac, Development › Services:**
  - **for each service:** its name and domain, connected instances against `max_replicas`, calls and tokens this hour and today, its alarms and its incident state;
  - **inside a service:** its instances (identity, hints "according to the instance", connected since, source address, rotations), the enrollments waiting for a decision during an incident (§8.2), the report, "Stop service", "Start incident mode" and "Rotate the enrollment token".
- **iOS:**
  - a "Services" section in the Agents sheet;
  - a red card above the vault for a clone alarm or an incident, like the theft signal of ADR 0036 E4.
- **Alarms and incidents:**
  - **pushes carry no text** (`service_alarm`): the app fetches the event and checks it in the chain before showing it;
  - **budget:** at most 10 `service_alarm` pushes per hour per account, like `sandbox_theft` (ADR 0036 E5). Beyond that, alarms still go into the chain and the list, and one more push says there are more;
  - **they are never hidden** by the "Development" switch (ADR 0033 E1).

#### 10.2 The CLI
- **The commands:**
  - `klav service add | ls | show | edit | remove`;
  - `klav service token rotate`;
  - `klav service stop | resume`;
  - `klav service instances [--freeze ID]`;
  - `klav service incident start | end | report`.
- **They are all the person's.** The skill lists them among the person's commands, which an agent never runs (ADR 0036 E1.2).

#### 10.3 "Pause agents" and services
- **How the pause works today:** ADR 0033 §7.1 has the server reject every signed request of a paused agent except `GET /v1/agent/me`, and ADR 0036 E2.2 relies on that to stop sandboxes. The proxy is an agent, so a global pause would also stop every service: a company's production app.
- **Omar's decision (Q3):**
  - the global pause (`all`) leaves services running. Sandboxes stop, as before;
  - pausing the proxy by its own ID stops everything, services included;
  - the "Pause agents" sheet lists the services that keep running, with a link to "Stop service".
- **The routes that stay open.** During a global pause, the server keeps answering a proxy whose grant has services, but only on these routes and only for its services:

  | Route | What for | Limited to |
  |---|---|---|
  | `GET /v1/agent/me` | Exempt for every agent already (ADR 0033 §7.1) | — |
  | `POST /v1/agent/services/lease` | The lease (§7.2) | The services in its grant |
  | `GET /v1/agent/services/state` | The signed stops and incidents, on startup and on waking (§8.6), and the enrollment decisions and freezes (§8.2) | Its services and `all` |
  | `GET /v1/agent/items` | Fetching the items again, after a restart or a grant change | The items that its services' profiles use |
  | `POST /v1/agent/access` | Reading an item's value for a service, the first time and when the lease shows a newer `version` (§7.2) | A request that declares a service, never a sandbox |
  | The signed requests that record `service.*` events (§9.3) | Lifecycle, usage, alarms and the applied events | `service.*` actions only |

  Anything else, and any request that declares a sandbox, gets `403 agents_paused` as before. Without this list, a proxy that restarted during a global pause couldn't fetch its items, read the state or record its events, and every service would stop.
- **ADR 0033 §7.1 and T133 change with it.** The pause no longer means "every request of every agent". ADR 0033 §7.1 carries a dated note pointing here, and T133 in the threat model says that the carve-out is accepted and pending implementation. Both are amended in this ADR's PR.
- **Why:** "Pause agents" is the button for a scare about coding agents. Taking a production app down by surprise is worse, and services have their own stop and incident mode.
- **What it costs:** a carve-out on the server, and `klav log verify` gains one check: during a global pause, an `agent.access` of a proxy is allowed only when it declares a service.

#### 10.4 A pending account deletion stops services at once
ADR 0037, accepted in PR #235, cuts every agent off as soon as the person asks to delete the account: during the 7 days, the server answers `403 account_deleting`. The proxy is an agent. Omar decided (Q-B) that services get no carve-out here.

- **The server refuses the lease** from the moment of the request. An honest proxy stops serving as soon as a renewal gets `403 account_deleting`, so within 30 seconds, and within 60 if renewals were failing anyway (§7.2).
- **The service's calls get `423`** with `Klav-Error: klav_account_deleting`, like `klav_agents_paused` and `klav_service_stopped`, with the `message` "The person asked Klav to delete this account, so Klav stopped this service's access to its AI keys." and a `next` telling the app's operators to ask the person.
- **Canceling the deletion** brings them back at the next lease. Canceling asks for presence (ADR 0037, A2).
- **The deletion sheet says so.** This ADR plans one more line for ADR 0037 §7.2, the first confirmation, shown only when the account has services. It is added in the apps' layer, not by editing ADR 0037:

  | es | en |
  |---|---|
  | Tus servicios desplegados también se detienen ahora: %@. Vuelven a funcionar si cancelas el borrado. | Your deployed services stop now too: %@. They start working again if you cancel the deletion. |

  The `%@` is the list of service names. The waiting screen (ADR 0037 §7.4) says "except for your agents and your deployed services" in the same case, and `klav account delete` prints the same line.

### 11. Running the proxy as production infrastructure
- **One process and one store:** the proxy is a single point of failure for every service it serves. If it goes down, their AI calls fail with `klav_proxy_unreachable`. Running two proxies would need a shared store and a shared view of every ratchet, and is out of the first version.
- **It is in the path of every AI call,** one more hop. Put it close to the services.
- **The hosting rules of ADR 0036 §11 still hold:**
  - a separate service;
  - its key in a volume file, never in a platform variable;
  - no injected token may reach the proxy's own host (T151).

  AI keys don't reach a PaaS, so for them T151 doesn't rule out the same platform.
- **A new rule:** the proxy doesn't run on the same platform account as the services it serves. Otherwise a single breach of that platform, like the ones in October, gives the attacker both the enrollment token and the proxy's volume with its key. `klav service add` warns when the service's domain and the proxy's look like the same platform.

### 12. Honest limits
1. **Code running inside the container is contained, not prevented.** While it runs, it can:
   - call the AI through the proxy, within the profile, with any model the provider key reaches and no spend cap (limit 4);
   - read the prompts and responses of the app;
   - enroll more instances through the domain, up to `max_replicas + surge`, with an alarm once the time above `max_replicas` adds up past `surge_window` (§4.2).

   That is residual risk 66. What changes from today:
   - there is no provider key to carry away;
   - when it loses execution, its access ends;
   - every call is tied to an identity, and its usage is in the chain within 5 minutes. Nothing alerts on it in this version: the person sees it by opening Development › Services on the Mac or the Services section on the iPhone (limit 4).
2. **Whoever controls the domain passes the challenge:** taking over the DNS, compromising the edge, or a PaaS control-plane attacker who can deploy or reroute traffic. In October, the attackers reached the variables; whether they could also deploy is not public. The signals that remain are the replica limit, liveness and the deploy in the platform's own log. ACME has the same limit (RFC 8555 §10.2).
3. **A clone inside the domain whose original is gone** gives no signal: no fork and no failed liveness check (residual risk 66).
4. **No spend caps and no usage alarm in this version** (Q-A, residual risk 69).
   - **The proxy bounds the number of calls** (the rate per service and per identity, 16 open calls), **not what each call costs:** the body picks the model, the length, `n`, `background` and stored context, and the proxy doesn't read it; a `background` call frees its slot at once.
   - Code inside the domain, or a clone until it is frozen, spends within those numbers, on any model the provider key reaches. Beyond them, what bounds the cost is the provider, where it offers a hard limit, and its model restrictions where it has them ([Later](#allowed-models)).
   - **Nothing alerts on usage.** The usage record has the calls and tokens within 5 minutes, but the person only sees them by opening Services. «Stop service» cuts the calls within one lease.
   - [Later](#later) says what caps need, and keeps a usage notice computed on the person's device.
5. **A leaked token can delay enrollments** until it is rotated (residual risk 65).
6. **The proxy sees prompts and responses,** and whoever operates its host can read its memory (residual risk 53). That's why there is no hosted proxy without an enclave (ADR 0036 §12).
7. **One proxy, and a lease tied to the Klav server** with 60 seconds of slack (§7.2, §11, residual risk 69).
8. **The server learns metadata:** service domains and limits, and when events happen and how big they are (residual risk 68).
9. **The first version covers** one region per service (any number on Fly, residual risk 67), up to about 120 connected identities per service (2,400 on Fly, §5.2, signal 3), web services with a public domain, and AI APIs. No workers, serverless or databases.
10. **The variables that can't go behind the proxy still leak** until the single-source ADR.

## Rejected alternatives
- **A MAC with the enrollment token as the answer to the challenge:** any real replica can answer for an attacker's key. It fails open (§3.1).
- **The instance pushes its proof to the proxy over the channel:** it proves nothing about the domain, and an attacker can push too. It fails open.
- **Platform instance IDs as proof** (`RAILWAY_REPLICA_ID`, `RENDER_INSTANCE_ID`): they aren't secret, and the instance itself reports them. They stay as hints.
- **The probe over the platform's private network:** the proxy would have to live in the services' network, on the same platform and project (Railway isolates each environment's network). That goes against the rule of §11. Later, as an optimization only, Render's `RENDER_DISCOVERY_SERVICE` could let the replica that gets a probe hand it to the right one in a single probe, still bound by the signature.
- **A service as an agent, or an agent per instance:** it puts a Klav key where others can copy it (§1).
- **The CI window as the only gate:** it fails closed on every restart outside a deploy and needs an RSA dependency (§3.7).
- **A one-time token per instance, like `ksb1_`:** someone would have to issue one on every restart and every autoscale-out, and nobody is there to do it.
- **Counting every unexpired identity for the replica limit:** every Railway deploy would raise an alarm (§4.1).
- **Usage in clear in the chain:** the server would learn a company's AI usage and where it comes from (§7.3, Q8).
- **A proxy hosted by Klav:** only as an attested proxy (ADR 0036 §12), and here with more reason, because it sees the prompts.

## Consequences
- **New formats,** each with a version byte from the first byte, and with its section of the spec and its vectors in `docs/vectores/` in its layer:
  - the `kse1_` token;
  - the grant with `services`, one version after ADR 0036's `v: 2`;
  - the signature labels `klav/v1/sig/service-probe`, `service-domain-proof`, `service-ratchet`, `service-retire`, `service-ping`, `service-state`, `service-enrollment` and `service-freeze`;
  - the channel messages (`enroll`, `rotate`, `retire`, `ping`);
  - the sealed bodies of `service.usage`, `service.alarm` and `service.enrollment_pending`;
  - the proxy's store, with the key histories and the order of the states it applied.

  This ADR doesn't take a section of the spec.
- **Protocol:**
  - `POST /v1/agent/services/lease` and `GET /v1/agent/services/state`. The lease answer carries the newest states, the newest enrollment decisions and freezes, and the `version` of each item the service's profiles use; the state route carries the same states, decisions and freezes;
  - a `service` field in `POST /v1/agent/access`, declared instead of a sandbox, to read an item's value for a service (§7.2, §10.3);
  - `POST /v1/services/state`, the enrollment decisions and the freezes, signed by the account;
  - the routes a global pause leaves open for services (§10.3), and the lease refused with `403 service_stopped` for a stopped service (§8.4) and with `403 account_deleting` during a pending deletion (§10.4);
  - the reason `not_approved` in `service.enrollment_failed` (§8.2);
  - the new actions in the closed table;
  - the push `service_alarm`, with its budget;
  - the forwarder's new errors: `klav_not_enrolled`, `klav_over_limit`, `klav_identity_frozen`, `klav_service_stopped` and `klav_account_deleting`;
  - a `service` event in `GET /v1/events`.
- **`klav-forward service run`** fronts `$PORT`, holds the instance key and rotates it. **`klav-proxy`** gains enrollment, campaigns, the ratchet, alarms, the AI presets, the usage record and the leases.
- **No new dependencies.**
  - Ed25519, HPKE and SHA-256 come from `klav-core`.
  - TLS uses `rustls` with `aws-lc-rs`, as in ADR 0036.
  - The CI window and Fly's OIDC token need JWT verification (`RS256` for GitHub) and their own ADR.
- **It diverges from ADR 0036 §2 on purpose:** a 60-second lease per service instead of per-call access, for services only (§7).
- **Docs:** `api.md`, `cli.md`, `macos.md`, `ios.md`, `self-hosting.md` (the proxy for services), the spec, and the threat model, §5.19 (T174–T185 and residual risks 65–69, marked "accepted, pending implementation").

## Plan in layers
Each layer is one PR in the stack, with its tests, its roadmap checkbox and, where it applies, its section of the spec and its vectors.

1. **This ADR** and the threat model.
2. **The definition and the token:** the grant with `services`, the `kse1_` token with its vector, `klav service add|ls|show|edit|remove` and `klav service token rotate`, and the bound of identities a definition may declare (§5.2, signal 3).
3. **`klav-forward service run`:** fronting `$PORT`, the outbound base URLs, enrolling, answering the probe, retiring on `SIGTERM`, `klav_not_enrolled`.
4. **Enrollment and the ratchet in `klav-proxy`:** campaigns, Fly's routing header, the store, rotations, the alarms (fork, two channels, liveness, over the limit, source change), freezing, and the lifecycle events in the chain and in `klav log verify`.
5. **Policies and usage:** the `openai` and `anthropic` presets, no `ask` in service profiles, and reading usage from responses (also when streaming), without reading or touching request bodies.
6. **The lease and stopping:** `POST /v1/agent/services/lease` with each item's `version`, item reads through `POST /v1/agent/access` with `service`, `klav/v1/sig/service-state`, stop and resume with the order kept on the proxy (§8.6) and `403 service_stopped`, the routes a global pause leaves open (Q3, §10.3), and the pending account deletion (Q-B, §10.4).
7. **Incident mode:** start and end; `service.enrollment_pending` and its card; enrollment decisions and freezes through the lease answer and the state route, each applied once; the `not_approved` timeout; `service.incident_applied`; the report; and the `service_alarm` push.
8. **The apps:** Development › Services on the Mac, the iOS section and the red card.
9. **End-to-end test** with three replicas behind a load balancer that picks at random, in the test harness:
   - three instances enroll;
   - a fourth process with the token, outside the domain, never enrolls and raises the alarm;
   - a copy of one instance's memory forks and is frozen, and the original comes back;
   - a deploy that doubles the replicas raises no alarm;
   - a streaming call's usage is read from its response, and a call without usage counts with no tokens;
   - an incident closes enrollments, and approving one lets it in.

Everything else is in [Later](#later).

## Later
Not in the first version. Each one needs its own decision, and some their own ADR:

- the CI window (§3.7, Q6), with its dependency ADR for `RS256`;
- Fly's OIDC token as an attestation (§3.4);
- probes from several regions (§3.6, Q1);
- workers and cron jobs with no domain (§3.8);
- databases;
- the TypeScript SDK with the probe handler (§3.9, Q7);
- a proxy with more than one replica (§11);
- spend caps, the list of allowed models and a usage notice, below.

### Spend caps
Omar moved them out of the first version on 2026-11-09 (Q-A): «por ahorita que klav no detecte topes, igual y como nueva version». The proposed design, a signed price table with dollar caps per hour and per day, a reservation before each call and settlement from its usage, failing closed with `429`, had a blocker the review found. A future ADR starts from it.

**Why caps in dollars came out low, with no bound** (review of 2026-11-09, B1):

- **Pricing tiers the price table didn't cover,** so settlement charged below the real bill, by up to about 2×:
  - OpenAI `service_tier` `"priority"` or `"fast"`: gpt-5.4 costs $2.50/$15 per million tokens on Standard and $5/$30 on Fast;
  - OpenAI's higher price above 272K input tokens;
  - Anthropic cache writes: 1.25× for the 5-minute cache, 2× for the 1-hour cache;
  - Anthropic `inference_geo: "us"`: 1.1×;
  - Anthropic fast mode, and Haiku 5.5's higher price above 100K tokens.
- **`background: true` without `stream`** returns the POST at once, and the usage only arrives through `GET /v1/responses/{id}`, which the profile blocked. The proxy would charge only its reservation, and the in-flight slot freed at once, so the bound of 16 calls in flight didn't hold. (Background *with* `stream` delivers `response.completed` on the same POST, which is fine.)
- **`previous_response_id` and `conversation`** bill input stored on OpenAI's side that isn't in the body. A reservation sized from the body's bytes underestimates it badly, and chained responses grow the stored context up to the model's window.
- A caller who cuts a stream got the same result as `background`: only the reservation was charged.

**What the review proposed for dollar caps:** refuse `background` without `stream` in the `openai` preset; when stored context is referenced, reserve the model's full context and settle from the usage; pin `service_tier`, `inference_geo` and fast mode to standard (and list them among the edited fields), or price each tier from the `service_tier` the response returns; add cache-write and long-context columns to the price table.

**The alternative: caps in tokens plus allowed models.** No price table: a cap per hour and per day in input and output tokens, per model, only for the models of a list of allowed models ([below](#allowed-models)). It avoids stale prices and pricing tiers, but it still needs the usage of every call, so the `background`, stored-context and cut-stream gaps above stay, and it needs the body edits this version dropped (`include_usage`, output caps).

**What else the dropped design had, for reference:**

- the proxy edited the body: it forced `stream_options.include_usage` in streaming Chat Completions and dropped the extra chunk if the app hadn't asked for it, lowered or added `max_tokens`, `max_completion_tokens` or `max_output_tokens`, and refused `n` above the policy's maximum;
- fixed windows on the hour and the day in a UTC offset signed in the definition, which let up to twice the hourly cap through across an hour boundary;
- a notice at 80 %, and raising a cap with Touch ID or Face ID (Q5);
- counters in the proxy's store that survived a restart, with outstanding reservations counted as spent.

### Allowed models
Omar took the per-service list of allowed models out of the first version on 2026-11-09. It was an optional list, signed in the service's definition: the proxy read `model` from the request body, refused any other model, and never changed the body.

- **Why it went with the caps:** it is a spend control. It bounds which models a stolen identity, or code inside the domain, can spend on, and it needs reading `model` from every request body. Without it, the proxy never parses a service's request body.
- **What a provider offers meanwhile,** checked on 2026-11-09 and only where its docs say so: OpenAI's project model permissions allow or block models for a project (`mode` set to `allow_list` or `deny_list`, with an Admin API key; [Admin APIs](https://developers.openai.com/api/docs/guides/admin-apis)). This ADR assumes nothing about other providers.

### A usage notice on the person's device
The first version has no usage alarm (§12, limit 4). The person's devices already open the sealed `service.usage` events (§7.3), so a device could compute a notice itself: compare each service's calls and tokens with its usual level and notify when they jump, without the server or the proxy learning the figures. A future decision has to say what "usual" is, which device notifies, and what happens while every device is asleep.

## Security
The new threats are in the threat model, §5.19 (T174–T185), with residual risks 65–69, marked "accepted, pending implementation".

## Questions for Omar
Answered on 2026-11-09 (see "Omar's answers"). Each question could be answered on its own, and the first option was the recommended one. Q-A, Q-B and Q-E came from the design review of 2026-11-09.

| # | Question | Options |
|---|---|---|
| Q1 | How does the proxy reach replicas of one service that run in several regions? (§3.6) | **(a) Not at first: one region per service, except on Fly, where the routing header reaches any Machine (Recommended)**<br>(b) Probes from several regions, with a small prober the person runs in each one<br>(c) Wait until each platform offers routing to a replica |
| Q2 | How does the Klav server take part in each AI call of a service? (§7) | **(a) A 60-second lease per service: a stop or an incident arrives within a minute, and the server sees two renewals a minute (Recommended)**<br>(b) Per call, as for sandboxes: everything arrives on the next call, at the cost of one round trip to the server before each call, an event per call, and an app that stops when the server does<br>(c) A lease the person sets, from 1 to 15 minutes |
| Q3 | Does "Pause agents" also stop deployed services? (§10.3) | **(a) No: the global pause stops agents and sandboxes; services keep running, have their own "Stop service" and incident mode, and the pause sheet says so; pausing the proxy itself does stop them (Recommended)**<br>(b) Yes: the global pause stops services too, and the sheet lists them before pausing<br>(c) The sheet asks each time whether to include services |
| Q4 | What does Klav do on its own when it finds a clone? (§5.5, §8.1) | **(a) It freezes that identity, keeps enrollment through the domain open so the original can come back, and alerts; incident mode is one tap away (Recommended)**<br>(b) It also closes that service's enrollments until the person looks<br>(c) It starts incident mode for that service on its own |
| Q5 | What happens when a service reaches its spend cap? (the old §6.5, now [Later](#later); replaced by Q-A) | **(a) Its calls are refused (`429`) until the next window, with a warning at 80%; the person raises the cap with Touch ID or Face ID (Recommended)**<br>(b) Only a warning; calls go on<br>(c) Refused at the daily cap, only a warning at the hourly one |
| Q6 | When does the CI window (GitHub Actions OIDC) come in? (§3.7) | **(a) Later, in its own ADR with the RSA dependency, after the first version (Recommended)**<br>(b) In the first version, as an optional strict mode<br>(c) Never; Fly's OIDC token is enough |
| Q7 | How does the domain challenge reach `klav-forward`? (§3.9) | **(a) `klav-forward` fronts the app's `$PORT` and passes everything else through, with no change to the app's code (Recommended)**<br>(b) Only a handler in the app, through the SDKs<br>(c) Both from the first version |
| Q8 | Where does each service's usage (calls, tokens, cost, addresses) go? (§7.3) | **(a) Into the audit chain, sealed for the account, one event per service per 5-minute window with calls (Recommended)**<br>(b) Into the chain in clear, so the server can see spend too<br>(c) Only in the proxy; the chain gets only the alarms |
| Q-A | Klav can't see what a call really costs (pricing tiers, `background`, stored context). Why track cost at all, and what does the first version do? (§6, [Later](#later)) | Caps in dollars, with the review's fixes<br>Caps in tokens, with allowed models<br>No caps for now |
| Q-B | During a pending account deletion (ADR 0037), the server cuts every agent, and the proxy is one. Are deployed services cut too? (§10.4) | **(a) Yes, at once, and the deletion sheet says so (Recommended)**<br>(b) No: they keep their lease until the deletion, as in the global pause |
| Q-E | A clone outside the domain whose original died (on Railway, every deploy kills with `SIGKILL`) could use the proxy for up to an hour. Close it? (§5.2) | **(a) A new domain proof each time an identity opens a new channel, without holding calls, and freeze it if it doesn't answer within 2 minutes; it costs one campaign per reconnect (Recommended)**<br>(b) Liveness sweeps every 5 minutes, and cut at the first failure<br>(c) Leave it as a residual risk, with the window written in T178 |

## Omar's answers (2026-11-09)
Omar accepted the ADR with option (a) for each of Q1–Q8. Omar's notes call them P1–P8. The design review of the same day raised Q-A, Q-B and Q-E, which Omar also answered, and Q-A replaced Q5. The review's Q-C and Q-D belong to ADR 0036's amendment (its E9).

| # | Answer |
|---|---|
| Q1 | **(a):** one region per service in the first version, except on Fly, whose routing header reaches any Machine (§3.6) |
| Q2 | **(a):** a 60-second lease per service, renewed every 30 seconds. A stop or an incident takes effect in under a minute, and the server sees two renewals a minute. It departs from ADR 0036 §2's per-call check, and says so (§7) |
| Q3 | **(a):** "Pause agents" stops agents and sandboxes, not deployed services. Each service has its own "Stop service" and incident mode, and the pause sheet says so. Pausing the proxy itself does stop them (§10.3) |
| Q4 | **(a):** on a clone, Klav freezes that identity, keeps enrollment through the domain open so the original comes back, and alarms. Incident mode is one tap away (§5.5) |
| Q5 | **(a), replaced by Q-A:** calls refused with `429` at the spend cap. There are no caps in the first version |
| Q6 | **(a):** the CI window (GitHub Actions OIDC) comes later, in its own ADR with the RSA dependency (§3.7) |
| Q7 | **(a):** `klav-forward` sits in front of the app's `$PORT`, answers the challenge and passes everything else through (§3.9) |
| Q8 | **(a):** usage goes into the audit chain, sealed for the account: one event per service per 5-minute window with calls (§7.3) |
| Q-A | **No spend caps in the first version:** «por ahorita que klav no detecte topes, igual y como nueva version». The caps, the price table, reservations and settlement, and the body edits that served them are out; the proxy touches headers only. Q8's usage record stays, without dollars. [Later](#later) keeps the review's findings and the tokens-plus-models alternative (§6) |
| Q-B | **(a):** during a pending account deletion, services are cut at once, and the deletion sheet says so (§10.4) |
| Q-E | **(a):** a new domain proof each time an identity opens a new channel, without holding calls; frozen if it doesn't answer within 2 minutes (§5.2) |

### Four more decisions (2026-11-09)
Applying the review left four points open. Omar answered the one about allowed models. The orchestrator, the agent that ran the review round for Omar, decided the other three the same day; the two numbers are defaults the implementation may tune.

| Point | Decision | By |
|---|---|---|
| Surge window | `surge_window` defaults to 30 minutes, or 2 minutes per declared replica when that is longer, and time above `max_replicas` adds up over the last `2 × surge_window` (§4.2). A default the implementation may tune | The orchestrator |
| Enrollment queue | At most `16 × (max_replicas + surge)` pending identities per service (§3.5). A default the implementation may tune | The orchestrator |
| Allowed models | No list of allowed models per service in the first version. It is a spend control, and it needs reading `model` from the request body, which the proxy doesn't do (§6.1, [Later](#allowed-models)) | Omar |
| Roadmap | This ADR's layers get their boxes in the roadmap, unchecked, as ADR 0036's and ADR 0037's did on acceptance | The orchestrator |

**After a re-check of the accepted text (2026-11-09).** The orchestrator applied what follows from these answers: the domain proof is owed by the identity, not by the channel (§5.2); approvals and freezes reach the person and the proxy (§8.2); a rotated key reaches the proxy through the lease (§7.2); and §12 says that the proxy bounds calls, not cost, and that nothing alerts on usage. Its new numbers are defaults the implementation may tune: 60 calls per minute per identity and `60 × max_replicas` per service (§6.1), 15 minutes for a decision during an incident (§8.2), and the bound of about 120 identities per definition, which follows the campaign's rate (§5.2).
