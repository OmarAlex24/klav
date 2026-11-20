# 0028 · Default server at `api.klav.dev`: pinned in the binary, "Use my own server" collapsed and the Railway accounts migrated without touching anything

- Status: accepted
- Date: 2026-11-05

## Context
Omar already owns the **`klav.dev`** domain. The production server runs on Railway with the domain Railway generated, with registration closed (`KLAV_ALLOW_REGISTRATION=false`, [`self-hosting.md`](../self-hosting.md) §8.5). The hosted plan will cost 20 USD a year, all included (roadmap, phase 8).

Today every client asks for the server:

- **CLI:** `klav signup --server URL` and `klav login --server URL`, or `KLAV_SERVER` ([`cli.md`](../cli.md) §3). Without a server, `signup` and `login` fail. `klav agent register` takes the one from this `KLAV_HOME`'s account, or `--server`.
- **iOS:** the first field of "Sign in on this iPhone" is "Server", with `https://klav.your-domain.com` as the example and the last one used (`preferences.lastServer`).
- **Extension:** it doesn't sign in (ADR [0017](0017-extension-de-navegador.md) §2). It uses `klavd`'s account.
- **Mac app:** it doesn't exist yet (ADR [0027](0027-app-de-mac.md)).

**Where the URL is stored:**
- `account.json`, field `server` (`klav-client::state::AccountFile`), one per `KLAV_HOME`, on the Mac and in the iOS container;
- `agents/<nombre>.json`, the account each agent pinned (ADR 0014 §1.4);
- the **emergency kit**, printed or in a file: `Server: …` (`klav-client::kit`, spec §4.2). Printed kits can't be corrected;
- the iOS preferences (`lastServer`) and the App Review notes for the demo account, in App Store Connect.

**Accounts that already point to the Railway URL:** Omar's (a Mac with the CLI and `klavd`, the extension in Dia and an iPhone with TestFlight 0.6.0) and the App Review demo account.

**What already protects the transport:** `klav-client` only accepts `https://` outside *loopback*, doesn't follow redirects and uses the system certificates (ADR [0011](0011-cliente-tls-y-jerarquia-local.md) §2). The server sends `Strict-Transport-Security: max-age=63072000; includeSubDomains`.

## Proposed decision

### 1. The host: `api.klav.dev`, as a custom domain on Railway
- **The API goes at `https://api.klav.dev`**, added as a *Custom Domain* to the same Railway service that answers today at the domain Railway generated. It is the same database behind both names. Railway issues the certificate.
- **`klav.dev` is kept for the web:** the site, the downloads (ADR 0027 §7) and the documentation.
- **Why `api.` and not `vault.`:** it describes what it is (a JSON API that isn't opened in the browser). It also leaves `vault.klav.dev` free in case there is ever a web vault, which would have a different threat model.
- **The interface says "klav.dev".** The full URL only appears where it matters: in the emergency kit, in `klav status` and in "Use my own server".
- **This ADR changes nothing on Railway or in DNS.** On accepting it, Omar adds the domain and the `CNAME` record (see Consequences).

### 2. Pinned in the binary, never discovered
- **A constant in `klav-client`**, `DEFAULT_SERVER = "https://api.klav.dev"`, used by the CLI, `KlavFFI` (iOS and Mac) and the SDK.
- **There is no discovery** (a `/.well-known/` on `klav.dev`, a DNS record, a remote list). Changing everyone's server with a single network response would be a single point of attack. Changing it requires shipping a new version of the clients.
- **What wins:** `--server` or `KLAV_SERVER`, then the `server` in `account.json`, and finally `DEFAULT_SERVER`.
- **Tests:** with `KLAV_NO_DEFAULT_SERVER=1` (set by `crates/klav-cli/tests/common`, the extension harness and `scripts/ios/test.sh`), a command without a server fails the same as today. That way no test can reach production by forgetting `--server`.

### 3. Sign-up and sign-in without asking for the server
**By default, the server isn't asked for.** "Use my own server" stays collapsed for those who self-host.

- **CLI:** `klav signup --email ana@example.com` and `klav login --email …` without `--server` use `api.klav.dev`.
  - Before asking for the password, they write to stderr `Server: https://api.klav.dev (klav.dev). Use --server URL for your own.` It is never silent.
  - `--server` stays the same.
- **iOS and the Mac app:** the form starts with the email.
  - Below the fields, a "Use my own server" link expands the "Server" field with the last one used.
  - If the person types `klav.dev`, `api.klav.dev` or the Railway URL there, `DEFAULT_SERVER` is used.
  - The footer text says "Your account lives on klav.dev." or "on <host>".
- **Extension:** it doesn't change, because it doesn't sign in. With no account in `klavd`, the *popup* says "Open Klav to sign in" (with the Mac app) or the CLI command. If the no-daemon mode ever exists (ADR 0017 §2), it will use this same rule.
- **Registration on `api.klav.dev` is closed today.** The server answers `403` to `register/finish` (api.md §2.2). While that lasts:
  - registration in the CLI, the Mac app and iOS says "Registration on klav.dev is not open yet. You can host your own server", with the link to [`self-hosting.md`](../self-hosting.md), **before** asking for the password (`GET /v1/health` gains the optional field `registration_open`);
  - sign-in works, because existing accounts don't change.

  It opens with the hosted plan (phase 8): billing and email verification (ADR 0010).

### 4. Migrating the accounts that point to Railway
**Existing accounts migrate on their own, without anyone typing anything.**

- **A fixed table in `klav-client`** says which old URL maps to which new URL. It has a single row: the exact URL Railway generated → `https://api.klav.dev`. There are no wildcards and no other `*.up.railway.app`.
- **When the account is loaded** (CLI, `klavd`, `KlavFFI`), if `account.json` has a URL from the table:
  1. with a valid session, the client calls `GET /v1/account` at the new URL, with the access token (never the refresh token);
  2. if it answers `200` with the same `account_id` and the same `public_identity` as the local account, it rewrites `account.json` atomically (ADR 0011 §5) with the new URL;
  3. if not (no network, `401`, another account), it changes nothing and tries again on the next load. The account keeps working against the old URL.
- **The same for `agents/<nombre>.json`:** the agent runtime checks with a signed request to `GET /v1/agent/me` at the new URL.
- **The cache, the *high-water marks* and the audit log head don't change:** they belong to the account, not the host. A new server that serves old data is detected the same way (T7).
- **`klav status` says so once:** `server: https://api.klav.dev (moved from <old host>)`.
- **Old emergency kits are still valid:** `klav login --server <URL de Railway>`, or the same value typed into "Use my own server", go through the table and land on `api.klav.dev`.
- **Reprinting the kit:** `klav account kit [--emergency-kit ARCHIVO]` and "Print the emergency kit" on iOS and Mac are proposed. They don't exist today. The kit is rebuilt from what is on the device (the Secret Key is in `$KLAV_HOME`) and it asks for the master password before showing it, because it puts the Secret Key on screen.
- **App Review demo account:** same database, so it lands on `api.klav.dev` without migrating anything. Omar updates the review notes in App Store Connect with the next upload: with the default server, reviewers no longer type one.
- **Moving an account by hand**, also when the domain goes down (§6): `klav account set-server URL` is proposed, and the same in iOS and Mac Settings. It does a full OPAQUE sign-in against the new URL, with the master password, and only saves the URL if `account_id` and `public_identity` match the local account. OPAQUE gives a fake server nothing it can attack offline (T2), and the current session's token never goes to an unverified host.

### 5. The Railway URL keeps working
- **Yes, without advertising it.** TestFlight builds last 90 days and old clients don't have the §4 table. Removing the Railway domain would leave them without a server.
- **It doesn't redirect:** clients don't follow redirects (ADR 0011 §2), so it answers the same as `api.klav.dev`.
- **It is reviewed after six months** (2027-05): if no device uses it (the server already stores each device's `last_seen_at`; it is enough to add the request host to the metrics), it is removed.

### 6. Security
- **TLS and HSTS:**
  - `.dev` is on the HSTS preload list as a top-level domain, so no browser opens `http://klav.dev` or `http://api.klav.dev`.
  - The server's `includeSubDomains` only covers what hangs off `api.klav.dev`.
  - Klav's clients don't depend on HSTS: `klav-client` rejects `http://` outside *loopback* (ADR 0011).
- **No certificate *pinning*.** Railway renews the certificate whenever it wants, and an outdated *pin* would leave everyone without a server. The vault's confidentiality doesn't depend on TLS but on end-to-end encryption. TLS protects the tokens and the metadata (ADR 0011 §2), and an attacker with a valid certificate is a malicious server, which is the case Klav is built for (below).
- **If the domain goes down or is lost:**
  - **It goes down** (it expired, DNS fails, Railway doesn't answer): no network for the clients, which keep reading their local copy (ADR 0026) and say so. There is no automatic backup server: a backup that switches on by itself is another point of attack. The way out is `klav account set-server` (§4) to the Railway URL or another one.
  - **It is lost** (someone takes the domain or the DNS and gets a valid certificate): that someone is a **malicious server** with the right URL.
    - **What it can't do:** read the vault, which is end-to-end encrypted; attack passwords through OPAQUE (T2); change the account's identity, because the sealed identity doesn't open (T9); serve old data to a device that already synced (T7).
    - **What it can do:**
      - deny service (T14);
      - see which emails sign in, at what time and from which IP, and the T13 metadata of each sync;
      - keep the **new** accounts registered while it holds it;
      - keep the access tokens that reach it, against the real server, while they last (15 min);
      - serve a fake DMG from `klav.dev` (ADR 0027 §7).
- **Recommendations for Omar**, which this ADR doesn't apply:
  - transfer lock and automatic renewal for several years at the registrar, with 2FA;
  - a `CAA` record that only allows the authority Railway uses;
  - DNSSEC if the registrar offers it;
  - a *Certificate Transparency* alert (Cert Spotter or crt.sh) for `klav.dev` and its subdomains.

**New threats.** They are in §5.12 of the [threat model](../modelo-de-amenazas.md) (§5.11 is reserved for ADR 0027):

| ID | Threat | Mitigation |
|---|---|---|
| T109 | Someone takes `klav.dev` or its DNS and impersonates the server | It is a malicious server (§6): T2, T7, T9 and end-to-end encryption still protect the vault. The §6 recommendations make it harder, and the CT alert makes it visible. Residual risk 30: new accounts registered during the theft stay on its server |
| T110 | A network response changes every client's server | The default server and the migration table are pinned in the binary (§2, §4). No response from the server or DNS changes the stored URL |
| T111 | An automatic migration sends the account to a host that doesn't have it, or the tokens to the wrong host | The table has a single exact row. The migration only sends the access token, and only saves the URL if the new host returns the same account and the same identity. `set-server` uses OPAQUE, with no tokens |
| T112 | A test forgets `--server` and reaches production | `KLAV_NO_DEFAULT_SERVER=1` in the test harnesses (§2) |

**New residual risk (30):** while someone holds the domain, accounts registered with the default server live on their server. Without the domain they have nowhere to go, and the data they stored can't be recovered from the good server, even though it is encrypted.

## Rejected alternatives
- **`klav.dev` as the API** (`https://klav.dev/v1/…`): it mixes the web, with its *scripts* and its CDN, and the API on the same origin and the same certificate. Also, moving the web to another provider would move the API.
- **`vault.klav.dev`:** §1.
- **Discovering the server** (`/.well-known/klav-server` or a `TXT` record): §2.
- **Redirecting the Railway URL to the new one:** clients don't follow redirects on purpose (ADR 0011 §2), and opening that door for a migration would leave it open forever.
- **Asking each person to sign in again:** there are only two accounts today, but the same rules will apply to any future host change.

## Consequences
- **`klav-client`:** `DEFAULT_SERVER`, the migration table and its check, and `KLAV_NO_DEFAULT_SERVER`.
- **CLI:** optional `--server` in `signup` and `login`, the stderr notice, `klav account set-server` and `klav account kit`. **iOS:** the form without "Server" in view. **Mac app:** the same from day one.
- **Server:** `registration_open` in `GET /v1/health`.
- **Documentation:** `cli.md` §3, `ios.md`, `self-hosting.md` ("Use my own server") and the `probar-*.md` guides, which keep using `KLAV_SERVER` for a local server.
- **Threat model:** §5.12 with T109–T112 and residual risk 30.
- **What Omar does on accepting:** add `api.klav.dev` on Railway and its `CNAME`, the §6 recommendations and the App Review notes. This ADR touches none of that.

## Omar's answers (2026-11-05)
Omar accepted all the default answers. `klav.dev` is at **Cloudflare Registrar** (H7).

| # | Question | Answer |
|---|---|---|
| H1 | Which host carries the API? | `api.klav.dev`, as a *Custom Domain* on the same Railway service; `klav.dev` for the web |
| H2 | Is the Railway URL still served? | Yes, without advertising it and without redirecting; reviewed in 2027-05 |
| H3 | How are existing accounts migrated? | On their own, when the account loads, with the §4 check and a notice in `klav status` |
| H4 | When does registration open on `klav.dev`? | With the hosted plan (phase 8: billing and email verification); until then the clients say so before asking for the password |
| H5 | Reprint the emergency kit with the new URL? | Yes, `klav account kit` and the same on iOS and Mac, asking for the master password; old kits are still valid |
| H6 | Pin the server certificate? | No |
| H7 | Which registrar holds `klav.dev`, and do we apply the §6 recommendations? | Cloudflare Registrar. Yes: lock, automatic renewal, 2FA, `CAA`, DNSSEC if available and a CT alert |
