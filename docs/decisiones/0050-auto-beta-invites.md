# 0050 · Auto-issued beta invites through Cloudflare Email Sending and Turnstile

- Status: accepted (2026-11-26). Omar approved a cap of 50 seats, Cloudflare Email Sending for the invite email and Cloudflare Turnstile on the form.
- Date: 2026-11-26
- Amends: ADR [0048](0048-invite-beta-and-distribution.md) §1.4 ("there is **no HTTP admin API**"), §4 (Omar's manual loop) and §7 (the rejected alternatives "an HTTP admin API for invites" and "emailing invites from `klav-web`"). Everything else in ADR 0048 stands: the code format, the digest, `invite/check`, the invite in `register/*`, the quotas and the sizing rule of §3.3.

## Context

- **ADR 0048 made the waitlist the invite queue, sent by hand.** Omar exports the pending addresses, runs `klav-server invite create` inside the server for each one, emails each code from his own mailbox and marks the rows (`sitio-web.md` §3). That takes several minutes per person, and somebody who asks on a Saturday waits until Omar sits down.
- **The beta needs traction now.** The goal is that someone who watches a demo and asks for an invite can sign up in the same sitting, while the first wave of seats lasts.
- **Why ADR 0048 rejected both halves of this:**
  - *An HTTP admin API for invites:* "a new secret in production and a new surface on the internet, for a command Omar runs a few times a week."
  - *Emailing invites from `klav-web`:* "it needs transactional email (domain, SPF/DKIM, a provider, a secret)."
- **What changed:**
  - Cloudflare Email Sending (a REST API, in public beta since April 2026) gives `klav.dev` transactional email with one API token and the domain already on Cloudflare.
  - Running the loop for every request, not a few times a week, is the point now. The surface can be made far narrower than a general admin API (§2).
- **What already exists and this ADR builds on:**
  - `registration_invites` (migration 0021) with `bound_email`, `max_uses`, `expires_at`, `note` and `revoked_at`. No new migration is needed.
  - `klav_core::crypto::invite` (generation and digest).
  - `klav_core::crypto::token` (labelled SHA-256 for bearer tokens), with `subtle` already a `klav-core` dependency.
  - On the site, schema 2 of `waitlist` (`invited_at`, `note`), and the honeypot and per-IP limit on `POST /api/waitlist`.

## Decision

### 1. The flow

1. A person submits the form on `klav.dev`. With Turnstile on, `klav-web` verifies the token with Cloudflare first (§3.1).
2. `klav-web` stores the address on the waitlist as before.
3. With auto-invites on, and the address not already sent an invite, the local cap not reached and the client under its own issuance limit (§3.2), `klav-web` calls `POST /v1/internal/invites/auto` on `klav-server` over Railway's private network.
4. On `201 { id, code, expires_at }`, `klav-web` emails the code with Cloudflare Email Sending, in the language of the page.
   - If the send succeeds, it sets `invited_at` and `note = 'auto-beta'` on the row, and answers `invited`.
   - If it fails, `klav-web` calls `POST /v1/internal/invites/auto/{id}/revoke`, so the seat isn't burned. The row stays pending, and the page answers `waitlisted`.
5. When the seats are gone (`409 cap_reached`, or the local cap), the address waits on the list. Omar's manual loop of ADR 0048 §4 still works for it.

### 2. `klav-server`

#### 2.1 Configuration

| Key | Variable | Default | Meaning |
|---|---|---|---|
| `invites.auto_token` | `KLAV_AUTO_INVITE_TOKEN` | unset | The shared bearer secret, at least 32 bytes. Never logged; `Debug` prints it redacted |
| `invites.auto_max` | `KLAV_AUTO_INVITE_MAX` | `0` | How many `auto-beta` invites may exist at once, not counting revoked ones. `0` turns the routes off |

- **The server refuses to start** with a token shorter than 32 bytes, or with `auto_max > 0` and no token.
- **A blank value is unset,** as with `KLAV_REGISTRATION_MODE`, so a template can leave it empty.
- **The routes exist only when all three hold:** `auto_max > 0`, a token, and `registration_mode = invite`. Otherwise both answer `404`, like an unknown path. With today's production variables nothing changes when this deploys.

#### 2.2 `POST /v1/internal/invites/auto`

- **The token comes first.** `Authorization: Bearer <token>` is compared in constant time by `klav_core::crypto::token::same_token`, which reduces both sides to their labelled SHA-256 digest and compares those with `subtle`. A missing, malformed or wrong token is `401`, **before the body is read and before the database is touched**.
- **Body:** `{ "email" }` only (`deny_unknown_fields`), at most 1 KiB (`413`), and normalized with the server's `validate::email` (`400` if invalid). The caller can't choose uses, expiry or note.
- **What it creates is fixed:** `max_uses = 1`, `bound_email = email`, `expires_at = now + 14 days`, `note = 'auto-beta'`, a fresh 128-bit code from `InviteCode::generate()`. Only the digest is stored, as for every invite.
- **One statement, so the cap holds under concurrency:**

  ```sql
  INSERT INTO registration_invites (…)
  SELECT … WHERE NOT EXISTS (an auto-beta invite for this email, not revoked)
           AND (count of auto-beta invites not revoked) < auto_max
  ```

  - On SQLite, the write is the first statement of the transaction. It takes the write lock at once and never upgrades a read lock (the same rule as `register/finish`, ADR 0048 §1.3).
  - On Postgres, `READ COMMITTED` would let two requests both see the last free seat. So the transaction first takes `pg_advisory_xact_lock` on a fixed key, which serializes issuance.
  - Tests race 12 requests against a cap of 3 on both databases.
- **Answers:**
  - `201 { "id", "code", "expires_at" }`, where `expires_at` is Unix milliseconds, as everywhere in this API.
  - `409 { "error": "already_invited" }` if the email already has an `auto-beta` invite that isn't revoked, **used or not**. A used seat is never issued again for the same email.
  - `409 { "error": "cap_reached" }` when no seat is left.
  - These `409` bodies are for `klav-web` only. They are not an `ErrorCode` of `klav-proto`, so no client changes.
- **Logs:** `auto invite issued` with the invite's `id`, never the code, the email or the token. A refused token logs one `warn` line with no detail.

#### 2.3 `POST /v1/internal/invites/auto/{id}/revoke`

- **The same gate,** in the same order (`404`, then `401`). No body.
- **It revokes only an unused `auto-beta` invite:** `UPDATE … SET revoked_at = now WHERE id = $1 AND note = 'auto-beta' AND used_count = 0 AND revoked_at IS NULL`. It answers `204`, or `404` for anything else: an unknown id, an invite already revoked, used, or not auto-issued.
- **Revoking frees both the seat and the email** for a later try. The cap and `already_invited` both skip revoked rows.
- `klav-server invite ls` shows these invites like any other, with the note `auto-beta`, and `invite revoke` works on them as before.

#### 2.4 What the token can and can't do

Someone who steals it can, at most:

- spend the remaining `auto-beta` seats on addresses of their choice. Each invite is bound to its address, so they can use one only with a mailbox they control: the squatting of residual risk 98, at most `auto_max` times;
- revoke unused `auto-beta` invites, so people who were just sent a code find it doesn't work.

It can't create a batch code, change the uses, the expiry or the note, read or list invites, read the codes of invites issued before, or touch accounts.

### 3. `apps/web`

Still no npm dependencies: native `fetch()` with a 10-second timeout on every outbound call, and `redirect: "error"`.

#### 3.1 Cloudflare Turnstile (optional)

- **On with both `KLAV_TURNSTILE_SITE_KEY` and `KLAV_TURNSTILE_SECRET`.**
  - The site key must look like one (`^[0-9]x[A-Za-z0-9_-]{10,100}$`) before it is put in the page.
  - One without the other, or a malformed key, stays off with a log line naming the variable, never its value.
  - `KLAV_TURNSTILE_VERIFY_URL` replaces Cloudflare's `siteverify` URL, for tests.
- **The page:**
  - the server replaces a `<!--turnstile-->` marker in the form with the widget (`data-size="flexible"`) and `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer>`;
  - the marker sits outside the inline `<script>` and `<style>`, so their CSP hashes don't move;
  - without Turnstile the marker is removed.
- **The CSP of `/` gains exactly** `https://challenges.cloudflare.com` in `script-src` and `frame-src https://challenges.cloudflare.com` (Cloudflare's CSP reference). Without Turnstile the policy is byte for byte what it was. `/privacy` never changes.
- **`POST /api/waitlist` checks Turnstile before the honeypot,** so a bot that fills the trap hears the same thing as a real signup:
  - no `turnstile_token` → `400 turnstile_required`;
  - `success: false` → `403 turnstile_failed`;
  - a verifier that errs, answers anything but `success: true`, or can't be reached → `503 turnstile_unavailable`. It **fails closed**: nothing is stored.
- **The client's IP is not sent to `siteverify`.** It is optional, and the site still keeps no IPs. The page resets the widget after every try, because a token works once.

#### 3.2 Auto-issued invites

- **On with `KLAV_BETA_AUTO_CAP` above 0 and every one of:**
  - `KLAV_AUTO_INVITE_URL` (`http://klav-server.railway.internal:8080`);
  - `KLAV_AUTO_INVITE_TOKEN` (the server's token, at least 32 bytes);
  - `KLAV_CF_ACCOUNT_ID` (32 hex characters);
  - `KLAV_CF_EMAIL_TOKEN` (an API token with *Email Sending: Edit*);
  - `KLAV_CF_EMAIL_FROM` (`invites@klav.dev` or `Klav <invites@klav.dev>`, sent as `{ address, name }`).

  `KLAV_CF_EMAIL_API_BASE` replaces `https://api.cloudflare.com/client/v4`, for tests. Anything missing or malformed leaves the site waitlist-only, with one log line naming the variables.
- **A double cap.** `klav-web` stops calling the server once it has `KLAV_BETA_AUTO_CAP` rows with `note = 'auto-beta'` and `invited_at` set. `klav-server` holds its own `auto_max` whatever `klav-web` believes. Omar sets both to 50.
- **One invite per address, without asking the server again:** a row that already has `invited_at` answers `already_invited` and nothing is called or sent.
- **A per-client issuance limit:** at most 2 invites sent automatically per client IP per hour. Past it, the address still goes on the list, and the answer is `waitlisted`, not `429`. This sits on top of the form's 5 tries per 10 minutes. It keeps one client from emptying the seats with made-up addresses as fast as the form allows.
- **The email** (`inviteEmail`), plain text, written natively in English and Spanish:
  - the code;
  - that it works once, only with that address, and the expiry date (UTC, 14 days);
  - the steps: `https://klav.dev/download/mac`, "Set up this Mac" → "Create an account" (or `klav signup`), and `https://docs.klav.dev`;
  - the beta terms the page states;
  - a line for anyone who didn't ask, and `support@klav.dev`.

  It is sent with `POST {api}/accounts/{account}/email/sending/send` and `{ from, to: [email], subject, text }`.
- **A send counts as sent only when** the answer is `2xx` with `success` not `false` and the address isn't listed in `result.permanent_bounces` or `result.suppressed_recipients`. Anything else revokes the invite (§2.3) and leaves the row pending. The log line gives Cloudflare's status and first error code, never the code or the token.
- **Answers of `POST /api/waitlist`:**

  | Mode | Answer |
  |---|---|
  | auto-invites off (as before this ADR) | `200 { "ok": true }` |
  | invite sent | `200 { "ok": true, "status": "invited" }` |
  | this address was already sent an auto invite | `200 { "ok": true, "status": "already_invited" }` |
  | no seat, issuance limit, or any failure upstream | `200 { "ok": true, "status": "waitlisted" }` |
  | honeypot (auto-invites on) | `200 { "ok": true, "status": "waitlisted" }`, nothing stored or called |

  The page has a message for each, in both languages.

### 4. What the form now reveals

**Without auto-invites,** the form answers the same for a new address and one already on the list (ADR 0048 §4), and that stays.

**With them,** `already_invited` tells anyone who types an address that it was sent an auto invite. That says the address asked for the beta, not that it has an account; whether it signed up, the form never says. Hiding it would mean telling a person who just asked again "you're on the list" when their invite is already in their inbox, or sending it a second time. This is the behaviour specified for the beta, and it is residual risk 106; whether to keep it is Omar's call. It is rate-limited like every other try, and Turnstile, when on, makes it costly to automate.

### 5. Security

- **No new dependency of any kind.** The token comparison is `subtle` and `sha2` inside `klav-core`, which already depends on both, with the existing `klav/v1/server/token` label: no new label and no new vector. `klav-server` adds no crate. `apps/web` stays dependency-free.
- **The routes are on the public listener.** `api.klav.dev` serves them like any other path, so the token is the access control, not the private network. Railway's private network keeps the token and the codes off the internet between the two services, nothing more.
- **Secrets never logged:**
  - the server logs the invite `id` only;
  - `klav-web` logs reasons and status codes only;
  - tests check both logs for the code and the tokens.
- **New threats** (§5.27 of the [threat model](../modelo-de-amenazas.md)): T267–T272. **New residual risks:** 106–108.

### 6. Rejected alternatives

- **`klav-web` writing to the server's database:** a second writer on `registration_invites`, across two services and two volumes. The internal route keeps the invite logic, its digest and its cap in one place.
- **A general admin API (create with any uses, list, revoke any invite):** ADR 0048 §7 still holds for that. This route can do one thing, within a cap.
- **Issuing the invite at sign-up time, without email:** the email is what binds the invite to a mailbox (ADR 0048 §3.5).
- **Re-sending the invite on a repeat request:** a resend endpoint would hand out codes again on demand. The code isn't stored anywhere it could be read back, by design.
- **Answering `waitlisted` to a repeat:** it hides the oracle (§4), but tells someone whose invite is already in their inbox to wait.
- **Another email provider or SMTP from Node:** SMTP needs a client library (a dependency) or a hand-written one. Cloudflare already serves `klav.dev`'s DNS.

## Consequences

- **`klav-core`:** `crypto::token::same_token`.
- **`klav-server`:**
  - `InvitesConfig` (`invites.auto_token`, `invites.auto_max`) and its validation;
  - `routes/auto_invites.rs`;
  - tests in `tests/auto_invites.rs`, run on SQLite and Postgres, and in `tests/logging.rs`.
- **`apps/web`:**
  - `turnstileFromEnv`, `autoInviteFromEnv`, `inviteEmail` and the flow in `server.mjs`;
  - the `<!--turnstile-->` marker, the statuses and the label in `public/index.html`;
  - `test/auto-invite.test.mjs`.
- **Docs:**
  - `sitio-web.md` §1–§4 and §6;
  - `self-hosting.md` §2.1 and §2.5;
  - `configuration.mdx`;
  - the privacy policy (`privacidad.md` and `public/privacy`), which names Turnstile and Cloudflare Email Sending;
  - the glossary;
  - threat model §5.27 and risks 106–108.
- **What Omar does, and nobody does for him (Railway and Cloudflare):**
  1. **Cloudflare:**
     - onboard `klav.dev` for Email Sending (SPF/DKIM records) and create an API token with *Email Sending: Edit*;
     - create a Turnstile widget for `klav.dev`;
     - keep all of them in Klav.
  2. **`klav-server` on Railway:** `KLAV_AUTO_INVITE_TOKEN` (`openssl rand -base64 48`) and `KLAV_AUTO_INVITE_MAX=50`, next to the `invite` mode it already runs.
  3. **`klav-web` on Railway:**
     - `KLAV_BETA_AUTO_CAP=50`;
     - `KLAV_AUTO_INVITE_URL=http://klav-server.railway.internal:8080`;
     - the same `KLAV_AUTO_INVITE_TOKEN`;
     - `KLAV_CF_ACCOUNT_ID`, `KLAV_CF_EMAIL_TOKEN`, `KLAV_CF_EMAIL_FROM`;
     - `KLAV_TURNSTILE_SITE_KEY` and `KLAV_TURNSTILE_SECRET`.
  4. **Before turning it on,** check the volume against the sizing rule of ADR 0048 §3.3: 50 seats fit within the first wave's numbers.

## Plan in layers

One branch, `adr-0050/auto-invite`, on top of ADR 0048 layer 3, because the site code needs schema 2.

| Layer | What |
|---|---|
| 1 · server | `same_token`; `InvitesConfig`; the two internal routes; tests on SQLite and Postgres |
| 2 · site | Turnstile, auto-invites, the email in both languages, the page; tests against local mocks of `klav-server`, Cloudflare Email Sending and `siteverify` |
| 3 · docs | This ADR, threat model §5.27, `sitio-web.md`, `self-hosting.md`, `configuration.mdx`, privacy policy, glossary, roadmap |
| — · switch-on (Omar) | The variables of "What Omar does" |

The server layer deploys production on merge. With `KLAV_AUTO_INVITE_MAX` unset, the routes are `404` and nothing else changes.
