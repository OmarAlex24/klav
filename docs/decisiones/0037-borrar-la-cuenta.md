# 0037 · Delete the account from the app: the master password again through OPAQUE, plus Face ID or Touch ID where Klav uses it; 7 days to cancel from any device, agents cut off at once, and no server response ever deletes a local copy

- Status: accepted (Omar accepted it on 2026-11-07 with the recommendation for each of P1–P8; see "Omar's answers")
- Date: 2026-11-07
- Amended: 2026-11-09, after the review of layers 2–5 (see "Amendment of 2026-11-09"): `--no-daemon` with Touch ID set up refuses, cancelling asks for presence (replaces P8), the vault stays readable after the deletion, and §1 promises less about Face ID and Touch ID

## Context
The iOS app is in TestFlight (0.9.0, build 6, uploaded on 2026-11-06) and it creates accounts: registration is closed on `api.klav.dev` (ADR [0028](0028-servidor-por-defecto-klav-dev.md) §3), but "Create an account" exists and works with your own server. Before it is published on the App Store, the account has to be deletable from the app ([publicar-extension.md](../publicar-extension.md) §1).

### What Apple asks for
- **Guideline 5.1.1(v)** ([App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)): *"If your app supports account creation, you must also offer account deletion within the app."*
- **[Offering account deletion in your app](https://developer.apple.com/support/offering-account-deletion-in-your-app/)**:
  - *"Apps submitted to the App Store that support account creation must also let people initiate deletion of their account within the app."*
  - *"Offer to delete the entire account record, along with associated personal data. […] only offering to temporarily deactivate or disable an account is insufficient."*
  - *"If the deletion request will take additional time to complete, let them know."* And in the FAQ: *"Inform the person how long it will take to delete the account and provide a confirmation when the deletion is complete."*
  - *"You may add steps to verify the identity of the person making the request, and to confirm that they want to delete the account […]. However, apps that make it unnecessarily difficult for someone to delete their account will not pass review."*
  - *"Apps not operating in highly regulated industries should not require people to make a phone call, send an email, use a chat support flow, or go through other support flows."*

### What exists today
- **The server can't delete an account.** For the account it only has `GET /v1/account` (`crates/klav-server/src/routes/auth.rs`, in `router()`).
- **[privacidad.md](../privacidad.md), "Borrar tu cuenta" (deleting your account),** asks people to write to `support@klav.dev`, and Omar deletes the account by hand. That is exactly the "send an email" Apple doesn't accept. Today that section is the specification of what is deleted and what isn't, and this ADR keeps it except where it says otherwise (§6).
- **The notes on deleting by hand** ([publicar-extension.md](../publicar-extension.md) §1):
  - deleting the `accounts` row deletes everything else in cascade (`ON DELETE CASCADE` in `crates/klav-server/migrations/`);
  - SQLite only does that with `PRAGMA foreign_keys = ON`, which the server sets on its connections (`crates/klav-server/src/db.rs`);
  - the hourly purge, `remove_orphan_files` in `crates/klav-server/src/purge.rs`, removes the attachment files from disk once their vault no longer exists.

### What is reused
- **OPAQUE** (suite `klav-opaque-v1`, spec §4.5) in `klav-core::crypto::opaque`. The server keeps each half-finished login in memory, for 120 s and single use (`crates/klav-server/src/logins.rs`).
- **The cascade from `accounts`** reaches every table except `server_state`, which belongs to the server. One column doesn't have it: `vault_members.member_id`, which names the member account without a foreign key (only `vault_id` deletes in cascade).
- **`delete_vault_data`** (`purge.rs`), which already deletes a whole vault and its files without waiting for the purge: it waits for any upload that is still writing and calls `remove_vault`.
- **The pause extractor** (ADR [0033](0033-agentes-desde-la-app-de-mac.md) §7.2), which refuses on the server every signed request from a paused agent, wherever it comes from.
- **APNs notifications** (`crates/klav-server/src/push.rs`): only a localization key, with no text from the server and no data ([api.md](../api.md) §3).
- **`GET /v1/health`**, which already reports `registration_open` so the clients know what the server can do before they ask for the password (ADR 0028 §3).
- **"Sign out and delete the local copy"** on iOS (`apps/ios/Klav/SettingsView.swift`) and the "Also delete this Mac’s copy of the vault" checkbox of "Uninstall Klav from this Mac" ([macos.md](../macos.md)).
- **The local key in the Secure Enclave** (spec §12.3), with the `biometryCurrentSet` ACL: it only opens with Face ID or Touch ID, never with the iPhone passcode.

### What doesn't exist yet, and weighs on the decision
- **Exporting the vault** (T14, phase 8). Today the person can't take a plaintext copy before deleting.
- **Changing the master password or rotating the Secret Key** ([api.md](../api.md) §10). Whoever steals them can't be locked out.
- **Outgoing email.** Klav sends no email until the hosted plan's verification (ADR [0010](0010-decisiones-fase-3-y-plan-alojado.md), phase 8), so there is no "code by email" like the one Apple suggests.
- **Sharing vaults with other accounts** ([api.md](../api.md) §10). Today each vault has a single owner and no other human member.

## Decision

### 1. Who can delete: the person, with their master password (P1)
Asking for the deletion takes, in this order:

1. **Face ID or Touch ID, if Klav uses it on that device.** It isn't an `LAContext` that asks yes or no: it opens a Secure Enclave key (spec §12.3) that only accepts the enrolled biometrics (`biometryCurrentSet`). The device passcode doesn't open it. It can change which faces or fingers are enrolled, though, and then the key stops opening and Klav stops using biometry: see A4 in the amendment (2026-11-09).
   - **On iOS** the app opens it itself: it is the local key of its Face ID unlock.
   - **On the Mac** the key belongs to `klavd` (ADR [0013](0013-touch-id-secure-enclave.md)), so the app asks `klavd` for it with an operation that only confirms presence, as when resuming agents (ADR 0033 §7.3). `klavd` deletes nothing and never sees the password: step 2 stays inside the app. The CLI does the same when `klavd` runs with Touch ID, so the terminal isn't a shortcut around it. With `--no-daemon` and Touch ID set up, the CLI refuses (A1 in the amendment).
   - **Turning Face ID or Touch ID off in Klav** asks for the device owner, never the master password alone (A4 in the amendment).
2. **The master password**, always. The client computes `O` (spec §4.3) from the password and the device's Secret Key, and runs a full OPAQUE exchange with the server on routes of its own (§5.1). The server checks it the same way as a sign-in. If it succeeds, that same request asks for the deletion.

Where Klav uses neither Face ID nor Touch ID (the CLI without `klavd` or outside macOS, a Mac without Touch ID, an iPhone where the person didn't turn it on in Klav), the password is enough.

**Why both, with an unlocked phone in mind:**
- **Whoever steals an unlocked iPhone often knows its passcode** (they watched it over the person's shoulder). With the passcode they open the phone and, if Klav was unlocked, Klav too. Face ID stops them there, because the local key doesn't accept the passcode. It doesn't stop one who enrolls their own face with that passcode: then the password alone is enough (A4 in the amendment, residual risk 57). The 7 days and the notices are the defense against them.
- **If the person saved the master password in Apple's Passwords,** Klav's password field (`.textContentType(.password)`) offers to fill it, and Passwords accepts the iPhone passcode. Without step 1, that thief would delete the account. With step 1, they can't (residual risk 57 covers the case without Face ID).
- **The password alone stops someone who only has the device,** and step 1 alone stops someone who has the device without the person's face.

**The proof is bound to the session and to its purpose:**
- `start` requires the person's session (`Authorization: Bearer kat_…`). The server takes the email from that session's account, never from the client.
- The half-finished login stores its purpose (`delete`) and the session ID. `finish` has to arrive within 120 s and from the same session. A sign-in `start` can't be finished as a deletion, nor the other way around.
- A wrong password answers **`403 reauth_failed`, never `401`**. `klav-client` takes any `401` as an expired session (`ClientError::SessionExpired` in `crates/klav-client/src/session.rs`), and a typo must not look like the end of the session.

**An agent can never delete the account.** No path leads there:
- There is no permission to delete the account: it isn't in `Permission`, no grant rule names it and no task can ask for it.
- There is no `klav mcp` tool, SDK function or `klavd` operation that deletes the account.
- The routes require a person's session. An agent has no session: it signs each request with its own key (`crates/klav-server/src/agentauth.rs`), and a signed request never reaches these routes.
- **The CLI** only deletes from a terminal. It doesn't accept `--password-stdin` or `--yes`: a program without a terminal can't give it the password.
- **The Mac app** deletes inside its own process with `KlavFFI`, like the sign-in (ADR [0027](0027-app-de-mac.md) §3). From `klavd` it only asks for the Touch ID confirmation of step 1, which deletes nothing.
- An agent with a terminal on the person's Mac is another process of the same user (residual risk 49). Even so, it can't get there without the master password, and no agent ever receives it. If the person gave it the password, that is already out of scope (threat model §6).
- While the deletion is pending, the server refuses every agent (§3).

### 2. Seven days to cancel (P2)
- **`finish` doesn't delete: it schedules the deletion** for 7 days later (`delete_at = requested_at + 7 days`). The response carries both dates and the device that asked.
- **Why wait:**
  - Klav can't export yet, so an immediate deletion by mistake can't be undone.
  - Whoever stole the password and the Secret Key (§8, T163) must not be able to delete everything without the person finding out. Seven days are enough to see the notification on another device.
  - Apple allows it if the app says how long it takes and confirms when it's done (Context).

**Meanwhile:**

| | During the 7 days |
|---|---|
| The person's devices | Everything keeps working: read, edit and sync. A persistent notice shows the date and offers "Cancel the deletion" |
| Signing in on another device | Allowed, to cancel from a new one if the others were lost |
| Creating an account with that email | No: the account still exists (`409`) |
| Agents | Cut off at once: `403 account_deleting` on every signed request, except `GET /v1/agent/me`, which says why. New registrations are not created: they get the usual silent `202` (A6 in the amendment) |
| Pending approvals and tasks | They stay as they are, but no agent can use them. They go with the account |
| Notifications | One to each phone when the deletion is asked for, another when it's canceled and another when it's done (§7.5) |

- **What the server keeps during the waiting period:** everything it keeps today, plus a row in `account_deletions` (the account, when it was asked for, when it will be deleted and from which device). The only new data is who asked and when.
- **Canceling:** `POST /v1/account/delete/cancel`, from any device with a session (P8). The row goes away, the agents come back and the phones get "The deletion of your account was canceled". Since 2026-11-09 the client asks for presence first, as when resuming agents (A2 in the amendment).
- **When `delete_at` arrives:** the hourly purge (`purge.rs`) deletes the account (§5.2). As with the trash (layer 07 of the security round), it checks inside its transaction, under the same lock that "Cancel" takes, that the deletion is still pending: a cancellation one second earlier wins.
- **There is no "Delete now".** See "Rejected alternatives".

### 3. What the other devices, the sessions and the agents see (P3)
**During the waiting period:**
- `GET /v1/account` and `GET /v1/sync` gain the optional field `deletion`: `{requested_at, delete_at, device_id, device_name}`. Old clients ignore it, because responses don't reject unknown fields.
- Each client keeps the date in its sealed local data (`0x41`, purpose `cache`) and shows the notice. After a cancellation, the next sync removes it.
- `klavd` learns it when it syncs and cuts off what it brokers for agents (the extension fills, `agent_rotate_begin`), as with the pause (ADR 0033 §7.2).

**After the deletion** the server has nothing left of the account:
- **Sessions:** `401`, like a revoked session. The server keeps no token digests to answer anything else (P3).
- **The client that knew the date** and gets a `401` at `delete_at` or later shows **"Klav deleted your account"** instead of the expired-session message. It stops syncing and leaves the local copy read-only: the vault stays on screen under that notice (A3 in the amendment).
- **A device that was offline for all 7 days** doesn't know the date and sees an ordinary `401`. If it tries to sign in, it fails like a wrong password: an email with no account gets OPAQUE's decoy (spec §4.5) and can't be told apart. The notifications in §7.5 cover almost every case.

**No server response ever deletes a local copy.** Not a `401`, not a `deletion`, not the final notification:
- A malicious server could fake a deletion so that every device deleted its copy at once (T165).
- While Klav can't export, the local copy is the only copy if the server fails (T14).

Each device offers to delete it with one tap: "Delete this iPhone’s copy" (the same path as "Sign out and delete the local copy") and "Delete this Mac’s copy". The CLI says where the copy is (`$KLAV_HOME`) and how to delete it. Today it has no command for that: [cli.md](../cli.md) and [klavd.md](../klavd.md) name a `klav logout` that the CLI doesn't implement, and layer 3 solves it.

**Agents:**
- **During the waiting period:** `403` with `{"error": "account_deleting", "delete_at": …}`.
  - MCP returns a result with `isError`: `{"status": "account_deleting", "next": "The person asked Klav to delete this account. Stop and tell the person; do not retry."}`.
  - `klav agent …` exits with a new code, **8** (3 to 7 are already taken: [cli.md](../cli.md), "Códigos de salida de los comandos de agente", lists the agent commands' exit codes), and the SDK with the error `AccountDeleting`.
- **After:** `401`, like an agent the server doesn't know. What the runtime already decrypted stays on its machine, as after a revocation (residual risk 11).

### 4. Where it lives (P4)
- **iOS** (what Apple asks for): Settings › Account, "Delete my account", below "Sign out on this iPhone".
- **Mac app:** Settings (⌘,) › Account, the same button. It goes through `KlavFFI` (§1).
- **CLI** (in English, like the whole CLI):
  - `klav account delete` asks for the deletion;
  - `klav account delete --cancel` cancels it;
  - `klav status` shows the date while it's pending, when `klavd` is running (A6 in the amendment).
- **Extension:** no. It doesn't sign in (ADR 0028 §3).
- **Servers:** any `klav-server` with this version, `api.klav.dev` or your own, with no setting to turn it off. `GET /v1/health` gains `account_deletion: true`. The clients check it **before** asking for Face ID or the password. With an old server they say "This server can’t delete accounts from the app. Ask whoever runs it."
- **Android** (phase 7), with the same rule when it exists.

### 5. The server

#### 5.1 Routes
All of them require the person's session.

| Route | Body | Response |
|---|---|---|
| `POST /v1/account/delete/start` | `{credential_request}` | `{handle, credential_response}` |
| `POST /v1/account/delete/finish` | `{handle, credential_finalization}` | `202 {requested_at, delete_at, device_id, device_name}` |
| `POST /v1/account/delete/cancel` | — | `204`; `404` if no deletion is pending |

- **New errors:** `403 reauth_failed` (wrong password, or a `handle` that expired, belongs to another session or comes from a sign-in) and `403 account_deleting` (agents, §3). A second request while one is pending gets `409 conflict`.
- **New fields:** `deletion` in `GET /v1/account` and in `GET /v1/sync`, and `account_deletion` in `GET /v1/health`.
- **Why a two-step `POST` and not `DELETE /v1/account`:** OPAQUE needs two round trips, and the second one is the deletion. That way the proof is spent in the same act, and there is no "recently verified session" left for a few minutes for whoever steals it.
- **OPAQUE across several instances:** `start` and `finish` have to reach the same instance, like the sign-in (residual risk 7).

#### 5.2 The deletion
One transaction, holding the account's lock:

1. Check that the deletion is still pending and due.
2. Read the IDs of its vaults and attachments and its APNs tokens.
3. Delete the `vault_members` rows that name the account as a member (`member_type = 'account'`), because `member_id` has no foreign key. Today there are none outside the account's own vaults, but they will come with sharing. What happens to a shared vault whose owner deletes their account is for the sharing ADR to decide.
4. `DELETE FROM accounts WHERE id = $1`, which deletes in cascade:
   - devices, sessions and APNs tokens;
   - vaults, projects, items, versions and attachments;
   - agents, `agent_projects`, `agent_nonces`, approvals, tasks, `task_targets`, assisted changes and pauses;
   - the audit log (`audit_events`, `audit_heads`) and `account_deletions`.

After the commit:

- **Each vault's files are deleted from disk at the same moment**, as in `delete_vault_data`: it waits for any upload that is still writing and calls `remove_vault`. `remove_orphan_files` stays as the fallback if something fails.
- The account's SSE streams are closed and its half-finished logins are forgotten.
- The final notification is sent (§5.4).
- The server log writes one line, `account deleted`, with the `account_id` and without the email (§5.5).

**Both databases:**
- **A new migration**, `0017_borrado_de_cuenta.sql`, in `sqlite/` and in `postgres/`, with the `account_deletions` table. No existing migration is touched.
- **SQLite** only deletes in cascade with `PRAGMA foreign_keys = ON`. The server already sets it on every connection (`db.rs`).
- **A test that walks every table** (`sqlite_master` in SQLite, `information_schema` in Postgres) and every column that names an account, a device or an agent (`account_id`, `owner_account_id`, `member_id`, `device_id`, `agent_id`, `author_agent_id`). After the deletion, no row names the account, its devices or its agents. It runs in the `test` and `test (postgres)` CI tasks. A new table without its foreign key makes it fail.
- **In memory** the only things left are the rate-limit buckets that carry the email (`auth-email:…`), which expire on their own and are never written to disk.

#### 5.3 The audit log
**The request, the cancellation and the deletion don't go into the chain.**
- The chain is deleted with the account: nobody would verify a deletion event.
- A new action breaks every earlier `klav log verify`, because the closed table (ADR 0030 §4) treats an unknown action as an error. The pause paid that price (ADR 0033 §7.6); here it buys nothing.
- The state is just as visible: the `deletion` field, the notifications and each device's screen say who asked and when.

#### 5.4 Notifications
Three new keys, with no text from the server and no data (`type: "account"`, no ID): on asking, on canceling and on completion. The final notification is built with the tokens read before the transaction and is sent only if the commit succeeded, because the cascade deletes them. Without APNs configured (your own server without the key), there are no notifications, and only the notice inside each app remains.

#### 5.5 The email, the log and the backups (P5)
- **The email is free again at once.** With registration open, another account can be created with it. It will be a different account, with another `account_id` and another OPAQUE registration, and nothing from the old one. On `api.klav.dev` registration stays closed (ADR 0028 §3).
- **The server keeps neither the email nor a digest of it.** The only thing left is the `account deleted` line in the log, with the `account_id`, so that whoever restores an earlier backup can delete that account again. [self-hosting.md](../self-hosting.md) explains it in the server layer.
- **Database backups** keep the account until they expire, as [privacidad.md](../privacidad.md) already says. Restoring one from before the deletion brings it back (residual risk 60).

#### 5.6 Limits
- **`start`** counts toward the authentication limits per IP and per email and IP ([api.md](../api.md) §7), with the account's email. On top of that, at most **5 attempts per account per hour**, whether they succeed or fail.
- **Only one deletion pending at a time**, and at most **3 requests per account every 7 days**, so that asking and canceling over and over can't flood the phones with notifications.
- **"Cancel"** only counts toward the general per-account limit.
- These limits are fixed in the code, not in the server's settings (A6 in the amendment).

Each attempt already costs a full Argon2id on the client (256 MiB), and guessing the password this way is no easier than with `login`: both routes need the password and the Secret Key.

### 6. What stays outside the server (P6)
- **Each device's local copy,** including the one on the device that asked for the deletion. That device keeps its session during the waiting period, so it can cancel. At the end, each device offers to delete its copy (§3), and none deletes it on its own.
- **The emergency kit.** Klav can't delete it. The final screen asks the person to destroy it: with the kit and the password, any copy that is left opens, on a device or in a server backup. Without the kit, whatever is left is ciphertext nobody can open. It is the only guarantee that doesn't depend on whoever runs the server (T165).
- **What was copied out of Klav.** Klav doesn't export yet. Whatever the person copied or revealed stays wherever they put it.
- **The agents' machines:** the file or keychain entry with the agent's key, and what its runtime already decrypted (residual risk 11). After the deletion, that key opens nothing new on the server.
- **The email on the `klav.dev` waitlist.** It is another database ([sitio-web.md](../sitio-web.md) §2), and the deletion doesn't touch it, as the policy already says.

**What changes in [privacidad.md](../privacidad.md) when this ships** (this PR doesn't touch it; it changes in layer 6, and with it its English version in `apps/web/drafts/privacy/index.html`). The Spanish sentences are quoted exactly as they appear in `privacidad.md`, because layer 6 replaces those words. The English sentences of today are the matching ones in the draft's English article; their replacements are translations of the Spanish ones, for layer 6 to use.
- "Quién es el responsable" (who is responsible):
  - es: «Para cualquier duda, sobre tu privacidad o para borrar tu cuenta, escribe a `support@klav.dev`» becomes «Para cualquier duda o sobre tu privacidad, escribe a `support@klav.dev`. Tu cuenta la borras tú desde la app (abajo, «Borrar tu cuenta»)».
  - en: "For questions, privacy requests or to delete your account, write to support@klav.dev" becomes "For questions or privacy requests, write to support@klav.dev. You delete your account yourself from the app (below, "Deleting your account")".
- "Borrar tu cuenta" (deleting your account), first paragraph:
  - es: «Escribe a `support@klav.dev` desde el correo de tu cuenta: así sabemos que lo pides tú. La borramos a mano y te avisamos cuando esté hecho.» becomes «Bórrala desde la app de iPhone o de Mac (Ajustes › Cuenta › Borrar mi cuenta) o con `klav account delete`. Klav te pide la contraseña maestra, y Face ID o Touch ID si lo usas. Se borra 7 días después; hasta entonces puedes cancelarlo desde cualquiera de tus dispositivos, y tus agentes dejan de funcionar al momento. Te avisamos cuando esté hecho.»
  - en: "Write to support@klav.dev from your account’s email address, so we know the request is yours. We delete the account by hand and tell you when it’s done." becomes "Delete it from the iPhone or Mac app (Settings › Account › Delete my account) or with `klav account delete`. Klav asks for your master password, and for Face ID or Touch ID if you use it. It’s deleted 7 days later; until then you can cancel it from any of your devices, and your agents stop working at once. We tell you when it’s done."
- The files:
  - es: «(los archivos se borran del disco en la limpieza siguiente del servidor, que corre cada hora)» becomes «(los archivos se borran del disco en el mismo momento)».
  - en: "(the files are removed from disk by the server’s next cleanup, which runs every hour)" becomes "(the files are removed from disk at the same moment)".
- Added to what is deleted: «Tu correo puede volver a registrarse» / "Your email can be registered again".
- "No se borra" (what is not deleted), first point: add «Klav nunca la borra sola: cada dispositivo te ofrece borrarla» / "Klav never deletes it on its own: each device offers to delete it". The Mac app example becomes «Borrar la copia de este Mac» / "Delete this Mac’s copy".
- "Cuánto tiempo se guardan los datos" (how long data is kept): «mientras exista la cuenta» becomes «mientras exista la cuenta, y 7 días después de que pidas borrarla»; in English, "while the account exists" becomes "while the account exists, and for 7 days after you ask to delete it".

And in [publicar-extension.md](../publicar-extension.md) §1, the paragraph «**Borrar una cuenta** no existe ni en las apps ni en la API» ("deleting an account doesn't exist in the apps or in the API") and its note about guideline 5.1.1(v) are replaced with a link to this ADR. For the App Review demo account: if the reviewer deletes it, it keeps working for 7 days, and Omar can cancel it with `klav account delete --cancel` and the credentials in the notes.

### 7. UI copy (P7)
It follows the app's style: short sentences, the informal «tú» in Spanish, Klav as the subject, no exclamation marks, and the red button says exactly what it does. The Mac app uses the same strings with «este Mac» / "this Mac". The CLI, in English, says the same.

#### 7.1 Settings › Account
| es | en |
|---|---|
| Borrar mi cuenta | Delete my account |

It is a red button (`SecondaryButtonStyle(danger: true)`), below "Sign out on this iPhone".

#### 7.2 First confirmation: what gets deleted
| es | en |
|---|---|
| ¿Borrar tu cuenta? | Delete your account? |
| Klav borra del servidor todo lo de tu cuenta: tus bóvedas con sus elementos, versiones y archivos, tus dispositivos, tus agentes y la bitácora. | Klav deletes everything your account has on the server: your vaults with their items, versions and files, your devices, your agents and the audit log. |
| Se borra el %@. Hasta entonces puedes cancelarlo desde cualquiera de tus dispositivos. Tus agentes dejan de funcionar ahora. | It’s deleted on %@. Until then you can cancel it from any of your devices. Your agents stop working now. |
| Klav todavía no exporta la bóveda: si quieres conservar algo, cópialo antes. | Klav can’t export your vault yet: if you want to keep something, copy it first. |
| No se borra la copia de tus dispositivos hasta que la borres, tu kit de emergencia ni lo que hayas copiado fuera de Klav. | Not deleted: the copy on your devices until you delete it, your emergency kit, and anything you copied out of Klav. |
| Continuar | Continue |
| Cancelar | Cancel |

"Continue" is red. The `%@` is the date, in the system's long format («14 de noviembre» / "November 14").

#### 7.3 Second confirmation: Face ID and the password
| es | en |
|---|---|
| Confirma que eres tú para borrar tu cuenta | Confirm it’s you to delete your account |
| Escribe tu contraseña maestra para borrar la cuenta %@. | Enter your master password to delete the account %@. |
| Contraseña maestra | Master password |
| Borrar mi cuenta | Delete my account |
| Comprobando… | Checking… |
| La contraseña maestra no es correcta. | The master password isn’t right. |

- The first row is the reason shown in the Face ID dialog.
- The `%@` in the second is the email.
- "Delete my account" is the red button; "Checking…" is its label while it waits.
- The last row is the error. It already exists in `Localizable.xcstrings`.

#### 7.4 During the waiting period
| es | en |
|---|---|
| Tu cuenta se borrará el %@ | Your account will be deleted on %@ |
| Lo pediste desde %@ el %@. Hasta entonces Klav sigue funcionando, salvo tus agentes. | You asked from %@ on %@. Until then Klav keeps working, except for your agents. |
| Cancelar el borrado | Cancel the deletion |
| Se canceló el borrado. Tus agentes vuelven a funcionar. | The deletion was canceled. Your agents work again. |

- The first two rows are the screen that stays in Settings › Account, and the first one is also the persistent notice above the vault, with "Cancel the deletion".
- The `%@` are the device and the date.
- The last row appears after canceling.

#### 7.5 Notifications (APNs)
| Key | es | en |
|---|---|---|
| `PUSH_ACCOUNT_DELETION_TITLE` / `_BODY` | Se pidió borrar tu cuenta de Klav · Abre Klav para ver cuándo y desde qué dispositivo. Si no fuiste tú, cancélalo. | Someone asked to delete your Klav account · Open Klav to see when and from which device. If it wasn’t you, cancel it. |
| `PUSH_ACCOUNT_CANCELED_TITLE` / `_BODY` | Se canceló el borrado de tu cuenta · Tu cuenta sigue en Klav. | The deletion of your account was canceled · Your account stays in Klav. |
| `PUSH_ACCOUNT_DELETED_TITLE` / `_BODY` | Klav borró tu cuenta · Abre Klav para borrar la copia de este iPhone. | Klav deleted your account · Open Klav to delete this iPhone’s copy. |

#### 7.6 After the deletion
| es | en |
|---|---|
| Klav borró tu cuenta | Klav deleted your account |
| El %@ se borró del servidor todo lo de %@. Este iPhone todavía guarda una copia cifrada. | On %@, everything in %@ was deleted from the server. This iPhone still keeps an encrypted copy. |
| Destruye también tu kit de emergencia: con él y tu contraseña se abre cualquier copia que quede. | Destroy your emergency kit too: with it and your password, any leftover copy opens. |
| Borrar la copia de este iPhone | Delete this iPhone’s copy |

The `%@` in the second row are the date and the email, and the last row is the button.

Since 2026-11-09 (A3 in the amendment), the first row is a fixed notice above the vault, which stays on screen read-only. The rest sits under that notice, and "Delete this iPhone’s copy" is one more button there, never the only way out.

#### 7.7 Server without the feature
| es | en |
|---|---|
| Este servidor no permite borrar la cuenta desde la app. Pídeselo a quien lo opera. | This server can’t delete accounts from the app. Ask whoever runs it. |

#### 7.8 CLI
```
$ klav account delete
This deletes everything account ana@example.com has on https://api.klav.dev:
vaults, items, versions, files, devices, agents and the audit log. It happens
in 7 days; until then, `klav account delete --cancel` cancels it.
Type the account email to continue: ana@example.com
Master password:
Deletion scheduled for 2026-11-14 18:03 UTC. Your agents are stopped now.
```

Typing the email is the CLI's first confirmation, because a terminal has no button to read. Without a terminal, the command fails and asks for nothing.

### 8. Threat model
This ADR adds no cryptography. The reauthentication is `klav-core`'s `klav-opaque-v1` suite, Face ID is the spec §12.3 unlock, and there are no new labels, blob types or signatures. **The spec only gains one line in §4.5, with the code:** OPAQUE also confirms a deletion.

The threats go in [`modelo-de-amenazas.md`](../modelo-de-amenazas.md) §5.18, marked «aceptado, pendiente de implementar» (accepted, not implemented yet). They follow ADR 0036's (T147–T161 and residual risks 51–56).

| ID | Threat | Mitigation |
|---|---|---|
| T162 | Someone with one of the person's unlocked iPhones or Macs (and perhaps its passcode) asks for the deletion | Face ID or Touch ID with the Secure Enclave key, which doesn't accept the passcode, where Klav uses it; turning it off in Klav asks for the device owner, never the master password alone (A4); the master password through OPAQUE always; 7 days, a notification to each phone and "Cancel" from any device, including a new one. Residual risk 57 |
| T163 | Account takeover to delete it (denial of service): whoever has the password and the Secret Key (the kit, or the device and the password) asks for the deletion, or asks again after each cancellation | OPAQUE needs both. A 7-day waiting period with notifications; one pending deletion at a time and at most 3 requests every 7 days; no local copy deletes itself. That attacker can already read the whole vault: the deletion is the least of the damage. Residual risk 58. Cancelling asks for presence, so an agent can't cancel to bring itself back (A2) |
| T164 | An agent, or a *prompt injection*, deletes the account | No permission, grant rule, task, MCP tool, SDK function or `klavd` operation does it. The routes require a person's session, which an agent doesn't have. The CLI requires a terminal, without `--password-stdin` or `--yes`, and the master password, which no agent receives. During the waiting period, the server refuses every agent with `account_deleting` |
| T165 | A malicious server pretends to delete and keeps the data, or fakes a deletion nobody asked for | What it keeps is ciphertext: it doesn't open without the Secret Key, and the final screen asks the person to destroy the kit. No server response deletes a local copy, so faking a deletion destroys nothing. The plaintext metadata (email, devices, agents' reasons, audit log) does stay with it. Residual risk 59 |
| T166 | An old deletion proof is replayed, or a sign-in is finished as a deletion | The OPAQUE state lives in memory, works once, expires after 120 s and is bound to the session and the purpose: a sign-in `start` can't be finished as a deletion, nor the other way around. `finish` spends the proof in the same request that schedules the deletion. A new account with the same email has another OPAQUE registration |
| T167 | The deletion leaves leftovers: tables without a foreign key, files on disk, state in memory, backups, the log | Explicit deletion of `vault_members` by `member_id`; cascade with `PRAGMA foreign_keys = ON`; a test in SQLite and Postgres that walks every table; files deleted at the same moment, with the hourly purge as the fallback; SSE streams closed and half-finished logins forgotten; the log only carries the `account_id`. Residual risk 60 |

**New residual risks:**

- **57. Without Face ID or Touch ID in Klav, an unlocked device and the password saved in Apple's Passwords are enough** to ask for the deletion (T162): Passwords accepts the iPhone passcode. The 7 days and the notifications let the person cancel it. Whoever has the passcode (or the Mac's login password) can also reach this case where Klav does use biometry, by enrolling their own face or finger (A4).
- **58. Without changing the password or rotating the Secret Key** ([api.md](../api.md) §10), whoever stole them can ask for the deletion again after each cancellation (T163), within the limit of 3 every 7 days. The real way out is to create another account and move the vault, and that comes with export.
- **59. The deletion is a promise from whoever runs the server** (T165): a malicious or careless one can keep the ciphertext and the plaintext metadata. Only destroying the kit and the local copies makes what it keeps unreadable, and only hosting your own server lets you check that it was deleted.
- **60. Database backups** keep the account until they expire, and restoring an earlier one brings it back (T167). Whoever runs the server deletes it again using the `account deleted` lines in the log, if they kept them.

### 9. Layer plan
One `gh stack` stack, branches `borrar-cuenta/NN-…`. Each layer brings its tests and its roadmap checkbox.

1. **This ADR, accepted,** with Omar's answers, the threat model (§5.18, T162–T167 and residual risks 57–60, «aceptado, pendiente de implementar»), the glossary and the roadmap.
2. **Server:**
   - migration `0017` in both dialects;
   - the §5.1 routes, with OPAQUE bound to the purpose and the session;
   - `account_deleting` in the agents' extractor;
   - the deletion in the purge, with the files at the same moment, the §5.4 notifications, `account_deletion` in `/v1/health` and the log line;
   - the test that walks every table, in SQLite and in Postgres;
   - [api.md](../api.md), [self-hosting.md](../self-hosting.md) (backups and the log) and the spec §4.5 line.
3. **`klav-proto`, `klav-client`, the CLI and `klavd`:**
   - asking, canceling and the date in the local data;
   - "Klav deleted your account" on a `401` after `delete_at`;
   - `klav account delete [--cancel]` and the date in `klav status`;
   - a command to delete the local copy, which doesn't exist today even though the docs name `klav logout` (§3);
   - exit code 8, MCP and the SDK's `AccountDeleting` error;
   - `klavd` cutting off what it brokers, and its operation that only confirms presence with Touch ID (§1);
   - [cli.md](../cli.md);
   - an end-to-end test: ask, cancel, ask again, move the clock forward, purge, see every table empty and the files gone, and check that another device sees "deleted" and keeps its copy.
4. **iOS:** `KlavFFI`, the §7 screens and notifications in `Localizable.xcstrings` (English and Spanish), and [ios.md](../ios.md) with the screenshots.
5. **Mac app:** the same feature through `KlavFFI`, with the Touch ID confirmation that `klavd` gives (§1), and [macos.md](../macos.md). `klavd`'s presence operation arrives in layer 3, with the CLI.
6. **On shipping:** [privacidad.md](../privacidad.md) and its page (§6), and [publicar-extension.md](../publicar-extension.md) §1.
7. **Omar's manual test,** in TestFlight with a throwaway account: ask, see the notification on another device, cancel, ask again and let it be deleted.

## Rejected alternatives
- **Keep the email to `support@klav.dev`:** Apple doesn't accept it outside regulated industries (Context).
- **A device signature with the account identity** (`klav/v1/sig/account-delete`, like the pause in ADR 0033 §7.3) instead of the password: the identity is in memory whenever Klav is unlocked, so the signature proves the device was open, not that the person is there. Against a malicious server it doesn't help either: the server can delete without any proof (T14).
- **Sign in again and then `DELETE /v1/account` with a "recently verified" session:** for a few minutes it leaves a token that deletes the account. With OPAQUE inside the same request, the proof is spent by the deletion.
- **A code by email** (Apple's example): Klav sends no email until phase 8, and an account's email isn't verified. The password through OPAQUE is stronger.
- **Deactivate the account instead of deleting it:** Apple says that isn't enough.
- **"Delete now" during the waiting period:** it would hand immediate deletion back to whoever stole the password, which is exactly what the waiting period prevents.
- **Clients delete their local copy when they learn of the deletion:** a malicious server would delete every copy at once by faking one (T165).
- **Keep token digests for 30 days to answer `410 account_deleted`:** that would mean keeping something of the account after deleting it, for a message that the client that knew the date already shows on its own (P3).
- **The request and the cancellation in the audit log:** the chain is deleted with the account, and a new action breaks every earlier `klav log verify` (§5.3).
- **A setting on your own server to turn deletion off:** the person has the right to delete their data, and whoever runs the server can already delete by hand.

## Consequences
- **Protocol:** three routes, the `reauth_failed` and `account_deleting` errors, the `deletion` field in `GET /v1/account` and `GET /v1/sync`, and `account_deletion` in `GET /v1/health`. All of them are added routes and fields: old clients keep working, and only new ones can delete.
- **Server:** migration `0017` in both dialects, the deletion in the purge and three new notifications.
- **CLI:** `klav account delete [--cancel]` and exit code 8 in the agent commands.
- **`klavd`:** an operation that only confirms presence with Touch ID, for the Mac app and the CLI. It deletes nothing.
- **No new cryptography, formats or dependencies.** The spec only gains one line in §4.5.
- **Docs:** `api.md`, `cli.md`, `klavd.md`, `self-hosting.md`, `ios.md`, `macos.md`, the spec line and, on shipping, `privacidad.md` and `publicar-extension.md` (§6).
- **What only Omar can do:**
  - the TestFlight test (layer 7);
  - decide how long the `api.klav.dev` backups last (the **[REVISAR]** in `privacidad.md`), which is how long a deleted account takes to really disappear.

## Questions for Omar
Each question can be answered on its own. The first option is the recommended one.

| # | Question | Options |
|---|---|---|
| P1 | What reauthenticates the person to delete? (§1) | **(a) Face ID or Touch ID where Klav uses it (the Secure Enclave key, which doesn't accept the device passcode: the app's on iOS, `klavd`'s on the Mac) and the master password through OPAQUE always; only the password where there are no biometrics (Recommended)**<br>(b) Only the master password through OPAQUE, in every client<br>(c) A device signature with the account identity (`klav/v1/sig/account-delete`) and Face ID or Touch ID, without the password<br>(d) (a) plus that signature, to have the proof on the server |
| P2 | Is it deleted at once or after a waiting period? (§2) | **(a) 7 days, with "Cancel" from any device; agents are cut off at once and everything else keeps working (Recommended)**<br>(b) At once, with no way back<br>(c) 30 days, like the trash |
| P3 | What do the other devices see after the deletion? (§3) | **(a) A `401`; the one that knew the date says "Klav deleted your account", leaves its copy read-only and offers to delete it, without deleting it on its own (Recommended)**<br>(b) The server keeps token digests for 30 days and answers `410 account_deleted` to everyone<br>(c) As well as (a), each device deletes its local copy as soon as it finds out |
| P4 | Where can the account be deleted? (§4) | **(a) iOS, the Mac app and the CLI, on any server with this version and with no setting to turn it off (Recommended)**<br>(b) Only iOS, which is what Apple asks for; Mac and CLI later<br>(c) As (a), with a setting so your own server can turn it off |
| P5 | What does the server keep afterwards, and can the email register again? (§5.5) | **(a) Nothing of the account in the database; one log line with the `account_id`, without the email, to delete it again after restoring a backup; the email is free again at once (Recommended)**<br>(b) As (a), plus an HMAC of the email for 30 days so it can't register again right away<br>(c) Not even the log line |
| P6 | What happens to the local copy on the device that asks for the deletion? (§6) | **(a) It keeps its session during the waiting period so it can cancel, and at the end it offers to delete its copy, like the others (Recommended)**<br>(b) It signs out and deletes its copy when it asks for the deletion; to cancel, you have to sign in with the kit on another device<br>(c) It deletes it on its own when the deletion completes, without asking |
| P7 | What does the double confirmation look like on iOS and Mac? (§7) | **(a) A screen with what gets deleted and the date, with "Continue", then Face ID and the password with the red "Delete my account" button (Recommended)**<br>(b) As (a), plus typing the email, as in the CLI<br>(c) As (a), plus typing «BORRAR» ("DELETE") |
| P8 | What does "Cancel the deletion" require? (§2, T162–T163) | **(a) Only a device with a session: undoing must cost nothing, and an extra cancellation only delays the deletion, with a notification to the phones (Recommended)**<br>(b) Face ID or Touch ID, or the password where there is none, like resuming agents (ADR 0033 §7.3)<br>(c) The master password through OPAQUE, like asking for the deletion |

## Omar's answers (2026-11-07)

Omar accepted the ADR as it is, with the recommendation for each question:

- **P1:** Face ID or Touch ID where Klav uses it, with the Secure Enclave key, and the master password through OPAQUE always. Where there are no biometrics, only the password.
- **P2:** 7 days with "Cancel" from any device. Agents are cut off at once.
- **P3:** a `401`. The device that knew the date says "Klav deleted your account", leaves its copy read-only and offers to delete it, without deleting it on its own.
- **P4:** iOS, the Mac app and the CLI, on any server with this version, with no setting to turn it off.
- **P5:** nothing of the account in the database; one log line with the `account_id`, without the email. The email is free again at once.
- **P6:** the device that asked keeps its session during the waiting period and at the end offers to delete its copy.
- **P7:** a screen with what gets deleted and the date, with "Continue", then Face ID and the password with the red "Delete my account" button.
- **P8:** a device with a session is enough to cancel. Replaced on 2026-11-09 by (b), presence as when resuming agents (A2 in the amendment).

## Amendment of 2026-11-09

Omar decided A1–A4 on 2026-11-09, after the review of layers 2 to 5 (#238, #244, #247, #249). A5 and A6 come from the same review. Where a section above disagrees with this one, this one wins; the sections above point here.

### A1. `--no-daemon` with Touch ID set up refuses (Omar's decision D-A)
When `touchid.json` exists in `KLAV_HOME`, `klav --no-daemon account delete` refuses before asking for anything. The message says how to delete instead: without `--no-daemon`, with the lid open and Touch ID available; from the Mac app; or from the iPhone.

- **Why:** `--no-daemon` skips `klavd`, and Touch ID is `klavd`'s (§1). Before this, the CLI without `klavd` asked only for the password even where Klav uses Touch ID. The terminal must not be a shortcut around step 1.
- **Not affected:** `klav --no-daemon account delete --cancel` (A2), and a Mac or a computer without `touchid.json`, where the password is enough (§1).
- [cli.md](../cli.md) says it in layer 3.

### A2. Cancelling asks for presence, like resuming agents (Omar's decision D-B; replaces P8, amends §2)
"Cancel the deletion" asks for Face ID or Touch ID, or the master password where there is none: what resuming agents asks for (ADR 0033 §7.3). Each client does what its own resume does:

| Where | What it asks |
|---|---|
| `klavd` (`cancel_account_deletion`, for the CLI and the Mac app) | Touch ID; the master password in the request when Touch ID can't confirm |
| `klav --no-daemon account delete --cancel` | the master password that unlocks the process, as `klav --no-daemon agent resume` |
| iOS | Face ID only (biometry, not the iPhone passcode), and the master password without it or when the person picks it |
| Mac app | Touch ID through `klavd`, or the master password |

- **Why:** P8 assumed that one cancellation too many only delays the deletion. It also brings the agents back (§2). An agent, or a prompt injection, that can reach the person's session (a call to `klavd`, the CLI in the person's terminal) could cancel to resume itself. ADR 0033 guarded resuming with presence. Cancelling is another way to resume, so it asks for the same.
- **The server doesn't change.** `POST /v1/account/delete/cancel` still takes only a session. The server can't check that a person is there, just as it can't when an agent is resumed. Presence is the client's rule, as in ADR 0033. Don't move it to the server.
- **The threat model** gains the case of an agent that cancels to resume itself (T163), in layer 3.

### A3. After the deletion, the vault stays readable (Omar's decision D-C)
§3 already says that the device that knew the date leaves its copy read-only. Layers 4 and 5 replaced the vault with the screen in §7.6, and this section corrects that:

- **iOS and the Mac** show the vault read-only under a fixed notice, "Klav deleted your account". Search and copy work; editing and sync don't.
- **iOS AutoFill and the Mac menu bar** keep filling from the copy, read-only.
- **"Delete this iPhone’s copy" / "Delete this Mac’s copy"** is a separate button under the notice, never the only way out.
- **Why:** Klav can't export yet (T14), so the local copy may be the only one. A malicious server that fakes the deletion (T165) must not push the person into deleting it.
- **The marker survives restarts and older versions.** Each client keeps the deletion's date, and whether the server already confirmed it, in a sealed file of its own next to `cache.bin` (`deletion.bin`, purpose `deletion`, spec §12.2), not inside `cache.bin`. An older klav, `klavd` or app that reads `cache.bin` keeps working. `klavd` also keeps what it knows in a plaintext file without secrets, as it does with the pauses, so the Mac app shows it while locked, also after a restart. Layer 3 has the details.

### A4. What Face ID and Touch ID really protect (Omar's decision D-D; corrects §1)
- **A newly enrolled face or finger is a residual risk, stated plainly.** Whoever has the device passcode, or the Mac's login password, can enroll their own face or finger in the system settings. The Secure Enclave key (`biometryCurrentSet`) then stops opening, and Klav stops using biometry, as when unlocking. From then on the master password alone asks for the deletion.
  - No design prevents this: unlocking with the password enrolls again whatever biometry the device has.
  - Step 1 still stops someone who has the device without the person's face or finger and doesn't change the enrolled biometry.
  - The real defense is the 7-day wait and the notice to the other devices. Residual risk 57 says so.
- **Turning Face ID or Touch ID off in Klav asks for the device owner.** That is LocalAuthentication's `deviceOwnerAuthentication` policy: Face ID or Touch ID, falling back to the iPhone's passcode or the Mac's login password. It never accepts the master password alone. Before this, anyone with the unlocked iPhone could turn Face ID off in Klav's Settings with no prompt and then delete with the password alone.
  - A master-password fallback would bring that hole back: fail Face ID on purpose until it locks out, then type the password.
  - The passcode fallback sits at the bar of the first point: whoever has the passcode can already enroll a face.
- **On the Mac, nothing in Klav turns Touch ID off.** `klavd --no-touch-id` (`KLAV_NO_TOUCH_ID`) only stops offering it. While `touchid.json` exists, the deletion asks `klavd` to confirm, and that `klavd` refuses. `klavd` removes `touchid.json` only when the key stops opening (the fingers changed) or the file is damaged, and signing out removes it with the rest. Another process of the same user can delete the file (residual risk 49), and it can enroll a finger too only with the Mac's password.

### A5. Known limit: sign-in and deletion share the OPAQUE context (review finding 8)
`klav-core::crypto::opaque` has a single context string, `klav/v1/opaque`, for every exchange. A sign-in and a deletion produce messages of the same shape, and the cryptography alone doesn't say which one an exchange is for.

- **What binds an exchange to its purpose** is the server's in-memory table of half-finished logins (`crates/klav-server/src/logins.rs`). `start` stores the purpose and the session, and `finish` checks both (§1, T166). That binding holds, and the server tests cover it.
- **It stays as it is.** A context per purpose would change the OPAQUE configuration and the spec (§4.5) and add nothing, as long as that table is the only place an exchange can finish.
- **If that changes,** for example several instances sharing half-finished exchanges (residual risk 7), the purpose has to go into the context.

### A6. Where the code differs from the text above, accepted in review
1. **New agent registrations during the waiting period** get the usual silent `202`, not a refusal. The registration isn't created and no phone is told. It is the same answer as an unknown email, so whoever knows the address can't learn that the account is going (§2's table).
2. **The Touch ID and Face ID check skips the unlock's 14-day and after-restart rules.** Those rules decide when an unlock needs the password. Here the password comes right after anyway, and a device that restarted must not lose its biometric step (§1).
3. **`klav status` shows the date only through `klavd`.** Without it, `klav status` doesn't unlock the account, and the date lives in sealed local data (§4).
4. **The deletion's limits can't be configured.** They are fixed in the code (5 `start` per account per hour, 3 requests every 7 days), not in the server's settings like the per-IP limits (§5.6).
5. **An older server answers "Cancel" with "nothing to cancel".** It has no route, so `POST /v1/account/delete/cancel` gets a `404`, the same code as "no deletion is pending". It is harmless: an older server can't have scheduled one (§5.1).
