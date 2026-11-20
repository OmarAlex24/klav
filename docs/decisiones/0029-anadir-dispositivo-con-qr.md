# 0029 · Add a device with a QR code: the device that is already signed in passes the Secret Key to the new one with HPKE, through the server as a blind relay, and the person only types their password

- Status: accepted
- Date: 2026-11-05

## Context
Today, signing in on a new device asks for the server, the email, the master password and the **Secret Key**: 34 characters copied from the emergency kit ([`cli.md`](../cli.md) §3, [`ios.md`](../ios.md) §2). Omar: "that QR thing would be amazing". The idea is similar to 1Password's "Sign in with another device": a device that is already signed in securely passes the new one whatever it needs so the Secret Key doesn't have to be typed, and the person only types their master password. The roadmap has it under "Polish after the first real use".

**What already exists and is reused:**
- **HPKE** (RFC 9180, `base` mode, suite X25519/HKDF-SHA256/ChaCha20-Poly1305) in `klav-core`, the same one that shares vault and project keys (spec §8). No new primitive is needed.
- **The 6-word code** from the EFF Large Wordlist with which the person compares an agent's key (spec §13.1, ADR [0014](0014-agentes-fase-4.md) §1.3).
- **Reading QR codes:** the iOS app already scans with the camera (`QRScanner.swift`, AVFoundation) for the importers (ADR [0024](0024-importadores.md)). `klav-import` reads PNG with `rqrr` behind the `qr-image` feature.
- **Generating QR codes:** iOS and macOS do it with Core Image (`CIQRCodeGenerator`), from the system. In Rust, `qrcode` 0.14 is only approved with the `samples` feature of `klav-import` and in tests (CLAUDE.md).
- **The usual login:** OPAQUE with `O`, Argon2id and the sealed identity that the client checks (spec §4.3–4.5 and §6.3; T2 and T9).

**What doesn't change:** the new device still does a full sign-in, with its own registration on the server and its own tokens. This ADR only changes **where it gets the Secret Key**, the server and the email from: it receives them from another device instead of the person typing them.

## Proposed decision

### 1. Who shows and who scans
There are two devices: **N**, the new one, still without a session, and **E**, one that is already signed in and unlocked.

- **Mode A, the new one shows (default).** N shows a QR code and E scans it with its camera.
  - The QR code carries N's ephemeral public key. Since it travels through the camera, the server can't change it.
  - A photographed QR code is useless: it carries no secrets and doesn't let anyone collect the package (§3).
- **Mode B, the signed-in one shows.** For when E has no camera at hand: a Mac adding an iPhone, or the CLI adding an iPhone.
  - E shows a QR code and N scans it.
  - N's public key reaches E **through the server**, so the word comparison (§4) is mandatory: E seals nothing until the person taps "They match".
  - E's QR code carries the server's full URL, so N doesn't have to type it either.

| E (signed in) → N (new) | How |
|---|---|
| iPhone → Mac | A: the Mac shows the QR code in the welcome screen (ADR [0027](0027-app-de-mac.md) §4, step 5) and the iPhone scans it |
| iPhone → iPhone | A: the new one shows it in "Sign in", the other one scans it |
| iPhone → CLI | A: `klav login --qr` draws the QR code in the terminal; the iPhone scans it |
| Mac → iPhone | B: the Mac shows the QR code in Settings › Devices › "Add a device", and the new iPhone scans it from "Sign in" |
| Mac → CLI | A as text: `klav login --qr` also prints the QR code's content as text (`KD1-…`), and the person pastes it into the Mac's "Add a device". It works over SSH |
| CLI → iPhone | B: `klav device add --show` draws the QR code in the terminal |
| CLI → CLI | A as text: `klav login --qr` on the new one and `klav device add KD1-…` on the one already signed in |

- **The text is the whole QR code**, never a short code (§9). The person copies it from a screen in front of them, so it is still an authentic channel.
- **The scanner lives inside Klav.** The QR code is not a link: it carries no `https://` or a scheme that would open the system camera or a browser (§7).

### 2. What travels and what doesn't
**Travels from E to N, inside the package sealed with HPKE (§5):**
- the Secret Key, in its text form (`K1-…`, spec §4.2);
- the server URL;
- the email and the `account_id`;
- who approved it: E's `device_id` and name;
- the date and the expiry;
- the account's signature (§5.3).

**Never travels:** the master password, the KEK, the OPAQUE input `O`, E's local key, its session tokens, the identity's private keys or any vault key. N registers as a new device with its own sign-in.

**On receiving it,** N shows the email and the server read-only (with "Not me" to cancel) and asks for the master password. Then it does the usual login. N sets the device name, as today.

### 3. The server, as a blind relay
For a few minutes the server stores a package it can't open, and hands it over only once to whoever proves they are N.

- **`link_id`** (16 bytes) is the name of the slot on the server. It goes in the QR code.
- **`fetch_key`** (32 random bytes) is the key to collect the package. N generates it and it **doesn't leave N** until N presents it.
  - In mode A, `link_id = SHA-256(tuple("klav/v1/link/id", fetch_key))[0..16]`: the QR code only carries the digest.
  - In mode B, N sends `claim_hash = SHA-256(tuple("klav/v1/link/id", fetch_key))[0..16]` with its offer.
  - Whoever photographed the QR code knows `link_id`, but not `fetch_key`, so they can't collect the package or spend it.
- **New routes** (written into `api.md` on implementation):

  | Route | Who | What for |
  |---|---|---|
  | `POST /v1/links` | E, with a session (mode B) | opens a slot with `link_id` |
  | `POST /v1/links/{id}/offer` | N, without a session (mode B) | leaves its public key, `claim_hash`, and the name and kind it claims to be; only once |
  | `GET /v1/links/{id}` | E, with a session | the state: N's offer (mode B), whether N is waiting and the network hint (§7) |
  | `PUT /v1/links/{id}/payload` | E, with a session | leaves the sealed package and the signature; only once |
  | `POST /v1/links/claim` | N, without a session, *long-poll* of up to 60 s | `{link_id, fetch_key}` → the package, and the server deletes it on handing it over. In mode A, N's first wait opens the slot: the server computes `link_id` from `fetch_key` |

- **Single use and expiry:**
  - each slot lives **5 minutes** from when it is opened, with or without a package;
  - the package is deleted when it is handed over, and a second collection gives `404`;
  - N discards its ephemeral key after opening the package or on expiry, so a package copied from the server is useless afterwards;
  - 5 collections with a wrong `fetch_key` close the slot.
- **Caps:**
  - at most 3 open slots per account;
  - the routes without a session use the per-IP authentication *rate limit*, like `POST /v1/agents/register` (ADR 0014 §1.2).
- **What the server sees:** that an account is adding a device, when, from which IP both are, and the name N claims. It doesn't see the Secret Key or the email in the package. It will see the email anyway at login.
- **The server in mode A:** N has to know which server to wait on.
  - By default it is `api.klav.dev` (ADR [0028](0028-servidor-por-defecto-klav-dev.md)). Self-hosters type only the URL in "Use my own server" before showing the QR code, or use mode B, which brings it in the QR code.
  - The QR code carries 8 bytes of that URL's digest. If it isn't E's, E refuses: "This device is waiting on another server (…); your account is on <host>".

### 4. Confirmation with words
- **The words** are the 6-word code from spec §13.1, computed over `SHA-256(tuple("klav/v1/link/words", oferta, pk_N))`:
  - `oferta` is the exact bytes of the QR code (§6);
  - `pk_N` is N's ephemeral public key.
- **In mode B they are the barrier.** E shows the words with the `pk_N` the server gave it, and N with its own. If the server swapped `pk_N` for one of its own, they don't match. To make them match it would have to find another key with the same words for an offer it didn't choose (a second preimage of ~77.5 bits) within the 5 minutes. E seals nothing until the person taps "They match".
- **In mode A they are a confirmation.** Both screens show them, and the person checks that they scanned the device in front of them. The key already arrived through the camera, so they aren't the barrier.
- **Same format as with agents:** the person already knows the 6-word card.

### 5. The sealed package
#### 5.1 HPKE in `base` mode
```
(enc, ct) = SealBase(pkR = pk_N, info, aad = header, pt = paquete)
info      = tuple("klav/v1/link/payload", link_id, SHA-256(oferta), pk_N)
blob      = header(2) ‖ enc(32) ‖ ct(n + 16)             header = 0x01 ‖ 0x22
```
- It is the same single-shot construction as types `0x20` and `0x21` (spec §8). The `info` binds the package to this slot, this offer and this key.
- **It stays in `base` mode.** `auth` mode would prove the sender inside HPKE with a static key of E's, but it would require another suite in `klav-core`, other vectors and an X25519 key of E's that N can't check before signing in. Authenticity comes from the §5.3 signature, which N verifies after login.

#### 5.2 What goes inside
Versioned JSON, so that a new field doesn't change the envelope format:

```
{v: 1, link_id, server, email, account_id, secret_key, approved_by: {device_id, device_name}, issued_at_ms, expires_at_ms, signature}
```

N rejects the package in any of these cases:
- unknown `v`;
- another `link_id`;
- a `server` different from the one it used to collect it;
- `expires_at_ms` past.

#### 5.3 The account's signature
E signs with the account's Ed25519 identity (spec §9):

```
mensaje = tuple("klav/v1/sig/device-link", account_id(16), link_id(16), pk_N(32), approved_by_device_id(16), server, u64_be(issued_at_ms))
```

- **It doesn't sign the Secret Key** or anything derived from it, so the signature can also go into the audit log.
- **N verifies it after signing in,** with the `public_identity` it already checked when opening its sealed identity (T9). If it doesn't verify, N signs out, deregisters and says so: the package wasn't made by the account.
- **The server stores it** in the `device.linked` audit log event (§7) and checks it against the account identity. No new format is needed: the audit log already stores signed bytes (spec §13.7).

### 6. Formats versioned from the first byte
**The offer**, what goes in the QR code, is a new type **`0x08` link-offer**, from the reserved range `0x08–0x0F`, next to the other public types (`0x05`, `0x06`, `0x07`):

```
modo A: 0x01 ‖ 0x08 ‖ 0x41 ('A') ‖ link_id(16) ‖ pk_N(32) ‖ server_hash(8)                      (59 bytes)
modo B: 0x01 ‖ 0x08 ‖ 0x42 ('B') ‖ link_id(16) ‖ qr_nonce(16) ‖ lp(server_url)                   (39 + n bytes)
server_hash = SHA-256(tuple("klav/v1/link/server", server_url canónica))[0..8]
texto       = "KD1-" ‖ BASE32(oferta) en grupos de 4 caracteres                        (alfabeto de §4.2)
```

- **The text uses QR alphanumeric mode.** Uppercase BASE32 fits in it, and the `KD1-` prefix ("Klav device", version 1) can't be confused with the Secret Key's `K1-`. The hyphenated groups are only for the copied text; inside the QR code goes `KD1-` and the BASE32 run together. When reading the text, hyphens, spaces and case are ignored, as with the Secret Key.
- **Size in mode A:** 59 bytes are 95 characters in BASE32, 99 with the prefix. They fit in a version 5 QR code with M correction (37 × 37 modules, up to 122 alphanumeric characters). In the terminal, with a half block per row, they fit in 23 lines including the margin. That is why mode A carries the URL's digest and not the whole URL.
- **In mode B,** `qr_nonce` binds the words to the QR code that was seen. The whole URL makes the QR code somewhat bigger, but that QR code is shown on a large screen or in a terminal that can grow.

**The package** is a new type **`0x22` link-payload**, the first of the range `0x22–0x2F` next to the other two HPKE types (§5.1). It is deleted on the server when handed over and N doesn't store it.

**New labels:** `klav/v1/link/id`, `klav/v1/link/server`, `klav/v1/link/words`, `klav/v1/link/payload` and `klav/v1/sig/device-link`.

**What will go into the spec on implementation,** without writing it now:
- a new section, "Add a device", before the changelog;
- types `0x08` and `0x22` in §3;
- the labels in §2.3.

**The vectors will go in `docs/vectores/dispositivo.json`:**
- offers A and B with their `KD1-` text;
- `link_id` from `fetch_key`, and `server_hash`;
- the 6 words for each mode;
- the sealed package with a fixed `enc`, as in `compartir.json`;
- the `device-link` signature;
- a package with another `link_id` and an expired one, which must be rejected.

### 7. Approval on the device that is already signed in
- **What the person sees on E** before approving:
  - "You're about to add a device to your account. Only do this with a device that is in front of you. If someone asked you to scan this code, cancel."
  - N's name and kind, labeled "according to the new device" (in mode B; the same pattern as T92). None of that is authenticated.
  - The 6 words.
  - **The network hint:** with what it already knows about the two IPs, the server says whether N is waiting from the same public network as E (`same_network`). If not, E says so prominently: "The new device is on another network". It is only a hint: an iPhone on mobile data next to a Mac on Wi-Fi also shows up as "another network".
  - If N isn't waiting yet (in mode A, nobody has started collecting), E says so: it may be an old or photographed QR code.
- **It approves with presence bound to Klav's key:**
  - Face ID or Touch ID **that opens Klav's Secure Enclave key** (`biometryCurrentSet`, spec §12.3), not just a standalone `LAContext`. Someone who knows the iPhone's passcode can enroll their face, and with that a standalone `LAContext` would pass, but Klav's key stops opening;
  - or the master password;
  - never the iPhone passcode alone, unlike the agent approvals in ADR 0018 §6.
- **Afterwards:**
  - N's login carries the `link_id` in `login/finish` (a new optional field in `api.md` §2.3), and the server records `device.linked` with the §5.3 signature;
  - **the other devices get a notification**: "New device on your account: <name>, added from <E>". On iOS it goes through APNs with a new `device` type and only the ID, like the others (ADR 0018 §5), and on the Mac as a local notification (ADR 0027 §1). The notification carries "Wasn't me", which opens the device list to revoke it;
  - the device list marks "added with a code from <E>".

### 8. Attacks
| Attack | What it gets | Why not more |
|---|---|---|
| **Someone photographs the QR code** (mode A) | Nothing. The QR code carries `pk_N`, `link_id` and the server digest | Without `fetch_key` it can't collect the package, and without N's private key it can't open it. If it scans it with its own Klav and approves before the person does, N receives the data of **another** account: it shows an email that isn't the person's ("Not me", §2), and with the person's password the login fails. The most it achieves is that the person has to start over |
| **Someone photographs the QR code** (mode B) | It can race to leave its own offer before N | The words don't match N's and E doesn't seal (§4). One offer per slot: if it wins the race, N sees "this code was already used" and the person starts over |
| **Malicious server as man in the middle** (mode A) | It can deny service, not hand over the package or hand over another one | It can't change `pk_N`, which traveled through the camera. A package it made doesn't open at login: without the person's password it has no OPAQUE registration or sealed identity that would open with it (T2, T9). Also, the §5.3 signature wouldn't verify |
| **Malicious server as man in the middle** (mode B) | Swap `pk_N` for its own | The words don't match (§4): a second preimage of ~77.5 bits in 5 minutes |
| ***Phishing***: "scan this QR code" in an email, a "support" chat or a web page | The attacker shows the offer of **their** N, and if the person scans and approves it, they receive the Secret Key, the server and the email | **The words don't stop it:** the attacker's page can show the same ones. What limits it: (1) without the master password they can't get in (Q1); (2) the §7 text, the network hint and the "N isn't waiting" notice; (3) the scanner only exists inside Klav and the QR code isn't a link, so it can't be opened with one tap from an email; (4) the notification to the other devices with "Wasn't me". **The damage that remains:** the attacker has the same as if they stole the emergency kit; against the server's database, the Secret Key no longer protects the password (T1). Residual risk 34 |
| **Stolen device, already unlocked** | The thief adds a device of their own | Approving asks for Face ID or Touch ID bound to Klav's key, or the master password (§7). Even if they manage it, the new device asks for the master password, and the Secret Key was already on the stolen device (ADR 0011 §5, ADR 0018 §2): they gain nothing they didn't already have |
| **Replay** | Using a package or a QR code again | Single use on the server, a 5-minute expiry inside the signed package, and N discards its ephemeral key (§3) |

**New threats.** The IDs are provisional (see ADR 0027 §8). On acceptance, they go into a new §5.13:
- **T113:** photographing the QR code;
- **T114:** man-in-the-middle server;
- **T115:** *phishing* with "scan this QR code";
- **T116:** stolen, unlocked device;
- **T117:** replay.

Each one carries the mitigation from the table above.

**New residual risk (provisional, 34):** a person tricked into scanning and approving an attacker's offer hands them their Secret Key. With that, the attacker only needs the master password, which they can try to get out of them with the same trick. Klav makes it hard (text, network hint, notification to the other devices), but it can't stop the person from approving.

### 9. Combinations and how it looks in each place
- **iOS:**
  - "Sign in" gains "Sign in with another device", which shows the QR code (mode A) and a "Scan a code" button (mode B);
  - Settings › Devices gains "Add a device", with the scanner (mode A) or "Show a code" (mode B).
- **Mac (ADR 0027):** the same in the welcome screen and in Settings. "Paste a code" accepts the `KD1-…` text.
- **CLI:**
  - `klav login --qr` does mode A: it draws the QR code, prints the text and waits;
  - `klav login --code KD1-…` is N in mode B: it pastes the text of the QR code E shows;
  - `klav device add KD1-…` approves a mode A text;
  - `klav device add --show` does mode B.

  All three approve with Touch ID through `klavd` or with the password.
- **Drawing the QR code in the terminal** needs a generator in Rust. The proposal is to use `qrcode` 0.14 in `klav-cli`, behind a `qr` feature that only the CLI turns on. It is already in `Cargo.lock`, but approved only for tests in `klav-import`, so **it is a new dependency for the CLI and Omar approves it** (Q6). It isn't cryptography. iOS and Mac use Core Image.
- **The CLI doesn't scan:** it has no camera. Wherever scanning would be needed, it uses the whole text.

## Rejected alternatives
- **A short code to type** (6 digits or 4 words) instead of the QR code or its whole text. If neither of the two ephemeral keys travels over an authentic channel, the server can man-in-the-middle both. It picks its two fake keys and looks for a pair with the same short code: it is a birthday attack, of about 2³⁹ attempts for 6 words, which fit in minutes on a GPU. Closing it would require a commit-and-reveal step, and a new PAKE or SAS protocol. With the QR code, or by pasting its whole text, `pk_N` (mode A) or `qr_nonce` (mode B) arrive over a channel the server doesn't touch.
- **Passing something that also avoids the master password** (the KEK, the local key or a session). It would turn any unlocked device into a way to clone the whole account, and the thief in §8 would gain something. See Q1.
- **A universal link or a custom scheme in the QR code** (`https://klav.dev/link#…`, `klav-link:`). The system camera and email clients would open it with one tap, which is exactly what *phishing* wants. Not `klav://…` either, which is already used for item references ([`cli.md`](../cli.md) §4).
- **Bluetooth or the local network instead of the server:** more permissions (Bluetooth, local network on iOS), it doesn't reach a CLI over SSH and it still needs the word comparison.
- **HPKE in `auth` mode:** §5.1.
- **Having N show the received Secret Key for the person to confirm:** it would put it on screen for no reason.

## Consequences
- **`klav-core`:** types `0x08` and `0x22`, the §6 labels, the `device-link` signature and its vectors. HPKE doesn't change.
- **`klav-client`:** N's flow (offer, wait and open) and E's (scan or show, check and seal), and `link_id` at login.
- **Server:** the slot table with expiry, the §3 routes, the `device.linked` event, the `device` notification and the optional field in `login/finish`. The packages are opaque.
- **Clients:** iOS, Mac (ADR 0027) and CLI, as in §9. The extension doesn't change, because it doesn't sign in.
- **Threat model:** §5.13 with T113–T117 and residual risk 34 (provisional IDs).
- **Dependencies:** `qrcode` 0.14 in `klav-cli`, behind the `qr` feature, approved by Omar (Q6). None cryptographic.

## Omar's answers (2026-11-05)
Omar accepted all the default answers, including `qrcode` in the CLI (Q6).

| # | Question | Answer |
|---|---|---|
| Q1 | Does the new device still ask for the master password? | **Yes, always.** The QR code only avoids typing the Secret Key. Without it, any unlocked device, or a person tricked with a QR code, would hand over the whole account |
| Q2 | Who shows the QR code? | The new one (mode A); mode B for when the signed-in one has no camera (Mac or CLI adding an iPhone), with the words mandatory |
| Q3 | How long does a code last? | 5 minutes and single use |
| Q4 | What approves on the signed-in device? | Face ID or Touch ID bound to Klav's key, or the master password; never the iPhone passcode alone |
| Q5 | Show the "the new device is on another network" hint? | Yes, as a warning; it doesn't block |
| Q6 | `qrcode` 0.14 in `klav-cli` to draw the QR code in the terminal? | Yes, behind the CLI's `qr` feature; it isn't cryptography |
| Q7 | Notify the other devices of each added device? | Yes, with "Wasn't me" to revoke it |
| Q8 | How many words? | 6, the same as agent registration |
