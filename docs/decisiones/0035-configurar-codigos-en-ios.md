# 0035 · Set up codes in Klav (iOS): the app opens `otpauth://` links, the person chooses the login and confirms, and nothing is replaced without "Replace"

- Status: accepted (Omar accepted it on 2026-11-06 with the recommendations of P1–P3; see "Omar's answer")
- Date: 2026-11-06

## Context
Omar wants Klav to appear in **Settings › General › AutoFill & Passwords › Set Up Codes In** (in Spanish, *Configurar códigos en*) and, once chosen there, to be the app that keeps new verification codes. Today that list only has Apple's Passwords.

The AutoFill extension already declares `ProvidesOneTimeCodes` (ADR [0018](0018-app-ios.md); [ios.md](../ios.md) §3), but that is something else: **filling** a code that is already in the vault. "Set Up Codes In" decides which app opens a **new** code: the link a site offers when turning on 2FA, or the QR code the camera scans.

### What Apple asks for
There is no *entitlement* or key of its own. It is enough for the app to open the `otpauth` scheme:

- **Apple, in the developer forums** (accepted answer from an Apple employee, April 2025, thread ["How to implement the "Set Up Codes In" feature"](https://developer.apple.com/forums/thread/780204)): *"Apps that support the otpauth:// URL scheme are displayed in that section and available to be set as the default handler."* In the same answer it points, as a separate API, to [*Providing one-time passcodes to AutoFill*](https://developer.apple.com/documentation/authenticationservices/providing-one-time-passcodes-to-autofill), which is what the extension already does.
- **WWDC24, "Streamline sign-in with passkey upgrades and credential managers"** ([session 10125](https://developer.apple.com/videos/play/wwdc2024/10125/)): *"you can make setting up that code a one-tap experience by offering an otpauth: link in addition to the standard QR code. This link opens the default verification code app on the system"*.
- **iPhone User Guide** (["Automatically fill in one-time verification codes on iPhone"](https://support.apple.com/guide/iphone/automatically-fill-in-verification-codes-ipha6173c19f/ios)): the QR code is scanned with the iPhone's camera (*"On iPhone, use the camera to scan the QR code"*) and then the account is chosen (*"select your account for the website or app"*). The camera opens the QR code's content, an `otpauth://` link, in the app from that list.
- **To take the person to that screen**, `ASSettingsHelper.openVerificationCodeAppSettings()` (*"Open the Settings app and navigate to the verification code provider settings"*, iOS 17 or newer, [documentation](https://developer.apple.com/documentation/authenticationservices/assettingshelper)). It is the sibling of `openCredentialProviderAppSettings()`, which the AutoFill welcome already uses.

**iOS version.** Apple doesn't document a minimum for the list. It exists since Passwords became an app of its own (iOS 18), and Klav already requires iOS 18 (`project.yml`), so nothing changes.

**`apple-otpauth://`** is the prefix that goes straight to Apple's Passwords (WWDC21, session 10105): Klav doesn't register it.

### What already exists and is reused
- `klav-core::totp::Totp::parse_otpauth` reads `otpauth://totp/…` (issuer, account, algorithm, digits and period), rejects `hotp` and repeated parameters, and ignores unknown ones, among them `image=`. `Totp` doesn't implement `Debug`, `Display` or `Clone`, and keeps the secret in a `SecretBox`.
- `klav-import` reads Google Authenticator's `otpauth-migration://` batches (ADR [0024](0024-importadores.md) §2), and the iOS import wizard already accepts them pasted, from the camera (`QRScanner.swift`) and from screenshots.
- The importer's rule for joining a code to a login (ADR 0024 §3.4): the issuer names the login's title or one of its hosts, and the account is its username.

## Decision

### 1. What the app registers
- `Klav/Info.plist` declares in `CFBundleURLTypes` the `otpauth` and `otpauth-migration` schemes, with the name `$(PRODUCT_BUNDLE_IDENTIFIER).otpauth`. Only the app: the AutoFill extension doesn't open links.
- **With that, Klav appears in "Set Up Codes In".** The app's Settings › AutoFill gains a row, "Set up codes in Klav", with a button that opens that iOS screen (`openVerificationCodeAppSettings`). iOS doesn't say which app the person chose, so the row can't be marked as done: it explains the way and nothing more.
- **`otpauth-migration`** doesn't go into Apple's list, which only looks at `otpauth`. It is registered so that Google Authenticator's "Transfer accounts" QR code, scanned with the iPhone's camera, opens the import wizard (§5; question P2). If another app registers the same scheme, iOS chooses which one opens, and there is no setting to change it.

### 2. What reaches Klav
iOS always delivers a **link**, through any of these paths:

| Path | What arrives |
|---|---|
| An `otpauth://totp/…` link in Safari or another app | the link |
| A site's QR code, with the iPhone's camera or with "Add Verification Code" when long-pressing the QR code in Safari | the QR code's content, which is that same link |
| Google Authenticator's "Transfer accounts" QR code, with the camera | an `otpauth-migration://offline?data=…`, a batch of an export that may come in several QR codes |

- **An `otpauth://` opens the "Save code" sheet (§3).**
- **An `otpauth-migration://` goes to the import wizard (§5).**
- **Anything else** (`otpauth://hotp/…`, a broken link, an `otpauth` without a secret) is rejected with a notice. The notice repeats nothing from the link. Klav only has time-based codes (TOTP), as ADR 0024 already said.

### 3. The "Save code" sheet
**`klav-core` reads the link as soon as it arrives**, in `klav-ffi`, and it never crosses into Swift in the clear. Swift receives an opaque `CodeLink` object and its description, without the secret: issuer, account, digits, period and algorithm. Before saving, the sheet shows:

- **what the link says:** the issuer large and the account below, marked as text "From the link". They go through `klav_core::text::shown`, like agents' names: without control or format (*bidi*) characters, on one line and trimmed. If the code isn't the usual one (6 digits, 30 s, SHA-1), it shows what it is like;
- **the logins that match:** first those that have the issuer and the account (the rule of ADR 0024 §3.4), then those with the issuer alone. Each row says whether the login has no code, already has another one, or already has **this** same one;
- **a search** to choose any other login in the vault;
- **"New login"**: title (the issuer or the account), username (the account), site and project (Personal / General by default). The site stays empty: Klav never infers it from the issuer, which is text from the link. Typing it is what makes the code fill in Safari (question P1).

**The person always chooses and confirms.** Nothing is saved without one tap on the target and another on the button of the confirmation screen, which names the login, its username and its site:

- **Login without a code:** "Save code".
- **Login with this same code** (in the field AutoFill uses, the first code field with a value: the same secret, compared in constant time with `Totp::same_secret`, and the same algorithm, digits and period): nothing is written and the sheet says "Already has this code". If the same code is only in another code field, or with other digits, period or algorithm, AutoFill would give a different one, so it counts as **another code**.
- **Login with another code:** the button is **"Replace"**, in red, with the explanation "Replacing it removes the code Klav has for this login. Do it only if the site just gave you this new one". Klav never replaces without it. The field AutoFill uses is replaced: the first code field with a value (`totp_of`). The other code fields (like the importer's "(imported)" one) stay as they are.
- **Issuer warning:** if the issuer names neither the title nor any of the login's **confirmed** sites (ADR [0030](0030-ronda-de-seguridad-2026-11.md) §7), the confirmation says so: "This link says it's for *X*, but *GitHub* is for github.com. Check that it's the right login". It is a warning, not a block: some issuers don't look like their domain ("Google" and `accounts.google.com` do match; "Microsoft" and `live.com` don't). The comparison is the importer's, moved to `klav_core::site::issuer_names_site`, so that both say the same thing.
- **An agent's pending sites:** saving is an edit by the person and confirms the sites an agent added (ADR 0030 §7). If the login has them, the confirmation says so with the URLs, like the editor.

**What is saved.** The field receives `Totp::to_otpauth()`: the normalized link, with the issuer and the account (so that the importer and the extension see them the same way) and without unknown parameters (`image=` and the others are lost). It is saved with `edit` or `create`, like any change by the person: without Face ID, like the editor.

**Checking and writing go together.** `save_code` in `klav-ffi` reads the login again, decides (new, same or different) and writes within the same call to the core, which serializes the app's calls. If the login changed on another device, the server answers `Conflict`. The sheet asks for the state again and asks again, without retrying blindly. If on confirming the login already has another code the person didn't see, `save_code` without `replace` returns "needs to replace" and doesn't write.

**After saving**, the sheet shows the current code with its countdown and "Copy". It is what the site asks for to finish turning on 2FA, and what Apple's guide does: *"A verification code appears… enter the verification code that appears on your iPhone"*.

### 4. Locked vault, several links and memory
- **With the vault locked** (or without a session), the link is read anyway (`CodeLink` doesn't need the vault) and kept **only in memory**, in `AppModel`. The lock screen says "Unlock Klav to save the code for *X*". The sheet appears on unlock.
- **It is never written to disk:** not to `UserDefaults`, not to the App Group, not to the log. The `dev.klav.ios` log only notes publicly that a link arrived and of which kind, never the issuer or the account.
- **If the app locks with the sheet open**, the sheet closes and the link keeps waiting, also in memory. It appears again on unlock. If iOS terminates the app, it is lost: the link has to be opened again.
- **It is forgotten** on saving, on canceling, when another link arrives (the last one wins) and on signing out.
- **The sheet appears on top of whatever is open** (the editor, Settings): what is underneath isn't lost. The privacy cover (T79) covers it like everything else.
- **The copies in Swift.** The `URL` iOS delivers is a Swift `String` and can't be zeroed, like the text pasted into the importer. Klav drops it as soon as `klav-core` has read it (residual risk 50). The batches of §5 don't: they wait whole as a `String`.

### 5. Google Authenticator batches (`otpauth-migration`)
- **They open the import wizard on "Google Authenticator"**, with the batch already added. The next QR codes of the same export, scanned with the camera, are added to the same wizard and its list says which ones are missing, as today.
- **Nothing is written before "Import".** The review shows each code and which login it goes to. The rules are those of ADR 0024 §3: a code never replaces another (§3.3) and is joined to a login only if the issuer and the account point to it without doubt (§3.4); if not, it stays as its own item.
- **It is the only deviation from §3:** in a batch, the person doesn't choose each code's target one by one, but reviews the whole plan and confirms it (question P2). With the vault locked, the links wait in memory and the wizard appears on unlock with all the ones received.
- **How they wait, unlike §4.** A batch isn't read on arrival: it waits whole, with all its secrets, as a Swift `String` in `AppModel` (and, with the wizard open, also in its list of read links). A `String` can't be zeroed. It waits from when it arrives until the person imports, closes the wizard or signs out, also while the vault is locked; locking doesn't drop it. It never goes to disk or to the log, and if iOS terminates the app, it is lost (residual risk 50).

### 6. No network
- **Klav opens nothing from the link:** not `image=` (the logo some sites add), not the issuer as a URL, not a site icon. The sheet uses the logos the app ships with (`SiteIcons`) or the initial, like the rest of iOS ([ios.md](../ios.md) §1).
- The only network is that of any edit: uploading the login's new version to the server, encrypted.

### 7. Where each thing lives
- **`klav-core`:** `site::issuer_names_site(issuer, title, hosts)`, the rule of ADR 0024 §3.4 (lowercase letters and digits; the title, the whole host or one of its labels). `klav-import` uses it instead of its own. Nothing new in cryptography.
- **`klav-ffi` (`codes.rs`):** `CodeLink` (reads the link; its description without secrets), `KlavCore::code_targets` (the logins with their match and their state) and `KlavCore::save_code` and `save_code_new` (deciding and writing in one call, §3). The decision is a pure function over the opened item, tested without a server. No type that carries the secret implements `Debug`.
- **iOS:** `onOpenURL` in the scene, the pending link in `AppModel`, the sheet in `Klav/CodeSetup.swift`, the Settings row and the texts in `Localizable.xcstrings`, in English and in Spanish.
- **Outside this ADR:** the browser extension and the CLI already create codes from a pasted `otpauth://` ("New item", `klav item create`), and Android will have its own in phase 7.

### Later
Outside this ADR, in case they are needed:

- reading each `otpauth-migration://` batch as soon as it arrives into an opaque `klav-ffi` object, like `CodeLink`, so that it doesn't wait as a Swift `String` with the vault locked (§5).

## Rejected alternatives
- **Saving without asking into the login that matches.** A link is a third party's text: a page can open an `otpauth://` with whatever issuer it wants. Without the person's choice, a link could put someone else's code into their login or, if it replaced, lock them out of their account.
- **Always replacing, or never replacing.** Replacing without asking is the attack above. Never replacing leaves no way out for whoever sets up 2FA again, which is exactly when the site invalidates the previous code.
- **Passing the link in the clear to Swift and saving it with `create_item`.** The secret would live in a Swift `String` on every screen. With `CodeLink`, it only lives in `klav-core`, which zeroes it on release.
- **Registering `apple-otpauth`.** It is the scheme of Apple's Passwords, and the sites that use it want Passwords.

## Consequences
- Klav appears in "Set Up Codes In" from the first build with the scheme. The person chooses it once in iOS Settings, and the app explains it.
- The replaced code leaves the login. It stays in the item's earlier versions the server keeps (encrypted), but no client shows them today (question P3, residual risk 50).
- A link that arrives with the app closed and the vault locked asks to unlock before showing anything.

## Threat model
New rows in [`modelo-de-amenazas.md`](../modelo-de-amenazas.md) §5.16: T143 (a link puts in or replaces a code), T144 (the link's text misleads in the sheet), T145 (the pending link with the vault locked) and T146 (another app receives the links, or a batch is imported without choosing the target), and residual risk 50.

## Questions for Omar
- **P1. "New" in the sheet: a login or a standalone code (kind `totp`)?** The browser extension and the importer create a standalone code. But on iOS only a login with a site fills the code in Safari and other apps: `credential_identities` and `one_time_code` only look at logins, because of the site check of T73. Besides, Apple's Passwords also asks for an account. **Recommendation: a login** (title, the account's username, an optional site the person types, and no password), and the implementation of layer 2 does it that way.
- **P2. `otpauth-migration`: is it registered, and does it open the wizard?** Apple doesn't need it for the list. For: whoever moves from Google Authenticator to Klav scans with the iPhone's camera, without going to Settings › Import. Against: it is the deviation of §5, because in a batch ADR 0024's merge decides and the person reviews and confirms the plan. **Recommendation: register it and open the wizard**, which already warns about everything before writing and never replaces. Layer 2 implements it that way. Removing it means deleting one line of `Info.plist` and one branch of `openLink`.
- **P3. What happens to the replaced code?** Today it leaves the login. The server's earlier versions keep it, but nothing shows it. Another option: leaving it in a second field, "One-time code (previous)". **Recommendation: let it go.** Whoever sets up 2FA again invalidates the previous code on the site. A second field would keep a dead secret nobody fills, because AutoFill uses the first one.

## Omar's answer (2026-11-06)

Omar accepted the ADR as it is, with each question's recommendation, which is what layer 2 implements:

- **P1:** "New" creates a login (title, the account's username, an optional site and no password).
- **P2:** `otpauth-migration` is registered and opens the import wizard.
- **P3:** the replaced code leaves the login.
