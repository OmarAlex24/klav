# iOS app listing on the App Store

The texts to paste into App Store Connect, in English (en-US) and Spanish
(es-MX), the privacy answers, the App Review notes and the screenshot list.
The step-by-step guide (what's missing, in what order and who does it) is in
[`docs/publicar-ios.md`](../../../docs/publicar-ios.md).

- What is inside a code block is pasted as is.
- Next to each field go its limit and the length of its text. Apple counts
  **characters**, except for the keywords and the App Review notes, where it
  counts **bytes** (an accented vowel or an «ñ» counts as 2). The numbers
  were measured on 2026-11-07 with the §9 command, and the App Review notes
  again on 2026-11-09; if you change a text, measure it again.
- The es-MX texts stay in Spanish, next to their en-US versions: they are
  what the Spanish listing shows.
- The App Review notes are **English only**: the reviewer reads them, not
  the people who install the app.
- **[CHECK]** marks something that couldn't be checked from the repository.
  Omar's decisions (D1–D13) are in
  [`publicar-ios.md`](../../../docs/publicar-ios.md) §8.
- What goes between `<filled in at submission: …>` is typed into the App
  Store Connect form at submission, and **never** into this file or the
  repository: the demo account's email, master password and Secret Key, and
  Omar's contact details.

Everything the listing says the app does was checked against the code and
[`docs/ios.md`](../../../docs/ios.md) on 2026-11-07 (0.9.0, build 6). If the
app changes, review §2 and §6.

## 1. Name, subtitle and promotional text

**Name** (*App Information* → *Name*, 30 characters; from 2 to 30). The app
record in App Store Connect is still called "Klav"
([probar-fase-6.md](../../../docs/probar-fase-6.md) §1, step 4). Omar chose
the long name (D2): the words in the name count in search, so they don't use
up keywords. The name under the iPhone icon stays "Klav"
(`CFBundleDisplayName` in `Klav/Info.plist`).

```text
Klav Password Manager
```

```text
Klav: gestor de contraseñas
```

(21 and 27 of 30.)

**Subtitle** (*Subtitle*, 30 characters). Apple doesn't allow naming other
apps or promising what can't be verified (guideline 2.3.7).

```text
For you and your AI agents
```

```text
Para ti y tus agentes de IA
```

(26 and 27 of 30.)

**Promotional text** (*Promotional Text*, 170 characters). It shows above the
description and can be changed without submitting a new version.

```text
Let your AI agents sign in for you without seeing your passwords. When one asks for more, approve it from the notification with Face ID.
```

```text
Deja que tus agentes de IA inicien sesión por ti sin ver tus contraseñas. Cuando uno pide algo más, apruébalo desde el aviso con Face ID.
```

(136 and 137 of 170.)

## 2. Description

*Description*, 4000 characters, plain text (no HTML), with line breaks.

**English:**

```text
Klav is an open-source, end-to-end encrypted password manager for people who work with AI agents. Everything you save is encrypted on your iPhone before it leaves for the server, and only your devices hold the key.

OPENS WITH FACE ID
Klav unlocks with Face ID, using a key kept in the iPhone's Secure Enclave. It locks itself when you leave the app or after the time you choose, and the app switcher only ever shows the lock.

AUTOFILL IN SAFARI AND APPS
Turn Klav on in Settings › General › AutoFill & Passwords, and it fills your passwords and one-time codes in Safari and other apps, with suggestions above the keyboard. It offers only the logins that match the site you are on.

PASSKEYS
Sign in with the passkeys you keep in Klav, and save new ones when a site or an app offers to create one. Every use asks for Face ID.

ONE-TIME CODES
The Codes tab shows all your live two-factor codes, large and easy to read, and a tap copies one. Choose Klav in Settings › General › AutoFill & Passwords › Set Up Codes In, and the setup QR codes you scan with the Camera open in Klav, ready to save in the right login.

YOUR AGENTS ASK, YOU APPROVE
When an AI agent on your computer needs your permission, your iPhone gets a notification. You see which agent is asking, for what and why, and you approve it once or for 15 minutes with Face ID, or deny it. For a bigger job, an agent asks for a task: one card covers everything it needs, and you can uncheck anything or shorten the time. A new agent shows six pairing words to compare before it gets anything. By default, agents get actions, not values: they fill and sign in without receiving your passwords. What they do is kept in an audit log that your devices sign.

VAULT HEALTH
See which passwords are reused, weak or old. If you turn it on, Klav also looks for breached passwords with Have I Been Pwned, sending only the first 5 characters of each password's hash. "Fix my reused passwords" hands the changes to one of your agents on your computer, which gets the sites of those logins, and you follow each site from your iPhone.

STRONG PASSWORDS
Smart passwords that follow each site's rules, random ones, memorable passphrases and PINs. Klav keeps a history of what it generates, and each login keeps its previous passwords.

BRING YOUR PASSWORDS
Import from Bitwarden, 1Password, Google Authenticator (with the camera or from screenshots), Chrome, Edge, Brave, Firefox, Safari and Passwords, or a CSV file. You review everything before it is saved.

PRIVATE BY DESIGN
- Your vault is encrypted, titles, usernames and sites included. The server never sees your master password or your Secret Key.
- No analytics, no ads, no tracking and no third-party SDKs.
- Notifications carry no names or text from your vault.
- What you copy is cleared from the clipboard after 30 seconds.

YOUR ACCOUNT
Klav works with a Klav account: you sign in with your email, master password and Secret Key, which are in your emergency kit. Klav's own server, klav.dev, does not take new accounts yet. Until it does, you can host your own Klav server, create your account there with the klav command, and sign in with "Use my own server".

Klav is open source: https://github.com/OmarAlex24/klav
Privacy policy: https://klav.dev/privacy
```

(3266 of 4000.)

**Spanish:**

```text
Klav es un gestor de contraseñas de código abierto, con cifrado de extremo a extremo, pensado para quien trabaja con agentes de IA. Todo lo que guardas se cifra en tu iPhone antes de salir hacia el servidor, y solo tus dispositivos tienen la llave.

SE ABRE CON FACE ID
Klav se desbloquea con Face ID, con una llave guardada en el Secure Enclave del iPhone. Se bloquea sola al salir de la app o tras el tiempo que elijas, y en el selector de apps solo se ve la cerradura.

AUTORRELLENO EN SAFARI Y EN TUS APPS
Activa Klav en Ajustes › General › Autorrelleno y contraseñas, y rellenará tus contraseñas y tus códigos de un solo uso en Safari y en otras apps, con sugerencias sobre el teclado. Solo te ofrece los logins que coinciden con el sitio en el que estás.

PASSKEYS
Inicia sesión con las passkeys que guardas en Klav, y guarda las nuevas cuando un sitio o una app te ofrezca crear una. Cada uso pide Face ID.

CÓDIGOS DE UN SOLO USO
La pestaña Códigos muestra todos tus códigos de verificación en vivo, grandes y fáciles de leer, y un toque copia el que elijas. Elige Klav en Ajustes › General › Autorrelleno y contraseñas › Configurar códigos en, y los QR de configuración que escanees con la Cámara se abrirán en Klav, listos para guardarse en el login correcto.

TUS AGENTES PIDEN, TÚ APRUEBAS
Cuando un agente de IA de tu computadora necesita tu permiso, tu iPhone recibe un aviso. Ves qué agente lo pide, qué pide y para qué, y lo apruebas una vez o por 15 minutos con Face ID, o lo deniegas. Para un trabajo más grande, el agente pide una tarea: una sola tarjeta cubre todo lo que necesita, y puedes desmarcar lo que quieras o acortar el tiempo. Un agente nuevo muestra seis palabras para que las compares antes de que reciba nada. De forma predeterminada, los agentes reciben acciones, no valores: rellenan e inician sesión sin recibir tus contraseñas. Lo que hacen queda en una bitácora que firman tus dispositivos.

SALUD DE LA BÓVEDA
Mira qué contraseñas están repetidas, son débiles o ya son viejas. Si lo activas, Klav también busca contraseñas filtradas con Have I Been Pwned, y solo envía los 5 primeros caracteres del hash de cada una. «Arreglar mis contraseñas repetidas» le pasa los cambios a uno de tus agentes en tu computadora, que recibe los sitios de esos logins, y tú sigues cada sitio desde el iPhone.

CONTRASEÑAS FUERTES
Contraseñas inteligentes que cumplen las reglas de cada sitio, aleatorias, frases fáciles de recordar y PIN. Klav guarda un historial de lo que genera, y cada login conserva sus contraseñas anteriores.

TRAE TUS CONTRASEÑAS
Importa desde Bitwarden, 1Password, Google Authenticator (con la cámara o desde capturas), Chrome, Edge, Brave, Firefox, Safari y Contraseñas, o un archivo CSV. Revisas todo antes de guardarlo.

PRIVADO DESDE EL DISEÑO
- Tu bóveda va cifrada, también los títulos, los usuarios y los sitios. El servidor nunca ve tu contraseña maestra ni tu Secret Key.
- Sin analítica, sin anuncios, sin rastreo y sin SDK de terceros.
- Los avisos no llevan nombres ni textos de tu bóveda.
- Lo que copias se borra del portapapeles a los 30 segundos.

TU CUENTA
Klav funciona con una cuenta de Klav: inicias sesión con tu correo, tu contraseña maestra y tu Secret Key, que vienen en tu kit de emergencia. El servidor de Klav, klav.dev, todavía no abre cuentas nuevas. Mientras tanto, puedes alojar tu propio servidor de Klav, crear ahí tu cuenta con el comando klav e iniciar sesión con «Usar mi propio servidor».

Klav es de código abierto: https://github.com/OmarAlex24/klav
Política de privacidad: https://klav.dev/privacy
```

(3584 of 4000.)

Where each claim comes from:

| Claim | Source |
|---|---|
| Face ID with a Secure Enclave key; locks on leaving the app or after 1, 5 or 15 min or 1 h; the app switcher only shows the lock | [ios.md](../../../docs/ios.md) §2 |
| AutoFill of passwords and codes, QuickType, only the logins that match the site | ios.md §3, "Suggestions, filling and memory" and "Order and 'Saved for a subdomain' (ADR 0025)" |
| Passkeys: sign in and save, always with Face ID | ios.md §3, "Passkeys (ADR 0020 §11)" |
| "Codes", a tap copies; "Set Up Codes In" | ios.md §1, "Tabs by kind and 'Codes'", and §3, "Set up codes in Klav (ADR 0035)" |
| Approve once, 15 min or deny; tasks; a new agent's six words | ios.md §4 |
| Agents get actions, not values | `CLAUDE.md`, «Reglas que no se negocian»; the default policy in [cli.md](../../../docs/cli.md) §9 (`reveal` in `deny`) |
| Vault health, Have I Been Pwned with 5 characters of the hash, "Fix my reused passwords" and the agent getting the sites | ios.md §9; `apps/ios/Klav/Health.swift:239` |
| Generator, history and previous passwords | ios.md §1, "Generator and previous passwords" |
| The import sources | `ImportSource` in `apps/ios/Klav/ImportView.swift:7-35`; ios.md §8 |
| Notifications without names or text | ios.md §4, "What a notification carries" |
| The clipboard is cleared after 30 s | `apps/ios/Shared/Clipboard.swift:11` and `:19` (`expirationDate`) |
| Sign-in with email, master password and the kit's Secret Key; "Use my own server" | `apps/ios/Klav/SignInView.swift:56-108` |
| Registration closed on klav.dev | ADR [0028](../../../docs/decisiones/0028-servidor-por-defecto-klav-dev.md) §3 |

Section names of `CLAUDE.md` stay in Spanish while that document is in
Spanish.

The description doesn't name Claude Code, Cursor or other agents, unlike the
extension's listing: guideline 2.3.7 asks not to fill the listing with other
companies' brands. The import sources do go by name, because that's what
people look for in the app. The "YOUR ACCOUNT" / «TU CUENTA» section
describes today's closed registration: if it opens before submitting, change
it (see D1 in [publicar-ios.md](../../../docs/publicar-ios.md) §8).

## 3. Keywords

*Keywords*, **100 bytes**, separated by commas with no space after the
comma. Each one longer than two characters. Apple doesn't allow names of
other apps or of companies, and it already searches by the app's and the
developer's names, so this leaves out "Klav" and the words of the name or the
subtitle ("password", "manager", "agents", «contraseñas», «agentes»…).

```text
passkey,2fa,authenticator,totp,otp,autofill,vault,secrets,encrypted,open source,mcp,api key,ssh
```

```text
passkey,llaves de acceso,2fa,autenticador,totp,autorrelleno,bóveda,secretos,cifrado,mcp,api key
```

(95 and 96 bytes of 100.)

## 4. URLs, category and the rest of the listing

| App Store Connect field | Value | Note |
|---|---|---|
| *Support URL* (required, per language) | `https://klav.dev/support` (D4) | Apple asks for it to lead to real contact information ("must lead to actual contact information"). Today `klav.dev` only serves `/` and the waitlist (`apps/web/server.mjs:19-23`), and `github.com/OmarAlex24/klav/issues` doesn't open while the repository is private. Omar decided on a `klav.dev/support` page with `support@klav.dev`, published together with `/privacy` (D4). **Still to do:** publish it (publicar-ios.md, blocker B8) |
| *Marketing URL* (optional) | `https://klav.dev` | |
| *Privacy Policy URL* (required) | `https://klav.dev/privacy` | Served from `apps/web/public/privacy/index.html` (source: [privacidad.md](../../../docs/privacidad.md)). Links to `SECURITY.md` in the repository, which opens when the repo goes public |
| *User Privacy Choices URL* (optional) | empty | Klav offers no privacy settings on a website |
| *Primary Category* | *Productivity* | Where password managers are |
| *Secondary Category* (optional) | *Developer Tools* (D11) | Because of the agents |
| *Content Rights* | *Yes, it contains, shows, or accesses third-party content* and *Yes, I have the rights* (D12) | The vault draws the logos of about 300 sites (Simple Icons, CC0; the brands belong to their owners) so that the person recognizes their accounts ([ios.md](../../../docs/ios.md) §1, "Site icons"), and vault health queries Have I Been Pwned if it's turned on. Answering no would also be defensible; answering yes costs nothing |
| *Age Rating* | 4+ | The questionnaire is in §5 |
| *Copyright* (required) | `2026 Omar Espinosa` (D13) | Apple adds the "©". It is the year the rights were obtained |
| *Price* | Free | No in-app purchases |
| *License Agreement* | Apple's standard EULA | The code is Apache-2.0; the EULA covers the store binary |
| *Version* | `1.0.0` (D6) | The `CFBundleShortVersionString` of the submitted build. Today `apps/ios/Klav/Info.plist` says `0.9.0`. **Still to do:** publicar-ios.md, blocker B6 |
| *Sign-In Information* | Yes, with the demo account | §7 |
| *App Review Notes* | The §7 text | |

## 5. Age rating

The App Store Connect questionnaire (*App Information* → *Age Rating*). The
questions are the ones in Apple's reference
([Age ratings values and definitions](https://developer.apple.com/help/app-store-connect/reference/app-information/age-ratings-values-and-definitions),
read on 2026-11-07), in its order. [CHECK: that the form still has these
questions; Apple changed the questionnaire in 2025 and may change it again.]

| Section | Question | Answer | Why |
|---|---|---|---|
| *In-App Controls* | *Parental Controls* | No | |
| | *Age Assurance* | No | |
| *Capabilities* | *Unrestricted Web Access* | No | The app has no browser inside: it doesn't use `WKWebView`, `SFSafariViewController` or `ASWebAuthenticationSession` (searched in `apps/ios/Klav`, `Shared` and `Credentials`). "Open" on an item opens the site in Safari, outside Klav |
| | *User-Generated Content* | No | What the person saves is theirs and nobody else sees it; nothing is distributed to other people |
| | *Social Media* | No | |
| | *Social Media Disabled for Users Under 13* | No | Doesn't apply: there is no social network |
| | *Messaging and Chat* | No | Agent requests aren't messages between people |
| | *Advertising* | No | |
| *Mature Themes* | *Profanity or Crude Humor* | None | |
| | *Horror/Fear Themes* | None | |
| | *Alcohol, Tobacco, or Drug Use or References* | None | |
| *Medical or Wellness* | *Medical or Treatment Information* | None | |
| | *Health or Wellness Topics* | No | "Vault health" is about passwords, not about the person |
| *Sexuality or Nudity* | *Mature or Suggestive Themes* | None | |
| | *Sexual Content or Nudity* | None | |
| | *Graphic Sexual Content and Nudity* | None | |
| *Violence* | *Cartoon or Fantasy Violence* | None | |
| | *Realistic Violence* | None | |
| | *Prolonged Graphic or Sadistic Realistic Violence* | None | |
| | *Guns or Other Weapons* | None | |
| *Chance-Based Activities* | *Gambling* | No | |
| | *Simulated Gambling* | None | |
| | *Contests* | None | |
| | *Loot Boxes* | No | |

**Result: 4+.** The rating is about the content, not the audience: the
policy says Klav isn't aimed at children under 13
([privacidad.md](../../../docs/privacidad.md), «Menores»), and the two don't
clash. If the form asks whether the app is *Made for Kids*: no.

## 6. App Privacy

The answers for the listing's "privacy label" (*App Privacy* → *Get
Started*). They cover the app and what `api.klav.dev`, the default server,
keeps. Whoever hosts their own server is responsible for theirs, but the
label describes the configuration the app ships with.

### 6.1 Apple's rule for end-to-end encrypted data

**Apple has no sentence about end-to-end encryption.** Checked on 2026-11-07
in
[developer.apple.com/app-store/app-privacy-details](https://developer.apple.com/app-store/app-privacy-details/)
and in the App Store Connect help
([Manage app privacy](https://developer.apple.com/help/app-store-connect/manage-app-information/manage-app-privacy)):
neither says "encrypt", "encrypted", "encryption" or "end-to-end". The rule
comes from how Apple defines "collect", which the first page does twice:

> "Collect" refers to transmitting data off the device in a way that allows
> you and/or your third-party partners to access it for a period longer than
> what is necessary to service the transmitted request in real time.

> "Collect" refers to transmitting data off the device and storing it in a
> readable form for longer than the time it takes you and/or your third-party
> partners to service the request.

> Data that is processed only on device is not "collected" and does not need
> to be disclosed in your answers.

And the sentence closest to our case, under *Payment Info*:

> If your app uses a payment service, the payment information is entered
> outside your app, and you as the developer never have access to the
> payment information, it is not collected and does not need to be
> disclosed.

**How it applies here:**

- What leaves the iPhone encrypted with keys that only the person's devices
  hold (items, titles, sites, usernames, attachments, vault and project
  names) doesn't let Klav "access" it and isn't stored "in a readable form".
  **It isn't collected**, even though the server stores it.
- What the server can read **is collected**, even if it only serves to make
  the app work. Apple puts it this way: *if you collect data solely for the
  purpose of app functionality, declare the data on your label and indicate
  that it is only being used for that purpose.*
- Everything collected is **linked to the person**: it is in their account,
  and Apple considers any personal data under the law to be linked.
- **Nothing is used for tracking.** Klav doesn't combine data with other
  companies' data or pass it to data brokers, has no advertising and no
  third-party SDKs (`apps/ios/Package.resolved` only pins Sparkle, which
  belongs to the Mac target: `apps/ios/project.yml:21-26`), and doesn't use
  `AppTrackingTransparency` or `AdSupport` (searched in `apps/ios`). The *Data
  Used to Track You* section stays empty.

### 6.2 Answer per data type

The first question: **"Yes, we collect data from this app"**. Then only the
types marked "Yes" are selected. For each one, the form's four steps: purpose
**App Functionality** (and nothing else), **linked to the user's identity:
yes**, **tracking: no**. Omar settled the unclear rows on 2026-11-09 (D10).

Every type Apple lists, in its order:

| Category | Type | Collected? | What it is and where it comes from |
|---|---|---|---|
| *Contact Info* | *Name* | No | Sign-in doesn't ask for a name (`apps/ios/Klav/SignInView.swift:56-108`) and `accounts` has no name column (`crates/klav-server/migrations/sqlite/0002_auth.sql:2-11`). Names saved in the vault are encrypted (§6.1) |
| | *Email Address* | **Yes** | The email is the account: it is typed at sign-in (`SignInView.swift:66`) and the server stores it in plain text (`0002_auth.sql:4`). [privacidad.md](../../../docs/privacidad.md):74 and :271. Purpose: authentication; it is also how people ask to delete the account until the deletion from ADR 0037 ships |
| | *Phone Number* | No | |
| | *Physical Address* | No | Addresses in the vault are encrypted (§6.1) |
| | *Other User Contact Info* | No | |
| *Health & Fitness* | *Health*, *Fitness* | No | |
| *Financial Info* | *Payment Info* | No | Cards in the vault are encrypted: it is the case of Apple's sentence in §6.1. No in-app purchases |
| | *Credit Info*, *Other Financial Info* | No | |
| *Location* | *Precise Location*, *Coarse Location* | No (D10) | The app doesn't use Core Location. The IP address: Apple asks to declare it according to what it is used for (*such as precise location, coarse location, device ID, or diagnostics*). Klav only uses it to rate-limit attempts, in memory and without writing it down (`crates/klav-server/src/ratelimit.rs:1`), and the server logs don't carry it (`crates/klav-server/src/telemetry.rs:4-5`; privacidad.md:97-104 and :293-298). If Railway's proxy kept logs with IPs that Omar could read and they weren't used for anything, it still wouldn't be location. **Still to do for Omar before submitting:** check that Railway's proxy logs keep no IPs (the **[REVISAR]** in privacidad.md:101-104) |
| *Sensitive Info* | *Sensitive Info* (includes biometrics) | No | iOS handles Face ID: the app only learns whether it succeeded (`LAContext.evaluatePolicy` in `apps/ios/Shared/Keystore.swift:48`) |
| *Contacts* | *Contacts* | No | |
| *User Content* | *Emails or Text Messages* | No | |
| | *Photos or Videos* | No | The Google Authenticator screenshots picked from Photos are read on the iPhone (`PhotosPicker` in `apps/ios/Klav/ImportView.swift:394`, `CIDetector` in `apps/ios/Klav/QRScanner.swift:16`) and don't leave it ([ios.md](../../../docs/ios.md) §8: "The image doesn't leave the iPhone and isn't saved") |
| | *Audio Data*, *Gameplay Content* | No | |
| | *Customer Support* | No | Support is by email, outside the app. If there is ever a support form inside the app, this changes |
| | *Other User Content* | **Yes** (D10) | The vault isn't collected (§6.1). But two things from the iPhone reach the server in plain text: the sites of the logins the person puts in a task when offering "Fix my reused passwords", so the agent gets them (ios.md §9; `task_targets.hosts` in `crates/klav-server/migrations/sqlite/0010_tareas.sql:30-39`), and their decisions on tasks and requests, with what those cover (`0010_tareas.sql:11-27`, `crates/klav-server/migrations/sqlite/0006_aprobaciones.sql:10-27`). Declaring it makes the listing say "User Content", which can read as if Klav saw the vault; not declaring it would fall short |
| *Browsing History* | *Browsing History* | No | AutoFill gets the site from iOS and compares on the iPhone (ios.md §3); the audit log of a passkey doesn't record the site (privacidad.md:88-92 and :285-289) |
| *Search History* | *Search History* | No | Vault search runs on the iPhone, over the decrypted data (`apps/ios/Klav/VaultFilter.swift`) |
| *Identifiers* | *User ID* | **Yes** | The account ID (`accounts.id`, `0002_auth.sql:3`), which everything else is tied to |
| | *Device ID* | **Yes** | The device record: a random ID, the name and the type, when it was added and when it was last used (`0002_auth.sql:14-22`; `last_seen_at` is written at most once a minute, `crates/klav-server/src/session.rs:20-22`), and the APNs notification token (`crates/klav-server/migrations/sqlite/0009_push.sql:5-11`; registered by `apps/ios/Klav/AppModel.swift:871-875`). privacidad.md:75-76, :93-95, :272-273 and :290-291. The name comes from "This iPhone’s name" (`SignInView.swift:88`), which defaults to `UIDevice.current.name`: without the device-name entitlement, which `apps/ios/Klav/Klav.entitlements` doesn't have, iOS 16 and later only return the model ("iPhone") |
| *Purchases* | *Purchase History* | No | |
| *Usage Data* | *Product Interaction* | No (D10) | The app doesn't record taps, screens or launches. The time of the last connection is in *Device ID* and in *Other Usage Data* |
| | *Advertising Data* | No | |
| | *Other Usage Data* | **Yes** (D10) | What the server can read of the account's activity: the time of each sync and sign-in (privacidad.md:81 and :278), the requests and tasks the person decides from the iPhone (`0006_aprobaciones.sql:10-27`, `0010_tareas.sql:11-27`) and the audit log, with which action, on which item and when (`crates/klav-server/migrations/sqlite/0007_bitacora.sql:7-17`; privacidad.md:86-92) |
| *Diagnostics* | *Crash Data* | No | Klav ships no crash SDK. The reports the person shares with Apple are Apple's: *You are not responsible for disclosing data collected by Apple.* |
| | *Performance Data*, *Other Diagnostic Data* | No (D10) | The server logs keep the method, the path without identifiers, the status code and the duration of each request, without IP or headers (`telemetry.rs:1-5`): they belong to nobody. Rejected: *Other Diagnostic Data*, **not linked** |
| *Surroundings* | *Environment Scanning* | No | The camera only reads QR codes, on the iPhone (`QRScanner.swift`; ios.md §8) |
| *Body* | *Hands*, *Head* | No | |
| *Other Data* | *Other Data Types* | No | Everything the server reads is above |

**What isn't Klav's and isn't declared:** Have I Been Pwned. It is a service
the iPhone asks directly, only if the person turns it on (off by default),
with the first 5 characters of each password's SHA-1
(`apps/ios/Klav/Health.swift:239`; privacidad.md:136-143). It isn't
third-party code inside the app and it passes nothing to Klav.

**How the label ends up:** *Data Linked to You*: *Contact Info*,
*Identifiers*, *User Content* and *Usage Data*, all for *App Functionality*.
*Data Used to Track You* and *Data Not Linked to You*: nothing.

**If a `PrivacyInfo.xcprivacy` is added** (publicar-ios.md §1, blocker B10),
its `NSPrivacyCollectedDataTypes` has to say the same as this table, with
`NSPrivacyTracking` set to `false`.

## 7. App Review notes

On the version's page, *App Review Information*:

| Field | What goes there |
|---|---|
| *Sign-in required* | Checked |
| *User name* | `<filled in at submission: demo account email>` |
| *Password* | `<filled in at submission: demo account master password>` |
| *Contact Information* (first name, last name, phone with `+52…`, email) | `<filled in at submission: Omar's contact details>` |
| *Notes* (**4000 bytes**) | The block below |
| *Attachment* | The short video of an agent approval (D3). [CHECK: whether the form has this field; if it doesn't, the video's link goes in the notes, step 5] |

The Secret Key has no field of its own: it goes in the notes. The account
can't expire (*The demo account is used during the App Review process and
must not expire*): it is a permanent account, not the extension's throwaway
one ([publicar-ios.md](../../../docs/publicar-ios.md) §3).

The `<filled in at submission: …>` markers are replaced in the form, not
here. With the markers, the block takes 3630 bytes: 370
bytes are left for the Secret Key, the deletion path and the video's link.

```text
Klav is an end-to-end encrypted password manager. On the iPhone, people unlock their vault, fill passwords, codes and passkeys, and approve what their AI agents ask for. The app needs iOS 18.

SIGNING IN
Use the demo account in Sign-In Information: the user name is the account email and the password is its master password. Klav also asks for a Secret Key, a second secret from the person's emergency kit that never leaves the device:
Secret Key: <filled in at submission: demo account Secret Key>
Leave "Use my own server" closed: the account lives on Klav's server (klav.dev), the default. Any device name works. The demo account holds only made-up sample data.

WHY THE APP HAS NO SIGN-UP
Klav's server (klav.dev) does not take new accounts yet; they open with Klav's hosted plan. Accounts are created with the klav command line or the Klav app for Mac, never in the iPhone app. To create one yourself, host your own Klav server (https://github.com/OmarAlex24/klav/blob/main/docs/self-hosting.md), run "klav signup --server <your server URL> --email <email>" on a computer, and sign in on the iPhone with "Use my own server".

DELETING THE ACCOUNT
<filled in at submission: where account deletion is in the app (ADR 0037)>

WHAT TO TRY
1. Face ID: after signing in, make sure "Unlock with Face ID" is on in Settings. Leave Klav for a minute and open it again: it asks for Face ID.
2. AutoFill: Klav shows how to turn it on in Settings > General > AutoFill & Passwords. Then open https://github.com/login in Safari, tap the username field and pick the Klav suggestion above the keyboard. The sample login is made up, so GitHub rejects it; the point is the fill.
3. Passkeys: on https://webauthn.io, register any user name, choose Klav to save the passkey and confirm with Face ID. Then sign in on the same page with it.
4. One-time codes: the Codes tab shows the sample codes, and a tap copies one. For "Set Up Codes In", choose Klav in Settings > General > AutoFill & Passwords > Set Up Codes In, then paste this sample link in Safari's address bar and open it:
otpauth://totp/Northwind:review@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Northwind
Klav asks which login to save the code in.
5. Agent approvals: AI agents run on a computer with the klav command line and ask the iPhone for permission. A short video shows one, from the notification to Face ID: <filled in at submission: "attached" or the video link>. To try one yourself, reply in App Store Connect and we'll send a live request to the demo account. A request shows the agent, what it wants and why, with "Approve once", "Approve 15 min" and "Deny"; approving asks for Face ID.
6. Vault health: Settings > Passwords > Vault health.

ENCRYPTION
Klav encrypts the person's own data with standard, published algorithms (XChaCha20-Poly1305, Argon2id, X25519, Ed25519, HPKE, OPAQUE and P-256 for passkeys) from open-source libraries. Info.plist sets ITSAppUsesNonExemptEncryption to NO, matching the export compliance answers on file for this app: standard algorithms, not distributed in France.

NO TRACKING
Klav has no analytics, ads or third-party SDKs, and it does not use App Tracking Transparency. The server keeps the account email, the device record, the push token, the decisions on agent requests and the audit log, and stores the vault encrypted, which it cannot read. Notifications carry only a type and a random ID. The optional breached-password check, off by default, sends Have I Been Pwned only the first 5 characters of a password's SHA-1 hash.

Source code: https://github.com/OmarAlex24/klav (Apache-2.0). Privacy policy: https://klav.dev/privacy
```

**What the demo account has to hold**, so that the notes are true
(publicar-ios.md §3): made-up data, like the screenshots' (§8); a login with
the site `https://github.com`, a made-up username and a generated password;
two or three logins with a one-time code, one of them titled "Northwind" for
step 4; and no `webauthn.io` passkey, so that step 3 starts from scratch.

**What depends on a decision or a blocker:**

- The "ENCRYPTION" sentence about France holds because France stays out of
  availability (D5 in publicar-ios.md). If the French declaration is ever
  uploaded, change it to "standard algorithms; the French encryption
  declaration is on file".
- "WHY THE APP HAS NO SIGN-UP" links to `self-hosting.md` on GitHub: it needs
  the public repository (blocker B7). If registration on klav.dev opens
  before submitting, that section goes.
- "DELETING THE ACCOUNT" is filled in once blocker B1 ships, with the path
  the app really has. ADR 0037 §4 puts it in Settings › Account, "Delete my
  account".
- `JBSWY3DPEHPK3PXP` is the sample secret from the TOTP documentation (the
  word "Hello!" in Base32), not any account's.

## 8. Screenshots

### Sizes

From Apple's
[screenshot specifications](https://developer.apple.com/help/app-store-connect/reference/app-information/screenshot-specifications),
read on 2026-11-07:

- **Required:** *iPhone with Dynamic Island (medium display)*, at least one:
  1206 × 2622 (iPhone 17, 17 Pro) or 1179 × 2556 (iPhone 16, 15, 14 Pro).
- **Also recommended:** *iPhone with Dynamic Island (large display)*,
  1320 × 2868 (iPhone 17 Pro Max). The page contradicts itself: at the top it
  only asks for the medium one, but the *Face ID (large display)* row says
  *Required if app runs on iPhone and screenshots for iPhone with Dynamic
  Island (large display) aren't provided*. With the large and the medium
  ones there's no doubt, and Apple scales the rest.
- **iPad: no.** The app is iPhone-only (`TARGETED_DEVICE_FAMILY: "1"`,
  `apps/ios/project.yml:34`), and Apple only asks for iPad ones *if your app
  supports iPadOS*.
- **iPhone Duo:** Apple will ask for them *starting in April 2027* from apps
  built with the iOS 27.1 SDK or later. It doesn't apply to this version.
- PNG or JPEG, **without an alpha channel** or transparency, 1 to 10 per size
  and per language.

### Which screenshots

Eight, in this order: the first three show in search results. One set in
English and one in Spanish (the app launched with `-AppleLanguages (es)`),
in light mode except number 4.

| # | File | What it shows | Data |
|---|---|---|---|
| 1 | `1-request.png` | An agent's request opened from a notification (the card highlighted in cobalt), with "Approve once", "Approve 15 min" and "Deny" | The agent `deploy-bot` asks for the one-time code of "Tidepool CI", with the reason "Finish the release sign-in" / «Terminar el inicio de sesión del release» |
| 2 | `2-vault.png` | The vault with the kind tabs and several logins with their live code | About eight made-up items (list below) |
| 3 | `3-autofill.png` | AutoFill's "Choose how to sign in" sheet in Safari, with a passkey and two logins for the site | A sign-in page on `northwind.example` [CHECK: how to make the Simulator open a made-up domain without touching the Mac's `/etc/hosts`; if it can't, leave this screenshot out and upload number 9 instead] |
| 4 | `4-codes-dark.png` | "Codes" in dark mode: the large codes, one just copied (✓) | The four or five logins with a code |
| 5 | `5-task.png` | "*deploy-bot* asks for a task": three items, one unchecked, and the duration set to 1 h | Tidepool CI, Quillstack and Kestrel Mail |
| 6 | `6-save-code.png` | The "Save code" sheet from "Set Up Codes In", with the issuer's logins | The Northwind `otpauth://` link from §7 |
| 7 | `7-health.png` | "Vault health" with reused and weak passwords and "Fix my reused passwords" | Two logins with the same password and one with a weak one |
| 8 | `8-unlock.png` | The dithered lock with "Unlock with Face ID" | — |
| 9 | `9-generator.png` (spare) | The smart generator with a site's rules | `quillstack.example` |

**The sample vault**, all made up, with `.example` domains and
`@example.com` emails:

| Title | Site | Username | Extras |
|---|---|---|---|
| Northwind | `https://northwind.example` | `ana@example.com` | code; a passkey (created in screenshot 3) |
| Northwind (trabajo) | `https://app.northwind.example` | `ana.ruiz@example.com` | |
| Tidepool CI | `https://ci.tidepool.example` | `ana` | code |
| Kestrel Mail | `https://mail.kestrel.example` | `ana@example.com` | code |
| Fernhill Bank | `https://fernhill.example` | `ana.ruiz` | code |
| Quillstack | `https://quillstack.example` | `ana@example.com` | same password as Kestrel Mail (for vault health) |
| Lumen Energy | `https://lumen-energy.example` | `ana.ruiz` | weak password (`spring2024`) |
| Deploy key | — | — | API key kind |

No name belongs to a real company, so the vault draws each site's initial
and no brand logos. Passwords don't show in any screenshot (they are
masked); the code secrets are random.

### How to take them in the Simulator

They weren't taken in this PR. The recipe, against a local server so as not
to touch `api.klav.dev` or a real account:

1. Build the CLI, the server and the app for the Simulator
   ([ios.md](../../../docs/ios.md) §5), with `target/` on the external disk:

   ```sh
   scripts/dev/espacio.sh
   nice -n 19 env CARGO_BUILD_JOBS=2 cargo build -p klav-cli -p klav-server --bins
   scripts/ios/test.sh build
   ```

2. Start a local server with its own `server.toml`: `listen =
   "127.0.0.1:0"`, a SQLite `database_url` and `data_dir` in a folder on the
   external disk ([self-hosting.md](../../../docs/self-hosting.md)). The port
   is in the `klav-server listening` log line. Klav accepts `http://` only to
   `127.0.0.1`, and the Simulator reaches it.
3. Create the account and the sample vault with the CLI, in a `KLAV_HOME` in
   that same folder and without `klavd`:

   ```sh
   export KLAV_HOME="$DIR/home" KLAV_NO_DAEMON=1
   klav --password-stdin signup --server "http://127.0.0.1:$PORT" \
       --email ana@example.com --emergency-kit "$DIR/kit.txt" < "$DIR/pw"
   klav --password-stdin item add login --title "Tidepool CI" --username ana \
       --url https://ci.tidepool.example -g password -s totp < "$DIR/pw"
   # … the rest of the table
   ```

   The kit holds the Secret Key: don't print it or copy it anywhere.
4. Prepare the Simulator (iPhone 17 Pro Max for 1320 × 2868, iPhone 17 for
   1206 × 2622) with a clean status bar:

   ```sh
   xcrun simctl status_bar booted override --time 9:41 --dataNetwork wifi \
       --wifiBars 3 --cellularBars 4 --batteryState charged --batteryLevel 100
   ```

5. Sign in to the app with "Use my own server" and the address from step 2.
   After the first sign-in, the AutoFill welcome covers the vault: "Not now"
   (or turn it on, for screenshot 3).
6. The request and the task: in another `KLAV_HOME`, `klav agent register
   --name deploy-bot --server "http://127.0.0.1:$PORT" --email
   ana@example.com`, approve it on the iPhone with "Compare words", and ask
   for something the default policy leaves at `ask`:
   `klav agent totp "klav://Personal/General/Tidepool CI" --reason "Finish the release sign-in"`
   ([cli.md](../../../docs/cli.md) §9). The task, with
   `klav agent task request task.toml`. For a notification's highlight,
   `xcrun simctl push` with the payload from ios.md §5.
7. Each screenshot: `xcrun simctl io booted screenshot --type=png <file>`.
   Check the size and that it has no alpha: `sips -g pixelWidth -g
   pixelHeight -g hasAlpha <file>`. The D3 video can be recorded the same
   way while you repeat step 6: `xcrun simctl io booted recordVideo
   --codec=h264 <file>.mov`, stopped with Ctrl-C.
8. Save them in `apps/ios/store/screenshots/{en,es}/`. When you're done,
   delete the server, the `KLAV_HOME` folders and the Simulator.

## 9. How the limits were counted

With Python, which counts Unicode characters, over the blocks in this
listing as they are (the descriptions with their line breaks):

```sh
python3 -I - apps/ios/store/ficha.md <<'EOF'
import re, sys
blocks = re.findall(r"```text\n(.*?)\n```", open(sys.argv[1], encoding="utf-8").read(), re.S)
for i, b in enumerate(blocks):
    print(i, len(b), "chars", len(b.encode("utf-8")), "bytes", repr(b[:40]))
EOF
```

| Field | Limit | English | Spanish |
|---|---|---|---|
| Name | 30 characters | 21 | 27 |
| Subtitle | 30 characters | 26 | 27 |
| Promotional text | 170 characters | 136 | 137 |
| Description | 4000 characters | 3266 | 3584 |
| Keywords | 100 bytes | 95 | 96 |
| App Review notes (English only, with the markers) | 4000 bytes | 3630 | — |
