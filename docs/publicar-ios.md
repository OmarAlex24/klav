# Publishing the iOS app on the App Store

What Omar has to do to publish the iPhone app. The app is in TestFlight
(0.9.0, build 6, uploaded on 2026-11-06). What is already in the
repository:

| What | Where |
|---|---|
| The build | `scripts/ios/archive.sh upload` ([ios.md](ios.md) §6) |
| Name, subtitle, promotional text, description and keywords, in English and Spanish, with their limits measured | [`apps/ios/store/ficha.md`](../apps/ios/store/ficha.md) §1–§3 |
| URLs, category, copyright and age rating | `ficha.md` §4 and §5 |
| The App Privacy answers, with the source of each one | `ficha.md` §6 |
| The App Review notes and what the demo account has to hold | `ficha.md` §7 and §3 of this guide |
| The screenshot list and how to take them in the Simulator, **not taken yet** | `ficha.md` §8 → `apps/ios/store/screenshots/{en,es}/` |
| Privacy policy | [`privacidad.md`](privacidad.md) and `apps/web/public/privacy/index.html`, served at `https://klav.dev/privacy` ([publicar-extension.md](publicar-extension.md) §5) |
| Encryption and export | §4 |

What this guide says about App Store Connect is from November 2026 (the
developer.apple.com pages were read on 2026-11-07), and it changes. What
couldn't be checked is marked **[CHECK]**. Omar's decisions (D1–D16, made
on 2026-11-07, 2026-11-09 and 2026-11-13) are in §8.

## In short

**Don't submit for review while any §1 blocker is left.** The steps below
clear them in order.

The public TestFlight beta comes before the App Store (Omar's decision of
2026-11-13) and needs fewer of these: §9.

1. Make the repository public (B7). It comes before the policy, because the
   policy and the listing link to it.
2. Publish the privacy policy and the support page on `klav.dev` (B2 and B8,
   D4). Before that, check that Railway's proxy logs keep no IPs (D10, part
   of B2).
3. Merge into the app the account deletion (B1, ADR 0037), the link to the
   policy (B3) and, if needed, the privacy manifest (B10). Set the version to
   `1.0.0` (D6), raise the build, and upload it to App Store Connect (B6).
4. Prepare the demo account (B4, §3).
5. Take the screenshots (B5, `ficha.md` §8) and record the short video of an
   agent approval (D3).
6. Fill in App Store Connect with `ficha.md` (§2): English (U.S.) as the
   primary language (D7), France out of availability (B9, D5), and Apple
   silicon Macs and Vision Pro off (D8).
7. Submit for review with manual release (D1).
8. When Apple approves it, release it when the hosted plan opens or when
   Omar decides self-hosters are enough (D1), and check the roadmap box
   (§7).

## 1. Blockers

| # | Blocker | What's missing | Who |
|---|---|---|---|
| B1 | **Deleting the account from the app** | Apple: *If your app supports account creation, you must also offer account deletion within the app* (guideline 5.1.1(v)). The iPhone app doesn't create accounts, but Klav does (the CLI and the Mac app), and today an account is only deleted by hand, with an email to `support@klav.dev` ([publicar-extension.md](publicar-extension.md) §1). ADR 0037, accepted on 2026-11-07 in another PR, designs deleting it from the app | Code PRs implement it (the ADR's layers). The path in the app goes in the notes (`ficha.md` §7, "DELETING THE ACCOUNT") |
| B2 | **The privacy policy, served at `https://klav.dev/privacy`** | Resolve the **[REVISAR]** markers in [privacidad.md](privacidad.md) and on the page, and serve it: [publicar-extension.md](publicar-extension.md) §5, steps 1 to 6. One of them (privacidad.md:101-104) is the D10 check: confirm that Railway's proxy logs keep no IPs. Before serving it, add what it doesn't say today: that offering "Fix my reused passwords" from the iPhone sends those logins' sites in plain text, for the agent (`ficha.md` §6.2, *Other User Content*). App Store Connect asks for the URL for every app (*A privacy policy URL is required for all apps*) | Omar (the **[REVISAR]** markers and the Railway check); an `apps/web` PR |
| B3 | **The link to the policy inside the app** | Apple: *All apps must include a link to their privacy policy in the App Store Connect metadata field and within the app in an easily accessible manner* (guideline 5.1.1(i)). Settings (`apps/ios/Klav/SettingsView.swift`) has none | A code PR: a row in Settings that opens `klav.dev/privacy` in Safari, with its text in English and Spanish |
| B4 | **The demo account on `api.klav.dev`** | It is the same database as the Railway URL, so it already answers on `api.klav.dev` without migrating anything (ADR [0028](decisiones/0028-servidor-por-defecto-klav-dev.md) §4). What's left: check that a clean install of the build being submitted signs in with the default server, load the `ficha.md` §7 data into the account and bring the notes up to date. It is the [roadmap](roadmap.md) checkbox «La cuenta de Omar y la de App Review migradas solas, y las notas de App Review al día» | Omar (§3) |
| B5 | **The screenshots** | Eight per language, at 1320 × 2868 and at 1206 × 2622 (`ficha.md` §8) | Omar, or an agent with the Simulator |
| B6 | **The version and the build** | 0.9.0 (6) has neither B1 nor B3, so another build is submitted. `CFBundleVersion` 7 or higher in `apps/ios/Klav/Info.plist` and `apps/ios/Credentials/Info.plist`, and `CFBundleShortVersionString` `1.0.0` in both (D6). Those `Info.plist` files are what counts, because they set the values by hand: the `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` in `apps/ios/project.yml` belong to the Mac target (`KlavMac`) and aren't used by the iOS targets | Omar, or the B1 PR; then `archive.sh upload` |
| B7 | **The repository, public** | The description, the notes and the policy say "open source" and link to `github.com/OmarAlex24/klav`, which is private today (`gh repo view`, 2026-11-07). Apple asks for *fully functional URLs* (guideline 2.1(a)). It is the same condition as in [publicar-extension.md](publicar-extension.md) §1 | Omar ([ADR 0031](decisiones/0031-repositorio-en-ingles-y-open-source.md)) |
| B8 | **A support URL with contact information** | Apple: *This URL must lead to actual contact information*. `klav.dev` only serves the home page and the waitlist. Omar decided on a `klav.dev/support` page with `support@klav.dev`, published together with `/privacy` (D4) | An `apps/web` PR; Omar publishes it |
| B9 | **France and the encryption declaration** | Omar decided to leave France out of the first version's availability (D5), so no French declaration is filed (§4). It only has to be unchecked in *Availability* | Omar, when filling in App Store Connect (§2) |
| B10 | **The privacy manifest** [CHECK] | The app uses the App Group's `UserDefaults` (`apps/ios/Shared/KlavHome.swift:14-15`), one of the *required reason APIs*, and has no `PrivacyInfo.xcprivacy`. Check whether the App Store Connect email after the build 6 upload warned with `ITMS-91053` (*Missing API declaration*) and which APIs it names. If it did, or to be safe, add the manifest to both targets, with the APIs from the warning (including those `KlavFFI` uses) and the data types in `ficha.md` §6.2 | A code PR |

## 2. App Store Connect, step by step

The app record already exists (`dev.klav.ios`, name "Klav", primary language
Spanish, [probar-fase-6.md](probar-fase-6.md) §1, step 4), and TestFlight
already uses it. It doesn't need to be created, but its primary language
changes to English (U.S.) (D7).

| Page and field | What goes there | `ficha.md` |
|---|---|---|
| *App Information* → *Name* and *Subtitle*, per language | "Klav Password Manager" / "Klav: gestor de contraseñas" (D2) and the subtitles from the listing | §1 |
| *App Information* → *Primary Language* | *English (U.S.)*, instead of Spanish (D7) | — |
| *App Information* → *Category* | *Productivity*; secondary *Developer Tools* (D11) | §4 |
| *App Information* → *Content Rights* | Yes, it contains third-party content, and yes, Klav has the rights (D12) | §4 |
| *App Information* → *Age Rating* | The questionnaire: everything "No" or "None", 4+ | §5 |
| *App Information* → *App Encryption Documentation* | Nothing: France stays out (D5, §4) | — |
| *Pricing and Availability* → *Price* | Free | §4 |
| *Pricing and Availability* → *Availability* | Every country and region except France (D5). Without the trader declaration, the app isn't offered in the European Union (D9) | — |
| *Pricing and Availability* → *iPhone and iPad Apps on Apple Silicon Macs* and *Apple Vision Pro* | Off (D8) | — |
| *App Privacy* → *Privacy Policy* | `https://klav.dev/privacy` (B2) | §4 |
| *App Privacy* → *Data Types* | "Yes, we collect data from this app" and the rows marked "Yes" (D10); then *Publish* | §6 |
| Version (*iOS App* → *Prepare for Submission*) → *Previews and Screenshots* | The 1320 × 2868 and 1206 × 2622 ones for each language (B5) | §8 |
| Version → *Promotional Text*, *Description*, *Keywords* | Per language | §1–§3 |
| Version → *Support URL*, *Marketing URL* | `https://klav.dev/support` (D4, B8); `https://klav.dev` | §4 |
| Version → *Version*, *Copyright* | `1.0.0` (D6); `2026 Omar Espinosa` (D13) | §4 |
| Version → *Build* | The B6 build, once App Store Connect finishes processing it | — |
| Version → *App Review Information* | The demo account, Omar's contact details, the notes and the agent approval video (D3) | §7 |
| Version → *App Store Version Release* | *Manually release this version* (D1) | — |

**Languages.** The listing has *English (U.S.)* and *Spanish (Mexico)*. Each
one has its own name, subtitle, promotional text, description, keywords,
support URL and screenshots. Whatever is missing in a language shows in the
primary language, English (U.S.) (D7).

**Accessibility.** App Store Connect lets you declare the app's accessibility
features (*Accessibility Nutrition Labels*). [CHECK: whether they are
already required to submit.] What has been checked is in [ios.md](ios.md)
§1: large text from AX1 to AX5, dark mode and VoiceOver on the main screens.
Only declare what you have tested on an iPhone.

When you're done: *Add for Review* → *Submit for Review*. Before that,
[CHECK: that the developer account has accepted the current agreements, in
*Business* → *Agreements*].

## 3. The App Review account

- **It is permanent, not throwaway.** App Store Connect says *The demo account
  is used during the App Review process and must not expire*. That is the
  opposite of the extension's account, which is created at submission and
  deleted once approved ([publicar-extension.md](publicar-extension.md) §1).
- **It already exists:** it is the one given to TestFlight, and it lives in
  the same database as `api.klav.dev` (ADR 0028 §4). No other one is created,
  because registration on `api.klav.dev` is closed and opening it each time
  is a risk.
- **Its details go only into App Store Connect:** the email and the master
  password in *Sign-In Information*, and the Secret Key in *Notes*, in the
  `ficha.md` §7 markers. Never in the repository, in a commit or in a PR, and
  neither does its emergency kit.
- **What it has to hold:** only made-up data, the data in `ficha.md` §7 (a
  `github.com` login for AutoFill, logins with codes and one called
  "Northwind"). Load it with the CLI pointed at that account, in a separate
  `KLAV_HOME`, never in Omar's, and without `klavd` (`KLAV_NO_DAEMON=1`).
  Before each submission, delete the `webauthn.io` passkeys left by the
  previous review.
- **If App Review tries deleting the account** (B1), it really deletes it.
  Then it has to be created again before the next submission, with
  registration open only in the meantime (`KLAV_ALLOW_REGISTRATION`,
  [self-hosting.md](self-hosting.md) §8.1, step 6), and its details changed in
  App Store Connect.
- **Seeing an agent approval** takes an agent on a computer (D3): App Review
  gets a short video, and the notes offer a live request. When App Review
  asks for one, Omar sends it with `klav agent totp` from a computer, against
  `api.klav.dev` (`ficha.md` §8, step 6), so keep an agent registered with
  the demo account while the version is in review.

## 4. Encryption and export

**What the app declares:** `ITSAppUsesNonExemptEncryption = false` in
`apps/ios/Klav/Info.plist`. It is what Apple stored with Omar's answer to the
build 2 questionnaire: standard algorithms, not in France
([probar-fase-6.md](probar-fase-6.md) §1, step 6).

**What Apple says** ([Export compliance documentation for encryption](https://developer.apple.com/help/app-store-connect/reference/app-information/export-compliance-documentation-for-encryption),
read on 2026-11-07):

| *Encryption algorithm in use* | *Required documentation* |
|---|---|
| *Your app uses encryption limited to that within the Apple operating system* | *No documentation required in App Store Connect.* |
| *Your app uses an industry standard algorithm, not provided within the Apple operating system* | *Upload your French encryption declaration in App Store Connect.¹* |
| *Your app uses proprietary encryption algorithms not accepted by international standard bodies* | CCATS and the French declaration |

> ¹ French encryption declaration form is only required if you're
> distributing your app on the App Store in France.

**Where Klav is:** in the second row. It encrypts with RustCrypto, `hpke` and
`opaque-ke` (`CLAUDE.md`), not with CryptoKit: they are standard algorithms
that aren't the system's. So:

- **With France out of availability**, as Omar decided (D5) and as the stored
  answer says, no document is needed. The notes' sentence "not distributed in
  France" (`ficha.md` §7) says that.
- **If France is added later**, the declaration has to be filed with ANSSI,
  uploaded in *App Information* → *App Encryption Documentation*, and the
  questionnaire answered again. Apple then gives a value that goes in the
  `Info.plist` (*Once your documentation is approved, Apple will provide you a
  key value. You must enter this value in Xcode*). [CHECK: whether
  `ITSAppUsesNonExemptEncryption` then becomes `true`, next to
  `ITSEncryptionExportComplianceCode`.]

[CHECK: what the United States requires. Apple says it is the developer's
responsibility to find out whether a formal classification (*CCATS*) is
needed; with standard algorithms and published code, it usually isn't, but
this wasn't verified.]

## 5. If App Review asks for changes

App Store Connect sends an email, and the message stays on the version's page
(*App Review*). Reply right there, in English.

- **"We couldn't sign in" or "we couldn't find the feature" (2.1).** Check
  the account (§3) and reply with the steps from the notes. If it's about the
  agents, send the live request the notes offer (D3).
- **Account deletion (5.1.1(v))** or **the link to the policy (5.1.1(i))**:
  with B1 and B3 done this shouldn't happen; reply with the exact path in the
  app.
- **"The app requires an account that can't be created."** Explain that it is
  the client of a service with its own accounts, that the hosted plan isn't
  open yet and that people who host their own server create the account with
  the CLI (the notes say so in "WHY THE APP HAS NO SIGN-UP"). If that isn't
  enough, go back to D1.
- **Sign in with Apple (4.8)** doesn't apply: Klav only uses its own account
  system (*Your app exclusively uses your company's own account setup and
  sign-in systems*).
- **The listing (2.3.x)**: fix it in App Store Connect and in `ficha.md`, and
  resubmit without a new build.
- **The code:** fix it with a PR, raise `CFBundleVersion` (B6) and submit the
  new build. If what the app does changes, update `ficha.md` §2 and §6 and
  [ios.md](ios.md).

## 6. How long it takes

[CHECK: Apple used to say most submissions are reviewed in less than 24
hours.] A first version with sign-in, an AutoFill extension and features that
depend on a computer can take longer or come back with questions. With manual
release (D1), the approved app waits in *Pending Developer Release* until
Omar releases it.

## 7. After publishing

- In [roadmap.md](roadmap.md), check the «Publicada en la App Store» box and
  remove the pending item from «Estado actual» if there is one.
- In [ios.md](ios.md), add the App Store link. In
  [probar-fase-6.md](probar-fase-6.md), install from the App Store instead of
  Xcode or TestFlight.
- Keep the privacy label up to date: *You're responsible for keeping your
  responses accurate and up to date*. If the server starts reading something
  new, change `ficha.md` §6 and App Store Connect (that doesn't need a new
  version).
- On each new version: a higher `CFBundleVersion`, the notes up to date and
  the demo account alive.

## 8. Decisions (Omar, 2026-11-07, 2026-11-09 and 2026-11-13)

Omar took the recommended option on every one.

- **D1. When to publish while registration on `klav.dev` is closed.** Today,
  whoever downloads the app can't create an account on `klav.dev`, only on
  their own server. Submit for review as soon as the blockers are cleared,
  with *Manually release this version*. Omar releases it when the hosted plan
  opens (phase 8) or once Omar decides self-hosters are enough. [CHECK: how
  long an approved version can wait.] Rejected: releasing as soon as it is
  approved, for self-hosters only; or not submitting until phase 8.
- **D2. The name.** "Klav Password Manager" (en-US) and "Klav: gestor de
  contraseñas" (es-MX): the words in the name count in search. The name under
  the icon stays "Klav". Rejected: just "Klav". Applied in `ficha.md` §1.
- **D3. How App Review sees an agent approval.** A short video (in
  *Attachment* if the form has it, or a link), plus an offer in the notes to
  send a live request to the demo account: Omar sends one with `klav agent
  totp` from a computer (`ficha.md` §8, step 6, against `api.klav.dev`).
  Rejected: a demo agent that asks for something every few minutes during the
  review; or the explanation alone. Applied in `ficha.md` §7, step 5, and §3
  of this guide.
- **D4. The support URL.** A `klav.dev/support` page with `support@klav.dev`,
  published together with `/privacy`. Rejected:
  `github.com/OmarAlex24/klav/issues` once the repository is public (it isn't
  "contact information"); or the home page with the email in the footer.
  Still to do: B8.
- **D5. France.** Out of availability for the first version, matching the
  stored export compliance answer. Rejected for now: filing the French
  declaration with ANSSI, uploading it and adding France (§4, B9).
- **D6. The App Store version.** `1.0.0` in both `Info.plist` files: it is the
  first public version. Rejected: staying on `0.9.x`. Still to do: B6.
- **D7. Primary language and languages.** *English (U.S.)* as primary (what
  any country without its own translation sees) and *Spanish (Mexico)* as
  secondary. Today the record's primary language is Spanish, so it changes in
  *App Information* (§2); Apple lets you change it at any time. Rejected:
  keeping Spanish as primary; also adding *Spanish (Spain)* with the same
  text.
- **D8. Apple silicon Macs and Vision Pro.** Off: Klav has its own Mac app,
  and AutoFill and Face ID don't work the same way there. Rejected: leaving
  them on.
- **D9. EU trader status (Digital Services Act).** The same answer as on the
  Chrome Web Store ([publicar-extension.md](publicar-extension.md) §3): if the
  hosted plan will be paid, "trader", with an address, a phone number and an
  email that can be public. [CHECK: where App Store Connect asks for it
  today.] Rejected: "non-trader" while nothing is paid.
- **D10. The unclear privacy rows** (`ficha.md` §6.2). Declare *Other User
  Content* and *Other Usage Data*. Don't declare *Product Interaction*, server
  diagnostics or IP-based location. **To do for Omar before submitting:** check
  that Railway's proxy logs keep no IPs (the **[REVISAR]** in
  privacidad.md:101-104, part of B2). Rejected: declaring less (leaving out
  *Other User Content*, which falls short with the tasks' sites); or declaring
  everything.
- **D11. The secondary category.** *Developer Tools*, because of the agents.
  Rejected: *Utilities*, or none.
- **D12. Content Rights.** Yes, the app contains third-party content (the
  site logos from Simple Icons, and Have I Been Pwned), and yes, Klav has the
  rights. Rejected: "No".
- **D13. Copyright.** `2026 Omar Espinosa`, the legal name on the developer
  account. Rejected: a company's name.

On 2026-11-13, for the public TestFlight beta (§9), Omar took the
recommended option on each:

- **D14. Versions.** `0.9.x` during the beta, `1.0.0` for the App Store
  (D6 stays).
- **D15. France in the beta.** The beta goes ahead with France included.
  It stays a [CHECK] (§9.2, B9), which says what to do if Beta App Review
  asks. D5 still holds for the App Store version.
- **D16. The public link.** No limit below TestFlight's own 10,000 testers,
  with the iOS 18 or later filter (§9.5, step 6).

## 9. The public TestFlight beta

Omar decided on 2026-11-13 that the iPhone app goes out first as a public beta on TestFlight, and on the App Store later. Anyone with the link joins, and the downloads section of `klav.dev` points at it once `iphone` is switched on (`KLAV_WEB_OPEN` and `KLAV_WEB_TESTFLIGHT_URL`, [sitio-web.md](sitio-web.md) §2). This section is the kit for it: what blocks it, the texts, what the reviewer needs, and Omar's clicks.

What it quotes from Apple was read on 2026-11-13 from [TestFlight overview](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview), [Invite external testers](https://developer.apple.com/help/app-store-connect/test-a-beta-version/invite-external-testers), [Provide test information](https://developer.apple.com/help/app-store-connect/test-a-beta-version/provide-test-information) and [developer.apple.com/testflight](https://developer.apple.com/testflight/).

### 9.1 What Apple asks for

- **A review of the first build.** *When you add the first build of your app to a group, the build gets sent to App Review to make sure it follows the App Review Guidelines. A review is required only for the first build. Subsequent builds may not require a full review.* The guidelines are the App Store's, so §1's blockers that come from them apply here too (§9.2).
- **Test information.** *Your beta app description and beta app review information are required in order to share your beta with external testers.* Of the fields, Apple's help page marks only the *Beta App Description* as required (*This field is required*). [CHECK: whether *Privacy Policy URL* is required for an iOS beta. [probar-fase-6.md](probar-fase-6.md) §1, step 5, lists it for external TestFlight.]
- **An internal group first.** *To create an external group for external testing, you must first create an internal group for internal testing.*
- **Testers need TestFlight.** *Testers install the free TestFlight app on their devices. Then they use their invitation email or a public link to accept invitations.*
- **Limits.** Up to 10,000 external testers per app. *You can test a build for up to 90 days.* Up to six builds can go to review in 24 hours.
- **The public link.** *Anyone can share this link, so testers could potentially join your testing group even if you do not invite them directly.* Testers who join through it show up as anonymous, with their installs, sessions and crashes.

### 9.2 What blocks it

From §1, for a beta:

| # | For the beta | Why |
|---|---|---|
| B1 | **Yes, already done in the code** | Account deletion (`apps/ios/Klav/DeleteAccount.swift`, Settings › Account › "Delete my account"). Guideline 5.1.1(v) applies to apps that create accounts, which this one doesn't (it only signs in), though App Review may still ask. The build sent has to carry it: 0.9.0 (6) doesn't (B6) |
| B2 | **Probably yes** | The *Privacy Policy URL* of the test information, if Apple asks for it ([CHECK] above), and guideline 5.1.1(i) in any case. `klav.dev/privacy` isn't published, and the policy still has its **[REVISAR]** markers |
| B3 | **Probably yes** | The link to the policy inside the app, a guideline the beta review checks too. [CHECK: whether a beta review rejects without it] |
| B4 | **Yes, and it exists** | The demo account (§3). It works on `api.klav.dev`, whose registration stays closed |
| B6 | **Yes** | A build with B1 and B3. `CFBundleVersion` is 8 in `apps/ios/Klav/Info.plist` on `main` (2026-11-13), and each upload needs a higher one. The version stays `0.9.x` during the beta, and `1.0.0` is for the App Store (D14) |
| B5, B8 | No | Screenshots and the support URL belong to the App Store version. With *App Information* checked, the invitation shows screenshots only *from the latest approved version in the Ready for Distribution state*, and there is none yet |
| B7 | No, with §9.4's notes | The beta's texts don't link to GitHub, so Beta App Review doesn't need it. Testers do: until the repository is public there is no download and no self-hosting guide, so the public link waits for it (§9.5, step 7). The App Store notes in `ficha.md` §7 link to GitHub. |
| B9 | [CHECK] | The beta includes France (D15). Apple's TestFlight pages say nothing about countries, and the French declaration footnote speaks of *distributing your app on the App Store in France*. [CHECK: Apple's *Overview of export compliance* says *The main items of control for France are Secure Storage, Secure Communications*, and a vault is secure storage. Whether that applies to a TestFlight beta, and not only to the App Store, isn't confirmed; the sentence was read in other developers' quotes of that page, not on the page itself] A public link reaches France too. The export compliance answer on file ("not in France") is the one the build is tested with. **If Beta App Review asks** about encryption or France: answer that Klav uses industry-standard algorithms that aren't Apple's (RustCrypto, HPKE and OPAQUE; §4's second row), none proprietary, and that this is a TestFlight beta, not the App Store. If Apple still asks for the French declaration, file it with ANSSI and upload it as §4 says for "If France is added later", answer the questionnaire again, and submit the build again; the beta waits until then |

### 9.3 Test information

App Store Connect › the app › *TestFlight* › *Additional* › *Test Information*. English (U.S.) first, then Spanish (Mexico), like the listing (D7).

| Field | Value |
|---|---|
| *Beta App Description* | The text below, per language |
| *Feedback Email* | `support@klav.dev`. It is also *the reply-to address in email invitations to testers*, so it has to receive mail |
| *Marketing URL* | `https://klav.dev` |
| *Privacy Policy URL* | `https://klav.dev/privacy`, once it is published (B2) |
| *App Information* (invitation) | Checked. It shows nothing until an App Store version is approved |

**Beta App Description, English (U.S.):** [CHECK: the field's limit. The App Store's *Description* takes 4000 characters, and this text has 711.]

```text
Klav is an open-source password manager, encrypted end to end, built for people who work with AI agents. On the iPhone you unlock your vault with Face ID, fill passwords, one-time codes and passkeys with AutoFill, and approve or deny what your agents ask for.

Before you install: the iPhone app signs in to an account you already have; it can't create one. Create your account with the Klav app for Mac or the klav command line, on a Klav server you host yourself, and choose "Use my own server" when you sign in. Klav's own server is a paid plan that isn't open yet. How to set it all up: https://klav.dev

Needs iOS 18 or later. This is a beta: keep your emergency kit somewhere safe, and expect rough edges.
```

**Beta App Description, Spanish (Mexico):**

```text
Klav es un gestor de contraseñas de código abierto, cifrado de extremo a extremo y pensado para quienes trabajan con agentes de IA. En el iPhone abres tu bóveda con Face ID, llenas contraseñas, códigos de un solo uso y passkeys con el autorrelleno, y apruebas o rechazas lo que te piden tus agentes.

Antes de instalarla: la app de iPhone entra a una cuenta que ya tienes; no puede crearla. Crea tu cuenta con la app de Klav para Mac o con la línea de comandos klav, en un servidor de Klav que montes tú, y al entrar elige «Usar mi propio servidor». El servidor de Klav es un plan de pago que todavía no abre. Cómo dejarlo todo listo: https://klav.dev

Necesita iOS 18 o más nuevo. Es una beta: guarda tu kit de emergencia en un lugar seguro y espera detalles por pulir.
```

**What to Test,** for each build, in the dialog that opens when the build is added to the group:

```text
Sign in with your account on your own server, then try: unlocking with Face ID; AutoFill for passwords, codes and passkeys in Safari and other apps (turn Klav on in Settings › General › AutoFill & Passwords); approving or denying an agent's request from its notification; and Vault health in Settings. To report something, take a screenshot in the app or use TestFlight's Send Beta Feedback.
```

```text
Entra con tu cuenta en tu propio servidor y prueba: desbloquear con Face ID; el autorrelleno de contraseñas, códigos y passkeys en Safari y otras apps (activa Klav en Ajustes › General › Autorrelleno y contraseñas); aprobar o rechazar la solicitud de un agente desde su notificación; y Salud de la bóveda en Ajustes. Para avisarnos de algo, haz una captura dentro de la app o usa «Enviar comentarios de la beta» en TestFlight.
```

[CHECK: the Spanish name of TestFlight's feedback button on an iPhone in Spanish.]

### 9.4 What the reviewer needs

*TestFlight* › *Test Information*, the beta app review part:

- ***Sign-in required*,** with the demo account of §3: its email and master password. The same rules hold: its details go only into App Store Connect, never into the repository.
- **Contact:** Omar's name, phone (`+52…`) and email.
- ***Notes*:** the `ficha.md` §7 block, with two changes so it needs neither the public repository nor a published guide:
  - in "WHY THE APP HAS NO SIGN-UP", the sentence that links `self-hosting.md` on GitHub becomes: `To create one yourself, host your own Klav server (see "Your own server" at https://klav.dev), run "klav signup --server <your server URL> --email <email>" on a computer, and sign in on the iPhone with "Use my own server".`;
  - the last line keeps only `Privacy policy: https://klav.dev/privacy`, without the GitHub link, until B7.

  The Secret Key goes in its marker, as in §3. The reviewer signs in on `api.klav.dev`, the default, so they don't need a server of their own. What the account has to hold is in `ficha.md` §7.

### 9.5 Omar's clicks

1. **Upload the build** with B1 and B3: `scripts/ios/archive.sh upload` ([ios.md](ios.md) §6). Answer export compliance if asked (§4).
2. **The internal group,** if there isn't one: *TestFlight* › *Internal Testing* › add Omar.
3. **The test information** of §9.3 and §9.4, in both languages.
4. **The external group:** *TestFlight* › *External Testing* › a new group, for example "Public beta". *Add Builds* › the build › *What to Test* (§9.3) › *Submit Review*. Select *Automatically notify testers*, so testers get the build as soon as it is approved. The choice is per build: select it again each time you add one.
5. **Wait for the review.** Apple emails the Admins when it approves. If it rejects, *General* › *App Review* shows why, and §5 applies.
6. **The public link:** in the group, *Testers* › *Create Public Link* › *Filter by Criteria* › *Next* › *Add Criteria* › iPhone, *Newer than or equal to* iOS 18.0 › *Confirm*. The app needs iOS 18, and the filter turns away anyone who couldn't run it. Don't use *Set Limit*: the only limit is TestFlight's own 10,000 testers (D16). Copy the link: `https://testflight.apple.com/join/…`.
7. **Switch the site on,** only once the repository is public and `docs` and `mac` or `linux` are already in `KLAV_WEB_OPEN` ([releasing.md](releasing.md) §2, step 9): before that, someone who joins has no way to create an account. On Railway, `klav-web` › *Variables*, set `KLAV_WEB_TESTFLIGHT_URL` to the link and add `iphone` to `KLAV_WEB_OPEN`, then deploy the staged changes: Railway applies a variable only after that deploy ([sitio-web.md](sitio-web.md) §2). Then `curl -sI https://klav.dev/download/iphone` answers `302` to the link.

### 9.6 While the beta runs

- **Each build lasts 90 days.** Upload a newer one before the last one expires, or the link leads to nothing to install. The group's insight cards warn when a build is about to expire.
- **The link can be closed or limited** at any time: *Manage*, next to *Public Link*. If it closes, switch `iphone` off on the site too, so `/download/iphone` leads back to the page.
- **Once the App Store version is out** (§7), the beta's builds stay installable until they expire: *If you don't expire your build and submit it to the App Store, testers who received an invitation to test will still be able to test your build even after it goes live on the App Store.* Expire them, and point the site at the App Store instead.
