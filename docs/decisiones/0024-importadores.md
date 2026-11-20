# 0024 · Importers: Bitwarden, 1Password, Google Authenticator and browsers, with format detection, lossless merging, and minimal in-house readers for ZIP and protobuf

- Status: proposed (accepted on merging the importers PR)
- Date: 2026-11-04

> Omar set the importers as the next piece of work (roadmap, "Orden de trabajo") and asked for migrating to be "as simple as possible". This ADR records the format and dependency decisions that required. The implementation subagent made them within what the assignment allowed. Omar reviews them in the PR, and merging it accepts them.

## Context
Without migrating from Bitwarden, 1Password or Google Authenticator, Klav can't be the everyday vault. A basic CSV importer already existed (phase 3), but it had three limits:

- it only read CSV;
- a repeated title was skipped, even if it carried a different password;
- it didn't know how to join an authenticator's code with its login.

The roadmap asked for:

- **Bitwarden:** the unencrypted JSON, with `login.totp`.
- **1Password:** the `.1pux`.
- **Google Authenticator:** the export QR code.
- **Browsers:** the CSVs from Chrome, Edge, Brave, Firefox and Safari.
- **Wizard:** "Where are you coming from?" in the extension and on iOS.
- **Merging:** one that doesn't lose any password.

## Decision

### 1. The `klav-import` crate
A new crate reads the formats, detects which one it is and plans the merge. It does no networking or cryptography: the items it produces are sealed in `klav-client`, like any other (CLAUDE.md, "cryptography lives only in `klav-core`"). It is used by:

- `klav-client` (`Unlocked::import_preview` / `import_apply`), and through it the CLI and `klavd`;
- `klav-ffi`, for iOS.

No error message or preview row carries values from the file. Rows carry title, kind, username, site and what changes. Positions are given as "row 4" or "item 12".

### 2. Formats

| Source | File | Notes |
|---|---|---|
| Bitwarden | unencrypted `.json` | `login.totp`, `passwordHistory`, custom fields, cards, identities, notes, folders as tags. What is in the trash (`deletedDate`) is skipped. The password-encrypted JSON is rejected with a clear message: it would need another KDF and AES-CBC |
| Bitwarden | `.csv` | `login_*` columns |
| 1Password | `.1pux` | a ZIP with `export.data`. Categories are mapped (login, card, identity, API, SSH) and the rest becomes a note. Sections go to fields, the password history is kept and attachments are noted without being imported. With several vaults, their name becomes a tag |
| 1Password | `.csv` | the columns of its CSV export |
| Google Authenticator | `otpauth-migration://offline?data=…`, as a link or as a PNG image of the QR code | protobuf `MigrationPayload`. A large export is spread over several QR codes (`batch_index`/`batch_size`): they are accumulated and the preview says which are missing. HOTP and MD5 codes are skipped with their reason, because Klav only has TOTP |
| Chrome, Edge, Brave (and Arc, Dia) | `.csv` | `chrome://` rows are skipped; app rows (`android://…@com.example.app/`) are imported with the package as the title |
| Firefox | `.csv` | `timePasswordChanged` dates the password |
| Safari | `.csv` | `OTPAuth` is imported as a code |
| Generic CSV | `.csv` | columns by alias, as in phase 3 |

- **Detection by content:** `PK` is a `.1pux`, the PNG signature is a QR code, `{` is Bitwarden, `otpauth-migration://` is Google Authenticator and the rest is CSV, with the dialect taken from the header. `--from` (or the choice in the wizard) is a hint that **is checked**: a Chrome CSV chosen as Bitwarden gives an error that says what it looks like.
- **Links** (ADR [0030](0030-ronda-de-seguridad-2026-11.md), layer 08): only `http`/`https` ones are imported; one without a scheme gets `https://`. The rest (`javascript:`, `data:`, `file:`, app links) are left out with a warning and don't give the item a title, except app links (`android://…@com.example.app/`), whose package is still the title.
- **Caps while reading** (ADR 0030, layer 08): 100 000 entries per file and per import, 100 warnings listed per file, 256 fields per item, 256 QR codes per Google Authenticator export and 16 exports per import. They are applied while the file is being read.
- **Passkeys** (note of 2026-11-05, with ADR [0020](0020-passkeys.md) implemented):
  - **Bitwarden** ones (`login.fido2Credentials` in the unencrypted JSON) are imported. Each one is checked when the file is read, so the preview already says what will happen:
    - an ECDSA P-256 key (`keyType`, `keyAlgorithm` and `keyCurve`, if present) in base64url PKCS#8 (`keyValue`), read by `PasskeyPrivateKey::from_pkcs8_der`;
    - `credentialId` as Bitwarden stores it: `b64.` plus base64url, or a GUID (16 bytes);
    - an `rpId` that is a registrable domain (`passkey::rp`, with the PSL; that is why `klav-import` turns on the `rp-id` feature);
    - a `userHandle` of 1 to 64 bytes.

    The names (`userName`, which if missing is the login's username; `rpName`, `userDisplayName`) are cleaned of control characters and trimmed. The key only exists in memory until the client seals it with the vault key (`0x15`, `Passkey::import`) when saving the login: it never goes to notes or fields, and no type that carries it implements `Debug`.
  - Klav stores one passkey per login. The first valid one goes to the login it comes with. The rest, and the ones that aren't valid, aren't imported and are counted, with a note on their row.
  - On merging: a login without a passkey receives it (`passkey_added`); one with the same credential doesn't change; one with **another** passkey keeps its own (`passkey_kept`), because replacing it is something the person confirms (ADR 0020 §2). A login that was already in the vault receives it only if its rpId matches a site the login already had (the rule for a chosen login; URLs added by the same import and an agent's pending ones don't count); if not, the row says `passkey_other_site` and the passkey doesn't go in (T119). If saving it adds the rpId's address, the preview shows it (`urls_added`). Importing doesn't confirm an agent's pending sites (ADR 0030 §7), and a passkey that can't be sealed leaves its login imported without it and appears in the result (`passkeys_failed`).
  - The **counter** (`counter`) isn't stored: Klav always signs with 0. If it came in greater than 0, it is imported anyway (decided by Omar on 2026-11-05) and the row warns about it, because a site that watches the counter may reject it. The warning says what to do then: sign in another way and register a new passkey in Klav for that site. Bitwarden only increments the counter if it was already greater than 0, so its own passkeys come out with `"0"`.
  - **1Password** (desktop `.1pux`): the `passkey` field doesn't carry the key. 1Password says it only exports passkeys from iOS and Android, with Credential Exchange. They are counted and a warning is given.
  - **Google** (Password Manager CSV): it has no passkey columns. Google doesn't export its own.
  - **FIDO's CXF/CXP** (Credential Exchange): future work, outside v1 (ADR 0020 §1).
- **Authy** has no official export. The CSV Twilio provides under the GDPR carries seeds encrypted with an undocumented scheme, and **it isn't imported**. The wizards explain the way: setting up 2FA again site by site.

### 3. Merging
The merge is against the live items of the **destination project** (Personal / General by default) and against what the same import already brings.

1. **Same site and same username** (any host in common, without `www.`; without URLs, same title and username): it is the same login. What the import adds (URLs, code, notes, fields, tags) is added, and nothing is duplicated. One URL per site is kept. Since one host in common is enough, an entry can also bring a site the login didn't have: the preview row names each site it adds ("sites added: …", `sites_added`), in the CLI, the extension and iOS, with the host that will be compared (in punycode, with its Unicode form next to it if it is an internationalized name), so that a file doesn't add a site to a login without saying so (T119; note of 2026-11-06).
2. **Different password:** the newest one wins.
   - Klav's stays only if the source dates its own and Klav knows the current one is newer. Klav knows it from the password history: the end of the last previous one marks since when the current one has been in use.
   - In any other case the imported one wins.
   - The losing one goes to the **password history** (`0x16`, ADR [0022](0022-generador-historial-y-cambio-asistido.md) §3), as does the source's own history.
   - A value the history already has doesn't count as a change.
   - **No password is lost.**
3. **One-time codes:** they never replace each other. If the login already has another code, the imported one goes in a second field ("One-time password (imported)").
4. **Google Authenticator:** a code joins the login whose title or host matches the issuer and whose username is the account, **when that login is unique**. If not, it joins a TOTP item with the same secret (the comparison is constant-time). If there isn't one either, it is created as its own TOTP item, and the preview marks it so.
5. **Other kinds** (cards, notes, identities…): they only join an item of the same kind and title whose values don't contradict each other.
6. **Title taken** for a new item: the username is appended ("Mail (bob)") or a number.
7. **Importing the same thing twice adds nothing.** If the import is cut off (network), repeating it finishes the rest.

These rules are also stated in the CLI's preview and in the wizards, in one sentence.

### 4. Dependencies
ADR [0005](0005-dependencias-criptograficas.md)'s criterion stays: few, maintained, and with licenses from `deny.toml`. `cargo deny check` passes.

- **ZIP: an in-house reader** of about 90 lines (`zip.rs`), plus `miniz_oxide` 0.9 (MIT OR Zlib OR Apache-2.0) for the deflate.
  - **Why in-house:** a `.1pux` only needs to read one entry (`export.data`) from the central directory.
  - **Why not the `zip` crate**, which the roadmap mentioned: `zip` 9 brings AES encryption, bzip2, zstd and lzma by default, too much to read one entry.
  - **What it doesn't support:** ZIP64, encrypted entries and methods other than *stored* or *deflate*. They are rejected with an error.
  - `miniz_oxide` already comes into the tree through `png` and `flate2`.
- **Protobuf: an in-house reader** of about 60 lines (`protobuf.rs`): varints and length-delimited fields, without `prost`. It goes in `klav-import` and not in `klav-core`, as the roadmap said, because it isn't cryptography.
- **QR from an image:** `png` 0.18 (MIT OR Apache-2.0) and `rqrr` 0.11 ((MIT OR Apache-2.0) AND ISC; it brings `g2p`, MIT/Apache-2.0, and `lru`, MIT).
  - They sit behind the `qr-image` *feature*, which only the CLI and `klavd` turn on.
  - `klav-ffi` doesn't turn it on: iOS reads QR codes with AVFoundation (camera) and Core Image (photos).
  - PNG only: a screenshot on macOS is already PNG. JPEG would need another decoder.
  - There is a limit of 40 million pixels.
- **`qrcode` 0.14** (MIT OR Apache-2.0): it only generates the sample images (*feature* `samples`, a development dependency).
- `csv` 1.4 and `data-encoding` were already approved.

### 5. Where it runs
- **CLI:** `klav import <archivo>… [--from] [--vault] [--project] [--dry-run] [--json]`.
  - `-` reads pasted Google Authenticator links from stdin. They never go in argv, because they carry secrets.
  - It works without `klavd` or through it.
  - It replaces `klav import csv`.
- **`klavd`:** four new operations.
  - `import_add` adds a file, in pieces with `more` because a native message carries 1 MiB at most. The others are `import_preview`, `import_apply` and `import_cancel`.
  - Each import lives **inside the unlocked session**: it is deleted on locking.
  - There are 4 at a time at most, and they expire after 30 min without use.
  - The preview carries 500 rows at most, to fit in a native message. The total goes separately.
- **Extension:** the native host allows those four operations. **This lifts the import ban of ADR [0017](0017-extension-de-navegador.md) §4**, which named `create_many`. The reasons:
  - none of the four return any value;
  - their effect is that of `create` and `edit`, which the extension can already do;
  - they never create duplicate titles, because the merge renames.
  - `create_many`, the old CSV operation, which could duplicate, **is retired** from `klavd` and from `klav-client`: nothing uses it any more.
  - The extension keeps the file's bytes only in memory.
- **iOS:** `klav-ffi` exposes an import session with the same operations.

### 6. The exported file
An unencrypted export is the most dangerous copy of the passwords. That is why:

- every import path ends with the reminder to **delete the file and empty the trash**;
- the test samples are synthetic (`examples/import/`, generated by `cargo run -p klav-import --features samples,qr-image --example import-samples`);
- no test uses real data.

## Consequences
- `klav import csv` goes away, and with it `create_many`. `klav import archivo.csv` does the same and also merges. `--allow-duplicate` is no longer needed because the merge renames what clashes.
- The formats can break when the managers change their export. The tests with synthetic samples protect the behavior, not fidelity to the real format. A format error says which part wasn't understood, without values.
- The merge only looks at the destination project. An identical login in another project is imported again, and vault health (ADR 0022 §4) will find it as reused.

## Rejected alternatives
- **The `zip` crate:** too many dependencies to read one entry (§4).
- **`prost`:** it requires `prost-build` or generated code for a five-field message.
- **Importing Authy's GDPR CSV:** the encryption scheme isn't documented, and guessing it with someone's 2FA seeds is a bad risk.
- **Having the extension parse in JavaScript:** it would duplicate the readers and the merge rules in another language.
- **Asking on every clash:** the merge of §3 is deterministic, and the preview shows what will happen before importing.
