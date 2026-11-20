# 0019 · Name: Lacre becomes Klav

- Status: accepted
- Date: 2026-11-03

## Context
The project started out as **Lacre**. Omar chose a new name, **Klav**. Nothing is published (no packages, no extension in the stores, no app on TestFlight) and there are no users, and the app identifiers don't exist yet in the Apple Developer Portal. Several format strings carry the name inside them (domain separation labels, key and token prefixes, the OPAQUE suite); changing them after launch would mean keeping both forms forever. Right now it costs nothing.

## Decision
Rename everything in a single change, without touching any algorithm, parameter or byte layout (names only):

1. **Crates, binaries and paths:** `crates/lacre-*` → `crates/klav-*` (`klav-core`, `klav-proto`, `klav-server`, `klav-client`, `klav-cli`, `klav-daemon`, `klav-touchid`, `klav-sdk`, `klav-wasm`, `klav-ffi`); binaries `klav`, `klavd`, `klav-server` and `klav-native-host`; directory `~/.klav`; socket `klavd.sock`; environment variables `KLAV_*`; references `klav://…`.
2. **Formats (spec §14, 2026-11-03):**
   - All `lacre/v1/…` labels become `klav/v1/…` and the OPAQUE suite becomes `klav-opaque-v1`.
   - Secret Key: prefix `L1` → `K1` (`K` for Klav, `1` for the version). `K` is in the RFC 4648 base32 alphabet just like `L`, and the prefix is validated before the body is read, so the design (checksum, mapping of `0`/`1`/`8`) doesn't change.
   - Agent private key: `lak1_` → `kag1_` (**k**lav, **ag**ent, version **1**). It keeps the `<producto><tipo><versión>_` shape and the 5 characters; `kak1_`, the direct equivalent, was rejected because in Spanish it reads as "caca" (poo) on every kit and in every log.
   - Session tokens: `lat_`/`lrt_` → `kat_`/`krt_` (the `l` was for Lacre).
   - Agent headers `Klav-Agent`, `Klav-Timestamp`, `Klav-Nonce` and `Klav-Signature`.
   - The vectors in `docs/vectores/` are regenerated with `KLAV_REGEN_VECTORS=1` (the RFC 9180 one only changes its description).
3. **Platform identifiers:** native messaging `dev.klav.host`; Firefox add-on `klav@klav.dev`; Keychain `dev.klav.agent`; iOS app `dev.klav.ios`, extension `dev.klav.ios.credentials`, App Group `group.dev.klav.ios`; launchd `dev.klav.klavd`; packages `@klav/sdk` and `@klav/extension`. The Chromium extension ID doesn't change: it comes from the development key, not from the name.
4. **Visual identity:** the wax seal stays; its letter changes from "L" to "K" and the extension icons, the app icon and the screenshots in `docs/img/extension` are regenerated. The `lacre*` color tokens become `klav*`. *(Superseded the same day in the extension by the visual direction in [`diseno-visual`](../diseno-visual/README.md): the wax seal is retired and the pixel key takes its place.)*
5. **Earlier ADRs (one-time exception):** in ADRs 0001–0018 only a mechanical rename of identifiers, paths, links and the product name is applied (including the file names `0007-crate-klav-proto.md` and `0012-daemon-klavd.md`). No decision changes in content; the prefixes they cite (`kag1_` in 0014) are the new ones because this ADR decides them. The immutability rule still holds for everything else.

## Consequences
- Any test installation with the old name (`~/.lacre`, `lacred`, accounts, agents, Keychain keys with `dev.lacre.*`, native host `dev.lacre.host`) stops working: it has to be created again. Data encrypted with the old labels doesn't open with the new ones, on purpose.
- The Apple IDs hadn't been created yet, so nothing is lost: they are created directly with `dev.klav.*`.
- Pending for Omar: rename the GitHub repository to `klav` (GitHub redirects the old URL) and register the `klav.dev` domain, which the Firefox add-on ID uses.
