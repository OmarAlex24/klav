# Testing phase 6 (iOS) on an iPhone

This guide covers what couldn't be tested in the simulator:

- real Face ID with the Secure Enclave key, also from the extension;
- AutoFill on an iPhone and its memory in *release*;
- real APNs notifications, in *sandbox* and in production;
- TestFlight.

First, what is needed has to be created in the Apple account (§1).

- **Time:** an hour the first time (the Apple account and the first
  build take the longest).
- **Isolated:** use a test Klav account on a test server. The
  iPhone doesn't touch your `~/.klav`. Step 9 deletes everything.
- The steps marked **[Face ID]** ask for your face.

## 0. Requirements

- A Mac with Xcode 26 or newer, XcodeGen (`brew install xcodegen`) and
  Rust (`rustup`).
- An iPhone with Face ID and iOS 18 or newer, in developer mode
  (Settings › Privacy & Security › Developer Mode).
- The Apple Developer account of team `SZ3F58F8LX`, signed in
  in Xcode (Settings › Accounts).
- **A Klav server with HTTPS** that the iPhone can reach. Klav only
  accepts `http://` to `127.0.0.1`, so `http://<IP del Mac>` won't do.
  Options: your deployed server, or a local one behind an HTTPS tunnel
  (Tailscale `serve`, `cloudflared`). See [self-hosting.md](self-hosting.md).

## 1. What you have to create in your Apple account

None of this was done in phase 6: your account wasn't touched.

1. **Identifiers** (developer.apple.com › Certificates, IDs & Profiles ›
   Identifiers). If you use another prefix, change it in `Local.xcconfig` and in
   the server's `topic`.
   - **App ID `dev.klav.ios`** with the App Groups, AutoFill
     Credential Provider, Push Notifications and Data Protection (*Complete
     Protection*) capabilities.
   - **App ID `dev.klav.ios.credentials`** with App Groups, AutoFill
     Credential Provider and Data Protection.
   - **App Group `group.dev.klav.ios`**, assigned to both App IDs.

   With automatic signing, Xcode can create them on its own the first time you
   build for the iPhone (step 2). Check afterwards that the capabilities
   ended up as above.
2. **APNs key** (Keys › +, "Apple Push Notifications service"):
   - download the `.p8`, which can only be downloaded once;
   - note the *Key ID*;
   - keep the file outside the repository, with `0600` permissions.

   The same key works for *sandbox* and production.
3. **Certificates and profiles:** there is no need to create them by hand. Xcode and
   `scripts/ios/archive.sh` use automatic signing
   (`-allowProvisioningUpdates`).
4. **App Store Connect › Apps › +:** iOS platform, name "Klav", primary
   language Spanish, *bundle ID* `dev.klav.ios` and an SKU (for example
   `klav-ios`).
5. **For external TestFlight** (internal doesn't need review):
   - test information: a contact email and notes for testers;
   - a privacy policy URL;
   - the app's privacy answers (Klav doesn't collect data for the
     developer; the server is each person's own).
6. **Encryption (export compliance):** the `Info.plist` declares
   `ITSAppUsesNonExemptEncryption = false`. That is what Apple saved when
   Omar answered the questionnaire for build 2 (standard algorithms, not
   France), so the following builds don't ask for it again. If Klav
   adds encryption that isn't standard, change the key and answer the
   questionnaire in App Store Connect.

## 2. Installing on the iPhone from Xcode

```sh
cd ~/dev/klav
cp apps/ios/Config/Local.xcconfig.example apps/ios/Config/Local.xcconfig
#   DEVELOPMENT_TEAM = SZ3F58F8LX   (ya viene así)
scripts/ios/build-xcframework.sh
cd apps/ios && xcodegen generate && open Klav.xcodeproj
```

In Xcode:

1. Choose your iPhone as the destination and press ▶ (Klav scheme, Debug
   configuration).
2. The first time, on the iPhone go to Settings › General › VPN & Device
   Management and trust your development certificate.

## 3. Real Face ID

1. Open Klav and sign in to the test server with a new account
   (create it first with `klav signup` on the Mac, in a throwaway
   `KLAV_HOME`).
2. **Expected:**
   - Face ID isn't asked for on signing in: the first unlock with the password
     enrolls it;
   - Settings › Face ID is on and the text below it does **not** mention the
     simulator.
3. Press "Lock" and then "Use Face ID" **[Face ID]**. The vault opens.
4. Lock, cancel the Face ID dialog and type the password. It also
   opens the vault.
5. Change the enrolled faces (the iPhone's Settings › Face ID & Passcode ›
   set up an alternate appearance). **Expected:** on returning, Klav asks for the
   master password. Afterwards Face ID works again.
6. Restart the iPhone. **Expected:** Klav asks for the password, because Face
   ID requires it after a restart.

## 4. AutoFill in Safari

1. After signing in, the app shows how to turn on Klav. Press "Open
   AutoFill & Passwords" and turn on Klav. **Expected:** that
   Settings page opens and, on returning to Klav, the screen's checkbox
   fills and closes on its own. If it was already on, turn it on in the
   iPhone's Settings › General › AutoFill & Passwords.
2. In the app, create a login for a test site that has a
   form (or use `examples/login-site` exposed with the same HTTPS
   tunnel).
3. Open the site in Safari and tap the username field. **Expected:** the
   keyboard suggests Klav's username.
4. Tap the suggestion **[Face ID]**. **Expected:** the username and
   password are filled. This is the key test: **the extension opens the
   Secure Enclave key the app saved.**
5. Tap the keyboard's key › Klav **[Face ID]**. **Expected:** the
   "Choose how to sign in" list appears, and "Fill" fills.
6. In a one-time code field (with an item that has TOTP)
   **[Face ID]**. **Expected:** the 6 digits are filled.
7. Open a site with another host and ask for Klav from the key. **Expected:** the
   list comes up empty, because Klav doesn't offer that item.

## 5. Real APNs notifications

1. Configure the test server with the key from step 1.2
   ([self-hosting.md](self-hosting.md) §2.4):

   ```sh
   KLAV_APNS_KEY_PATH=/ruta/AuthKey_XXXXXXXXXX.p8
   KLAV_APNS_KEY_ID=XXXXXXXXXX
   KLAV_APNS_TEAM_ID=SZ3F58F8LX
   KLAV_APNS_TOPIC=dev.klav.ios
   ```

   Restart the server. If the key isn't valid, the server doesn't start.
2. On the iPhone, open Klav and unlock. Accept notifications. **Expected:**
   - Settings › Agent notifications says "On for this iPhone";
   - in the server's database, `push_tokens` has a row with `sandbox`
     (an Xcode build uses the *sandbox*).
3. Close Klav (swipe it out of the app switcher). On the Mac, register
   a throwaway agent:

   ```sh
   KLAV_HOME=~/klav-prueba-f6/agente klav agent register --name prueba \
     --server https://<tu servidor> --email <correo de prueba> --key-store file
   ```

   **Expected:** "An agent wants to join" arrives. The notification doesn't say which agent
   it is.
4. Tap the notification **[Face ID]**. **Expected:** the "New agent" sheet opens
   with the same six words as the terminal, numbered in the same
   order. Check a project (its chip shows ✓) and press
   "They match: approve" **[Face ID]**. `klav agent status` says `active`.
5. With the app closed:

   ```sh
   KLAV_HOME=~/klav-prueba-f6/agente klav agent totp "klav://<Bóveda>/<Proyecto>/<Elemento>" \
     --agent prueba --reason "probar avisos" --wait 3m
   ```

   **Expected:** "An agent is asking for permission" arrives. On tapping it, the card shows
   highlighted with a cobalt border. "Approve once" **[Face ID]** and the terminal receives the code.
6. Sign out on the iPhone. **Expected:** `push_tokens` is left empty and no more
   notifications arrive.

## 6. The extension's memory in *release*

1. In Xcode, Product › Scheme › Edit Scheme › Run › Build Configuration:
   **Release**. Install again.
2. Mac › Console › your iPhone. Filter by `subsystem:dev.klav.ios
   category:autofill`.
3. Fill a password as in §4. **Expected:** the
   `footprint …` lines stay close to or below what was measured in the simulator with
   Debug (≈ 29–32 MiB, see [ios.md](ios.md) §3), and the fill isn't interrupted. If the extension
   closes on its own halfway through the fill, iOS killed it for using too much memory.
   Note the values in [ios.md](ios.md) §3.

## 7. TestFlight

```sh
scripts/ios/archive.sh check    # comprueba que compila para el dispositivo
scripts/ios/archive.sh upload   # firma, archiva y sube a App Store Connect
```

1. In App Store Connect › TestFlight, wait for the build to finish
   processing. Add yourself as an internal tester.
2. Install from the TestFlight app. This build uses **production**
   APNs: repeat §5 and check that `push_tokens` says
   `production`.
3. For the next upload, bump `CFBundleVersion` in `Klav/Info.plist` and
   `Credentials/Info.plist`.

## 8. What was already tested in the simulator

- Signing in, unlocking and locking, with simulated Face ID.
- Viewing, searching, creating, editing and moving to the trash.
- AutoFill of passwords and codes, the list, "Open Klav first" and
  the QuickType suggestions.
- The APNs *token* registered and deleted on signing out.
- Notifications with `simctl push`, in Spanish, that lead to their request.
- Approving an agent by comparing the words.
- Approve once, approve 15 min and deny.
- The new interface ([diseno-visual](diseno-visual/README.md)) in light and
  dark, the vault with large accessibility text, and "Show" and the light
  that floods the lock on unlock, recorded on video.

## 9. Cleaning up

- Delete the app from the iPhone (long-press the icon › Delete App). That also
  deletes the App Group container.
- Turn off Klav in AutoFill & Passwords, if it is still in the list.
- Delete `~/klav-prueba-f6` and the test account from the server.
- Remove the `.p8` key from the test server if you won't use it any more.
