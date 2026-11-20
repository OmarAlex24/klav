# Testing the Mac app on a clean Mac

This guide covers what couldn't be tested without touching a real Mac ([ADR 0027](decisiones/0027-app-de-mac.md), layer 7):

- installing from the published DMG, with real Gatekeeper;
- the LaunchAgent registered with `SMAppService` and its permission in "Login Items";
- the `/usr/local/bin/klav` link, which asks for an administrator's password;
- the manifests and the extension in real Dia and Chrome profiles;
- Touch ID with a finger;
- a Sparkle update installed over a real copy;
- uninstalling.

All of that was already tested with temporary paths and homes ([macos.md](macos.md) §3 to §6). Here it is tested end to end, as a person would.

- **Time:** an hour, plus however long two *release* builds with notarization take (about 15 minutes each).
- **Isolated:** everything happens in a new macOS user. Your user, your `klavd`, your `~/.klav`, your browsers and your keychain aren't touched. Step 10 deletes the user.
- **Test account:** use a test email on a test server (for example, a local one, [self-hosting.md](self-hosting.md)), not your account.
- Steps with **[Touch ID]** ask for a finger, and those with **[admin]** for an administrator's password.

## 0. Requirements

- A Mac with Apple Silicon and macOS 15 or newer, with Touch ID (the Mac's or a Magic Keyboard's).
- In your user, what [macos.md](macos.md) §5 lists:
  - team SZ3F58F8LX's "Developer ID Application" identity in the keychain;
  - the notarization key's path, key ID and issuer ID in your local build config ([ios.md](ios.md) §5).
- Dia and Chrome. If they aren't in `/Applications`, install them from the test user.
- A test Klav server that accepts sign-ups.

## 1. The two DMGs

The update test needs two versions signed with the same Sparkle key. Use a test key and a local *appcast*, not the production one ([macos.md](macos.md) §6): that way the test doesn't take it out of the vault. From your user, in the repository:

```sh
mkdir -p ../klav-mac-prueba
scripts/macos/appcast.sh test-key ../klav-mac-prueba/sparkle-prueba.key   # imprime la pública
export KLAV_SPARKLE_PUBLIC_KEY=<la pública que imprimió>
export KLAV_SPARKLE_FEED_URL=http://127.0.0.1:18741/appcast.xml

KLAV_MAC_VERSION=0.1.0 KLAV_MAC_BUILD=1 scripts/macos/build-app.sh release
cp target/macos/dist/Klav-0.1.0.dmg ../klav-mac-prueba/

KLAV_MAC_VERSION=0.1.1 KLAV_MAC_BUILD=2 scripts/macos/build-app.sh release
cp target/macos/dist/Klav-0.1.1.dmg ../klav-mac-prueba/
scripts/macos/appcast.sh make --key-file ../klav-mac-prueba/sparkle-prueba.key \
  --url-base http://127.0.0.1:18741 --out ../klav-mac-prueba/appcast.xml \
  ../klav-mac-prueba/Klav-0.1.1.dmg
```

- These DMGs carry a test key and a local *appcast*: **they are not published**.
- Both have to pass the budget (the script fails if not) and `spctl` has to say "Notarized Developer ID".
- Copy `Klav-0.1.0.dmg`, `Klav-0.1.1.dmg` and `appcast.xml` to `/Users/Shared/klav-prueba/`, so the test user can see them. The private key stays in your user.

## 2. The test user

1. System Settings › Users & Groups › "Add User": for example "Klav Prueba", **administrator** (for step 4.2).
2. Log in as that user (log out of yours or use fast user switching).
3. Enroll a finger in System Settings › Touch ID & Password.
4. Open Dia and Chrome once, so they create their profiles.

## 3. Opening the DMG

1. Open `/Users/Shared/klav-prueba/Klav-0.1.0.dmg`.
   - **Expected:** it mounts without Gatekeeper warnings. It carries `Klav.app` and an alias to Applications.
2. Open `Klav.app` **from the DMG**, without moving it.
   - **Expected:** the window asks to move it to Applications and doesn't run any step.
3. Quit Klav, drag `Klav.app` to Applications, eject the DMG and open it from Applications.
   - **Expected:** the icon shows in the menu bar and "Set up this Mac" opens with the five steps.

## 4. Set up this Mac

1. **Background service** › "Turn on".
   - If macOS asks, allow Klav in System Settings › General › Login Items.
   - **Expected:** the step is marked done and Klav shows in "Login Items". In Terminal, `launchctl print gui/$(id -u)/dev.klav.klavd` shows it running, with the program at `Klav.app/Contents/Helpers/klavd.app/Contents/MacOS/klavd`. It is the only thing in that layer that couldn't be tested without a clean user: `SMAppService` registering the *plist* with that `BundleProgram` (ADR 0027, note of 2026-11-05).
2. **Command line** › "Add klav". **[admin]**
   - **Expected:** `ls -l /usr/local/bin/klav` points to `/Applications/Klav.app/Contents/Helpers/klav`.
   - If there was already a `klav` at that path, the app shows what it is and asks before replacing it.
3. **Browsers** › "Connect the browsers", first without changing anything.
   - **Expected:** the step says "Chrome: waits for Klav in the Chrome Web Store" and the same for Dia, and the button disappears. There is only a `dev.klav.host.json` in `~/Library/Application Support/Mozilla/NativeMessagingHosts/`; not in the Chrome and `Dia/User Data` folders. `grep -c niiplppgdljgimbnmokojdkofdcjkgao ~/Library/Application\ Support/klav/native-host/klav-native-host` gives `0`.
   - "Advanced options" › check "Development extension". Before checking it, read the sentence about the risk: any unpacked extension with the repository's public key could talk to `klavd`. This test needs it because Klav isn't in the Chrome Web Store yet.
   - "Connect the browsers" again.
   - **Expected:** Chrome and Dia turn green. `dev.klav.host.json` is in `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`, `~/Library/Application Support/Mozilla/NativeMessagingHosts/` (Dia reads this one) and `~/Library/Application Support/Dia/User Data/NativeMessagingHosts/`, and its `path` points inside `Klav.app`. `defaults read dev.klav.mac devExtension` gives `1`.
4. **Extension:** "How to install it" in each browser, and follow [extension.md](extension.md#cargar-sin-empaquetar) in Chrome and in Dia.
   - **Expected:** on opening each one's *popup*, the app says "Connected in Chrome" and "Connected in Dia".
   - Quit and open the app: "Development extension" is still checked.
5. **Account** › "Create an account", with "Use my own server" and the test server.
   - **Expected:** the emergency kit shows. "I’ve kept it" stays off until the PDF is printed or saved; canceling the print dialog doesn't turn it on.
   - Save the PDF in the test user (it is deleted with the user in step 10).
   - On closing the sheet, the vault stays open in the window.

## 5. Touch ID **[Touch ID]**

1. ⌘L (or the Klav menu › "Lock Klav").
   - **Expected:** the window switches to the lock and the icon looks dimmed.
2. "Unlock with Touch ID".
   - **Expected:** the system dialog names "Klav", with the app's icon, and says "… is trying to unlock your vault for the Klav app (<correo>)." (in Spanish, «… está intentando desbloquear tu bóveda para la app de Klav (<correo>).», if the Mac is in Spanish). The app says "macOS asks on behalf of Klav’s background service" while it waits. With a finger, the vault opens.
3. Cancel the dialog once.
   - **Expected:** the app offers "Use the master password".

## 6. The extension and the CLI

1. In Chrome, save a test login (any form on a test site) and fill it again from the extension. Do the same in Dia.
   - **Expected:** the item shows in Klav's window without reloading.
2. Open **a new terminal** and run:

   ```sh
   which klav            # /usr/local/bin/klav
   klav status           # la cuenta de prueba, desbloqueada, y el klavd de Klav.app
   klav item ls
   ```

   - **Expected:** `klav status` says `klavd` is unlocked (it is the same one the app uses) and `klav item ls` shows the item from step 1.
3. `klav lock`.
   - **Expected:** the app switches to the lock on its own within a few seconds. The extension is locked too.

## 7. Updating **[Touch ID]**

1. In **your** user, serve the *appcast* (only for 127.0.0.1):

   ```sh
   cd /Users/Shared/klav-prueba && python3 -I -m http.server 18741 --bind 127.0.0.1
   ```

   The test user sees the same 127.0.0.1.
2. In the test user: the Klav menu › "Check for Updates…".
   - **Expected:** Sparkle offers 0.1.1. Install it.
3. On quitting and opening Klav again:
   - **Expected:** Klav › About says 0.1.1, signed by SZ3F58F8LX (`codesign -dv /Applications/Klav.app` shows `TeamIdentifier=SZ3F58F8LX`).
   - `klav status` shows 0.1.1's `klavd`: the app relaunched it on seeing another version.
   - The link, the manifests and the extension keep working without touching them, because they point inside the *bundle*.
4. Optional, the rejection: a 0.1.2 signed *ad hoc* (not by the team) with an *appcast* signed with the same test key. In your user, with the same variables as step 1:

   ```sh
   KLAV_MAC_VERSION=0.1.2 KLAV_MAC_BUILD=3 scripts/macos/build-app.sh adhoc
   cp target/macos/dist/Klav-0.1.2.dmg /Users/Shared/klav-prueba/
   scripts/macos/appcast.sh make --key-file ../klav-mac-prueba/sparkle-prueba.key \
     --url-base http://127.0.0.1:18741 --out /Users/Shared/klav-prueba/appcast.xml \
     /Users/Shared/klav-prueba/Klav-0.1.2.dmg
   ```

   With the server running, "Check for Updates…" again.
   - **Expected:** Sparkle accepts the EdDSA signature, but Klav warns "Klav 0.1.2 wasn’t installed", deletes the download and stays on 0.1.1 ([macos.md](macos.md) §6).

When you're done, stop the server (⌃C).

## 8. Memory at rest

With the vault locked and the window closed, in Activity Monitor › Memory:

- **Expected:** Klav is around 19 MB and 0 % CPU (the figure in [macos.md](macos.md) §7). With the window open it rises to a few tens of MB and drops when it closes.

## 9. Uninstalling

First, turn off the development extension: Settings › This Mac › "Development extension", uncheck it.

- **Expected:** without asking anything else, Chrome and Dia go back to "waits for Klav in the Chrome Web Store". The `dev.klav.host.json` files of Chrome and `Dia/User Data` disappear; Mozilla's stays. `grep -c niiplppgdljgimbnmokojdkofdcjkgao ~/Library/Application\ Support/klav/native-host/klav-native-host` gives `0`, and the Chrome and Dia *popups* no longer connect to `klavd`.

1. The Klav menu › "Uninstall Klav from this Mac…". Leave "Also delete this Mac’s copy of the vault" unchecked.
   - **Expected:** the sheet says what it removes and what it leaves before doing anything. On confirming, it asks for **[admin]** for the link.
2. Check:
   - Klav no longer shows in "Login Items" and `launchctl print gui/$(id -u)/dev.klav.klavd` doesn't find it;
   - `/usr/local/bin/klav` no longer exists;
   - Mozilla's `dev.klav.host.json` is gone (Chrome's and Dia's went away when the development extension was turned off);
   - `~/Library/Application Support/klav` is still there, because you didn't check it.
3. "Show Klav in Finder" and drop `Klav.app` in the Trash.

## 10. Cleaning up

1. Log out of the test user and, from yours, delete it (Users & Groups › "Delete User", without keeping the folder).
2. Delete `/Users/Shared/klav-prueba/` and `../klav-mac-prueba/` (with the test key: `rm -P`).
3. The test account stays on the test server.

## What to note down

If something doesn't go as **Expected** says, note the step, what happened and, if it's the app's, the log:

```sh
log show --last 30m --predicate 'subsystem == "dev.klav.mac"' --info
```

When everything passes, check the "Prueba a mano en un Mac limpio" box in [roadmap.md](roadmap.md).
