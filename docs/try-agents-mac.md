# Testing agents from the Mac app by hand

This guide covers what the automated tests of [ADR 0033](decisiones/0033-agentes-desde-la-app-de-mac.md) can't: real agent clients (Claude Code, Codex and Cursor) in a clean macOS user, Touch ID with a finger, a screen lock in the middle of a key change, and the iPhone app against the same account. It covers the ADR, its amendment of 2026-11-06 (§7) and its amendment of 2026-11-10 (F8, layer 6).

- **Time:** about three hours, a few minutes of them loading items.
- **Isolated:** everything runs in a new macOS user, against a test server, with a test account. Your user, your `klavd`, your Klav home and your account are never touched. Step 14 deletes the test user.
- **Never production:** before the first request of every client (the Mac app, `klav`, `klav-proxy`, the iPhone), check that it names the test server's URL, and stop if it doesn't.
- Steps marked **[Touch ID]** need a finger.

Check each box as it passes. When something fails, write down what you saw and the step, and stop that section.

## 0. Requirements

- An Apple Silicon Mac with Touch ID and macOS 15 or newer.
- A new macOS user with Claude Code, Codex and Cursor installed and signed in to their own providers. Set its language to English (System Settings › General › Language & Region) before opening Klav, and the iPhone's too before step 13: this guide quotes the English labels.
- A Klav build of the commit under test:
  - the Mac app ([macos.md](macos.md) §4 to build it, §5 for the DMG);
  - the iPhone app on a simulator or a device ([ios.md](ios.md));
  - `klav-proxy`, built in your own user with `cargo build --release -p klav-proxy` and copied to `/Users/Shared/klav-proxy`.
- A Klav test server that accepts sign-ups ([self-hosting.md](self-hosting.md)), reachable from the Mac and the iPhone. A local one at `http://127.0.0.1:<port>` works for the Mac and a simulator.
- In every terminal of the test user, paste this first, with the test server's URL (never `klav.dev`) and the test account's e-mail:

  ```sh
  export TEST_SERVER=http://127.0.0.1:<port>
  export TEST_EMAIL=<the test account's e-mail>
  load=(); for p in $(seq -w 1 12); do load+=(--project "Personal/Load-$p"); done
  check_server() {
      case "$TEST_SERVER" in
          '' | *klav.dev*) echo "STOP: TEST_SERVER is empty or production"; return 1 ;;
      esac
      [ "$(klav status | sed -n 's/^server: *//p')" = "${TEST_SERVER%/}" ] \
          || { echo "STOP: klav is not on $TEST_SERVER"; return 1; }
      klav status | grep '^home:'
  }
  rotated() { klav log --since 7d --limit 100000 | grep -c project.rotated; }
  ```

  - `load` is the twelve load projects of step 1, as `klav agent approve` flags.
  - `check_server` stops when the person's `klav` is not on the test server, or when `TEST_SERVER` is empty or production. It prints `STOP` until step 1.2. From then on, run it wherever this guide says, and stop if it prints `STOP`.
  - `rotated` counts the `project.rotated` lines of the audit log, with no limit on lines. `klav log --since` alone also shows the lines of earlier steps, and at most 50.

- The agents outside the Mac app live in a second Klav home in the test user, `~/klav-agent-b`. Every command for them starts with `KLAV_HOME=~/klav-agent-b`. The test user's own `klav` (no `KLAV_HOME`) is the person's, and talks to the app's `klavd`. That `klavd` keeps its files in `~/Library/Application Support/klav`.

## 1. The account and the Mac app

1. Sign up on the test server from the Mac app, in the test user. Keep the emergency kit outside the repository.
2. Go through «Set up this Mac» to the end, so `klav` runs in a new terminal.
3. In Settings, check that the server is the test server. In a terminal, run `check_server`: it prints the home, `~/Library/Application Support/klav` of the test user, and no `STOP`.
4. Add the projects and items:

   ```sh
   klav project create --vault Personal Work
   klav item add login --title GitHub --username ana --url https://github.com -g password
   klav item add api-key --title OpenAI -g api_key
   klav item add login --title Jira --project Work --username ana --url https://jira.example.com -g password
   klav item add api-key --title Railway --project Work -g api_key
   ```

5. Add twelve load projects of 300 items each. Steps 10 and 13 lock the screen or force-quit the iPhone app in the middle of a key change, and a key change of a few small projects ends before anyone can:

   ```sh
   for p in $(seq -w 1 12); do
       klav project create --vault Personal "Load-$p"
       { echo "name,url,username,password"
         for i in $(seq 1 300); do echo "Load $p-$i,https://load$p.example.com,load$i,pw-$p-$i-$RANDOM"; done
       } > ~/load.csv
       klav import ~/load.csv --from chrome --project "Load-$p"
   done
   rm ~/load.csv
   ```

- [ ] The app is unlocked against the test server, with four items in `General` and `Work`, and 300 in each of `Load-01` to `Load-12`.

## 2. Connecting clients (ADR 0033 §3)

1. Development › Clients: connect Claude Code, Codex and Cursor. Read the summary before each one writes. Each client's agent takes the client's name: `claude-code`, `codex` and `cursor`.
2. Approve each one's request in the app, comparing the words. Check these projects (the approval sheet checks none):
   - Claude Code: `General`.
   - Codex: `General` and `Work`.
   - Cursor: `General`.
3. Register the agent outside the app, and approve it in the app with `General`, comparing the words its command printed:

   ```sh
   KLAV_HOME=~/klav-agent-b klav agent register --name watcher \
       --server "$TEST_SERVER" --email "$TEST_EMAIL" --key-store file
   ```

4. In each client, ask for a value from `klav://Personal/General/GitHub` with a reason.

- [ ] Each client is connected with its own agent. Each summary says "this Mac compares the words for you" only if the app registers the agent and its helpers are signed by Klav's team; otherwise it says to compare them by eye in Requests. `watcher`'s words are compared by eye.
- [ ] Each one gets an answer within its grant, and the activity shows each use under its agent.
- [ ] Claude Code's, Codex's and Cursor's configuration files keep everything the app didn't write: comments, order and other servers.

## 3. Pausing (ADR 0033 §7)

1. Development › Agents › «Pause agents»: pick «15 min» and press «Pause».
2. Ask each client for a value again. Then run the agent outside the app:

   ```sh
   KLAV_HOME=~/klav-agent-b klav agent run --agent watcher --reason "pause check" \
       -e TOKEN=klav://Personal/General/GitHub/password -- true; echo "exit $?"
   ```

3. «Resume» **[Touch ID]**.
4. On Codex's row in Development › Agents: «Pause» › «15 min». Then «Pause agents» › «Until I resume» › «Pause», and «Resume» **[Touch ID]**.
5. In the menu bar: «Pause agents» › «1 hour» (the menu bar offers «1 hour» and «Until I resume»). Then resume from Development › Agents **[Touch ID]**.
6. After the checks below, on Codex's row: «Resume» **[Touch ID]**. Its own 15-minute pause outlasts a resume of everyone, and step 7 needs Codex running.

- [ ] All three clients and `watcher` get the paused error (`exit 7` for `klav`).
- [ ] Resuming asks for Touch ID, and after it every client works again.
- [ ] Pausing one agent stops only that one, and pausing every agent leaves it paused after a resume of everyone.
- [ ] The menu bar's pause stops every agent too.

## 4. Skill, malformed files and restore (ADR 0033 §3.4, §3.6)

1. Edit the installed skill by hand (add a line). Update the app (install a newer build over it).
2. Break Cursor's `mcp.json` (remove a brace) and open Development › Clients.
3. Make Codex's `config.toml` a symlink into a dotfiles folder and connect Codex again.
4. Disconnect Claude Code, then `klav client restore claude-code`.

- [ ] The edited skill is not overwritten, and the app says it differs.
- [ ] The malformed file is reported and not rewritten.
- [ ] The symlink stays a symlink, and the target file is the one edited.
- [ ] Restore puts back the file as it was before connecting.

Fix Cursor's `mcp.json` and connect Claude Code again before going on.

## 5. Activity (ADR 0033 §8)

- [ ] An item's «Who used it» lists the uses from §2 with the reason "according to the agent" and how each was allowed.
- [ ] An agent's page lists its timeline by day, and «Verify now» moves the verified mark.

## 6. Claude Code connecting by itself (amendment of 2026-11-06)

1. Disconnect Claude Code. Install the skill from «Set up this Mac» › Agents.
2. In a new Claude Code session, ask for a task that needs a secret.

- [ ] Claude runs `klav client connect claude-code` by itself and shows the words.
- [ ] The app's card asks you to compare the words by eye and approves with Touch ID **[Touch ID]**. Approve it with `General`.
- [ ] Note whether the open session sees the new MCP without restarting Claude Code (E2.2, not confirmed so far).

## 7. Changing permissions (amendment of 2026-11-10, F3, P9)

Two more agents first. The credential proxy is an agent of the account, and its upstream is never a real one. `klav proxy use` asks for Touch ID; `klav proxy grant` asks for the proxy's six words, then Touch ID:

```sh
/Users/Shared/klav-proxy --home ~/klav-proxy init --email "$TEST_EMAIL" --server "$TEST_SERVER" --key-store file
klav proxy use own klav-proxy
klav proxy grant Railway --profile test --upstream https://example.com \
    --header authorization --prefix "Bearer " --method GET --path-prefix / \
    --every-device-is-updated
```

Then an agent with a rule scoped to a tag. `klav agent approve` asks for the six words its register printed, then Touch ID:

```sh
KLAV_HOME=~/klav-agent-b klav agent register --name rules \
    --server "$TEST_SERVER" --email "$TEST_EMAIL" --key-store file
cat > ~/rules.json <<'EOF'
{"rules": [{"permission": "reveal", "effect": "allow", "scope": {"tags": ["prod"]}}]}
EOF
klav agent approve rules --project Personal/General --policy-file ~/rules.json
```

`--every-device-is-updated` says every device of the account reads per-item grants. That holds here: at this step the only device is this Mac, on the commit under test (the iPhone signs in at step 13).

The key-change checks compare `rotated` (§0) before and after.

1. Run Codex's agent once, and count the `project.rotated` lines:

   ```sh
   klav agent run --agent codex --reason "before narrowing" \
       -e TOKEN=klav://Personal/General/GitHub/password -- true; echo "exit $?"
   rotated
   ```

   Then Codex's page › «Change permissions…»: remove `Work`, and set «Inject into commands» to «deny». «Review changes». On the review, check «Also change the key of the projects you take away» (it shows only there, unchecked), then «Sign». Run both commands again.
2. «Change permissions…» › add `Work` back. «Review changes», «Sign», and cancel Touch ID. Then do it again and confirm **[Touch ID]**.
3. Run `rotated`. «Change permissions…» › remove `Work` again, and leave «Also change the key of the projects you take away» unchecked. «Review changes», «Sign». Run `rotated` again. Then add `Work` back **[Touch ID]**.
4. «Change permissions…» on Codex › «Create items» › «deny», and «Review changes». With the review open, run in a terminal:

   ```sh
   klav agent approve codex --project Personal/General --deny inject
   ```

   It lists the differences, says it only narrows, and asks `Sign it? [y/N]`: answer `y`. Then «Sign» in the app.
5. Open the pages of `klav-proxy` and `rules`.

- [ ] Narrowing asks for nothing, and the review says it only narrows. Codex's agent ran with `exit 0` before step 1 and is refused with `exit 5` after it.
- [ ] With the box checked, a toast says "Permissions changed." and the `rotated` count grew.
- [ ] With the box unchecked, the `rotated` count is the same before and after, and the page says nothing about keys.
- [ ] Widening asks for Touch ID, the prompt says what it widens, and cancelling signs nothing **[Touch ID]**.
- [ ] «Sign» after the terminal changed the grant says "The grant changed while you were looking at it. Nothing was signed: go back and check it again.", and Codex's grant is the terminal's.
- [ ] Neither page offers «Change permissions…». The proxy's says "This is the credential proxy’s grant. The terminal changes it." The other says "This grant has rules the app can’t edit (tags, vaults or projects in a rule, an expiry per rule). The app shows them and never signs a simpler copy."

After step 4, Codex holds only `General`, and «Inject into commands» is denied.

## 8. Revoking with the key change (F2)

1. On Cursor's page, «Change permissions…» › add `Work` **[Touch ID]**. Then «Revoke…», with «Also change its projects’ keys» checked, and «Revoke».
2. While it runs, ask Cursor for a value.

- [ ] The sheet shows what it saw: both projects, the items the log says it used, and the attempts Klav denied.
- [ ] The page says «Revoked» at once and "Revoked. Done: every key changed." only at the end.
- [ ] Cursor's next request gets `revoked`.
- [ ] Claude Code, which holds `General`, keeps working with its new grant and compares no words.

## 9. Revoking without the key change (P7)

1. Register one more agent:

   ```sh
   KLAV_HOME=~/klav-agent-b klav agent register --name declined \
       --server "$TEST_SERVER" --email "$TEST_EMAIL" --key-store file
   ```

2. Approve it in the app with `General` and `Work`, comparing the words. Then have it read one item, and run `rotated`:

   ```sh
   KLAV_HOME=~/klav-agent-b klav agent run --agent declined --reason "one use" \
       -e TOKEN=klav://Personal/Work/Jira/password -- true; echo "exit $?"
   rotated
   ```

3. Its page › «Revoke…»: uncheck «Also change its projects’ keys», then «Revoke». Run `rotated` again.
4. Quit the app (⌘Q), open it again, and open the agent's page.

- [ ] The agent's run printed `exit 0`.
- [ ] The page says «Revoked» and never "Changing keys" or "Done: every key changed". The `rotated` count is the same as in step 2.
- [ ] After reopening, the page still says «Revoked», with no «Finish».

Not reachable by hand: «Finish» after a restart for a revocation without the key change. It needs an agent that held projects and also an item granted one by one whose vault went away and came back. Klav grants items one by one only to an agent without projects, and no client deletes or restores a vault. `testFinishWithoutAFlowKeepsThePersonsChoice` (Mac suite) covers it.

## 10. A screen lock in the middle (P11)

How long a key change lasts was not measured. The estimate is 1–2 s for each project of 300 items, so about 15–30 s for the twelve load projects: enough to lock the screen in the middle, not much more.

1. Give Codex the load projects. It widens: answer `y`, then Touch ID **[Touch ID]**.

   ```sh
   klav agent approve codex --project Personal/General "${load[@]}" --deny inject
   ```

2. «Revoke…» Codex with «Also change its projects’ keys» checked, and lock the screen (⌃⌘Q) as soon as the page says «Revoked».
3. Unlock the screen, then Klav **[Touch ID]**.

If the page already said "Revoked. Done: every key changed." before the screen locked, this step tested nothing. Do it again with a spare agent: register it, approve it (type the six words the register printed, then Touch ID), and revoke `spare-10` as in step 2.

```sh
KLAV_HOME=~/klav-agent-b klav agent register --name spare-10 \
    --server "$TEST_SERVER" --email "$TEST_EMAIL" --key-store file
klav agent approve spare-10 --project Personal/General "${load[@]}"
```

- [ ] Right after unlocking, the page says what is left ("Revoked. Changing keys: … of 14 projects" or "Revoked. Keys left to change (… of 14)"), never «Done». Codex counts 14: the 13 projects it holds, and `Work`, which it held until step 7 (a revocation changes the key of every project the agent ever held). `spare-10` counts 13.
- [ ] `klavd` goes on by itself, and the page ends in "Revoked. Done: every key changed."

## 11. A record Klav can't read

Only with the test user's files. Keep the copy until the last command. Without putting it back, this Mac can't approve, revoke or change a grant until the file is moved aside.

1. Run `check_server`, and stop if it prints `STOP`.
2. Quit the app (⌘Q) and open it again: Codex's revocation from step 10 then has no flow in the app, which shows only what `klavd` says.
3. Make the record unreadable:

   ```sh
   cp ~/Library/Application\ Support/klav/revocations.bin ~/revocations.bin.bak
   printf x >> ~/Library/Application\ Support/klav/revocations.bin
   ```

4. Open Development › Agents, then Codex's page.
5. Run `klav agent show codex` in a terminal.
6. Put it back, then open Development › Agents again:

   ```sh
   cp ~/revocations.bin.bak ~/Library/Application\ Support/klav/revocations.bin
   ```

- [ ] The page says "Klav can’t read its record of the key changes it owes, so it can’t tell what is left. In the terminal, klav agent show <ID> says why." and never «Done».
- [ ] `klav agent show` says the record cannot be read and that Klav does not overwrite it.
- [ ] After putting it back, the page reads as before.

A record written by a newer Klav can't be made by hand: it is sealed with the account's local key. `testARecordFromANewerKlavSaysToUpdate` (Mac suite) and `a_record_from_a_newer_klav_says_to_update_and_is_left_as_it_is` (`klav-client`) cover it.

## 12. Revoking while locked (P12)

1. Development › Agents › `watcher` › «Revoke…». Leave the sheet open.
2. In a terminal: `klav lock`.
3. On the lock screen: «Pause every agent now». Then run `watcher` as in §3.
4. Unlock Klav **[Touch ID]**. Before resuming anything, run `watcher` again.
5. Cancel the sheet, and resume the agents **[Touch ID]**.

A pause made while Klav is locked holds only on this Mac: it stops what this Mac's `klavd` mediates, but not an agent that talks to the server itself, like `watcher`, until the unlock signs the pause and sends it to the server.

- [ ] Within two seconds the sheet closes, and the lock screen says "You were revoking an agent: unlock to go on. Meanwhile, pausing every agent stops them at once."
- [ ] «Pause every agent now» works while locked, and `watcher` still gets `exit 0` then.
- [ ] After unlocking, `watcher` gets `exit 7`.
- [ ] After unlocking, «Revoke…» opens again on `watcher`, and nothing was revoked.

The sheet's own locked view ("Unlock to revoke") shows only if Klav locks between opening the sheet, or pressing «Revoke», and the app's next status read, every two seconds. Nobody can hit that window on purpose. `testRevokeWhileLockedOpensAgainAfterUnlocking` and `testLockingClosesTheSheetsAndRevokeComesBack` (Mac suite) cover the model, not the sheet's view.

## 13. From the iPhone (layer 5, P10)

1. Set the iPhone's language to English (Settings › General › Language & Region). Sign in on the iPhone with the test account, and check that the server is the test server.
2. Register four more agents (`spare-13` is for redoing step 5):

   ```sh
   for name in phone-a phone-b mac-c spare-13; do
       KLAV_HOME=~/klav-agent-b klav agent register --name "$name" \
           --server "$TEST_SERVER" --email "$TEST_EMAIL" --key-store file
   done
   ```

3. Approve `phone-a` in the app with `General`, comparing the words. Approve the other three with `General` and the load projects: each asks for the words its register printed, then Touch ID.

   ```sh
   for name in phone-b mac-c spare-13; do
       klav agent approve "$name" --project Personal/General "${load[@]}"
   done
   ```

   Then have `phone-a` use one item:

   ```sh
   KLAV_HOME=~/klav-agent-b klav agent run --agent phone-a --reason "one use" \
       -e TOKEN=klav://Personal/General/GitHub/password -- true; echo "exit $?"
   ```

4. On the iPhone: «Agents» (the robot button on the home screen) › `phone-a` › «Revoke…», with «Also change its projects’ keys» on, and «Revoke».
5. Revoke `phone-b` the same way, and force-quit the app while its page says "Revoked. Changing keys: … of 13 projects". Open it again and unlock. If the page already said «Done» before the force-quit, this step tested nothing: do it again with `spare-13`.
6. Revoke `mac-c` from the Mac with the key change and, while `klavd` runs it, open `mac-c` on the iPhone.

- [ ] `phone-a`'s run printed `exit 0`.
- [ ] The iPhone sheet shows what it saw and the cost, and «Revoke» asks for no Face ID.
- [ ] The page ends in "Revoked. Done: every key changed." and the agent's next request gets `revoked`.
- [ ] After the force-quit and unlock, the page picks up where it left off and ends in «Done».
- [ ] For the Mac's key change, the iPhone says only «Revoked» (no progress, no «Finish»).

## 14. Cleaning up

1. Sign out of the iPhone app and delete it (or erase the simulator).
2. Stop the test server and delete its data.
3. Delete the test macOS user from System Settings › Users & Groups, with its home folder. That takes `~/klav-agent-b`, `~/klav-proxy`, `~/rules.json` and `~/revocations.bin.bak` with it.
4. Delete `/Users/Shared/klav-proxy`.

- [ ] Nothing of the test is left: no user, no server data, no app on the iPhone, no `klav-proxy` in `/Users/Shared`.
