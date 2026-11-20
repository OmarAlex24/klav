# 0025 · Parent site: offer a login saved for a subdomain on its parent domain's page, only when the person picks it

- Status: accepted
- Date: 2026-11-05

## Context
In the first real use (2026-11-04), Omar opened `1password.com` in Safari. The login was saved for `my.1password.com`, the way 1Password exports it.

- **iOS offered Omar the login on the keyboard (QuickType).** Klav registers each site with `ASCredentialServiceIdentifier(type: .domain)`, and iOS suggests it across the whole registrable domain.
- **When Omar opened the list, Klav said "No login is for 1password.com."** `klav-core::site` only accepts the item's exact host or a subdomain of it (ADR 0017 §5, T61 and T73), and `1password.com` is the **parent** of `my.1password.com`, not a subdomain.

The case is common. Password managers export the host of the page where the account was saved (`my.`, `accounts.`, `login.`, `signin.`, `id.`), and the person comes back through the site's home page. Today the only way out is to edit the item and add the domain by hand.

The strict rule is there against *phishing*, and Klav doesn't consult the *Public Suffix List* for site matching (ADR 0006, and ADR 0020 §6, which only allows it for the passkeys' rpId).

## Proposed decision
### 1. The page can be the parent of the saved site, and only in that direction
A page with host `P` matches an item with host `H` if `H` ends in `.P` **and** `P` has at least two labels: `1password.com` yes; `com` never, because it isn't a page.

- **What works today doesn't change:** the item's exact host and its subdomains keep matching as always.
- **Siblings still don't match:** `mail.example.com` doesn't get the `accounts.example.com` login. That would need the PSL, and it would open up `user1.github.io` versus `user2.github.io`.
- **No PSL.** The remaining risk is a parent page that belongs to a different owner than the saved subdomain. For example, `github.io` would get the `ana.github.io` login. But those parents are controlled by the suffix operator (GitHub, Google, Shopify), not by an attacker: an attacker can't serve a page on `github.io` or on `blogspot.com`. In addition, the person has to pick the login by hand (§2).

### 2. Only when the person picks it, never for agents or without interaction
- **Extension and iOS:** the parent site's logins appear in a separate group, "Saved for a subdomain", with the saved host in view (for example `my.1password.com`). They are never filled on their own: the person picks them, as with logins from other sites from the search today.
- **iOS without interaction:** `provideCredentialWithoutUserInteraction`, the QuickType suggestion that fills directly, keeps the strict rule. If the page is the parent, it asks for the interface (`ASExtensionError.userInteractionRequired`) and the list shows it in that group.
- **Agents** (`fill_login`, SDK, MCP and assisted password change): **strict rule, unchanged.** There is no person looking at the page there, and *prompt* injection can take the agent to any URL (T21).
- **When it is picked,** the extension and the app offer "Add 1password.com to this item?", one tap so that next time it matches exactly.

### 3. Order: whatever matches exactly comes first, always
When several logins work for a page, they are offered by their relation to the page's host, and that order overrides any other (recent use, name):

1. **Exact:** the saved host is the page's host.
2. **Subdomain:** the item is for a domain and the page is a subdomain of it, for example one for `1password.com` on `my.1password.com`.
3. **Parent:** the item is for a subdomain and the page is its parent (§1), in its separate group.

- **Never the other way around.** On `my.1password.com`, if the person has a login for `my.1password.com` and another for `1password.com`, the `my.1password.com` one goes first. Omar asked for this on 2026-11-05.
- What gets filled without interaction (the first in the list in the extension, QuickType or `provideCredentialWithoutUserInteraction` on iOS) is always the best one in that order, and never a **Parent** one (§2).
- The rule applies to the *popup*, the in-page menu, `klavd`'s `suggest` and `autofill`, `klav-wasm` and the iOS Credential Provider (`klav-ffi`), which today can mix exact matches and subdomains.

### 4. Where it lives
- `klav-core::site` gains `host_relation(host, item_urls) -> Exact | Subdomain | Parent | None`. `host_matches` and `page_matches` still return only `Exact | Subdomain`, which is what agents use.
- `klavd` (`suggest`), `klav-wasm` and `klav-ffi` (the Credential Provider's suggestions) expose the new group.
- `autofill` in `klavd` accepts `Parent` only if the request comes from the person (the menu or the popup), never through the agent channel.

## Rejected alternatives
- **Using the PSL to match by registrable domain**, like iOS: it would make siblings match (`user1.github.io` with `user2.github.io` without an up-to-date list) and would add the PSL to every client's rule, against ADR 0006.
- **Leaving it as it is:** the person has to know they must add the domain by hand, and the iOS keyboard would keep offering a login that the list then refuses.
- **Registering only the exact host on iOS:** iOS matches by domain with both `.domain` and `.URL`, so it doesn't avoid the inconsistency.

## Consequences
- **Threat model:**
  - T61 and T73 are updated with the "parent" direction, chosen by the person.
  - New residual risk: a parent page with a different owner (a shared suffix like `github.io`) can receive, if the person picks it, a subdomain's login.
- **`docs/extension.md` §4 and `ios.md`:** the new group and the "Add this site" button.
- **Tests in `klav-core::site`:**
  - the Exact, Subdomain and Parent order (§3);
  - `1password.com` versus `my.1password.com` gives `Parent`;
  - `com` never;
  - siblings, no;
  - the agent channel rejects `Parent`.
- **QuickType inconsistency:** it resolves itself, because what iOS suggests now appears in the list.

## Omar's answer (2026-11-05)
| # | Question | Answer |
|---|---|---|
| S1 | Offer subdomain logins on the parent page, only if the person picks them and never to agents? | Yes, with the order in §3: the exact match first, never the main domain's one before it |
