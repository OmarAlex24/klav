# Glossary (Spanish → English)

> The public glossary of product terms, for people and agents who use Klav, is [`glossary.mdx`](../apps/docs/src/content/docs/reference/glossary.mdx) (in `apps/docs/src/content/docs/reference/`). This file is the translators' list; a new product term goes in both.

Klav's docs are moving from Spanish to English ([ADR 0031](decisiones/0031-repositorio-en-ingles-y-open-source.md)). Several agents translate them in parallel, so everyone uses this list and the docs keep matching the product.

**Where the terms come from.** In this order:

1. The English UI: `apps/ios/Shared/Localizable.xcstrings` and `apps/extension/_locales/en/messages.json`.
2. The code identifiers in `crates/`.
3. The accepted ADRs.

When the UI and the code disagree, prose follows the UI and identifiers are quoted verbatim in backticks: «elemento» is "item" in prose, and the type is `ItemKind`.

**Rules for translators**

- Translate the meaning, not word by word. Short sentences, plain words, American spelling (*color*, *license*, *behavior*).
- Keep identifiers, file paths, CLI commands, error codes, permission names and binary format tags exactly as they are, in backticks.
- Section numbers (§5.2), threat IDs (T15), ADR numbers and the decision itself never change. If you find a mistake, note it in the PR; don't fix it in a translation.
- Spanish quotes «…» become "…". Spanish UI strings quoted in a doc become their English UI string, from the files above.
- If a term is missing here, add it in the same PR, with where it came from.

## Product and accounts

| Spanish | English | Source / note |
|---|---|---|
| Klav | Klav | Never translated. Formerly "Lacre" (ADR 0019) |
| gestor de contraseñas | password manager | |
| cifrado de extremo a extremo | end-to-end encrypted (adj.), end-to-end encryption (n.) | site (`apps/web`) |
| *zero-knowledge* | zero-knowledge | |
| cuenta | account | UI "Account" |
| correo (electrónico) | email | UI "Email" (iOS `SignInView.swift`); "email" in running text, not "e-mail". The emergency kit prints `E-mail:`, quoted as is |
| contraseña maestra | master password | UI "Master password"; lowercase in running text |
| Secret Key | Secret Key | Already English; always capitalized, like the UI |
| kit de emergencia | Emergency kit (heading), emergency kit (running text) | UI "Emergency kit", "Print the emergency kit". Not "Emergency Kit" |
| palabras de la cuenta | account words | UI "Account words" |
| las 6 palabras / palabras de emparejamiento | the six words / pairing words | code `pairing_words`, `pairing_code` |
| dispositivo | device | UI |
| añadir un dispositivo (con un QR) | add a device (with a QR code) | ADR 0029 |
| alta (de un dispositivo, de biometría) | enrolment (code), enroll (prose verb) | code uses British `enrolment`. Quote it verbatim when citing code; in prose prefer "add a device" or "set up Touch ID" |
| iniciar sesión / cerrar sesión | sign in / sign out | UI "Sign in", "Sign out on this iPhone" |
| borrar la cuenta / Borrar mi cuenta | delete the account / Delete my account | ADR 0037; UI "Delete my account" (iOS and Mac, Settings › Account), CLI `klav account delete`. Not "remove" or "close" the account |
| cancelar el borrado | cancel the deletion | ADR 0037; UI "Cancel the deletion", CLI `klav account delete --cancel` |
| Klav borró tu cuenta | Klav deleted your account | ADR 0037 §7.6; UI and CLI. The copy stays: UI "Delete this iPhone’s copy" / "Delete this Mac’s copy" |
| la espera (antes de borrar la cuenta) | the waiting period | ADR 0037 §2: the 7 days between asking for the deletion and the deletion |
| desbloquear / bloquear | unlock / lock | UI "Unlock with Face ID", "Lock Klav" |
| servidor por defecto | default server | ADR 0028 |
| Usar mi propio servidor | Use my own server | UI |
| alojar tú mismo / autoalojado | self-host / self-hosted | `docs/self-hosting.md` |
| proxy inverso | reverse proxy | self-hosting.md §3; Caddy or nginx with TLS in front of `klav-server`. Not the credential proxy |
| registro (de cuentas nuevas) abierto / cerrado | registration open / closed | `allow_registration`, `registration_open` in `/v1/health` |
| modo de registro | registration mode | ADR 0048 §1.1: `registration_mode` (`open`, `invite`, `closed`) in the server configuration and in `/v1/health` |
| código de invitación | invite code | ADR 0048 §1.3: `KLAV-` and 26 Crockford base32 characters (128 bits), single-use and bound to one email by default; the server stores only its digest. Error `invite_invalid` |
| código de grupo | batch code | ADR 0048 Q3: an invite code with no bound email and more than one use (at most 50, expiring within 14 days) |
| cuota (de la cuenta) | quota | ADR 0048 §3: a per-account ceiling on attachments, vault data, items or vaults (`[limits]`, `KLAV_MAX_*`). Error `quota_exceeded` |
| beta | beta | ADR 0048: the free, invite-only period of `api.klav.dev`. Not the TestFlight "public beta" (below) |
| volumen (Docker, Railway) | volume | `klav-data` in `docker-compose.yml`; mounted at `/data` |
| verificación de salud | health check | `klav-server healthcheck`, `/v1/health` |
| límite de peticiones | rate limit / limit per IP address | `[rate_limit]` in the server's configuration; `429` with `Retry-After` |
| plan alojado | hosted plan | site |
| lista de espera | waitlist | site |
| beta con invitación (de `api.klav.dev`) | invite-only beta | site; ADR 0048. Free while it lasts; not the TestFlight public beta |
| invitación a la beta | beta invite | site; requested on klav.dev (`#beta`), the waitlist is its queue, sent automatically while seats last (ADR 0050), otherwise by hand (`sitio-web.md` §3) |
| invitación automática | auto-issued invite | ADR 0050: an invite `klav-server` issues on its internal route for `klav-web` (single-use, bound, 14 days, note `auto-beta`), emailed at once; capped by `KLAV_AUTO_INVITE_MAX` and `KLAV_BETA_AUTO_CAP` |
| verificación de Turnstile | Turnstile check | ADR 0050: Cloudflare Turnstile on the beta invite form, verified with `siteverify`; optional, fails closed |
| relevo ciego | blind relay | ADR 0029 |

## Vaults and items

| Spanish | English | Source / note |
|---|---|---|
| bóveda | vault | UI "Your vault" |
| proyecto | project | UI "Choose a project" |
| referencia | reference | `klav://vault/project/item[/field]`, an item's address; Docs site, Reference › Glossary |
| proyecto de sistema | system project | code `system_project_id` |
| elemento | item | UI "New item"; code `ItemKind` |
| tipo (de elemento) | kind | code `ItemKind`; UI uses the kind's name |
| inicio de sesión / login (tipo) | login | UI "Login"; code `ItemKind::Login` |
| tarjeta | card | UI |
| identidad (tipo de elemento) | identity | UI. Not the same as the identity key pair below |
| llave SSH | SSH key | UI |
| archivo | file | UI; stored as an attachment |
| adjunto | attachment | code `Attachment` |
| código (TOTP) / códigos | code / codes; the "Codes" view | UI "Copy the code" |
| código suelto | code on its own: an item of kind `totp`, not a login's code | code `ItemKind::Totp`; `Suggestions.codes` lists those that name the page |
| nota | note | UI; "secure note" for the kind |
| API key | API key | |
| campo | field | |
| sección | section | code `Section` |
| papelera | trash | UI "Move to the trash" |
| sitio | site | UI "Site", "No site" |
| sitio padre | parent site | ADR 0025; code `ParentSuggestion` |
| Guardado para un subdominio | Saved for a subdomain | UI |
| copia local | local copy | UI "Sign out and delete the local copy" |
| sincronizar | sync | UI "Not synced yet" |
| cola de salida | outbox | code `outbox` |
| *rollback* / datos más viejos | rollback | code `Rollback` |
| marcas (anti-*rollback*) | *high-water marks* | ADR 0026, ADR 0028, ADR 0030 |
| importar / importador | import / importer | UI "Import into Klav"; crate `klav-import` |
| ¿De dónde vienes? (asistente de importación) | Where are you coming from? | UI, extension and iOS (ADR 0024) |
| fusionar (al importar) | merge | CLI `klav import`: the `merge` action; UI "Merged" |
| passkey | passkey | ADR 0020; never translated |
| entorno | environment | ADR 0032; `ItemKind::Environment` (`kind = environment`) in `klav-core` and the server since layers 1–2; `klav env`, `klav run --env` and `klav inject --env --dotenv` since layer 3 |
| código de salida | exit code | Docs site, Reference › CLI commands; `crates/klav-cli/src/error.rs` |

## Passwords and the generator

| Spanish | English | Source / note |
|---|---|---|
| generador de contraseñas | password generator | UI |
| frase de paso | passphrase | UI |
| reglas por sitio | per-site password rules | ADR 0022; file `password-rules.json` |
| historial del generador | generator history | UI; code `GeneratorHistory` |
| historial de contraseñas | password history | ADR 0022 |
| registro (de contraseñas de un elemento) | record | code `crypto::record`. Not "registration" |
| salud de la bóveda | vault health | UI "Vault health"; code `VaultHealth` |
| repetidas | reused | UI "Reused · N" |
| débiles | weak | UI |
| filtradas | breached | UI "Breached"; code `breach_check` |
| cambio (de contraseña) asistido | assisted password change | code `assisted`; permission `rotate` |
| Cambio pendiente | Pending change | UI "Pending change: did the new password work?" |
| Arreglar mis contraseñas repetidas | Fix my reused passwords | UI |
| página de cambio de contraseña | change-password page | code `change_password_url` |

## Agents, permissions and approvals

| Spanish | English | Source / note |
|---|---|---|
| agente | agent | UI |
| agente personal | personal agent | Site. An agent that works for one person (the one you built, or Muse, Grok Bot or Dots); «en la nube» / "in the cloud" when it runs on its provider's computer |
| registrar un agente / unirse | register an agent / join | UI "wants to join your account" |
| permiso | permission | UI; code `Permission` |
| `list`, `fill`, `inject`, `totp`, `reveal`, `create`, `update`, `delete`, `passkey`, `rotate` | same, in backticks | code `Permission`. Never translate |
| rellenar | fill | UI "Fill" |
| autollenado (iOS) | AutoFill | UI "AutoFill & Passwords" (Apple's name) |
| autollenado (general) | autofill | |
| inyectar | inject | UI |
| revelar | reveal | permission `reveal` |
| acciones, no valores | actions, not values | design principle |
| política | policy | code `Policy` |
| alcance | scope | |
| caducidad / caduca | expiry / expires | UI "Expiry date", "Expires" |
| horario | schedule | ADR 0014 |
| *grant* | grant | code `Grant` |
| petición (de un agente) | request | |
| petición firmada | signed request | |
| aprobación | approval | code `approval_id` |
| aprobar / aprobar una vez / denegar | approve / approve once / deny | UI |
| mismo destino | same target | ADR 0015; code `target_key` |
| arrendamiento | lease | code `lease_until` |
| tarea | task | UI "End task" |
| solicitud de tarea | task request | ADR 0021; code `task_request` |
| un agente pide permiso | an agent is asking for permission | UI |
| aviso (notificación *push*) | notification | UI "Agent notifications" |
| aviso (en una página) | notice | UI "Klav notice" |
| aviso (en una respuesta de `klavd` o la CLI) | warning | ADR 0012 §6, ADR 0026; CLI "offline (…); using the local copy" |
| revocar / revocación | revoke / revocation | code `revoke`, `revoked_at` |
| rotación (de llaves) | rotation | code `rotation_id` |
| bitácora | audit log | CLI "The audit log is intact" |
| registro de actividad | activity log | Docs site (Agents › "The activity log"): the audit log as people see it, after the UI "Activity"; the CLI and the spec say "audit log", and a page says both once |
| redacción (de la salida de `klav agent run`) | redaction | code `REDACTED`, `[redacted by klav]` (`klav-sdk`); each value, its usual encodings (base64, hex, URL, JSON escaping) and its pieces of 12 characters or more replaced in the output a command returns to an agent. A safety net for mistakes, not a barrier: a value the command transforms its own way gets through (residual risk 31) |
| cabeza firmada (de la bitácora) | signed head | spec §13.7 |
| qué vio (el agente) | what it saw / "what it used" report | CLI "What {name} used (from the audit log)" |
| pausar agentes / reanudar | pause agents / resume | ADR 0033 §7; UI "Pause agents"; CLI `klav agent pause\|resume` |
| Actividad / Quién lo usó | Activity / Who used it | ADR 0033 §8; UI (Mac and iOS) |
| cliente de agentes | agent client | ADR 0033; `klav client`. Claude Code, Claude Desktop, Codex, Cursor, VS Code |
| ampliar / reducir (un grant) | widen / narrow | ADR 0033, amendment of 2026-11-10 (F3). Widening asks for presence; narrowing does not (P8) |
| presencia | presence | ADR 0014 §5.4. Touch ID, Face ID or the master password; code `confirm`, `password` |
| Cambiar permisos… | Change permissions… | UI (Mac app, Development › Agents; `AgentPage.swift`), ADR 0033 amendment of 2026-11-10 (F5) |
| Revocado. Faltan llaves por cambiar | Revoked. Keys left to change | UI (planned), ADR 0033 amendment of 2026-11-10 (F2); `agent_revocations` |
| cambio de llaves | key change | ADR 0033 amendment of 2026-11-10 (F2): the projects' keys a revocation or a narrowing changes, one per step; `rotation_step`, `revocations.bin` (spec §12.2) |
| Terminar (una rotación) | Finish | UI (Mac app, the agent's page; `AgentPage.swift`), ADR 0033 amendment of 2026-11-10 (F2) |
| sitios que añadió un agente | sites an agent added | ADR 0030 §7, `docs/features.md`; UI "Sites added by an agent"; `klav item sites` |
| skill (de Klav) | (Klav's) skill | The rules an agent follows to use Klav; `klav skill install`, `klav client connect` |
| hoja (del cambio de un grant) | sheet | ADR 0033, amendment of 2026-11-10 (F3); `GrantChangePreview`, `grant_change_prepare` in `docs/klavd.md` §3: the differences shown before signing |
| ventana de presencia | presence window | ADR 0041 §2: how long one presence lets `klavd` hand out values to one key (a terminal session, the browser, a parent process, or a connection); Always, 5 minutes or While unlocked, sealed in `klavd`'s local data (`presence.bin`). On since layer 6; add it to the public glossary when Omar lists ADR 0041 there |
| identidad del par | peer identity | ADR 0041 §1.1; `klav_daemon::peer::Identity`: what `klavd` knows about the other end of its socket (known, unknown, or no `SO_PEERPIDFD`), and the window key it gives (`WindowKey`). A key with a named residual, never proof of which code asks. Internal; not a product term |
| comprobación del descriptor | fd-ownership check | ADR 0041 §1.1: on macOS, that the process the audit token names holds, right now, a descriptor for the other end of the connection (`klav_touchid::holds_peer_end`) |
| identificador único (de un proceso) | unique ID | ADR 0041 §1.1: macOS's `p_uniqueid`, not reused within a boot and kept across `exec`; read first and again last (`klav_touchid::unique_id`) |
| puerta de presencia | presence gate | ADR 0041 §2–§3: `klavd`'s check, before an operation that hands out a value, that the caller's key has an open presence window (`presence::require`); built off in layers 2–5 behind a hidden `--presence-gate` flag, on for everyone since layer 6 |
| clave de la ventana | window key | ADR 0041 §2.1; `WindowKey`, `presence::Key`: what a presence window is kept for (a terminal session, a parent process, the connection, or none). Internal |
| terminal de control | controlling terminal | ADR 0041 §2.4: the terminal a process belongs to (`/dev/tty`). `klavd` reads the peer's, and `klav` its own, with the same reader and the same name (`klav_daemon::peer::own_terminal`, `terminal_name`); `klav` asks for the master password for presence only there, never on stdin. Unix term, not a product term |
| pregunta de presencia (lo que pide `klavd`) | presence ask | ADR 0041 §2.4: the `presence` object of `presence_required` (key, setting, terminal, what the password grants: `lasts` or one `value`). `klavd` checks a password only as the answer to the ask it last sent that connection, unchanged (`Pending`, own choice 32). Internal |
| conexión del navegador | browser connection | ADR 0041 §3.1: one extension attached to `klavd` (`extension_attach`). With the presence gate, an agent's values ask once per browser connection until Klav locks (each value on Always), and with more than one attached, exactly one must be in front (`browser_ambiguous` otherwise, P25). Not in the public glossary until the gate ships |
| aviso (de Touch ID) | notice | ADR 0041 §2.4, Omar's decision 2 of 2026-11-19: the line `klavd` writes before a Touch ID dialog to a request that set `notify`, so the CLI prints its terminal's name first (`Notice::TouchId`). Internal |
| conexión declarada | declared connection | ADR 0041 §1.2: a connection that sent `hold`; the next verification on it holds it. A declaration survives a lock, a held connection doesn't |
| conexión retenida | held connection | ADR 0041 §1.2: a connection to `klavd` that sent `hold`; its `unlock`, or the gate's window verification on it, lasts until Klav locks (not with Always, which drops the declaration). The Mac app keeps one. Replaced the "holder secret" of the ADR's second version. `hold` answers `not_supported` until layer 6, and always on Linux |
| tarjeta de `inject` | `inject` card | ADR 0041 §5: an approval card that shows the command or file "according to the agent"; `claims.command`. Not built |
| excepción (de `inject`) | exception | ADR 0041 §6: an agent the person keeps without asking for `inject`, signed with presence in the migration (an explicit `inject: allow` project rule) |
| modo directo (de `klav`) | direct mode | `docs/klavd.md` §1: `klav` unlocks in its own process when `klavd` isn't running |

## Sandboxes and the credential proxy

Terms from ADR [0036](decisiones/0036-sandboxes-de-agentes.md) and its amendment of 2026-11-09. The UI strings are planned; the English column is what the apps will say.

| Spanish | English | Source / note |
|---|---|---|
| sandbox | sandbox | ADR 0036. A disposable VM or container where an agent works (Boat) |
| proxy de credenciales | credential proxy | ADR 0036 §1; `klav-proxy`. UI "Credential proxy" (planned) |
| proxy propio / proxy atestado | your own proxy / attested proxy | ADR 0036 §1, §12; `proxy.mode = own`. The attested proxy is Klav Cloud's hosted proxy of ADR 0051 (accepted, not built; `proxy.mode = "klav"`): `klav-proxy` in an AWS Nitro Enclave that a device verifies before it wraps anything for it. UI "Klav Cloud proxy" (planned). Not in the public glossary until built |
| proxy alojado (de Klav Cloud) | (Klav Cloud's) hosted proxy | ADR 0051. Same thing as the attested proxy; "hosted" says who runs it, "attested" why it can be trusted. Not in the public glossary until built |
| manifiesto del enclave | enclave manifest | ADR 0051 §2.4, spec §15.5: the Klav Enclave Transparency Manifest, a signed list of the enclave images the release authority accepts (`current`, `draining`, `revoked`), with a `seq` watermark and a 30-day expiry; `klav/v1/sig/enclave-manifest`. Not in the public glossary until built |
| autoridad de publicación | release authority | ADR 0051 §2.1, §11.5: whoever holds the key that signs the enclave manifest (today, Omar), with an offline backup key; both public halves pinned in `klav-core`. Not in the public glossary until built |
| PCR | PCR | AWS Nitro Enclaves: a Platform Configuration Register, a 48-byte SHA-384 measurement in the attestation document. PCR0 is the image, PCR1 the kernel, PCR2 the application, PCR3 the parent instance's IAM role. All zeros means a debug-mode enclave. Never translated |
| vínculo de la atestación | attestation binding | ADR 0051 §2.2, spec §15.6: the `user_data` of an attestation, a SHA-256 over the account, the agent and its keys (`klav/v1/proxy/enclave-binding`), which proves an approved image holds those keys |
| llave de servicio (del proxy alojado) | (hosted proxy's) service key | ADR 0051 §8, spec §15.8: an identity derived from the enclave's seed (`klav/v1/proxy/hosted-service`), one for every account, whose Ed25519 key marks the agent registrations the hosted proxy sends to the server (`klav/v1/sig/hosted-proxy-registration`); the server holds that public key in `KLAV_HOSTED_PROXY_SERVICE_KEY` and marks those agents `hosted`. Not in the public glossary until built |
| traspaso (de la semilla) | hand-off | ADR 0051 §4.2: one enclave seals the master seed with HPKE to another after each verifies the other's attestation and the manifest is public in the repository (`klav/v1/proxy/enclave-handoff`) |
| reenviador | forwarder | `klav-forward`, inside the sandbox: claims it over the pinned channel and relays `127.0.0.1` to the proxy (ADR 0036 §5, api.md §8.11) |
| emisor | issuer | ADR 0036 §4. The program or agent that starts sandboxes; `klav proxy issuer add`. Listed in the proxy's grant (`issuers`); its own grant names the proxy (`sandbox`) |
| grant de emisores / `v: 3` | issuer grant / version 3 grant | Spec §13.4; `GrantPayload` `v: 3`, only with `issuers` or `sandbox` |
| paquete del sandbox | sandbox package | `ksb1_…`, ADR 0036 §4. Not the ADR 0029 «paquete» |
| huella fijada del proxy | proxy pin | Spec §13.10. SHA-256 of the SPKI of the proxy identity's Ed25519 key; what the forwarder pins |
| secreto de un solo uso / resumen del secreto | one-time secret / secret digest | Spec §13.10. The proxy keeps only the digest |
| reclamar / reclamo (un sandbox) | claim | ADR 0036 §5; action `sandbox.claimed` (amendment) |
| marca de reclamo | claim marker | api.md §8.11. `klav-forward`'s non-secret file `<state>/claimed/<sandbox_id>` (`setup::Marker`), written before the first byte of a claim so a later `up` with the same package refuses locally (`klav_forward_already_claimed`) |
| socket de control | control socket | api.md §8.11. The running forwarder's unix socket `<state>/down.sock` (0600, same uid only), through which `klav-forward down` asks it to release its sandbox and stop; never a signal to the pid in `state.json` |
| socket local (del proxy) | (the proxy's) local socket | ADR 0036 E3.5, api.md §8.14. `<KLAV_HOME>/agents/<name>.sock` (0600, same uid only), where the person lists the proxy's live sandboxes and revokes them with no signature, also with `klavd` locked; `klav proxy local`, `klav_client::local_proxy` |
| en este Mac | on this Mac | ADR 0036 E2.3, E4 (layer 11). UI "On this Mac", "Revoked on this Mac": the account's proxy runs on this Mac and answers on its local socket |
| llave del canal | channel key | ADR 0036 §5. `sandbox.claimed` names it by `channel_key_sha256`, the SHA-256 of its SPKI (spec §13.10) |
| canal fijado | pinned channel | ADR 0036 §6, spec §13.10. TLS 1.3 between the forwarder and the proxy, with raw Ed25519 keys on both ends; the forwarder accepts only the proxy pin; `klav_forward::channel` |
| llave pública en bruto | raw public key | RFC 7250. A TLS peer's bare `SubjectPublicKeyInfo` instead of a certificate; both ends of the pinned channel use one |
| señal de robo | theft signal | ADR 0036 §5; push `sandbox_theft` (amendment) |
| perfil (del proxy) | profile | ADR 0036 §2; `--profile` |
| preferencias de la cuenta | account preferences | ADR 0032 §7; system item `kind = preferences`, spec §7.3 |
| ajuste del proxy | proxy setting | ADR 0036 §3; `preferences.proxy`, `klav proxy use` |
| modo (a) / URL base | mode (a) / base URL | ADR 0036 §7. A tool calls `http://127.0.0.1:8790/<profile>/<path>`; mode (b) is `HTTPS_PROXY` |
| puerta MCP / modo (c) | MCP gate / mode (c) | ADR 0036 §7, note of 2026-11-19. An MCP client in a sandbox reaches a remote MCP server through the proxy, which adds the bearer key: a profile on mode (a)'s routing (`http://127.0.0.1:<port>/maple/mcp`) with its own limits for `text/event-stream` answers. Built (steps M2–M4); the by-hand test in a real sandbox (M5) is pending |
| secreto principal | main secret | Spec §13.4. What a profile without `field` injects: `password` (login), `api_key` (API key) |
| pasarela MCP | MCP gateway | ADR [0049](decisiones/0049-mcp-gateway.md) (accepted; layers 1–3 built, the proxy part is layer 4): `klav-proxy` with MCP profiles, per-tool rules signed in the grant (`v: 4`), a filtered `tools/list`, tool-level approvals and audit. Not the MCP gate of ADR 0036 (mode (c)), which it builds on. Not in the public glossary until it ships (ADR 0039 §3) |
| perfil MCP | MCP profile | ADR 0049 §2.1; `ProxyProfile.mcp`: a profile that also knows its upstream's MCP endpoint, which the proxy reads, checks and filters |
| *endpoint* MCP | MCP endpoint | ADR 0049 §2.1; `mcp.endpoint`, the one path an MCP profile forwards |
| regla de herramientas / patrón de herramienta | tool rule / tool pattern | ADR 0049 §5.3; `Scope.mcp_tools`, `ToolPattern`: an exact tool name, a prefix with one trailing `*`, or `*` alone; case-sensitive |
| herramienta sin regla | unlisted tool | ADR 0049 §5.3, Q3: a tool no rule names; denied and hidden from `tools/list` |
| cliente local / token de cliente local | local client / local client token | ADR 0049 §3.2, spec §13.16: an MCP client on the person's Mac (`claude-code`, `cursor`) and its `klc1_` bearer to the proxy's loopback listener; the proxy's grant carries only its digest (`local_clients`) |
| resumen de los argumentos | argument digest | ADR 0049 §5.4, spec §13.16; `claims.mcp_args`. "Once" binds it; a lease binds only the tool |
| argumentos sellados | sealed arguments | ADR 0049 §5.4 (layer 8, not built): a tool call's arguments sealed with HPKE to the person's devices (blob `0x27`) |
| interruptor de la pasarela MCP | MCP gateway switch | ADR 0049 §9; the account's `mcp_gateway`, off by default, turned on once with `POST /v1/account/mcp-gateway`; `400 mcp_gateway_off` while off |
| llamador (de una aprobación) | caller | ADR 0049 §5.4; `ApprovalRequest.caller`: the sandbox or the local client a proxied call is for, according to the proxy, under the person's signature |
| redacción (del proxy) | redaction | ADR 0036 §8. The whole injected value replaced in the provider's answer, never a piece of it (E9, T149) |
| emisión por fin de línea | line-end flush | ADR 0036 §7, note of 2026-11-19; `StreamRedactor::by_lines` in `klav-sdk`. The stream redactor emits each chunk up to its last CR or LF instead of holding back its tail; falls back to the default rule when a value holds a line end |
| grant por elemento | per-item grant | ADR 0036 §2; `GrantPayload` `v: 2` with `items`, spec §13.4 |
| llave de elemento compartida | shared item key | Blob `0x23`, spec §8.2 |
| permiso `proxy` | `proxy` permission | ADR 0036 §2. Use a value inside an HTTP request the proxy builds, never return it |
| prefijo de ruta | path prefix | `Scope.path_prefixes`; matches on segment boundaries |
| llave nueva del elemento / cambiar la llave del elemento | new item key / rekey an item | ADR 0036 §18; `attachment_keys` in `PUT /v1/vaults/{v}/items/{i}` |
| ruta canónica | canonical path | Spec §13.4; `klav_core::policy::is_canonical_path`. One spelling per byte, compared byte for byte |
| *preset* | preset | ADR 0036 §7 |
| líneas de configuración (del sandbox) | setup lines | What `klav sandbox start` prints for the sandbox's setup script, with no secrets (`SETUP` in `crates/klav-cli/src/commands/sandbox.rs`, plus the `northflank login` line for that profile); hand test in [try-sandboxes.md](try-sandboxes.md) |
| latido (del proxy) | heartbeat | Amendment E3.3; `sandbox_state` in `GET /v1/sync` |
| almacén (del proxy) | sandbox store | ADR 0036 §4; `<home>/agents/<name>.sandbox-store`, 0600 (not a `.json`, which the CLI would list as an agent): each live sandbox with its secret's digest, and the ends the server has not taken yet (`api.md` §8.9) |
| época del almacén | store epoch | Amendment E3.3; `store_epoch`, announced by `sandbox.store_reset` |
| marca de agua (del latido) | heartbeat watermark | The highest `seq` of the proxy's heartbeat this device accepted under one store epoch, kept in `sandbox-marks.bin` (sealed, one per proxy); a lower one is a rollback, never shown |
| sin señales (el proxy) | no signs (the proxy) | Amendment E2.1, E3.3. No heartbeat counts, or the last one is older than 10 min while the proxy has sandboxes waiting or active (or of a status this build does not know), or 40 min otherwise; `quiet` and `no_signs` in the sandbox list |
| API del emisor | issuer API | `/_klav/sandboxes` on the proxy's loopback listener, signed by the issuer (`api.md` §8.9) |
| llamada local | local call | A profile call on the proxy's loopback listener (mode (a)), from any program on the proxy's host, with no identity. `klav-proxy serve --no-local-calls` refuses every one (ADR 0042 §3) |
| volcado de memoria | core dump | What the kernel writes of a crashed process's memory. `klav-proxy` turns them off (`RLIMIT_CORE` to 0, ADR 0044 §3.1) |
| no volcable | not dumpable | Linux's `PR_SET_DUMPABLE` 0: no core dump, even to a piped `core_pattern`, and no `ptrace` or `/proc/<pid>/mem` by the same user. `dumpable` in `klav-proxy status` (ADR 0044 §3.1) |
| memoria bloqueada | locked memory | Pages kept out of swap with `mlockall`; `locked` in `klav-proxy status`, only with an unlimited `memlock` limit and once `VmLck` reads back more than 0 (ADR 0044 §3.2) |
| bloqueo al tocar | lock on fault | `MCL_ONFAULT` with `mlockall`: each page is locked once the process touches it, and none is made resident only to be locked. How `klav-proxy` locks (ADR 0044 §3.2, decision 11) |
| interruptor del bloqueo | memory lock switch | `--no-memory-lock` or `KLAV_PROXY_MEMORY_LOCK=off`: `klav-proxy` starts without locking its memory; core dumps stay off (ADR 0044 decision 12) |
| barrido (del proxy) | sweep | Ends sandboxes on `ttl`, `inactivity` and `issuer_removed`, and sends the ends the server has not taken (`klav-proxy`, `sandboxes::sweep`) |
| Sandboxes activos | Active sandboxes | UI, amendment E2: the list's header in Desarrollo › Sandboxes on the Mac (⌘7, `macos.md` §9); «Sandboxes activos (todos los proxies)» / "Active sandboxes (all proxies)" with the security flag |
| Revocar / Revocar todos | Revoke / Revoke all | UI, amendment E2 (Mac; iOS planned). No Touch ID |
| revocación por la persona (de sandboxes) | the person's revocation (of sandboxes) | Amendment E3.3; `POST /v1/sandboxes/revoke`, signed by the account (`klav/v1/sig/sandbox-revoke`, spec §13.11), logged as `sandbox.revoke_requested`. One sandbox of a proxy or `all`; the server bars them from then on, and the proxy reads them by the revocation cursor and ends them with `person` |
| cursor de revocaciones | revocation cursor | `GET /v1/agent/sandboxes/revocations?since=`: a revocation's `seq`, the position of its `sandbox.revoke_requested` in the account's log (`api.md` §8.8) |
| Esperando el reclamo / Revocando… | Waiting to be claimed / Revoking… | UI (planned), amendment E2. The CLI's state words, as in E6.2 (`klav sandbox list`, `klav proxy sandboxes`): `waiting for claim` and `revoking`; a state a newer `klavd` sends that this build does not know is `unknown state`, never ended |
| proxy revocado (un sandbox) | proxy revoked (a sandbox) | A sandbox's state once the account revoked its proxy and that proxy had logged no end, which it never can: `SandboxStatus::ProxyRevoked`, `"status": "proxy_revoked"` with `proxy_revoked_at`, from the account's signed `agent.revoked` in the verified chain alone. Not live and never ended (ADR 0036 risk 62). Only a sandbox issued before that revocation in the chain. CLI words: `proxy revoked: its end can no longer be logged`; until the apps get their own words, `klav-ffi` gives them the status the row had before (revoking, expired, active or waiting), as an older `klavd` does |
| En pausa / se confirma al reanudar | Paused / confirmed when resumed | UI (planned), amendment E2.1 and E3.3 |
| según el emisor | according to the issuer | Like «según el agente», UI "(according to the agent)" |
| vivo (un sandbox) | live (a sandbox) | UI: waiting, active, revoking or a state this build does not know; «6 vivos» / "6 live" next to the pane's title |
| Terminados en las últimas 24 h | Ended in the last 24 h | UI, amendment E2.1: the folded section of Desarrollo › Sandboxes, each with why it ended |
| Pausar al emisor | Pause the issuer | UI, on a theft signal: pauses that one agent (`pause_agents` with its ID) |
| Entendido (una señal de robo) | Got it (a theft signal) | UI: the person saw it; it moves to «Terminados en las últimas 24 h», kept on that Mac |
| Ningún proxy de confianza / Sin proxy | No proxy trusted / No proxy | UI: the proxy header without a proxy set (`preferences.proxy` empty) or with the security flag (an agent wrote the preferences) |
| El servidor no registró tu revocación | The server didn’t register your revocation | UI, amendment E3.3: a read after the server's answer doesn't show the person's revocation in the verified log; in red, with «Revocar otra vez» / "Revoke again" |
| plantilla del sandbox | sandbox template | ADR [0042](decisiones/0042-sandboxes-for-daily-use.md) §7, Omar's decision of 2026-11-17: a Boat saved snapshot with `klav-forward`, Tailscale, `klav-tailnet-up` and the tools, and no state, login or secret; saved from a normal machine of an empty build environment, never `--no-env`, and rebuilt for each release. Its scripts are in `deploy/sandbox-template/` (`build-template`, `check-template`, the manifest); building it is the person's step |
| entorno de construcción | build environment | ADR 0042 §7: the Boat environment, with everything off, where the template's build machine runs |
| `klav-tailnet-up` | `klav-tailnet-up` | ADR 0042 §4: the template's root-owned script that joins a sandbox to the tailnet with the key on standard input, and checks its tag (`deploy/sandbox-template/`) |
| costura de prueba | test seam | Lines of a shipped script, marked `klav-test-seam`, that its tests replace with fake paths and nothing else; the tests check that the rest is the shipped file (`deploy/sandbox-template/klav-tailnet-up` and `build-template`, `deploy/sandbox/new-sandbox`) |
| registro de la construcción | build record | ADR 0042 §7: `/etc/klav-sandbox-template/manifest` in the template, written by `build-template`: the manifest's values, its allow list, and the SHA-256 of `klav-forward` and `klav-tailnet-up`, which `check-template` checks the installed files against |
| lista de permitidos | allow list | ADR 0042 §7: the `ALLOW=<SHA-256>  <path>` lines of the sandbox template's manifest. `check-template` excuses a base-image file from the string scan and from Boat's folder only while it has that path and that SHA-256, and never excuses a login, a key or state (`deploy/sandbox-template/README.md`) |
| entorno diario | daily environment | ADR 0042 §7, Omar's decision of 2026-11-17, first used on 2026-11-18: the minimal Boat environment of daily sandboxes, with only the agent's model login, GitHub, and the setup script that runs `klav-tailnet-up` and the setup lines. Boat's GitHub token reaches every repository its app's installation covers, which Omar accepted on 2026-11-18 ([try-sandboxes.md](try-sandboxes.md#14-a-daily-sandbox) §14) |
| llave de Tailscale del sandbox | sandbox's Tailscale key | ADR 0042 §4, Omar's decision of 2026-11-17: a single-use, ephemeral, pre-approved Tailscale auth key tagged `tag:klav-sandbox`, valid one hour, made for one sandbox by the helper on the proxy's host (later, by the proxy); `KLAV_TAILNET_KEY`, never in the `ksb1_` package. A daily sandbox ran on 2026-11-18 (layer 6); the public glossary still names no sandbox term while sandboxes are "On the way" (ADR 0039 §3) |
| ayudante (del emisor) | helper | ADR 0042 §5: `deploy/sandbox/new-sandbox`, the command of `klav sandbox start` on the proxy's host that makes the Tailscale key and creates the Boat machine; prints only Boat's sandbox ID |
| aviso de seguridad (de un latido que retrocede) | security warning (a heartbeat rollback) | UI, decision of 2026-11-16 «Un latido que retrocede»: shown in red, never as a quiet proxy |
| alarma de red nueva | new-network alarm | ADR [0044](decisiones/0044-proxy-key-at-rest.md) §1 (accepted, not built): the server tells the person when a proxy's key is used from a network it hadn't used; push `agent_network`, alert `new_address`. Not in the public glossary until built |
| red (de un agente) | network (of an agent) | ADR 0044 §1.1 (accepted, not built): the client address the server saw, an IPv4 address or an IPv6 `/64`; `baseline`, `new`, `known` or `refused`. Not in the public glossary until built |
| salida firmada / pin de salida | egress pin | ADR 0044 §2 (accepted, not built): the networks a proxy may connect from, signed by the account (`klav/v1/sig/agent-egress`) and enforced by the server (`403 agent_egress_refused`); it is the strict network profile. Not the proxy pin of spec §13.10 |
| perfil de red: de aviso / estricto | network profile: alert / strict | ADR 0044 §2.5 (accepted, not built): per proxy. Alert, the default: a new network raises the alarm and the call goes on. Strict: the egress pin; a new network is refused until a device signs it in with presence, and a pinned network unseen for 90 days lapses (§2.6). Not the provider profile of ADR 0036 §2 (`--profile`): always say "network profile" or name it. Not in the public glossary until built |
| red caducada (del perfil estricto) | lapsed network | ADR 0044 §2.6 (accepted, not built): a pinned network the server hasn't seen for 90 days. It stays in the signed list, but the server refuses it until the person lets it in again with presence, and a device signs a narrower list without it. Not in the public glossary until built |
| fuente de la dirección del cliente | client address source | ADR 0044 §1.1, self-hosting.md §3.2: where the server takes the client's address from (the TCP peer, `X-Forwarded-For` or a trusted header); `agent_addresses` is off unless the operator checked it. Not in the public glossary until built |

## Cryptography

| Spanish | English | Source / note |
|---|---|---|
| llave | key | Docs say «llave» for cryptographic keys; always "key" |
| llave de bóveda / de proyecto / de elemento | vault key / project key / item key | code `VaultKey`, `ProjectKey`, `ItemKey` |
| llave local | local key | code `LocalKey` |
| par de llaves de identidad | identity key pair | code `crypto::identity` |
| KEK | KEK (key-encryption key) | |
| derivación | derivation | |
| envoltura / envolver | wrapping / wrap | code `crypto::wrap` |
| sellar / sellado | seal / sealed | code `Sealed` |
| compartir (llaves) | share | code `crypto::share` |
| almacén de llaves / llavero (de la plataforma) | keystore; Keychain when it is Apple's | code `KeyStore` |
| firma | signature | code `crypto::sign` |
| separación de dominio | domain separation | |
| etiqueta (criptográfica) | label | code `LABEL_VAULT_KEY` |
| metadatos | metadata | code `crypto::meta` |
| formato binario con versión | versioned binary format | |
| vectores de prueba | test vectors | `docs/vectores/` (to become `docs/vectors/`) |
| especificación criptográfica | crypto spec | `docs/especificacion-cripto.md` (to become `docs/crypto-spec.md`) |
| modelo de amenazas | threat model | |
| frontera de confianza | trust boundary | |
| riesgo residual | residual risk | |
| servidor malicioso (que trabaja en tu contra) | dishonest server | Threat model §2 («honesto pero curioso», diseñado para resistir uno malicioso). Docs site, Security: "a server working against you" |
| OPAQUE | OPAQUE | Spec §4.5: the sign-in protocol; the server never receives the password. Not translated |
| *prompt injection* | prompt injection | Threat model T20: instructions in a page, email or file that make the model misbehave |
| fuera de alcance | out of scope | Threat model §6, `SECURITY.md` "Scope" |
| divulgación coordinada | coordinated disclosure | `SECURITY.md` "What to expect" |
| código del iPhone | (the iPhone's) passcode | Apple's term. Docs site, Security: approving on the iPhone falls back to it when Face ID can't be used |
| Public Suffix List | Public Suffix List | Never translated; Klav doesn't use it for site matching (`klav-core/src/site.rs`, ADR 0025 §1) |

## Deployed services

Terms from ADR [0038](decisiones/0038-deployed-services.md) (accepted). The sandbox and credential proxy terms it builds on (credential proxy, forwarder, sandbox package, theft signal) come from ADR 0036's amendment, in its own section. The UI strings are planned; the English column is what the apps will say.

| Spanish | English | Source / note |
|---|---|---|
| servicio desplegado | deployed service | ADR 0038. An app on a PaaS that reaches AI APIs through the person's credential proxy |
| federación de identidad de cargas | workload identity federation | ADR [0045](decisiones/0045-keyless-services.md) §1 (accepted, not built): the provider trusts a signer the person registered and trades its signed assertion for a short-lived token. Not in the public glossary until built |
| llave de firma (de un servicio) | (service) signer | ADR 0045 §1.3 (accepted, not built): the ES256 key, one per service, whose public half the person registers as an issuer at the provider. Kept as an API key item granted to the proxy (`federation.signer_item`), never on the proxy's disk. Not the account's or an agent's signing key |
| aserción | assertion | ADR 0045 §1.4 (accepted, not built): the JWT the proxy signs for one instance identity and trades at the provider |
| token acuñado | minted token | ADR 0045 §1.7 (accepted, not built): the provider's short-lived bearer token (`sk-ant-oat01-…` at Anthropic), only in the proxy's memory |
| camino de federación / camino del portador | federation path / bearer path | ADR 0045 §1, §2 (accepted, not built): a signed identity where the provider accepts one; the provider key with its limits where it doesn't |
| aprobación por despliegue | approval per deploy | ADR 0045 §4 (accepted, not built): `approve_enrollments`, per service, off by default; every enrollment waits for the person, as during incident mode |
| declaración de la llave del proxy | proxy-key statement | ADR 0045 §3.1 (accepted, not built): `klav/v1/sig/service-proxy-key`, signed by the account with presence: which key is the credential proxy's current one. Instances of a deployed service accept the proxy only with it. Not the egress pin of ADR 0044 |
| suelo (del token de enrolamiento) | floor (of the enrollment token) | ADR 0045 §3.1 (accepted, not built): `floor_at_ms` in `kse1_`; an instance refuses a proxy-key statement older than it |
| periodo de gracia (del token de enrolamiento) | grace period (of the enrollment token) | ADR 0045 §3.2 (accepted, not built): the 24 hours after a rotation in which the previous token still enrolls; none after an incident or when the person says the old token leaked (Q11) |
| detección de copias (de un sandbox) | copy detection (of a sandbox) | ADR 0045 §10.1 (accepted, not built): ADR 0038's clone detection reused for sandboxes, built with the services. Not the theft signal of a second claim (ADR 0036 §5) |
| enrolamiento / enrolar (una instancia) | enrollment / enroll | ADR 0038 §3. American spelling. Not the «alta» of a device or of biometry (code `enrolment`) |
| token de enrolamiento | enrollment token | `kse1_…` in `KLAV_SERVICE`, ADR 0038 §2.2 |
| desafío de dominio / prueba de dominio | domain challenge / domain proof | ADR 0038 §3; like ACME HTTP-01 |
| sonda / campaña (de sondas) | probe / campaign | ADR 0038 §3.2–3.3 |
| identidad de instancia | instance identity | ADR 0038 §1. Not a Klav key |
| (identidad) pendiente / enrolada | pending / enrolled | ADR 0038 §3.2 |
| *ratchet* (de llaves) | key ratchet | ADR 0038 §5; label `klav/v1/sig/service-ratchet` |
| época | epoch | ADR 0038 §5 |
| bifurcación | fork | ADR 0038 §5.2: two successors of the same key |
| clon / detección de clones | clone / clone detection | ADR 0038 §5.2 |
| barrido de vida | liveness sweep | ADR 0038 §5.2 |
| congelar (una identidad) | freeze | ADR 0038 §5.5; `service.frozen`. UI "Freeze this instance" (planned) |
| registro de uso | usage record | ADR 0038 §7.3; `service.usage`, sealed for the account. Calls and tokens, no dollars |
| límite de réplicas / margen de despliegue | replica limit / surge | `max_replicas`, `surge`, `surge_window`, ADR 0038 §4 |
| arrendamiento (de un servicio) | (service) lease | ADR 0038 §7. The same word as the approval lease (`lease_until`) |
| modo incidente | incident mode | ADR 0038 §8. UI "Start incident mode" (planned) |
| informe del incidente | incident report | ADR 0038 §8.2 |
| Detener servicio / Reanudar | Stop service / Resume | UI (planned), ADR 0038 §8.4 |
| según la instancia | according to the instance | Like «según el agente», UI "(according to the agent)" |
| señal de red de salida | egress signal | ADR 0038 §8.3; `egress_change` |
| tope de gasto | spend cap | ADR 0038 Q-A: left for a later version, no ADR yet |
| fuente única | single source of truth | roadmap; with `klav rotate`, no ADR yet |
| *canary* | canary | roadmap; a decoy value that reveals a leak, no ADR yet |

## Apps and components

| Spanish | English | Source / note |
|---|---|---|
| núcleo | core | `klav-core` |
| servidor | server | `klav-server` |
| limpieza (del servidor, cada hora) | purge, the hourly purge | code `purge.rs`; ADR 0037 |
| daemon | daemon | `klavd` |
| identidad de la compilación (el *commit* y su fecha) | build identity | `klav --version`, `klavd --version`, `klav-proxy --version`, `klav-forward --version`, `commit` and `commit_time` in `klavd`'s `status`; `crates/klav-daemon/build.rs`. Tells two builds of the same version number apart |
| extensión (de navegador) | (browser) extension | |
| *host* de native messaging | native messaging host | `klav-native-host` |
| *wrapper* del *host* | host wrapper | `$KLAV_HOME/native-host/klav-native-host`, written by `klav extension install-host`. The browser's manifest points to it; it runs `klav-native-host` with this `KLAV_HOME` and the extensions it lets in |
| ventana emergente / *popup* | popup | |
| barra de menús (de macOS) / panel de la barra de menús | menu bar / menu bar panel | macOS; `apps/ios/Mac/MenuBar.swift`, the Mac app's panel under the key |
| menú en la página | in-page menu | |
| app de iOS / app de Mac | iOS app / Mac app | |
| Ajustes | Settings | UI |
| Configurar este Mac | Set up this Mac | UI; ADR 0027 §4 |
| servicio en segundo plano | background service | UI, the first step of "Set up this Mac": `klavd` as a login item |
| ítem de inicio / «Abrir Klav al iniciar sesión» | login item / "Open Klav at login" | UI "Login Items & Extensions" (System Settings › General, the pane's name since macOS 15), "Open Klav at login"; `SMAppService`. Klav has two: `klavd`'s LaunchAgent (the background service) and, when that switch is on, the app itself (`SMAppService.mainApp`) |
| extensión de desarrollo | development extension | UI "Development extension"; the build loaded unpacked, allowed with `klav extension install-host --dev` |
| cargar sin empaquetar | load unpacked | Chrome's "Load unpacked"; Firefox calls it a temporary add-on |
| Desarrollo (sección de la app de Mac) | Development | UI; ADR 0033 E1 |
| sitio web | website | `apps/web`, klav.dev |
| sitio de documentación / docs públicos | docs site, public docs | `apps/docs`; ADR 0039. Not "the website", which is `apps/web` |
| Nimbus | Nimbus | The docs site's framework (`@cloudflare/nimbus-docs`, scaffolder `@cloudflare/create-nimbus-docs`); ADR 0039. Never translated |
| versión en Markdown (de una página) | Markdown version | Nimbus's term for `/<slug>/index.md`; ADR 0039. Not "twin" or "mirror" |
| `llms.txt` | `llms.txt` | The docs site's index for agents; `llms-full.txt` holds every page in one file. Always in backticks |
| receta (de Nimbus) | recipe | Nimbus: Markdown instructions that `nimbus-docs add <feature>` prints for an agent to apply |
| en camino (sección de los docs) | On the way | ADR 0039: the docs section for accepted ADRs not built yet, with no dates. The landing page's badge stays "Coming soon" |
| Configurar códigos en (Ajustes de iOS) | Set Up Codes In | Apple's name in iOS Settings › General › AutoFill & Passwords; Klav's row is "Set up codes in Klav" (`SettingsView.swift`) |
| tarjeta de arriba (extensión) | sign-in card | UI "Sign in with Klav" (`frame_card`); docs site, Apps › "The browser extension" |
| buscador central (extensión) | Klav's search | UI "Search Klav" (`frame_find`) |
| inicio de sesión en varios pasos | sign-in in several steps | extension.md §5; an email first, then the password, then a code |
| portapapeles | clipboard | The Mac app, the iPhone app and the extension clear a copied value after 30 s; on Apple devices it stays off Universal Clipboard |
| barra de guardar | save bar | `docs/extension.md` §6; `save.html`, the extension's offer to save or update a login after a submit |
| glifo (de Klav, en un campo) | glyph | `docs/extension.md` §5: the key Klav draws at the end of a field it recognizes; a click opens the field menu |
| marco (de una página, de Klav) | frame | `docs/extension.md`: a page's `iframe` (`sender.frameId`), and the extension pages Klav draws inside a site, such as the passkey frame (`passkey.html`) |
| ficha (de un elemento o de un agente) | item page / agent page | `docs/ios.md`: the screen with one item's fields, or one agent's state and timeline. Not the store listing (below) |
| franja (arriba de la bóveda) | band | `docs/ios.md` §11: the fixed strip with the deletion date, or the read-only notice |
| rebanada (de un XCFramework) | slice | `docs/ios.md` §5: one platform's build inside `KlavFFI.xcframework` |
| huella (de una llave) | fingerprint | `docs/diseno.md` §5.1: the key's fingerprint, shown as the six pairing words (above) both sides compare; not the proxy pin |
| tarea ofrecida | offered task | ADR 0022 §6: a task the person signs for an agent without a prior request (`request` empty) |
| verificación de usuario (UV) / presencia (UP) | user verification (UV) / user presence (UP) | ADR 0020 §8; WebAuthn flags |
| registro de contraseñas | password record | ADR 0022 §3; blob `0x16`, `password_record` |
| cambio asistido (de contraseña) | assisted (password) change | ADR 0022 §5; permission `rotate` |
| fusión (al importar) | merge | ADR 0024 §3 |
| asistente (de importación) | wizard | ADR 0024; UI "Where are you coming from?" |
| Tinta, Papel, Niebla, Gris, Cobalto… (colores de la paleta) | kept as is | `docs/diseno-visual`; they are identifiers in code (`tinta`, `--niebla` in `Theme.swift` and `klav.css`) |
| conjunto protegido | protected set | ADR 0032 §3.1; `protected_set` in `klav-core`: the items a protected environment's references point to. Each device keeps its own in `protection.bin` (layer 3), which only shrinks with proof |
| interruptor «Desarrollo» | "Development" switch | ADR 0032 §7; system item `kind = preferences`. Shows or hides the Mac app's Development section (ADR 0033 E1) |
| pedir cada vez (`ask once`) | ask every time | ADR 0032 §4.2; `Rule.once`: no lease, one use, never in a task |
| regla heredada (`origin: "protected"`) | inherited rule | ADR 0032 §3.1; `Rule::protected`, `RuleOrigin::Protected`: an `ask once` rule on the items of the protected set, which only tightens a decision |
| marca efectiva (`protected`) | effective flag | ADR 0032 §3; `effective_protected`: the `protected` flag of the latest version the person wrote; with none, on or named `production`/`prod` |
| aprobación del entorno | environment's approval | ADR 0032 §3.1; an approval whose request lists `items`: one use of the environment and one of each protected item it names, in the same call; never a lease or a task (`bundle_for` in `klav-sdk` picks the items) |
| doble barrera | double barrier | ADR 0032 §4.4: the server and the agent's runtime apply the same signed grant, and the runtime also requires a signed approval for an environment whose effective flag is on, even if the server says `allow` |
| liberados (`released`) | released | ADR 0032 §3.1; `GrantPayload.released`: the items a reissued grant stops protecting, with proof; without them the server answers `409` |
| variable (de un entorno) | variable | ADR 0032 §1; `Variable`: a name (`[A-Za-z_][A-Za-z0-9_]{0,127}`, case-sensitive) with a value or a `klav://` reference |
| volver a emitir (un grant) | reissue | ADR 0032 §3.1, ADR 0033 F1; `regrant_agents` |
| pin de confianza (de `klav run`) | trust pin | `trusted-projects.json`, by path and exact text; ADR 0032 §2 |
| autoría por versión / sitios confirmados | per-version authorship / confirmed sites | ADR 0030 §7; `author_agent_id`. The sites of the latest version the person wrote |
| alta (de un agente en un sitio) | sign-up | ADR 0030 §7, ADR 0022 §7: the agent creates the login and fills the registration form |
| resumen (de lo mostrado o del cambio) | digest | ADR 0030 §5, ADR 0033 F3: the SHA-256 that binds a signature to what the person saw |
| skill fina | thin skill | ADR 0033 E3: only the stable rules; tool details come live from `klav mcp` |
| arranque (de una máquina de CI) | start | ADR 0034: Boat bills one per job that gets a runner |
| lote (`otpauth-migration`) | batch | ADR 0024, ADR 0035: one QR code of a Google Authenticator export |

## Project workflow

| Spanish | English | Source / note |
|---|---|---|
| fase / hito | phase / milestone | roadmap |
| ficha (de una tienda) | store listing | `apps/extension/store/ficha.md`, `apps/ios/store/ficha.md` |
| notas para la revisión | App Review notes (App Store); notes to reviewer (browser stores) | App Store Connect *Notes*; AMO *Notes to Reviewer* |
| cuenta de demostración / cuenta para quien revisa | demo account / reviewer account | App Store Connect *Sign-In Information* |
| respuestas de privacidad / etiqueta de privacidad | App Privacy answers / privacy label | App Store Connect *App Privacy* |
| clasificación por edad | age rating | App Store Connect *Age Rating* |
| declaración de cifrado (exportación) | export compliance | App Store Connect; `ITSAppUsesNonExemptEncryption` |
| comerciante (ley de servicios digitales) | trader (Digital Services Act) | store accounts |
| descargas (de Klav) | downloads | The files people get from `klav.dev/download/…`: the Mac app, the extension zips, the Linux binaries; `docs/releasing.md` |
| *release* / versión publicada | release | A GitHub Release of the repository, tag `vX.Y.Z`; `docs/releasing.md`. In Spanish docs, *release* in italics |
| kit de publicación | release kit | `scripts/release/kit.mjs`: one release's files under stable names, with `SHA256SUMS`; `docs/releasing.md` |
| *appcast* | appcast | The Mac app's Sparkle update feed, `appcast.xml`; macos.md §6 |
| compilación con llave (de la extensión) | keyed build | The Chromium extension with the development `key`, so its ID is fixed; `klav-<v>-chromium-dev.zip` from `package.sh` |
| beta pública (de TestFlight) | public beta, public link | TestFlight external testing through a public link; `docs/publicar-ios.md` |
| complemento sin listar (de Firefox) | unlisted add-on, signed `.xpi` | A Firefox add-on that addons.mozilla.org signs without a public listing; the release's `klav-extension-firefox.xpi`; `docs/releasing.md` §3 |
| bloqueo (para publicar) | blocker | `docs/publicar-ios.md` §1 |
| disponibilidad (países y regiones) | availability | App Store Connect *Availability* |
| **[REVISAR]** / **[DECIDIR]** (marcas en un documento) | **[CHECK]** / **[DECIDE]** | `docs/publicar-ios.md`, `apps/ios/store/ficha.md`; in English docs, keep **[REVISAR]** only when pointing at a marker in a Spanish file |
| Estado actual | Current status | roadmap |
| entregable | deliverable | |
| casilla | checkbox | |
| configuración local de compilación | local build config | `~/.config/klav-dev/config.env`, outside every checkout: DerivedData, the Swift package cache and the notary key of the build scripts; `scripts/dev/local-config.sh`, `docs/ios.md` §5 |
| pila (de PRs) / capa | stack / layer | `gh stack` |
| mezclar (un PR) | merge | |
| plan de pruebas | test plan | |
| ADR propuesto / aceptado / reemplazado | proposed / accepted / superseded | |
| ronda de seguridad | security round | ADR 0030 |
| ronda de consolidación | consolidation round | roadmap, Omar's decision of 2026-11-10 |
| mapa de funciones | feature map | roadmap; `docs/features.md` |
| superficie | surface | `docs/features.md`: where a capability lives (CLI, `klavd`, extension, iOS app, Mac app, `klav mcp`, SDK, skill) |
| ola (de traducción) | wave | ADR 0031 |
| *ruleset* (de `main`) | ruleset | ADR 0031 §6, ADR 0040. GitHub's rules on a branch: PR required, required checks, merge method |
| check obligatorio | required check | ADR 0040 §5. A CI check the ruleset requires by name before a merge |
| colaborador externo / contribuidor externo | outside contributor | ADR 0040. Someone without write access; GitHub's settings say "external contributor" |
| *Discussions* (de GitHub) / categoría | Discussions / category | ADR 0040 §2: Announcements, Ideas, Q&A. Category names are never translated |
| límite de PRs abiertos | open-PR limit | ADR 0040: GitHub's native cap on open PRs per person without write access |
| límite de interacción (temporal) | (temporary) interaction limit | ADR 0040: GitHub's moderation setting, 24 hours to 6 months |
| lista de confianza (*vouch*) | vouch list | ADR 0040: T3 Code's `VOUCHED.td` and its `vouch:*` labels |
| Estado / Fecha / Cambia (ADR header) | Status / Date / Changes | ADR wave 1 (ADR 0031) |
| Contexto / Decisión / Decisión propuesta / Consecuencias | Context / Decision / Proposed decision / Consequences | ADR headings, wave 1. "Decisión propuesta" stays "Proposed decision" even in accepted ADRs |
| Alternativas descartadas / Descartado | Rejected alternatives / Rejected | ADR headings, wave 1 |
| Respuesta(s) de Omar | Omar's answer(s) | ADR headings, wave 1 |
| Preguntas para Omar | Questions for Omar | ADR headings (ADR 0037) |
| Notas de implementación / Notas del rediseño | Implementation notes / Redesign notes | ADR 0017 |
| hueco (del relevo) | slot | ADR 0029; routes `/v1/links` |
| paquete (sellado) | package | ADR 0029; type `0x22` link-payload |
| oferta | offer | ADR 0029; type `0x08` link-offer. Kept as `oferta` inside formulas and code blocks |
| el que ya está dentro (dispositivo) | the device that is already signed in | ADR 0029 |
