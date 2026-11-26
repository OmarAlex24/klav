# Klav — guía para agentes que trabajan en este repo

Gestor de contraseñas open source, cifrado de extremo a extremo y pensado para agentes. Antes de tocar código, lee:

1. [`docs/diseno.md`](docs/diseno.md): el qué y el porqué (aprobado).
2. [`docs/roadmap.md`](docs/roadmap.md): en qué fase vamos y qué sigue. **Trabaja solo en la fase en curso.**
3. [`docs/decisiones/`](docs/decisiones/): ADRs. Si tu cambio contradice el diseño, escribe primero un ADR nuevo.
4. `docs/especificacion-cripto.md` y `docs/modelo-de-amenazas.md` (cuando existan).

## Reglas que no se negocian

- **La criptografía vive solo en `crates/klav-core`.** Ningún otro crate o app implementa primitivas; todos llaman al core.
- **Nada de criptografía propia.** Solo RustCrypto (`chacha20poly1305`, `argon2`, `x25519-dalek`, `ed25519-dalek`, `hkdf`, `sha2`), `hpke` y `opaque-ke`. Para añadir una dependencia criptográfica hace falta un ADR. Además, aprobados por ADR:
  - `p256` 0.14 y `ecdsa` 0.17 (RustCrypto) para las passkeys, [ADR 0020](docs/decisiones/0020-passkeys.md) §6. Condición: la capa que los añada fija en el workspace `elliptic-curve >= 0.14.3` o `crypto-bigint >= 0.7.9`, y `deny.toml` rechaza `crypto-bigint` 0.7 anterior a 0.7.6, porque el `ignore` de RUSTSEC-2026-0387 va por ID y taparía una 0.7.5.
  - `p256` 0.14 y `ecdsa` 0.17 también para firmar en `klav-core` las aserciones ES256 de los servicios desplegados (la federación de identidad de cargas), [ADR 0045](docs/decisiones/0045-keyless-services.md) §1.3 y Q1, aprobado por Omar el 2026-11-18: las mismas versiones y features que las passkeys, la misma condición sobre `elliptic-curve` y `crypto-bigint`, y sus propios vectores. Solo `klav-core` firma; si hiciera falta otra feature de `p256`, vuelve al ADR.
  - `psl` 2.1, solo para validar el rpId de las passkeys, detrás de la feature no predeterminada `rp-id` de `klav-core`; `klav-wasm` no la compila y la coincidencia de sitios sigue sin PSL (ADR 0020 §6). `ciborium` 0.2 solo como *dev-dependency*.
  - Para verificar el proxy alojado de Klav Cloud ([ADR 0051](docs/decisiones/0051-hosted-nitro-enclave-proxy.md) §5 y Q4, aprobado por Omar el 2026-11-26), solo en `klav-core` detrás de la feature no predeterminada `nitro-attestation`, que `klav-wasm` nunca compila: `p384` 0.14 (RustCrypto, con `ecdsa`, solo verificación, con la misma condición sobre `elliptic-curve` y `crypto-bigint` que `p256`), `x509-cert` 0.3 (sin features por defecto; trae `der_derive` y `flagset`), y `der` 0.8 y `spki` 0.8 como dependencias directas. También quedó aprobado `ciborium` 0.2 como dependencia normal detrás de la feature, pero la capa 2 no lo usa (lee el CBOR con un lector estricto propio) y sigue solo como *dev-dependency*.
  - No criptográfico, para el enclave del ADR 0051 (§5.2 y Q4, aprobado por Omar el 2026-11-26), solo en `klav-proxy` detrás de la feature `enclave` y solo en Linux: `aws-nitro-enclaves-nsm-api` 0.5 (el cliente de `/dev/nsm` de AWS; su `unsafe` vive en la dependencia), `tokio-vsock` 0.7 y `vsock` 0.5. El primero trae `serde_cbor` 0.11, sin mantener (RUSTSEC-2021-0127): la capa que lo añada (la 3) pone en `deny.toml` un `ignore` con su motivo, no antes. Nunca el SDK de C de Nitro ni `kmstool`.
  - `sha1` 0.11 (RustCrypto) en `klav-core` detrás de la feature `breach-check`, solo para el prefijo de HIBP ([ADR 0022](docs/decisiones/0022-generador-historial-y-cambio-asistido.md) §4). TOTP ya lo usaba.
  - No criptográfico: `zxcvbn` 3.1 en `klav-client` detrás de la feature `health`, sin compilarse en `klav-wasm` (ADR 0022 §4).
  - `aws-lc-rs`, solo para transporte, nunca para la bóveda ni en `klav-core`: es el proveedor de `rustls` en el TLS de los clientes y del servidor ([ADR 0011](docs/decisiones/0011-cliente-tls-y-jerarquia-local.md)), y `klav-server` firma con él el JWT ES256 de APNs ([ADR 0018](docs/decisiones/0018-app-ios.md) §5). `ring` sigue prohibido en `deny.toml`: aparece en `Cargo.lock` solo como dependencia opcional (la feature `http3` de `reqwest` vía `quinn`, y la feature `ring` de `rustls-webpki`), que nadie activa, y `cargo tree -i ring --all-features --target all` no lo encuentra en ningún grafo.
  - No criptográfico, para los importadores ([ADR 0024](docs/decisiones/0024-importadores.md) §4), en `klav-import`: `miniz_oxide` 0.9 (el *deflate* del `.1pux`); `png` 0.18 y `rqrr` 0.11 detrás de la feature `qr-image`, que solo activan la CLI y `klavd`; `qrcode` 0.14 solo con la feature `samples` y en pruebas.
  - No criptográfico: `qrcode` 0.14 en `klav-cli` detrás de la feature `qr`, para mostrar en la terminal el QR de añadir un dispositivo ([ADR 0029](docs/decisiones/0029-anadir-dispositivo-con-qr.md), Q6).
  - No criptográfico: `nix` 0.31 en `klav-sdk`, solo para el escritor de archivos con secretos (`klav_sdk::secret_file`): sin features para comparar errnos, aprobado por Omar el 2026-11-16, y con la feature `fs` para escribir con `openat` por el directorio que abrió (la forma de archivo de `inject`), aprobada por Omar el 2026-11-17 ([ADR 0041](docs/decisiones/0041-presence-for-values-and-the-inject-card.md) §5.1 y §9, capa 9). `fs` no añade crates; ya la usa `klav-cli`. Ya estaba en el árbol por `klav-cli`, `klav-daemon` y `klav-proxy`.
  - No criptográfico: `memoffset`, como dependencia transitiva de `nix` 0.31 con la feature `socket`, para leer `SO_PEERPIDFD` en Linux (la identidad del par de `klavd`), aprobado por Omar el 2026-11-17 ([ADR 0041](docs/decisiones/0041-presence-for-values-and-the-inject-card.md) §1.1 y §9, capa 1). Solo `klav-daemon` declara la feature, detrás de su feature `server`; por la unificación de features de Cargo, `memoffset` entra en todo binario que enlaza `klav-daemon` con `server` (`klavd`, `klav` y lo que enlace `klav-sdk`), no en la app de Mac. Las features de `nix` que no añaden crates y el ADR 0041 §9 lista (`process` en `klav-daemon` y `term` en `klav-cli`) no piden otra aprobación.
  - No criptográfico, para editar la configuración de los clientes de agentes sin reescribir lo ajeno ([ADR 0033](docs/decisiones/0033-agentes-desde-la-app-de-mac.md) §3.6, P6), solo en `klav-cli` y fijadas exactas (`=`): `toml_edit` 0.25.17 (ya estaba en el árbol de forma transitiva) y `jsonc-parser` 0.34.0 con la feature `cst`, que conserva comentarios y espacios.
  - `rustls` 0.23 y `tokio-rustls` 0.26 como dependencias normales, solo para el canal de los sandboxes (ADR 0036 §6, capa 6), en `klav-forward` (su `channel`) y en `klav-proxy`: solo TLS 1.3, `aws-lc-rs` como proveedor y nunca `ring`; llaves Ed25519 en bruto (RFC 7250) en los dos extremos; las firmas del *handshake* las verifica `rustls`, y las de Klav salen de `klav_core::crypto::channel::TlsSigner`, que solo firma un `CertificateVerify` de TLS 1.3. Ya estaban en `Cargo.lock` por `reqwest`.
  - No criptográfico, solo en `klav-proxy`, aprobado por Omar el 2026-11-11 (ADR 0036 §6): `hyper` 1.12 con `server` y `http1`, y `hyper-util` 0.1.21 con `tokio` y `service`, para servir HTTP/1.1 en el canal fijado conexión por conexión (plazo para la cabecera, cerrar una conexión sola con gracia, la llave de cada conexión). Ya estaban en `Cargo.lock` por `axum` y `reqwest`.
  - Sparkle 2 (Swift Package Manager, versión fijada exacta), solo en el *target* de macOS, para las actualizaciones de la app de Mac ([ADR 0027](docs/decisiones/0027-app-de-mac.md) §7). Su firma EdDSA autentica la distribución, no toca la bóveda; la app comprueba además el Team ID de la versión nueva.
- **Los secretos nunca se loguean ni se imprimen.** Tipos en `secrecy::SecretBox`/`zeroize`; nada de `Debug`/`Display` derivados en tipos con secretos; nada de `println!` de secretos en tests.
- **Por defecto, los agentes reciben acciones, no valores.** Cualquier ruta nueva que devuelva un secreto en claro debe pasar por el permiso `reveal`.
- **Los formatos binarios llevan versión** desde el primer byte y quedan documentados en la especificación con vectores de prueba en `docs/vectores/`.
- **`unsafe`** está prohibido salvo en `klav-ffi` y en el shim de Touch ID, siempre con un comentario `// SAFETY:`.

## Flujo de trabajo

- Commits: `<type>: <description>` or `<type>(<scope>): <description>` (`feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`), in English. The DCO `Signed-off-by:` line (ADR 0031, P3) starts when the repository goes public, and a person adds it: agents never sign for Omar.
- Los PRs de una fase van en pila con `gh stack`, una rama por capa. Omar mergea. En el plan de pruebas del PR, solo casillas marcadas (lo que de verdad se corrió).
- Antes de dar algo por hecho: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
- Al terminar un entregable, marca su casilla en `docs/roadmap.md` dentro del mismo PR y actualiza **Estado actual** si cambia la fase.
- A PR that changes user-visible behavior updates its page in the public docs site (`apps/docs`) in the same PR; `docs/features.md` decides which section may mention a feature ([ADR 0039](docs/decisiones/0039-public-docs-site.md) §3).
- Everything in the repository is in English: docs, ADRs, the roadmap, code, identifiers, comments, commit messages, PR titles and bodies, and review comments. Use the terms in [`docs/glossary.md`](docs/glossary.md); if a term is missing, add it in the same PR.
- The UI ships in English and Spanish. User-facing strings live in `apps/ios/Shared/Localizable.xcstrings` and `apps/extension/_locales/{en,es}`; write each language natively, never as a literal translation.
- While a document is still in Spanish (translation waves, ADR 0031 §3), edit it in Spanish and leave the translation to its wave. New documents are written in English.
- Never translate the `cases` in `docs/vectores/*.json` or edit an existing SQL migration: both are bytes that tests or databases check.
- Contributions follow [`CONTRIBUTING.md`](CONTRIBUTING.md): one problem per PR, evidence of what you ran, and the model and harness that did the work named in the PR and in `Co-Authored-By`.
- Espacio en disco:
  - `target/` puede ser un enlace simbólico a un disco externo: no lo reemplaces ni apuntes `CARGO_TARGET_DIR` al disco interno.
  - No crees directorios de compilación extra en `/tmp` o `$TMPDIR`; si hace falta uno aparte (verificar en limpio, MSRV), ponlo junto al `target/` real y bórralo al terminar.
  - Corre `scripts/dev/espacio.sh` al empezar cada fase o capa y tras corridas largas de pruebas; si falla, detente.
  - Las pruebas (e2e incluidas) borran sus directorios temporales al terminar, también si fallan.

## CI

La CI corre en Boat, en `boat-large` ([ADR 0034](docs/decisiones/0034-ci-en-boat.md); el diseño viene del [ADR 0023](docs/decisiones/0023-ci-en-celesto.md)): un solo job `ci` en `.github/workflows/ci.yml`. Boat cobra un arranque por cada job que recibe máquina, también si después se cancela. Ese job lanza ocho tareas en paralelo (lista en `.github/ci-tasks.json`) y cada una publica su propio check: `fmt`, `clippy`, `test`, `test (postgres)`, `docker`, `extension`, `cargo-deny` y `docs`.

- **Para ver por qué falló**, lee primero el check de la tarea y después el log del job:
  ```
  gh pr checks <pr>
  gh api repos/OmarAlex24/klav/check-runs/<id> --jq .output.text
  ```
  El log completo de cada tarea está en el artefacto `ci-task-logs-<intento>`.
- **Para reintentar**, usa solo `gh run rerun <id> --failed`, que salta las tareas que ya pasaron sobre el mismo código. Nunca «Re-run all jobs»: sobre una corrida verde paga un arranque para nada. Para correr todo otra vez, haz un push nuevo.
- **Una tarea nueva** necesita tres cosas que se llamen igual: su entrada en `.github/ci-tasks.json`, sus pasos `start` y `result` en el workflow y su nombre de check en `CI_TASK_CHECK_NAMES`. Las pruebas del motor se corren con `cd .github/boated-ci && bun test`.
- **Un comando que pueda fallar** va dentro del script de su tarea, no en un paso aparte: en un reintento, un paso aparte se saltaría junto con la tarea.
- **In a Boat sandbox, build through the CI cache** so the PR's CI reuses what you compile (details: the `ci-cache` skill). A Boat sandbox has `BOAT_ID` set and a `~/.ci-cache/` directory; anywhere else, skip this. From `/home/user/klav`, before the first build:
  ```
  bash ~/.ci-cache/install-sccache.sh && bash ~/.ci-cache/ci-cache-env.sh
  ```
  Start every shell that runs `cargo` with `source ~/.ci-cache.env`. Run `ci-cache-env.sh` again after switching branches and every 6 h: the session belongs to one branch and expires. Build on the PR's head branch, rebase onto `origin/main` right before the final build, and don't override `RUSTFLAGS` or `CARGO_*`: the sandbox already matches CI.
