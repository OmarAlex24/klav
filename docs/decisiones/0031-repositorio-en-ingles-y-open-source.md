# 0031 · Repositorio en inglés y listo para open source

- Estado: aceptado; reemplazado en parte por [0040](0040-contribution-gating-and-discussions.md) (qué se acepta de fuera, *Discussions*, el formulario de función, los ocho checks, y las aprobaciones, el *bypass* y la revisión de CODEOWNERS del *ruleset*)
- Fecha: 2026-11-05

## Contexto

El 2026-11-05 Omar pidió dos cosas: que el repositorio quede **en inglés**, para que cualquiera pueda leerlo y contribuir, y que esté **lo más listo posible para abrirlo**. Los commits viejos se quedan como están.

Hoy, `CLAUDE.md` dice: «Docs internos en español; código, identificadores y comentarios de código en inglés». El código ya está en inglés. Lo que está en español es esto:

- todos los documentos de `docs/`: 29 ADRs, el diseño, la especificación criptográfica, el modelo de amenazas, el roadmap y las guías;
- `README.md`, `SECURITY.md` y `CLAUDE.md` (`AGENTS.md` es un enlace simbólico a `CLAUDE.md`);
- los nombres de varias rutas (`docs/decisiones/`, `docs/vectores/`, `especificacion-cripto.md`…) y de varias pruebas (`crates/klav-client/tests/salud.rs`…);
- los mensajes de commit y los cuerpos de los PRs.

La interfaz ya está en español y en inglés: `apps/ios/Shared/Localizable.xcstrings` y `apps/extension/_locales/{en,es}`.

Entonces el repositorio era privado y `main` no tenía protección ni *rulesets*. Las únicas etiquetas son las que GitHub crea por defecto, no hay plantillas de issue ni de PR, no hay `CONTRIBUTING.md` ni código de conducta, y no hay versiones publicadas: el *workspace* va en `0.0.0` y la app de iOS en 0.6.0 build 3. Comprobado con `gh api` el 2026-11-05.

Hay dos pilas abiertas, con 15 PRs, y cuatro *worktrees* con trabajo sin PR:

- **ronda de seguridad:** #128–#139. Su ADR todavía se llama `0025-ronda-de-seguridad-2026-11.md` en las ramas y choca con el `0025-sitio-padre.md` de `main`. Al rebasarla tomará el número 0030, y por eso este ADR es el **0031**;
- **filtros:** #151–#153;
- **passkeys:** `passkeys/01-core`;
- **app de Mac:** `t3/app-mac-nativa-dmg`;
- **materiales de tiendas:** `extension/tiendas`;
- **botón «+» de la extensión:** `extension/agregar`.

Si las traducciones o los renombres chocan con esas pilas, cada rebase se vuelve un conflicto en casi todos los documentos.

## Lo investigado

Revisé dos repositorios grandes de herramientas para desarrolladores construidas con agentes, y dos gestores de contraseñas *open source* serios. Todas las fuentes se consultaron el **2026-11-05**. Las URLs de GitHub salen de `gh api repos/<dueño>/<repo>`, no de memoria. `sst/opencode` redirige hoy a `anomalyco/opencode`.

### opencode (`anomalyco/opencode`, MIT, rama por defecto `dev`)

- **[CONTRIBUTING.md](https://github.com/anomalyco/opencode/blob/dev/CONTRIBUTING.md).** Dice qué cambios tienen más probabilidad de aceptarse: correcciones de errores, LSPs, rendimiento y documentación. Las funciones nuevas de UI o del núcleo necesitan revisión de diseño antes de implementarlas. Correcciones, *chores* y pruebas deben enlazar un issue (`Fixes #123`). Los PRs, «pequeños y enfocados». Títulos `type(scope): summary` con `feat|fix|docs|chore|refactor|test`.
  - Sobre la IA: «*Long, AI-generated PR descriptions and issues may be ignored. Write a short explanation in your own words.*»
  - Prohíbe los issues en blanco; las dudas van a Discord. Una comprobación automática marca los issues sin plantilla o «*AI-generated walls of text*» y los cierra a las dos horas si nadie los corrige.
- **[Plantilla de PR](https://github.com/anomalyco/opencode/blob/dev/.github/pull_request_template.md).** Pide el issue, el tipo de cambio, qué hace el PR y cómo se verificó. Exige entender el cambio: «*It is expected that you understand why your changes work and if you do not understand why at least say as much*». Avisa que una descripción larga claramente hecha con IA puede cerrarse.
- **[Plantillas de issue](https://github.com/anomalyco/opencode/tree/dev/.github/ISSUE_TEMPLATE)** en formularios YAML (`bug-report.yml` y `feature-request.yml`), con `blank_issues_enabled: false`.
- **[SECURITY.md](https://github.com/anomalyco/opencode/blob/dev/SECURITY.md).** Empieza por un modelo de amenazas corto: no hay *sandbox*, y el modo servidor es opcional. Sigue una tabla de lo que queda fuera del alcance y el reporte por GitHub Security Advisories, con un correo de escalada si no responden en 6 días hábiles.
  - Sobre la IA: «*We do not accept AI generated security reports … automatic ban from the project.*»
- **[CODEOWNERS](https://github.com/anomalyco/opencode/blob/dev/.github/CODEOWNERS).** Asigna dueños por paquete y protege `/.github/` con el equipo `@anomalyco/releasers`, porque ahí viven los *jobs* de publicación que tienen secretos.
- **[AGENTS.md](https://github.com/anomalyco/opencode/blob/dev/AGENTS.md)** con guía de estilo, ramas, commits y pruebas. Cada paquete tiene su propio `AGENTS.md` cerca del código.
- **Versiones.** Un [CHANGELOG.md](https://github.com/anomalyco/opencode/blob/dev/CHANGELOG.md) escrito para personas, por versión y con enlaces a los PRs; la última es `v2.2.5` (2026-10-30). Publica versiones *nightly* y *beta* por *workflow*. No pide CLA ni DCO.
- **Triage automático** con *workflows* `triage-*`, por ejemplo `triage-pr-standards.yml`. Comprueban el título convencional (etiqueta `needs:title`) y el issue enlazado.
- `gh api …/branches/dev/protection` devuelve 404. Es probable que usen *rulesets*, que no se ven sin permisos.

### T3 Code (`pingdotgg/t3code`, MIT, rama por defecto `main`)

- **[CONTRIBUTING.md](https://github.com/pingdotgg/t3code/blob/main/CONTRIBUTING.md).** Es el más estricto de los dos:
  - Dice que no buscan contribuciones externas y que abrir un PR no obliga a revisarlo.
  - Las funciones necesitan aprobación explícita previa en una *Discussion* enlazada.
  - «**Un problema por PR**», contando problemas y no issues.
  - Pide evidencia del cambio: «*A checkbox or "tests pass" alone does not show that the change works*». Los cambios de UI llevan capturas de antes y después, sin subir esos archivos al repositorio.
  - Las reglas valen igual para los borradores.
  - Cada cierre por política cita la regla y explica cómo corregirlo.
  - Sobre la IA: «*We assess the problem, scope, approval, and evidence, not an author's writing style or whether we think an agent wrote the PR.*»
  - Rechaza los PRs escritos con ciertos modelos, según la línea de atribución que el PR declara.
- **[Plantilla de PR](https://github.com/pingdotgg/t3code/blob/main/.github/pull_request_template.md)** con las secciones *Problem*, *Change*, *Scope and approval* y *Verification*. Termina con «*If you used an agent, end with the model and harness that did the work*».
- **[AGENTS.md](https://github.com/pingdotgg/t3code/blob/main/AGENTS.md)** (`CLAUDE.md` es `@AGENTS.md`). Las reglas de documentación dicen que los documentos internos son para decisiones y restricciones difíciles de descubrir, no para catálogos de archivos ni resúmenes de PRs. Cuando una decisión cambia, se reescribe el texto en lugar de añadirle otro relato.
- **Triage.** Aplican etiquetas `size:*` con [`pr-size.yml`](https://github.com/pingdotgg/t3code/blob/main/.github/workflows/pr-size.yml) y `vouch:*` con [`pr-vouch.yml`](https://github.com/pingdotgg/t3code/blob/main/.github/workflows/pr-vouch.yml), que usa `mitchellh/vouch` y la lista [`VOUCHED.td`](https://github.com/pingdotgg/t3code/blob/main/.github/VOUCHED.td). Solo los nombres de [`TRIAGE_EXEMPTIONS.td`](https://github.com/pingdotgg/t3code/blob/main/.github/TRIAGE_EXEMPTIONS.td) se saltan el triage, que hace un agente con una *skill* leída siempre de `main`, nunca del PR.
- **[Plantillas de issue](https://github.com/pingdotgg/t3code/tree/main/.github/ISSUE_TEMPLATE)**: `bug_report.yml` (con desplegable de área y casillas «busqué duplicados») y `config.yml`, sin issues en blanco y con las ideas mandadas a *Discussions*.
- **[SECURITY.md](https://github.com/pingdotgg/t3code/blob/main/.github/SECURITY.md)** corto, con un correo y un enlace a la política completa, que incluye *safe harbor*.
- **Versiones.** *Nightlies* etiquetadas `v0.1.8-nightly.20261105.N` y versiones estables por *tag*, sin CHANGELOG en el repositorio. No pide CLA ni DCO. No tiene código de conducta.

### Bitwarden (`bitwarden/server` y `bitwarden/clients`)

- **[Guía de contribución](https://contributing.bitwarden.com/contributing/).** Exige firmar un **CLA** ([cla-assistant](https://cla-assistant.io/bitwarden/clients)) antes de mezclar: «*Pull requests cannot be accepted and merged unless the author has signed the Contributor Agreement*». Los cambios de UX se discuten antes de escribir código. Los PRs van contra `main`.
- **[SECURITY.md](https://github.com/bitwarden/clients/blob/main/SECURITY.md).** El programa está en [HackerOne](https://hackerone.com/bitwarden/) y admite reportes cifrados con PGP. Pide un tiempo razonable antes de divulgar y prohíbe la denegación de servicio, el *spam*, la ingeniería social y los ataques físicos. Solo se prueba contra cuentas propias.
- **[Auditorías](https://bitwarden.com/help/is-bitwarden-audited/).** Bitwarden publica cada año los informes de terceros: Cure53, entre otros, revisa el código, la criptografía y la infraestructura. También publica SOC 2/3.
- **[Plantilla de PR](https://github.com/bitwarden/clients/blob/main/.github/PULL_REQUEST_TEMPLATE.md)** con *Tracking*, *Objective* y capturas.
- No tiene código de conducta en el repositorio, según `community/profile`.

### Proton Pass (clientes en `protonpass/*` y en `ProtonMail/WebClients`, GPL-3.0)

- **[Bug bounty](https://proton.me/security/bug-bounty).** Los reportes van a `security@proton.me`, con PGP si se desea. Las recompensas llegan a 100 000 USD y se pide una prueba de concepto reproducible.
- **[Política de divulgación](https://proton.me/security/vulnerability-disclosure).** Proton acusa recibo en 5 días hábiles. El investigador guarda silencio 120 días desde ese acuse. Se admiten reportes anónimos.
- **[Safe harbor](https://proton.me/security/safe-harbor).** Considera autorizada la investigación de buena fe y se compromete a no llevar a juicio a quien siga las reglas, aunque aclara que no puede obligar a terceros.
- **[Auditoría y apertura](https://proton.me/blog/pass-open-source-security-audit).** Cure53 auditó los clientes como caja blanca antes de abrirlos el 2023-07-19, y Proton publicó el informe con el anuncio. El servidor no es abierto.

### Lo que se repite

1. Hay una guía corta que dice **qué cambios se aceptan** y exige **discutir antes** las funciones.
2. Los títulos son convencionales y hay **un problema por PR**.
3. Se exige **evidencia** del cambio, no basta con decir «las pruebas pasan».
4. Plantillas en formulario y **sin issues en blanco**.
5. Las vulnerabilidades **se reportan en privado**, con plazos y con alcance escrito.
6. **CODEOWNERS** en lo que tiene secretos o publica versiones.

Sobre la IA, hay dos posturas:

- juzgar el trabajo y no al autor (T3 Code);
- desconfiar del texto generado (opencode).

Los gestores de contraseñas añaden **auditorías públicas** y ***safe harbor***. Ninguno de los cuatro repositorios trae un código de conducta en la raíz.

## Decisión

### 1. Idioma

A partir de la aceptación de este ADR, va **en inglés**:

- los documentos: `docs/`, ADRs, roadmap, guías, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CLAUDE.md` y la *skill*;
- los mensajes de commit y los títulos y cuerpos de los PRs;
- los issues y las revisiones.

El código ya lo estaba.

- **La interfaz sigue en español y en inglés.** Los textos de la UI no se tocan: viven en sus catálogos y cada idioma se escribe como nativo.
- **Los ADRs existentes se traducen en su sitio**, con el mismo número y la misma decisión.
  - Esta es la **segunda excepción** a la regla de que un ADR aceptado no se edita. La primera fue el cambio de nombre del [ADR 0019](0019-nombre-klav.md).
  - La traducción es mecánica: no cambia ninguna decisión, ni un número, ni un plazo. Si quien traduce encuentra un error, lo anota en el PR y no lo arregla ahí.
  - El texto original queda en la historia de git. El `README.md` de `decisiones/` lo dirá.
- **Los commits viejos no se reescriben.** Sus mensajes en español se quedan en la historia.
- **Los términos** salen de [`docs/glossary.md`](../glossary.md), tomados de la UI en inglés y del código. Las olas de traducción, hechas por varios agentes a la vez, lo usan como fuente única; si falta un término, se añade al glosario en el mismo PR.
- **Datos de prueba que son bytes.** Los `cases` de `docs/vectores/*.json` llevan texto en español dentro de entradas que se cifran o se firman, como `task_request` o `"API de Acme"` en `metadatos.json`. **No se traducen**: cambiarlos cambia los vectores. Solo se traducen `description` y `encoding`, regenerándolos desde `vectors.rs` (§2).
- **Las migraciones SQL no se editan.** sqlx 0.9 guarda el *checksum* de cada una y rechaza un cambio de contenido con `VersionMismatch` (`sqlx-core` 0.9.0, `migrator.rs:274`). Las migraciones nuevas se escriben en inglés.

### 2. Mapa de rutas a renombrar

Revisado con `git grep` sobre `main` (`70750b3`): qué leen el código, las pruebas, la CI, los scripts y los binarios publicados.

**No se renombran nunca.** Hay URLs fijadas en binarios ya distribuidos, y GitHub no redirige un `blob/main/<ruta>` cuando la ruta cambia:

| Ruta | Quién la usa |
|---|---|
| `docs/self-hosting.md` | `crates/klav-client/src/server.rs:35` (mensaje de error de la CLI, `klavd`, iOS), su prueba `crates/klav-cli/tests/servidor.rs:78` y `apps/web/public/index.html` (dos enlaces) |
| `SECURITY.md` (raíz) | `apps/web/public/index.html:534` y el enlace que GitHub pone en la pestaña *Security* |
| `docs/` como carpeta | `apps/web/public/index.html:330` enlaza a `tree/main/docs` |
| `crates/klav-server/migrations/*/NNNN_*.sql` | Técnicamente se podrían renombrar: sqlx identifica cada migración por número y *checksum*, no por nombre. Pero no se gana nada y confunde a quien ya aloja su servidor. Se quedan; las nuevas van en inglés |

**Se renombran en el PR final (ola 3).** Ese PR **no es solo de documentos**: toca código, pruebas y vectores.

| De | A | Lo que hay que cambiar además del archivo |
|---|---|---|
| `docs/decisiones/` | `docs/decisions/` | Unas 100 líneas con enlaces en Markdown; los comentarios `docs/decisiones/0023` de `.github/CODEOWNERS` (#139) |
| `docs/decisiones/NNNN-<titulo-es>.md` | `docs/decisions/NNNN-<title-en>.md` | El número se queda; el título se traduce con el glosario. Lista exacta en el script |
| `docs/diseno.md` | `docs/design.md` | `crates/klav-cli/src/cli.rs:599` (comentario de ayuda) y `CLAUDE.md` |
| `docs/especificacion-cripto.md` | `docs/crypto-spec.md` | `klav-core/src/lib.rs:11` y `crypto/mod.rs:1`, `klav-proto/src/lib.rs:10`, y **`crypto/vectors.rs:1608`**, que escribe la ruta en el campo `spec` de cada vector. Hay que cambiar esa cadena y regenerar con `KLAV_REGEN_VECTORS=1` |
| `docs/modelo-de-amenazas.md` | `docs/threat-model.md` | `SECURITY.md`; enlaces en Markdown |
| `docs/vectores/` | `docs/vectors/` | **`crypto/vectors.rs:34`** (`dir()`), **`model/item.rs:989`** (`elemento.json`) y **`totp.rs:355`** (`totp.json`); `klav-core/src/lib.rs:11` y `vectors.rs:1` |
| `docs/vectores/<nombre>.json` | `docs/vectors/<name>.json` | El campo `name` de cada `VectorFile` en `vectors.rs` (el nombre del archivo sale de ahí). Mapa abajo |
| `docs/diseno-visual/` | `docs/visual-design/` | Comentarios en `apps/extension/src/**` (4), `apps/ios/**` (5) y `apps/web/public/index.html` (1) |
| `docs/sitio-web.md` | `docs/website.md` | Comentarios en `apps/web/Dockerfile`, `entrypoint.sh`, `server.mjs` y `tools/og.html` |
| `docs/probar-hito-a.md` | `docs/try-milestone-a.md` | `examples/login-site/server.mjs` y `examples/playwright/login.mjs` |
| `docs/probar-fase-5.md` | `docs/try-extension.md` | `apps/extension/e2e/ejemplo.spec.ts`, `examples/sitio-extension/server.mjs` y `README.md` |
| `docs/probar-fase-6.md` | `docs/try-ios.md` | `README.md`, `docs/roadmap.md` |
| `docs/probar-agentes-mac.md` | `docs/try-agents-mac.md` | Ya se llama así desde #312: solo quedan las dos menciones del ADR 0033, que aún dicen `probar-agentes-mac.md` |
| `examples/sitio-extension/` | `examples/extension-site/` | **`apps/extension/e2e/ejemplo.spec.ts:12`** y **`pasos.spec.ts:15`** arman la ruta con `resolve(…)` |
| `docs/img/**/<nombre-es>.png` | `docs/img/**/<name-en>.png` | 60 referencias en `docs/*.md`. Opcional: se puede dejar si la ventana es corta |
| `crates/*/tests/<nombre-es>.rs` | `crates/*/tests/<name-en>.rs` | Seguro: la CI corre `cargo test --workspace` y nadie las nombra con `--test`. Solo `docs/ios.md` cita `crates/klav-ffi/tests/cambio_asistido.rs` |
| `apps/extension/e2e/<nombre-es>.spec.ts` | `…/<name-en>.spec.ts` | Seguro: Playwright toma todo `e2e/` (`testDir: "e2e"`) |

Nombres de los vectores, tomados del módulo de `klav-core/src/crypto/` que los calcula:

| Vector | Nombre en inglés | Vector | Nombre en inglés |
|---|---|---|---|
| `adjunto` | `attachment` | `identidad` | `identity` |
| `agentes` | `agent` | `llavero` | `keystore` |
| `compartir` | `share` | `metadatos` | `meta` |
| `elemento` | `item` | `registro` | `record` |
| `envoltura` | `wrap` | `firma` | `sign` |

`secret-key`, `kdf`, `local`, `hpke-rfc9180` y `totp` se quedan como están.

**Cómo se comprueba la regeneración.** Tras `KLAV_REGEN_VECTORS=1 cargo test -p klav-core vectors_match_spec`, el `git diff docs/vectors/` solo puede tocar `spec`, `description` y `encoding`. Los `cases` quedan idénticos byte a byte; si cambia uno solo, el PR está mal.

**Nombres de pruebas en español fuera de `tests/`.** Las funciones `#[test]` con nombres en español, si quedan, se traducen en la ola de su crate, no en la ola 3: no son rutas.

### 3. Plan por olas

**Ola 1, ya.** Se traduce en su sitio, sin renombrar, lo que no toca ningún PR abierto ni ninguna rama en curso. Lo calculé con `gh pr diff <n> --name-only` sobre #128–#139 y #151–#153, y con `git status` en los cuatro *worktrees* sin PR.

- `README.md`;
- `docs/sitio-web.md` y `docs/probar-fase-6.md`;
- los ADRs 0001–0019, 0025 (sitio padre), 0026, 0028 y 0029;
- `crates/klav-core/src/generator/{PASSWORD-RULES,CHANGE-PASSWORD-URLS,WORDLIST}-NOTICE.md`.

`SECURITY.md` ya se traduce en este PR.

Quedan fuera de la ola 1 aunque ningún PR los toque:

- `0020-passkeys.md`, que lo tocará `passkeys/01-core`;
- `0027-app-de-mac.md`, por la app de Mac;
- las `description` de los vectores: viven en `vectors.rs`, que `passkeys/01-core` ya modifica y que #129 y #137 regeneran.

La ola 1 puede repartirse entre varios agentes, un archivo por agente, siempre con el glosario. Va en un PR o en una pila corta; no mezcla traducción con cambios de contenido.

**Ola 2, conforme se mezclen las pilas.** Se traduce en su sitio cada documento cuando su pila deje de tocarlo:

| Cuando se mezcle | Se traduce |
|---|---|
| Ronda de seguridad (#128–#139) | `docs/modelo-de-amenazas.md`, `docs/roadmap.md`, `docs/api.md`, `docs/cli.md`, `docs/klavd.md`, `docs/especificacion-cripto.md`, `docs/diseno.md`, `docs/self-hosting.md` (en su sitio), `docs/probar-hito-a.md`, `docs/probar-fase-5.md`, `skill/SKILL.md`, los ADRs 0021–0024 y 0030, `docs/decisiones/README.md`, y `CLAUDE.md` con la regla nueva (§7) |
| Filtros (#151–#153) | `docs/extension.md`, `docs/ios.md` y `docs/diseno-visual/README.md` |
| Passkeys | `0020-passkeys.md` y las `description` de los vectores en `vectors.rs` |
| App de Mac | `0027-app-de-mac.md` |
| Tiendas y botón «+» | lo que esas ramas añadan en `docs/extension.md` |

Mientras dure la ola 2, los documentos nuevos se escriben ya en inglés. Un PR que toque un documento todavía en español lo deja en español, para no mezclar idiomas en un archivo.

**Ola 3: un solo PR de renombres.**

- **Cuándo:** en una ventana sin otros PRs abiertos y **antes de hacer público el repositorio**, porque GitHub no redirige las URLs `blob/` de archivos renombrados.
- **Qué lleva:**
  - Un script, `scripts/dev/rename-docs.sh`, que mueve cada archivo con `git mv` según el mapa del §2. Reescribe los enlaces relativos y las rutas citadas en `*.md`, `*.rs`, `*.ts`, `*.mjs`, `*.swift`, `*.yml`, `Dockerfile` y `.github/CODEOWNERS`, y regenera los vectores. El script queda en el repositorio para que se pueda revisar.
  - Una **comprobación de enlaces** en CI: un script sin dependencias nuevas que recorre los `*.md`, resuelve cada enlace relativo y su ancla, y falla si alguno no existe.
    - Siguiendo [ADR 0023](0023-ci-en-celesto.md), va como paso de la tarea `fmt` o como tarea propia. Una tarea propia exige su entrada en `ci-tasks.json`, sus pasos `start` y `result` y su nombre en `CI_TASK_CHECK_NAMES`.
    - Se prueba primero sobre `main` sin renombrar.
- **Cómo se verifica:** `cargo test --workspace`, la extensión con e2e, los vectores (§2), la comprobación de enlaces y un `git grep` de cada ruta vieja, que debe devolver vacío salvo en este ADR y en la historia.

### 4. Gobierno del proyecto

| Tema | Lo que adopta Klav | Lo que no, y por qué |
|---|---|---|
| **`CONTRIBUTING.md`** | Sí ([borrador](../../CONTRIBUTING.md)). Dice qué se acepta (correcciones, rendimiento, documentación, importadores, plataformas). Las funciones se discuten en un issue antes y, si cambian el diseño, pasan por un ADR. **Un problema por PR**, con evidencia. Separa el flujo de quien mantiene (`gh stack`, ramas en este repositorio) del flujo externo (*fork* sin CI, §6). <br>**Nota del 2026-11-13:** el [ADR 0040](0040-contribution-gating-and-discussions.md) reemplaza qué se acepta de fuera: correcciones, documentación, traducciones y lo que un mantenedor aceptó en una Idea o un issue. Las funciones, los cambios de rendimiento, los importadores y las plataformas pasan antes por una Idea de *Discussions*, no por un issue; una corrección de fiabilidad cuenta como corrección | No copia el «no buscamos contribuciones» de T3 Code: Klav quiere comunidad. Tampoco obliga a enlazar un issue en cada corrección, como opencode, porque es demasiado para un proyecto pequeño |
| **Contribuciones con IA** | Se aceptan, juzgadas por el trabajo y no por quién lo escribió (T3 Code). Se exige: <br>(1) **declarar** el modelo y el *harness* en el PR y en el commit (`Co-Authored-By`); <br>(2) que **una persona** firme el DCO, entienda y pueda explicar cada línea, y responda a la revisión; <br>(3) **evidencia** de lo corrido, no «tests pass»; <br>(4) descripciones cortas y propias; <br>(5) **nunca** pegar datos reales de una bóveda, secretos ni logs sin redactar en issues, PRs o *prompts* compartidos; <br>(6) el agente sigue `AGENTS.md`. | Klav no tiene lista negra de modelos (T3 Code sí): no es auditable y envejece mal. Tampoco prohíbe los reportes de seguridad hechos con IA (opencode): exige una prueba de concepto reproducida por una persona, y cierra sin respuesta los volcados de escáneres o LLMs sin verificar |
| **Plantillas** | Formularios YAML de error y de función, y `config.yml` con `blank_issues_enabled: false` y un enlace de contacto a `SECURITY.md`. Un enlace no deja abrir el reporte por error en público, cosa que una plantilla «de seguridad» sí permitiría. Plantilla de PR con *Problem*, *Change*, *Design and rules* y *Test plan* de **solo casillas marcadas**. <br>**Nota del 2026-11-13:** el [ADR 0040](0040-contribution-gating-and-discussions.md) lleva el formulario de función a *Discussions* › Ideas (`.github/DISCUSSION_TEMPLATE/ideas.yml`), y `config.yml` enlaza la seguridad, Ideas y Q&A | No hay *Discussions* por ahora (pregunta P6). **Nota del 2026-11-13:** reemplazado por el [ADR 0040](0040-contribution-gating-and-discussions.md): *Discussions* con Announcements, Ideas y Q&A. Tampoco hay triage automático con agentes ni cierre a las dos horas: con el volumen de hoy es más ruido que ayuda |
| **Código de conducta** | [Contributor Covenant 3.0](../../CODE_OF_CONDUCT.md), sin el *front matter* TOML, con el canal de reporte relleno y la atribución intacta (CC BY-SA 4.0) | Ninguno de los cuatro lo tiene en la raíz, pero GitHub lo cuenta en el *community profile*, y sin él no hay a dónde reportar |
| **CODEOWNERS** | #139 ya lo crea. Propongo añadir en la ola 2, como regla final (gana la última que coincide): `/docs/especificacion-cripto.md`, `/docs/vectores/`, `/docs/modelo-de-amenazas.md`, `/SECURITY.md`, `/crates/klav-server/migrations/`, `/crates/klav-ffi/` (el `unsafe`), `/crates/klav-touchid/` y `/apps/ios/Config/` | No hay equipos: hoy solo existe `@OmarAlex24`. <br>**Nota del 2026-11-13:** como el *ruleset* ya no exige la revisión de CODEOWNERS ([ADR 0040](0040-contribution-gating-and-discussions.md), Q10 enmendada), `CODEOWNERS` solo pide la revisión; nunca bloquea un *merge* |
| **Revisión, CI y protección de `main`** | *Ruleset* sobre `main` (§6): PR obligatorio, los siete checks de [ADR 0023](0023-ci-en-celesto.md) (**nota del 2026-11-13:** son ocho, con `docs`; [ADR 0040](0040-contribution-gating-and-discussions.md) §5), revisión de CODEOWNERS, conversaciones resueltas, sin *force push* y sin borrar la rama. Omar queda en la lista de *bypass*, porque GitHub no deja aprobar el PR propio. <br>**Nota del 2026-11-13:** el [ADR 0040](0040-contribution-gating-and-discussions.md) (Q10, enmendada ese mismo día) cambia esto: PR obligatorio con 0 aprobaciones, sin exigir la revisión de CODEOWNERS y con la lista de *bypass* vacía, así que las reglas atan a todos, también a Omar. Un mantenedor sigue revisando, y solo quien tiene permiso de escritura puede hacer *merge*: eso viene de los permisos de GitHub, no del *ruleset*. Las aprobaciones suben a 1, con un ADR nuevo, cuando haya un segundo mantenedor. Tampoco exige conversaciones resueltas (Q10, segunda enmienda del mismo día): los comentarios siguen a la vista, pero no bloquean | No se exigen commits firmados: los agentes no tienen llaves, y el DCO cubre el origen |
| **Commits** | Se mantiene `<tipo>: <descripción>` con `feat`, `fix`, `docs`, `refactor`, `test`, `chore` y `ci`; el *scope* es opcional, como en opencode (`fix(extension): …`). El título del PR sigue la misma forma, porque es el commit al mezclar con *squash* | No se añade `commitlint` ni otra dependencia: basta la revisión, y más adelante un *check* sin dependencias |
| **Changelog y versiones** | `CHANGELOG.md` en la raíz, escrito para personas por versión (como opencode), con los PRs enlazados. Se escribe **al publicar**, no en cada PR. El *workspace* de Rust, la extensión y el SDK comparten versión SemVer (`vX.Y.Z`; antes de la 1.0, una *minor* puede romper). iOS y Mac llevan su versión de tienda con *tags* `ios/vX.Y.Z` y `mac/vX.Y.Z`. Notas en GitHub Releases. Los formatos binarios tienen versión propia en su primer byte, sin relación con SemVer | Sin *changesets*: hay un solo paquete npm publicable y ya existe la disciplina del roadmap. Sin *nightlies* hasta que haya usuarios que las pidan |
| **CLA o DCO** | **DCO 1.1**: cada commit lleva `Signed-off-by:` (`git commit -s`) de la **persona** responsable. El *inbound* es igual al *outbound* (Apache-2.0 §5; AGPL en `klav-server`). Se comprueba con un *check* cuando llegue el primer PR externo; así se resuelve lo que dejó abierto [ADR 0003](0003-licencias.md) | No hay CLA (Bitwarden sí lo tiene): frena a quien quiere contribuir y solo sirve si Omar quiere relicenciar `klav-server`. Esa decisión es suya (pregunta P3) |
| **Etiquetas y triage** | Tipo: `bug`, `enhancement`, `documentation`, `question`. Área: `area:core`, `area:server`, `area:cli`, `area:klavd`, `area:extension`, `area:ios`, `area:mac`, `area:web`, `area:ci`. Revisión: `crypto` (pide la revisión de `klav-core`), `adr-needed`. Estado: `needs-triage` (lo ponen las plantillas), `needs-info`, `accepted`. Entrada: `good first issue`, `help wanted`. Cierre: `duplicate`, `wontfix`, `invalid`. Omar hace triage una vez por semana; `needs-info` sin respuesta en 14 días se cierra a mano | Sin `size:*` ni `vouch:*` automáticos (T3 Code): sin volumen de PRs externos no aportan nada todavía |
| **Vulnerabilidades** | [`SECURITY.md`](../../SECURITY.md) revisado, en inglés:<br>• **Canales:** GitHub Private Vulnerability Reporting, y el correo como respaldo, porque el reporte privado de GitHub solo existe en repositorios públicos y hoy devuelve 404.<br>• **Plazos:** acuse en 72 h, triage en 7 días y corrección según severidad.<br>• **Divulgación coordinada:** 90 días como tope (Proton pide 120; Bitwarden, un tiempo «razonable»). La corrección sale publicada con aviso CVE vía GHSA.<br>• **Alcance:** el del modelo de amenazas.<br>• **Reglas de prueba:** solo cuentas propias, sin DoS ni ingeniería social, y mejor un servidor propio que `api.klav.dev`.<br>• ***Safe harbor*** al estilo de Proton.<br>• **IA:** se exige una prueba de concepto verificada por una persona.<br>• **Auditorías:** los informes externos se publican en `docs/audits/` (hito C del roadmap). | Sin *bug bounty* con dinero por ahora, solo crédito en el aviso y en el CHANGELOG. Sin HackerOne. Sin PGP: el reporte privado de GitHub ya cifra en tránsito y deja todo en un solo lugar |
| **Licencias** | Ver §5 | — |

### 5. Licencias y avisos de terceros

- **Se mantiene [ADR 0003](0003-licencias.md):** `LICENSE-APACHE` en la raíz para todo, y `crates/klav-server/LICENSE` con AGPL-3.0-only. GitHub detecta Apache-2.0. **No se añade MIT**: la doble licencia MIT/Apache es costumbre en Rust, pero cambiarla es decisión de Omar (pregunta P2).
- **`NOTICE` de Apache-2.0:** no hace falta mientras Klav no tenga avisos propios que exigir. No se crea.
- **Falta un aviso de terceros en la raíz.** Se propone `THIRD-PARTY-NOTICES.md`, que se creará en la ola 1 o en un PR aparte. Debe listar lo que Klav **empaqueta**:
  - **Apple `password-manager-resources`, MIT**, dos archivos: `password-rules.json` y `change-password-urls.json`, en `klav-core/src/generator/`. Entran en cada binario con `include_str!` (`rules.rs:25` y `change_password.rs:20`), y la MIT exige llevar el aviso «*in all copies or substantial portions*». Hoy el aviso está solo en el código fuente (`*-NOTICE.md`). Hay que llevarlo también a lo que se distribuye: la sección «Acknowledgements» de iOS y Mac, el `about` de la CLI o un archivo junto al binario, y la extensión.
  - **EFF Large Wordlist, CC BY 3.0 US** (`eff_large_wordlist.txt`, también con `include_str!`). Exige atribución en lo distribuido.
  - **Geist y Departure Mono, SIL OFL 1.1**, en `apps/ios/Shared/Fonts/`, `apps/extension/static/fonts/` y `apps/web/public/fonts/`. Ya llevan su licencia al lado.
  - Las dependencias de Rust y npm: sus licencias ya las comprueba `cargo-deny`. Un generador (`cargo about` o similar) sería una dependencia nueva, y va en su propio ADR si hace falta.
- Esto no cambia el código. Mostrar los avisos en las apps sí lo cambia, y va en su propio PR.

### 6. Configuración de GitHub propuesta (no se aplica en este PR)

Nada de esto lo toca un agente: lo hace Omar en *Settings* cuando acepte, en este orden.

**Antes de hacer público el repositorio:**

1. Revisar toda la historia en busca de secretos (`gitleaks detect --log-opts="--all"` o similar), porque los commits viejos se quedan. Si aparece algo, se rota, no se reescribe.
2. Mezclar la ola 3 (renombres) con la comprobación de enlaces en verde.
3. Revisar que `docs/` no tenga datos personales ni URLs internas que no deban salir. Por ejemplo, la URL de Railway, que ADR 0028 citaba y que sigue sirviendo.

**Al hacerlo público:**

4. *Security*:
   - activar *Private vulnerability reporting*;
   - activar *Secret scanning* con *Push protection*;
   - activar las alertas de Dependabot. Sus actualizaciones automáticas no hacen falta, porque `cargo-deny` ya vigila los avisos.
5. *Actions*:
   - exigir aprobación para los *workflows* de colaboradores externos, la nota de 2026-11-05 en [ADR 0023](0023-ci-en-celesto.md);
   - dejar los permisos del `GITHUB_TOKEN` en solo lectura por defecto.
6. *Rules* → *Ruleset* «main»:
   - PR obligatorio, con 1 aprobación y revisión de CODEOWNERS. **Nota del 2026-11-13:** 0 aprobaciones y sin exigir la revisión de CODEOWNERS ([ADR 0040](0040-contribution-gating-and-discussions.md), Q10 enmendada);
   - los siete checks: `fmt`, `clippy`, `test`, `test (postgres)`, `docker`, `extension` y `cargo-deny`. **Nota del 2026-11-13:** son ocho, con `docs` ([ADR 0039](0039-public-docs-site.md)); el [ADR 0040](0040-contribution-gating-and-discussions.md) los fija y [`docs/github-settings.md`](../github-settings.md) trae el *ruleset* entero;
   - conversaciones resueltas. **Nota del 2026-11-13:** ya no se exigen ([ADR 0040](0040-contribution-gating-and-discussions.md), Q10, segunda enmienda): cualquiera con cuenta podría abrir un hilo en un PR de Omar, y un solo hilo sin resolver tumba un `gh stack merge` entero;
   - bloquear *force push* y el borrado de la rama;
   - *bypass*: Omar. **Nota del 2026-11-13:** la lista queda vacía ([ADR 0040](0040-contribution-gating-and-discussions.md), Q10 enmendada). En una emergencia, Omar, como administrador, desactiva el *ruleset* en *Settings* y lo vuelve a activar. Es la única salida, y es a propósito: cualquier cambio al *ruleset* mismo es una acción de administrador en *Settings*.

   Recordatorio de #139: un PR desde un *fork* no corre la CI, así que se prueba empujando su rama aquí.
7. *General*:
   - activar «Automatically delete head branches»;
   - dejar el *squash merge* como método por defecto (pregunta P7).
8. Etiquetas del §4: `gh label create`, a mano o con un script en la ola 1.

### 7. Texto nuevo para `CLAUDE.md` (se aplica al aceptar, en la ola 2)

`CLAUDE.md` no cambia en este PR. Al aceptar este ADR, la línea «Docs internos en español; código, identificadores y comentarios de código en inglés.» del apartado *Flujo de trabajo* se cambia por estas, ya en inglés (el resto del archivo se traduce en la ola 2):

```markdown
- Everything in the repository is in English: docs, ADRs, the roadmap, code, identifiers, comments, commit messages, PR titles and bodies, and review comments. Use the terms in [`docs/glossary.md`](docs/glossary.md); if a term is missing, add it in the same PR.
- The UI ships in English and Spanish. User-facing strings live in `apps/ios/Shared/Localizable.xcstrings` and `apps/extension/_locales/{en,es}`; write each language natively, never as a literal translation.
- While a document is still in Spanish (translation waves, ADR 0031 §3), edit it in Spanish and leave the translation to its wave. New documents are written in English.
- Never translate the `cases` in `docs/vectors/*.json` or edit an existing SQL migration: both are bytes that tests or databases check.
- Contributions follow [`CONTRIBUTING.md`](CONTRIBUTING.md): one problem per PR, evidence of what you ran, and the model and harness that did the work named in the PR and in `Co-Authored-By`.
```

Y la línea de commits pasa a:

```markdown
- Commits: `<type>: <description>` or `<type>(<scope>): <description>` (`feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`), in English, with a human `Signed-off-by:` line (DCO) once ADR 0031 is accepted.
```

## Consecuencias

- Klav se puede leer y contribuir en inglés, sin perder la UI en español.
- Durante las olas 1 y 2 hay documentos en dos idiomas. Es aceptable: el glosario mantiene los mismos términos, y cada archivo está en un solo idioma.
- La ola 3 congela los PRs durante una ventana corta y toca código, pruebas y vectores. A cambio, las rutas quedan en inglés antes de que exista un solo enlace externo.
- `docs/self-hosting.md` y `SECURITY.md` quedan fijados para siempre. Si algún día se reorganiza `docs/`, esas dos rutas siguen existiendo, aunque sea como página que remite a la nueva.
- El DCO añade una línea a cada commit y obliga a que firme una persona, no un agente.
- Los archivos de comunidad de este PR valen desde que se mezcle, con las respuestas de Omar de abajo. Las reglas de idioma de `CLAUDE.md` cambian en la ola 1.

## Preguntas para Omar

| # | Pregunta | Respuesta por defecto si no dices nada |
|---|---|---|
| P1 | ¿Se acepta el inglés para docs, commits y PRs desde ya, con la UI en es/en? | Sí, desde que se mezcle este PR, con las olas del §3 |
| P2 | ¿Doble licencia `MIT OR Apache-2.0` para lo que no es el servidor, como es costumbre en Rust? | No: se queda Apache-2.0 (ADR 0003) |
| P3 | ¿DCO o CLA? | DCO 1.1, sin CLA. Si quieres poder relicenciar `klav-server` (por ejemplo, una licencia comercial del servidor), entonces CLA solo para `crates/klav-server/` |
| P4 | ¿Qué correo usan `SECURITY.md` y el código de conducta? | Una dirección personal por ahora. Propuesta: crear `security@klav.dev` y `conduct@klav.dev` (tienes el dominio) y cambiarlos antes de abrir el repositorio |
| P5 | ¿Divulgación coordinada a 90 días y *safe harbor* en `SECURITY.md`? | Sí a ambos, con el texto del borrador. Es un compromiso legal: si prefieres no darlo todavía, se quita la sección |
| P6 | ¿Activar GitHub *Discussions* para ideas y dudas? | No por ahora: las ideas van a un issue con la plantilla de función. **Nota del 2026-11-13:** reemplazada por el [ADR 0040](0040-contribution-gating-and-discussions.md) |
| P7 | ¿Método de mezcla en `main`? | Solo *squash*, como hoy (cada PR es un commit `… (#N)`); quitar *merge commit* y *rebase* |
| P8 | ¿Renombrar también las capturas `docs/img/**` y las pruebas con nombre en español en la ola 3? | Las pruebas sí; las capturas también, si la ventana lo permite |
| P9 | ¿Cuándo es la ventana de la ola 3? | Al mezclar la ronda de seguridad, los filtros y las passkeys, y siempre antes de hacer público el repositorio |
| P10 | ¿El triage semanal y el cierre de `needs-info` a los 14 días? | Sí, a mano. Sin automatizar hasta que haya volumen |
| P11 | ¿Nombre del producto en inglés para el «kit de emergencia»? | «Emergency kit», como ya dice la UI (no «Emergency Kit»). El «Secret Key» sigue con mayúsculas |

## Respuesta de Omar (2026-11-05)

| # | Respuesta |
|---|---|
| P1 | Sí: inglés para docs, commits y PRs desde que se mezcle este PR; la UI sigue en es/en. **Nota del 2026-11-06:** Omar pidió aplicar ya la regla del §7 a `CLAUDE.md`, sin la línea del DCO |
| P2 | No: se queda Apache-2.0 |
| P3 | DCO 1.1, sin CLA (tampoco para `crates/klav-server/`). **Nota del 2026-11-06:** el `Signed-off-by:` empieza cuando el repositorio sea público y lo pone una persona; los agentes nunca firman por Omar |
| P4 | `security@klav.dev` para seguridad y `conduct@klav.dev` para conducta, con reenvío de Cloudflare Email Routing. Omar los crea antes de mezclar este PR. **Nota del 2026-11-06:** `klav.dev` todavía no recibe correo (no tiene registros MX). Hasta que lo reciba, `SECURITY.md` y `CODE_OF_CONDUCT.md` usan una dirección personal; se cambian a las dos direcciones de `klav.dev` antes de hacer público el repositorio. **Ese mismo día, más tarde:** Omar activó Cloudflare Email Routing (MX de Cloudflare y SPF), y los dos archivos ya usan `security@klav.dev` y `conduct@klav.dev` |
| P5 | Sí a ambos: divulgación coordinada a 90 días y *safe harbor* |
| P6 | Sin *Discussions* por ahora. **Nota del 2026-11-13:** el [ADR 0040](0040-contribution-gating-and-discussions.md) la reemplaza: *Discussions* con Announcements, Ideas y Q&A, y las ideas fuera de los issues |
| P7 | Solo *squash* |
| P8 | Las pruebas sí; las capturas, si la ventana lo permite |
| P9 | Al mezclar la ronda de seguridad, los filtros y las passkeys, antes de hacer público el repositorio |
| P10 | Sí, a mano |
| P11 | «Emergency kit» |
