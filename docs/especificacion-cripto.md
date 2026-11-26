# Especificación criptográfica de Klav (formato v1)

Estado: **borrador v1**, implementado por `crates/klav-core` (fase 1). Cualquier cambio de bytes exige subir la versión del formato o del tipo afectado, actualizar este documento y regenerar los vectores de `docs/vectores/`.

Este documento describe **byte a byte** lo que hace el núcleo. Otra implementación que siga esta especificación debe producir exactamente los vectores de prueba de §11. El *porqué* está en [`diseno.md`](diseno.md) §4 y en el [modelo de amenazas](modelo-de-amenazas.md).

---

## 1. Primitivas y dependencias

| Uso | Primitiva | Crate (ADR [0005](decisiones/0005-dependencias-criptograficas.md)) |
|---|---|---|
| Cifrado simétrico autenticado | XChaCha20-Poly1305 (nonce de 24 bytes, tag de 16) | `chacha20poly1305` 0.11 |
| Adjuntos por bloques | STREAM (variante `StreamBE32`) sobre XChaCha20-Poly1305 | `aead-stream` 0.6 |
| Derivación desde contraseña | Argon2id, versión 0x13 (RFC 9106) | `argon2` 0.6 |
| Derivación de llaves | HKDF-SHA256 (RFC 5869) | `hkdf` 0.13, `sha2` 0.11 |
| Cifrado a una llave pública | HPKE (RFC 9180), modo `base` | `hpke` 0.15 |
| Autenticación con el servidor | OPAQUE (RFC 9807), suite `klav-opaque-v1` (§4.5) | `opaque-ke` 4.0 (ADR [0009](decisiones/0009-opaque.md)) |
| Firmas | Ed25519 (RFC 8032), verificación estricta | `ed25519-dalek` 3 |
| Aleatoriedad | CSPRNG del sistema operativo | `getrandom` 0.4 |
| Comparación en tiempo constante | — | `subtle` 2.6 |
| Contraseñas filtradas (opcional, solo el prefijo de Have I Been Pwned; ADR [0022](decisiones/0022-generador-historial-y-cambio-asistido.md) §4) | SHA-1, nunca para un uso de seguridad de Klav | `sha1` 0.11, feature `breach-check` (TOTP usa HMAC-SHA1 aparte, RFC 6238) |
| Secretos en memoria | `SecretBox`, borrado al soltar | `secrecy` 0.10, `zeroize` 1.9 |
| Atestación del proxy alojado (opcional, feature `nitro-attestation`; ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md)) | ECDSA P-384 con SHA-384 y X.509, solo verificación (§15) | `p384` 0.14, `x509-cert` 0.3, `der` 0.8, `spki` 0.8 |

No hay primitivas implementadas a mano. Todo el material aleatorio (llaves, nonces, sales, IDs) sale del CSPRNG del sistema operativo; si este falla, el proceso aborta (no hay forma segura de seguir).

## 2. Codificaciones comunes

### 2.1 Enteros
Todos los enteros van en **big-endian**: `u32_be(x)` ocupa 4 bytes y `u64_be(x)` ocupa 8.

### 2.2 Prefijo de longitud
`lp(x) = u32_be(len(x)) ‖ x`. Un campo no puede pasar de 2³²−1 bytes.

### 2.3 Tuplas con etiqueta
```
tuple(label, f1, …, fn) = lp(label) ‖ lp(f1) ‖ … ‖ lp(fn)
```
`label` es una cadena ASCII que separa dominios. Como cada campo lleva su longitud, la codificación es inyectiva: `tuple(l, "ab", "c") ≠ tuple(l, "a", "bc")`. Nunca se concatenan campos sin prefijo.

Etiquetas usadas en v1 (todas empiezan con `klav/v1/`):

| Etiqueta | Dónde |
|---|---|
| `klav/v1/kdf/secret-key` | info de HKDF, rama del Secret Key (§4.3) |
| `klav/v1/kdf/kek` | info de HKDF, KEK (§4.3) |
| `klav/v1/kdf/opaque` | info de HKDF, entrada de OPAQUE (§4.3, §4.5) |
| `klav/v1/kdf/local-key` | info de HKDF (dentro de `tuple`), llave local del dispositivo (§12.2) |
| `klav/v1/opaque` | contexto de OPAQUE (§4.5) |
| `klav/v1/server/decoy-kdf-salt` | sal de los parámetros señuelo (§4.5) |
| `klav/v1/server/token` | resumen de los tokens de sesión (§4.6) |
| `klav/v1/server/invite` | resumen de los códigos de invitación al registro, ADR [0048](decisiones/0048-invite-beta-and-distribution.md) (§4.7) |
| `klav/v1/secret-key/checksum` | checksum del Secret Key (§4.2) |
| `klav/v1/identity/secrets` | AAD de las llaves privadas selladas (§6.3) |
| `klav/v1/identity/fingerprint` | huella de una identidad (§6.2) |
| `klav/v1/wrap/project-key` | AAD de llave de proyecto envuelta (§5.2) |
| `klav/v1/wrap/item-key` | AAD de llave de elemento envuelta (§5.2) |
| `klav/v1/wrap/attachment-key` | AAD de llave de adjunto envuelta (§5.2) |
| `klav/v1/item/overview` | AAD de la sección *overview* (§7) |
| `klav/v1/item/details` | AAD de la sección *details* (§7) |
| `klav/v1/vault/meta` | AAD de los metadatos de una bóveda (§7.2) |
| `klav/v1/project/meta` | AAD de los metadatos de un proyecto (§7.2) |
| `klav/v1/local/identity` | AAD de la identidad local del dispositivo (§12.2) |
| `klav/v1/local/data` | AAD de los datos locales del dispositivo (§12.2) |
| `klav/v1/kdf/keystore-wrap` | `info` de HKDF de la llave que envuelve la llave local en el almacén de la plataforma (§12.3) |
| `klav/v1/local/keystore-wrap` | AAD de la llave local envuelta por el almacén de la plataforma (§12.3) |
| `klav/v1/share/vault-key` | `info` de HPKE, llave de bóveda (§8) |
| `klav/v1/share/project-key` | `info` de HPKE, llave de proyecto (§8) |
| `klav/v1/share/item-key` | `info` de HPKE, llave de un elemento compartida en un grant por elemento (§8, §13.4) |
| `klav/v1/sig/vault-key` | la cuenta dueña firma su llave de bóveda compartida, ADR [0030](decisiones/0030-ronda-de-seguridad-2026-11.md) (§8.3) |
| `klav/v1/attachment` | AAD de cada bloque de un adjunto (§10) |
| `klav/v1/sig/…` | prefijo obligatorio de toda firma (§9) |
| `klav/v1/agent/labels` | AAD de los nombres que acompañan un grant (§13.4) |
| `klav/v1/sig/agent-request` | petición firmada de un agente (§13.3) |
| `klav/v1/sig/agent-grant` | grant firmado por la cuenta (§13.4) |
| `klav/v1/grant-change` | resumen local `SHA-256(tuple(etiqueta, bytes firmados del grant vigente, JSON de lo que el cambio resuelve: IDs de proyecto, política y `rotate_removed`))` que ata el cambio de un grant a la hoja que vio la persona; no es una firma, no sale del dispositivo y no cambia ningún formato, ADR [0033](decisiones/0033-agentes-desde-la-app-de-mac.md), enmienda del 2026-11-10, F3 (§13.4; vector `grant_change_digest` en `agentes.json`) |
| `klav/v1/sandbox/secret` | resumen del secreto de un sandbox que guarda el proxy en lugar del secreto (§13.10) |
| `klav/v1/sig/approval` | decisión sobre una aprobación `ask` (§13.5) |
| `klav/v1/sig/agent-revocation` | revocación de un agente (§13.6) |
| `klav/v1/audit/event` | eslabón de la cadena de la bitácora (§13.7) |
| `klav/v1/sig/audit-head` | cabeza de la bitácora firmada por un dispositivo (§13.7) |
| `klav/v1/passkey/private-key` | AAD de la llave privada de una passkey sellada con la llave de bóveda, ADR [0020](decisiones/0020-passkeys.md) (§14.3) |
| `klav/v1/local/outbox` | AAD de la cola de salida local (§14.7): en el escritorio, la del historial del generador (ADR [0022](decisiones/0022-generador-historial-y-cambio-asistido.md)); en iOS, la de las passkeys (ADR [0020](decisiones/0020-passkeys.md)) |
| `klav/v1/sig/task-decision` | decisión sobre una solicitud de tarea, ADR [0021](decisiones/0021-solicitudes-de-tarea.md) (§13.8) |
| `klav/v1/sig/task-end` | la persona termina una tarea, ADR [0021](decisiones/0021-solicitudes-de-tarea.md) (§13.8) |
| `klav/v1/item/password-record` | AAD del registro de contraseñas de un elemento, sellado con la llave de bóveda (§7.3) |
| `klav/v1/sig/agent-pause` | pausa o reanudación de los agentes, ADR [0033](decisiones/0033-agentes-desde-la-app-de-mac.md) (§13.9) |
| `klav/v1/sig/sandbox-revoke` | la persona revoca un sandbox de un proxy o todos, ADR [0036](decisiones/0036-sandboxes-de-agentes.md) E3.3 (§13.11) |
| `klav/v1/agent/secret-request` | `info` de HPKE de la propuesta cifrada de una solicitud de secreto (tipo `0x25`), ADR [0046](decisiones/0046-agent-secret-requests.md) (§13.14) |
| `klav/v1/sig/secret-request-decision` | decisión de la persona sobre una solicitud de secreto de un agente, ADR [0046](decisiones/0046-agent-secret-requests.md) (§13.14) |
| `klav/v1/proxy/local-client` | resumen del token de un cliente local que lleva el grant del proxy, ADR [0049](decisiones/0049-mcp-gateway.md) (§13.16) |
| `klav/v1/proxy/mcp-args` | resumen de los argumentos de una llamada `tools/call` de la pasarela MCP, ADR [0049](decisiones/0049-mcp-gateway.md) (§13.16) |
| `klav/v1/proxy/tool-definition` | solo local: resumen de la definición de una herramienta que mostró `tools/list`, que el proxy guarda en memoria para notar que cambió (ADR [0049](decisiones/0049-mcp-gateway.md) §5.2). Nunca sale del proxy, nadie lo firma y no tiene vectores |
| `klav/v1/proxy/hosted-account` | `info` de HKDF (dentro de `tuple`) de las llaves por cuenta del proxy alojado, ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md) (§15.6) |
| `klav/v1/proxy/enclave-binding` | vínculo que lleva el `user_data` de la atestación del proxy alojado, ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md) (§15.6) |
| `klav/v1/proxy/enclave-handoff` | `info` de HPKE de la semilla que un enclave pasa a otro, ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md) (§15.6) |
| `klav/v1/sig/hosted-proxy-enroll` | la cuenta pide al proxy alojado su agente, ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md) (§15.6) |
| `klav/v1/proxy/hosted-seed` | `info` de HKDF (dentro de `tuple`) que mezcla la entropía del NSM en una semilla nueva del proxy alojado, ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md) (§15.6) |
| `klav/v1/proxy/hosted-service` | `info` de HKDF (dentro de `tuple`) de la llave de servicio del proxy alojado, ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md) §8 (§15.6) |
| `klav/v1/sig/hosted-proxy-registration` | el enclave marca con su llave de servicio el registro del agente alojado de una cuenta, ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md) §8 (§15.6, §15.8) |
| `klav/v1/sig/enclave-manifest` | la autoridad de publicación firma el manifiesto de los enclaves, ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md) (§15.5) |

Las etiquetas de HKDF (`kdf/…`) y el contexto de OPAQUE se usan como bytes ASCII tal cual, sin `lp`, salvo `kdf/local-key` y `kdf/keystore-wrap`, que llevan contexto y van dentro de `tuple` como `server/decoy-kdf-salt`; `proxy/hosted-account`, `proxy/hosted-seed` y `proxy/hosted-service` también van dentro de `tuple`. El resto siempre va dentro de `tuple`.

### 2.4 Encabezado y AAD
Todo dato binario persistido o transmitido empieza con un encabezado de dos bytes:

```
header = version(1) ‖ kind(1)        version = 0x01 en este documento
```

Un lector **rechaza** cualquier `version` desconocida y cualquier `kind` distinto del que espera la operación. En todo blob cifrado con AEAD:

```
AAD = header ‖ tuple(label, contexto…)
```

El encabezado entra en el AAD, así que no se puede cambiar el tipo ni la versión de un blob sin que falle la autenticación. Además, la etiqueta depende del tipo: aunque se reescriba el byte `kind`, el AAD calculado por el lector no coincide.

### 2.5 Identificadores
Cuentas, bóvedas, proyectos, elementos, adjuntos y campos se identifican con **UUID v4 de 16 bytes**, generados por el cliente (deben existir antes de cifrar, porque van en el AAD). Dentro de `tuple` y de los formatos binarios van como los 16 bytes crudos. En texto van en forma canónica con guiones (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).

## 3. Tipos de blob

| `kind` | Nombre | Longitud total | Contenido | Sección |
|---|---|---|---|---|
| `0x01` | identity-secrets | 106 | llaves privadas de identidad selladas con la KEK | §6.3 |
| `0x02` | project-key-wrap | 74 | llave de proyecto envuelta con la de bóveda | §5.2 |
| `0x03` | item-key-wrap | 74 | llave de elemento envuelta con la de proyecto | §5.2 |
| `0x04` | attachment-key-wrap | 74 | llave de adjunto envuelta con la de elemento | §5.2 |
| `0x05` | public-identity | 66 | llaves públicas X25519 + Ed25519 | §6.2 |
| `0x06` | kdf-params | 30 | parámetros de Argon2id y sal | §4.4 |
| `0x07` | agent-secret | 66 | llaves privadas de un agente, sin cifrar (solo en la máquina del agente) | §13.2 |
| `0x10` | item-overview | 42 + n | sección *overview* de un elemento | §7 |
| `0x11` | item-details | 42 + n | sección *details* de un elemento | §7 |
| `0x12` | vault-meta | 42 + n | nombre y descripción de una bóveda | §7.2 |
| `0x13` | project-meta | 42 + n | nombre y descripción de un proyecto | §7.2 |
| `0x14` | grant-labels | 42 + n | nombres de bóveda y proyecto para un agente, sellados con la llave de proyecto | §13.4 |
| `0x15` | passkey-key | 74 | llave privada P-256 de una passkey, sellada con la llave de bóveda (ADR 0020) | §14.3 |
| `0x16` | password-record | 42 + n | contraseñas anteriores y pendiente de un elemento, selladas con la llave de bóveda (ADR 0022) | §7.3 |
| `0x20` | shared-vault-key | 82 | llave de bóveda cifrada con HPKE para un miembro | §8 |
| `0x21` | shared-project-key | 82 | llave de proyecto cifrada con HPKE para un miembro | §8 |
| `0x23` | shared-item-key | 82 | llave de un elemento cifrada con HPKE para un agente con un grant por elemento (ADR 0036 §2 y E10) | §8, §13.4 |
| `0x25` | secret-request-proposal | 50 + n | propuesta JSON de una solicitud de secreto cifrada con HPKE para la cuenta (ADR 0046 §1) | §13.14 |
| `0x28` | enclave-handoff | 82 + n | semilla del proxy alojado y estado del enclave, cifrados con HPKE para la llave X25519 atestiguada de otro enclave (ADR 0051 §4.2) | §15.6 |
| `0x30` | attachment | 25 + n + 16·k | adjunto cifrado con STREAM | §10 |
| `0x40` | local-identity | 106 | llaves privadas de identidad selladas con la llave local (nunca salen del dispositivo) | §12.2 |
| `0x41` | local-data | 42 + n | datos locales sellados con la llave local (caché, tokens) | §12.2 |
| `0x42` | keystore-wrap | 74 | llave local envuelta con un secreto del almacén de la plataforma (Secure Enclave) | §12.3 |
| `0x43` | local-outbox | 42 + n | cola de salida local, sellada con la llave local (nunca sale del dispositivo): la del historial del generador en `klavd` (ADR 0022) y la de la extensión de iOS (ADR 0020) | §14.7 |

Los valores `0x08–0x0F`, `0x17–0x1F`, `0x22`, `0x24`, `0x26`, `0x27`, `0x29–0x2F`, `0x31–0x3F` y `0x44–0xFF` están reservados. El `0x22` es del paquete del enlace del ADR 0029, el `0x24` del comando de `inject` del ADR 0041, el `0x26` del reporte de origen del ADR 0047 y el `0x27` de §13.15 (ADR 0049), todavía sin implementar. El rango `0x40–0x4F` es para blobs que solo existen en el dispositivo: un servidor nunca debe recibirlos.

### 3.1 Sobre XChaCha20-Poly1305
Los tipos `0x01–0x04`, `0x10–0x14` y `0x40–0x42` usan el mismo sobre (y también `0x15`, `0x16` y `0x43`):

```
blob = header(2) ‖ nonce(24) ‖ ciphertext(n) ‖ tag(16)
ciphertext ‖ tag = XChaCha20-Poly1305-Encrypt(key, nonce, plaintext, AAD)
AAD  = header ‖ tuple(label, contexto…)
```

- `nonce` son 24 bytes aleatorios nuevos en cada sellado. Con nonces de 192 bits, la probabilidad de colisión es despreciable aunque una llave selle muchísimos mensajes.
- Sobrecarga fija: 42 bytes.
- Al abrir: se valida el encabezado (§2.4), que haya al menos `24 + 16` bytes tras él y luego el tag. **Cualquier** fallo de autenticación (llave equivocada, bit alterado, contexto distinto, versión distinta) devuelve el mismo error opaco `Decryption`.

## 4. Llaves de la cuenta

### 4.1 Contraseña maestra
La contraseña se normaliza con **Unicode NFKD** (crate `unicode-normalization`) y se codifica en UTF-8:

```
P = UTF-8(NFKD(contraseña))
```

No se recortan espacios ni se cambia mayúsculas/minúsculas. NFKD hace que la misma contraseña escrita en teclados o sistemas distintos (por ejemplo, `é` precompuesta frente a `e` + acento combinado) produzca los mismos bytes.

### 4.2 Secret Key
- 16 bytes aleatorios (`sk`), generados en el registro y que **nunca** salen del cliente ni llegan al servidor.
- `checksum = SHA-256(tuple("klav/v1/secret-key/checksum", sk))[0..4]`.
- Forma de texto (42 caracteres):

  ```
  "K1" ‖ "-" ‖ g1 ‖ "-" ‖ g2 ‖ … ‖ "-" ‖ g8
  g1…g8 = BASE32(sk ‖ checksum) partido en 8 grupos de 4 caracteres
  ```

  `BASE32` es el alfabeto RFC 4648 (`A–Z`, `2–7`) sin relleno; 20 bytes producen exactamente 32 caracteres. `K1` es el prefijo de versión: `K` de Klav y `1` de la versión del formato.
- Al leer: se ignoran mayúsculas/minúsculas, guiones y espacios. En el cuerpo (después de `K1`), los dígitos `0`, `1` y `8`, que no están en el alfabeto, se leen como `O`, `I` y `B`. Si el prefijo no es `K1`, se rechaza por versión no soportada. Si el checksum no coincide (comparación en tiempo constante), se rechaza como error de tecleo.
- El **kit de emergencia** contiene: correo de la cuenta, ID de la cuenta, URL del servidor y el Secret Key en forma de texto. El núcleo expone esos datos (`EmergencyKit`); los clientes generan el PDF.

### 4.3 Derivación de la KEK
```
A   = Argon2id(versión 0x13, P, sal, m, t, p, longitud = 32)       (sin secret ni ad)
B   = HKDF-SHA256(salt = sal, ikm = sk, info = "klav/v1/kdf/secret-key", L = 32)
KEK = HKDF-SHA256(salt = ∅,   ikm = A ⊕ B, info = "klav/v1/kdf/kek",  L = 32)
O   = HKDF-SHA256(salt = ∅,   ikm = A ⊕ B, info = "klav/v1/kdf/opaque", L = 32)
```

- `sal`: 16 bytes aleatorios por cuenta. Es la misma de Argon2id y de la rama del Secret Key, y se guarda en los parámetros (§4.4).
- `salt = ∅` significa HKDF sin sal (RFC 5869: una cadena de 32 ceros).
- `⊕` es XOR byte a byte. Es la fórmula del diseño (§4.1): `KEK = HKDF(Argon2id(…) ⊕ HKDF(secret_key))`.
- Sin el Secret Key, la base de datos del servidor no permite atacar solo la contraseña: `B` tiene 128 bits de entropía.
- La KEK solo sella las llaves privadas de identidad (§6.3).
- `O` es la entrada de OPAQUE (§4.5). Sale de `A ⊕ B` con otra etiqueta HKDF, nunca de la KEK: conocer `O` no revela nada de la KEK ni al revés. Un solo cálculo de Argon2id produce ambas (`derive_account_keys`).

### 4.4 Parámetros versionados (`kind = 0x06`)
```
kdf_params = 0x01 ‖ 0x06 ‖ u32_be(m_kib) ‖ u32_be(t) ‖ u32_be(p) ‖ sal(16)          (30 bytes)
```

| Parámetro | Producción v1 | Mínimo aceptado | Máximo aceptado |
|---|---|---|---|
| `m_kib` (memoria en KiB) | 262 144 (256 MiB) | 262 144 | 4 194 304 (4 GiB) |
| `t` (iteraciones) | 3 | 3 | 64 |
| `p` (paralelismo) | 4 | 1 | 64 |

- Los parámetros los guarda el servidor junto a la cuenta y el cliente los lee al iniciar sesión. El cliente **rechaza** parámetros por debajo del mínimo (para que un servidor malicioso no los baje y facilite la fuerza bruta de lo que el cliente vuelva a cifrar) y por encima del máximo (para que no pueda bloquear al cliente con un costo absurdo).
- El servidor aplica el mismo rango al registrar una cuenta y responde `400` fuera de él (defensa en profundidad, ADR [0010](decisiones/0010-decisiones-fase-3-y-plan-alojado.md)): un cliente defectuoso no puede crear una cuenta con parámetros débiles.
- Las pruebas usan parámetros reducidos con un constructor que solo existe en pruebas (`KdfParams::insecure_for_tests`, detrás de `cfg(test)` o del feature `insecure-test-kdf`). El código de producción no puede crearlos ni decodificarlos.
- Subir los costos en el futuro no cambia el formato. Cambiar el algoritmo o la estructura sí exige una nueva `version`.

### 4.5 Autenticación con OPAQUE
El servidor autentica a la cuenta con OPAQUE (RFC 9807) usando `opaque-ke` 4.0. Nunca recibe la contraseña, el Secret Key, la KEK ni `O`.

**Suite `klav-opaque-v1`:**

| Componente | Valor |
|---|---|
| OPRF | ristretto255-SHA512 (RFC 9497) |
| Intercambio de llaves | 3DH sobre ristretto255 con SHA-512 |
| Función de estiramiento (KSF) | identidad (ver abajo) |
| Contexto | `"klav/v1/opaque"` (bytes ASCII) |
| Identidades | las predeterminadas de RFC 9807 §4.1.2 (llaves públicas de cliente y servidor) |
| `credential_identifier` | correo normalizado (sin espacios a los lados y en minúsculas) |

- **Contraseña de OPAQUE:** `O` (§4.3), no la contraseña maestra.
- **KSF = identidad, a propósito.** Argon2id ya se ejecutó en el cliente para calcular `A`, así que cumple el papel de KSF antes de OPAQUE. Repetirlo dentro de OPAQUE duplicaría el costo de cada desbloqueo (256 MiB más) sin ganar nada: `O` ya lleva los 128 bits del Secret Key. Quien robe la base de datos del servidor (registro de OPAQUE, semilla OPRF y llave del servidor) no puede atacar la contraseña sin el Secret Key. Y si además robó el kit de emergencia, cada intento le cuesta un Argon2id completo (256 MiB, t=3), igual que atacar las llaves privadas selladas (§6.3). Ver ADR [0009](decisiones/0009-opaque.md).
- **Llave de exportación y llave de sesión de OPAQUE:** no se usan. La KEK sale de la KDF (§4.3) y el servidor emite sus propios tokens (§4.6) cuando el login termina bien.
- **Mensajes:** viajan con la codificación de RFC 9807 para esta suite, sin el encabezado `versión ‖ tipo` de §2.4 (no son formatos de Klav sino del protocolo estándar). La versión de la suite va implícita en la ruta de la API (`/v1/auth/…`) y en la clave de la configuración del servidor (`opaque_server_setup_v1`). Un cambio de suite exigirá rutas nuevas y volver a registrar las cuentas en el siguiente login.
- **Cuentas desconocidas.** El servidor responde a `login/start` con una respuesta señuelo de `opaque-ke`, indistinguible de una real; el login falla en `login/finish` igual que con una contraseña equivocada. El *prelogin*, que entrega los parámetros de la KDF antes de OPAQUE, devuelve para un correo desconocido parámetros de producción con una sal señuelo estable:

  ```
  sal_señuelo = HKDF-SHA256(salt = ∅, ikm = secreto_del_servidor(32),
                            info = tuple("klav/v1/server/decoy-kdf-salt", correo_normalizado), L = 16)
  ```

- **Borrar la cuenta** repite el login completo dentro de una sesión (`/v1/account/delete/start|finish`, ADR [0037](decisiones/0037-borrar-la-cuenta.md) §1): misma suite, mismo registro y mismo `credential_identifier` (el correo de la cuenta de la sesión). El estado del servidor queda ligado a la sesión y al propósito, y un `finish` que verifica programa el borrado en la misma petición.
- Las llaves de larga duración del servidor (semilla OPRF, par de llaves de 3DH y `secreto_del_servidor`) se generan en el primer arranque y se guardan en la base de datos.
- `opaque-ke` valida su implementación con los vectores de RFC 9807; las pruebas de `klav_core::crypto::opaque` cubren el registro, el login, la contraseña equivocada, la cuenta desconocida, otro `credential_identifier`, otras llaves del servidor y mensajes alterados.

### 4.6 Tokens de sesión
Tras un login correcto el servidor entrega un *access token* (vida corta, 15 min por defecto) y un *refresh token* de un solo uso (30 días deslizantes), ligados a un dispositivo:

```
token   = prefijo ‖ BASE64URL(32 bytes aleatorios)       prefijo = "kat_" (acceso) | "krt_" (renovación)
resumen = SHA-256(tuple("klav/v1/server/token", token))
```

El servidor solo guarda `resumen`, así que una copia de la base de datos no contiene tokens utilizables. Usar un *refresh token* ya rotado revoca la sesión entera (detección de robo). Revocar un dispositivo revoca todas sus sesiones.

### 4.7 Códigos de invitación al registro
Con `registration_mode = "invite"` (ADR [0048](decisiones/0048-invite-beta-and-distribution.md) §1.3), registrarse pide un código de invitación. No es un formato binario con versión: lo fijan su forma canónica, su resumen y los vectores de `invite.json`.

```
código  = "KLAV-" ‖ g1 "-" g2 "-" g3 "-" g4 "-" g5       grupos de 5, 5, 5, 5 y 6 símbolos
símbolos = Crockford base32 (0123456789ABCDEFGHJKMNPQRSTVWXYZ) de 16 bytes aleatorios (128 bits) seguidos de 2 bits a cero
resumen = SHA-256(tuple("klav/v1/server/invite", 16 bytes canónicos))
```

**Forma canónica:** se quitan guiones y espacios y se pasa a mayúsculas (cualquier otro carácter lo invalida). Con 30 caracteres, los 4 primeros deben ser `KLAV` y se quitan por longitud, no por patrón (`K`, `A` y `V` son símbolos de Crockford, y `L` se lee como `1`); con 26, es el código sin prefijo; cualquier otra longitud lo invalida. Después `I` y `L` valen `1`, y `O` vale `0`, y los 26 símbolos se decodifican a 16 bytes. Los 2 bits que sobran del último símbolo deben ser cero: si no, dos escrituras darían los mismos bytes. Un código que no cumple todo esto se rechaza antes de tocar la base de datos.

El servidor guarda solo `resumen`, como con los tokens (§4.6). El código va en un `SecretString` (`klav_core::crypto::invite::InviteCode`), sin `Debug` que lo muestre.

## 5. Jerarquía de llaves

### 5.1 Llaves
Todas son de 256 bits, aleatorias e independientes (no se derivan unas de otras):

```
Llave de bóveda      ── compartida con cada miembro mediante HPKE (§8)
 └─ Llave de proyecto ── envuelta con la de bóveda (§5.2) y, si hay grant, con HPKE para el agente (§8)
     └─ Llave de elemento ── envuelta con la de proyecto (§5.2) y, si hay un grant por elemento, con HPKE para el agente (§8); cifra las secciones del elemento (§7)
         └─ Llave de adjunto ── envuelta con la de elemento (§5.2); cifra un adjunto (§10)
```

En el código, cada nivel tiene su propio tipo (`VaultKey`, `ProjectKey`, `ItemKey`, `AttachmentKey`, `Kek`), así que el compilador impide envolver con una llave del nivel equivocado. Ninguno implementa `Debug`, `Display` ni `Clone`.

### 5.2 Envoltura simétrica (`kind = 0x02, 0x03, 0x04`)
Sobre de §3.1 con `plaintext` = los 32 bytes de la llave envuelta (blob de 74 bytes):

| `kind` | Llave que envuelve | Llave envuelta | `tuple` del AAD |
|---|---|---|---|
| `0x02` | bóveda | proyecto | `tuple("klav/v1/wrap/project-key", account_id, vault_id, project_id)` |
| `0x03` | proyecto | elemento | `tuple("klav/v1/wrap/item-key", account_id, vault_id, project_id, item_id)` |
| `0x04` | elemento | adjunto | `tuple("klav/v1/wrap/attachment-key", account_id, vault_id, project_id, item_id, attachment_id)` |

Consecuencias:
- Mover un elemento a otro proyecto obliga a volver a envolver su llave (ADR 0004).
- Rotar la llave de un proyecto obliga a volver a envolver las llaves de sus elementos, sin volver a cifrar los datos (ADR 0002).

## 6. Identidades

Cuentas y agentes tienen una **identidad**: un par X25519 (para recibir llaves con HPKE) y un par Ed25519 (para firmar).

### 6.1 Llaves privadas
- **X25519:** 32 bytes guardados ya *clampeados* (RFC 7748: `k[0] &= 248; k[31] &= 127; k[31] |= 64`), es decir, el resultado de `DeserializePrivateKey`/`SerializePrivateKey` de RFC 9180 para DHKEM(X25519). Al generar, se toman 32 bytes aleatorios y se clampean. La llave pública es `X25519(k, 9)`.
- **Ed25519:** la semilla de 32 bytes de RFC 8032. La llave pública se deriva de ella.

### 6.2 Identidad pública (`kind = 0x05`)
```
public_identity = 0x01 ‖ 0x05 ‖ x25519_pk(32) ‖ ed25519_pk(32)                       (66 bytes)
fingerprint     = SHA-256(tuple("klav/v1/identity/fingerprint", x25519_pk, ed25519_pk))   (32 bytes)
```

Al decodificar se rechaza: longitud distinta de 66, encabezado incorrecto, una llave Ed25519 que no sea un punto válido o sea de orden pequeño, y una llave X25519 de puros ceros. Los demás puntos de orden pequeño de X25519 hacen fallar el encapsulado de HPKE (RFC 9180 §7.1.4).

La huella (`fingerprint`) entra en el `info` de HPKE (§8) y es la base del código de 6 palabras que se muestra al registrar un agente (§13.1).

### 6.3 Llaves privadas selladas con la KEK (`kind = 0x01`)
Sobre de §3.1 (106 bytes) con:

```
plaintext = x25519_sk(32) ‖ ed25519_seed(32)
AAD       = 0x01 ‖ 0x01 ‖ tuple("klav/v1/identity/secrets", account_id, public_identity(66))
```

Al abrir, el cliente usa la identidad pública que **espera** (la que tiene en caché o la que viene del servidor) para construir el AAD. Después recalcula las llaves públicas desde las privadas descifradas y las compara con las esperadas (`KeyMismatch` si no coinciden). Así, un servidor que cambie las llaves públicas guardadas por las suyas hace que el blob no abra, en lugar de lograr que otros cifren para él sin que se note.

Los agentes no tienen KEK. Su identidad se guarda en el llavero o en un archivo 0600 (fase 4).

## 7. Elementos

Un elemento se guarda como **dos** blobs independientes, cifrados con su llave de elemento:

| `kind` | Sección | Contenido (texto en claro) | Quién la descifra |
|---|---|---|---|
| `0x10` | *overview* | metadatos: tipo, título, URLs, usuario, etiquetas | permiso `list` |
| `0x11` | *details* | campos con valores, notas, referencias a adjuntos | `fill`, `inject`, `totp`, `reveal`… |

Separar las secciones permite listar y buscar sin tener los secretos en memoria. El texto en claro de cada sección es JSON UTF-8 con el esquema de §7.1; el formato binario no depende de su contenido.

Sobre de §3.1 con:

```
AAD = header ‖ tuple(label, account_id, vault_id, project_id, item_id, u64_be(version))
label = "klav/v1/item/overview" | "klav/v1/item/details"
```

- `version` es el número de versión del elemento: empieza en 1 y cada edición lo incrementa. Ambas secciones de una misma edición llevan el mismo número.
- Al descifrar, el cliente pasa la versión que **espera** según los metadatos de sincronización. Si el servidor entrega un blob de otra versión (o de otro elemento, proyecto, bóveda o cuenta), falla la autenticación.
- **Limitación:** si el servidor entrega a la vez un blob viejo *y* su número de versión viejo, el descifrado funciona. Detectar eso requiere que el cliente recuerde la última versión vista de cada elemento (*high-water mark*). Eso llega con la sincronización (fases 2–3); ver el modelo de amenazas.

### 7.1 Esquema JSON v1 de las secciones

Ambas secciones son objetos JSON UTF-8 que **rechazan claves desconocidas**. `v` es la versión del esquema (independiente de la versión del formato binario) y un lector rechaza cualquier valor distinto de 1.

*Overview* (no contiene secretos):

| Clave | Tipo | Obligatoria | Notas |
|---|---|---|---|
| `v` | entero | sí | `1` |
| `kind` | texto | sí | `login`, `card`, `identity`, `ssh_key`, `file`, `totp`, `note`, `api_key`, `generator_history` (ADR 0022), `preferences` (ADR 0032 §7, ADR 0036 §3), `agent_labels` (ADR 0047), `environment` (ADR 0032 §1) |
| `title` | texto | sí | 1–256 caracteres, sin caracteres de control; es el nombre del elemento en `klav://`. Con `kind = environment`, además `[a-z0-9][a-z0-9_-]{0,63}` y sin forma de UUID: es el nombre del entorno |
| `username` | texto | no | valor del primer campo de tipo `username` no vacío |
| `urls` | lista de texto | no | URLs para autocompletar (hasta 2048 bytes cada una) |
| `tags` | lista de texto | no | etiquetas (1–256 caracteres) |
| `passkey` | objeto | no | ADR 0020: solo con `kind = login`; resumen `{rp_id, credential_id, user_name}` de la passkey de *details* (§14.2), sin secretos |
| `environment` | objeto | no | ADR 0032 §1: obligatoria con `kind = environment` y prohibida en los demás tipos; `{protected, variables}`, que rechaza claves desconocidas: `protected` (booleano) es la marca de esa versión y `variables` la lista de nombres, en el orden de *details* |

*Details*:

| Clave | Tipo | Obligatoria | Notas |
|---|---|---|---|
| `v` | entero | sí | `1` |
| `kind` | texto | sí | igual al del *overview* |
| `fields` | lista | no | campos, en orden de presentación |
| `fields[].id` | UUID (texto) | sí | único dentro del elemento |
| `fields[].name` | texto | sí | `[a-z0-9][a-z0-9_-]{0,63}`, único, sin forma de UUID; es el nombre del campo en `klav://` |
| `fields[].label` | texto | no | etiqueta para mostrar |
| `fields[].type` | texto | sí | `username`, `password`, `totp`, `file`, `text`, `concealed`, `url`, `email`, `phone`, `date`, `month_year` |
| `fields[].value` | texto | sí | `file`: UUID del adjunto; `totp`: URI `otpauth://totp/…` o secreto base32; `date`: `AAAA-MM-DD`; `month_year`: `AAAA-MM`; el resto, texto libre |
| `notes` | texto | no | notas seguras |
| `attachments` | lista | no | `{id, file_name, size, media_type?}` de cada adjunto (§10) |
| `passkey` | objeto | no | ADR 0020: solo con `kind = login`, como mucho una por elemento; esquema en §14.2 |
| `password_record` | base64url | no | ADR 0022: blob `0x16` con las contraseñas anteriores y la pendiente (§7.3); los clientes lo conservan intacto al editar otros campos |
| `generated` | lista | no | ADR 0022: solo con `kind = generator_history`; entradas `{value, created_at, host?, saved_in?}`, `value` secreto |
| `preferences` | objeto | no | ADR 0032 §7 y ADR 0036 §3: solo con `kind = preferences`; `{developer?, proxy?}`, que rechaza claves desconocidas. Ver «Preferencias de la cuenta» en §7.3 |
| `variables` | lista | no | ADR 0032 §1: obligatoria con `kind = environment` (puede estar vacía) y prohibida en los demás tipos. Cada variable es `{name, value}` o `{name, ref}`, nunca las dos ni ninguna, y rechaza claves desconocidas. `name`: `[A-Za-z_][A-Za-z0-9_]{0,127}`, único y **distingue mayúsculas**; `value`: secreto, como un campo `concealed`; `ref`: una referencia `klav://` con los cuatro segmentos como UUID (bóveda, proyecto, elemento y campo), a un elemento que no es un entorno. Hasta 512 variables |

Los tipos `password`, `totp` y `concealed` son secretos: el núcleo los guarda en memoria como `SecretValue` y nunca los incluye en el *overview*. Al reconstruir un elemento, el cliente comprueba que `kind` y `username` del *overview* coincidan con lo que se deriva de *details*; si no, lo rechaza (`SectionMismatch`). La misma comprobación vale para el resumen `passkey` del *overview* frente a la `passkey` de *details* (ADR 0020).

**Entornos** (`kind = environment`, ADR [0032](decisiones/0032-entornos-por-repositorio.md) §1). Un elemento por proyecto y entorno (`development`, `staging`, `production`):

- `environment.variables` del *overview* es exactamente la lista de nombres de `variables` de *details*, en el mismo orden; si no, `SectionMismatch`.
- Un entorno no lleva `urls`, `fields`, `attachments`, `passkey` ni `password_record`.
- Los valores (`value`) son secretos y nunca van en el *overview*; las referencias (`ref`) tampoco.
- Una referencia no apunta a un entorno, tampoco al propio: no hay cadenas ni ciclos. El elemento solo no lo sabe; lo comprueba quien conoce el tipo del destino (`Environment::check_references`).
- En una referencia a un entorno, el cuarto segmento es el nombre de una variable y distingue mayúsculas (`klav://Trabajo/acme-api/production/STRIPE_KEY`); en los demás tipos sigue siendo un campo. Al analizar una referencia, el cuarto segmento puede ser un nombre de campo o de variable; `resolve_variable` y `resolve_field` lo resuelven según el tipo.
- **La marca efectiva** (`effective_protected`, ADR 0032 §3): cuenta la `protected` de la última versión que escribió la persona. Sin versión de la persona, el entorno está protegido si alguna versión tiene la marca o se llama `production` o `prod` (sin distinguir mayúsculas ASCII); sin ninguna versión, también.
- **El conjunto protegido** (`protected_set`, ADR 0032 §3.1): para cada entorno se toma su última versión escrita por la persona; si tiene `protected`, el elemento de destino de cada `ref` entra en el conjunto. Las versiones de un agente no cuentan, y un entorno que solo escribieron agentes no añade nada.
- Vectores en [`docs/vectores/entorno.json`](vectores/entorno.json).

**Tipo desconocido.** Si el JSON no se lee y su `kind` es un texto que este cliente no conoce, el error es `UnknownKind` («unknown item kind; update Klav»), no «does not decrypt»: lo escribió un cliente más nuevo, no es una manipulación. El elemento se salta igual, y este cliente no puede editarlo ni sobrescribirlo.

### 7.2 Metadatos de bóvedas y proyectos (`kind = 0x12, 0x13`)

Los nombres de las bóvedas y los proyectos (los que usan las referencias `klav://`) van cifrados en el campo `meta` de la API. Sobre de §3.1 con:

| `kind` | Llave | AAD |
|---|---|---|
| `0x12` | bóveda | `header ‖ tuple("klav/v1/vault/meta", account_id, vault_id, u64_be(version))` |
| `0x13` | proyecto | `header ‖ tuple("klav/v1/project/meta", account_id, vault_id, project_id, u64_be(version))` |

- `account_id` es la cuenta dueña de la bóveda y `version` la versión de la bóveda o del proyecto (empieza en 1 y sube con cada `PUT`), igual que en los elementos (§7).
- Los metadatos de un proyecto usan la llave **del proyecto**: un agente con un *grant* de proyecto puede leer su nombre sin tener la llave de la bóveda.
- Texto en claro: JSON UTF-8 que rechaza claves desconocidas.

| Clave | Tipo | Obligatoria | Notas |
|---|---|---|---|
| `v` | entero | sí | `1` |
| `name` | texto | sí | 1–64 caracteres, sin caracteres de control, sin `/`, sin espacios a los lados y sin forma de UUID |
| `description` | texto | no | hasta 1024 caracteres |
| `repos` | lista de texto | no | ADR 0032 §2: solo en un proyecto, los repositorios enlazados, normalizados a `host/dueño/repo` (minúsculas, sin esquema, usuario, contraseña, puerto, `.git` ni `/` final; las rutas con grupos van enteras). Hasta 32, sin repetir, cada uno hasta 256 bytes. Vacía no se escribe: los metadatos sin enlaces no cambian. Un lector anterior la rechaza y salta el proyecto entero (ADR 0032 §2, «los lectores primero») |

### 7.3 Registro de contraseñas (`kind = 0x16`)

> ADR [0022](decisiones/0022-generador-historial-y-cambio-asistido.md) §3. Implementado en `klav-core` (`crypto::record`, `model::record`), con vectores en [`docs/vectores/registro.json`](vectores/registro.json).

Sobre de §3.1 con la **llave de bóveda**, como `0x15`, para que un agente que recibe los *details* no pueda leer las contraseñas anteriores:

```
AAD       = 0x01 ‖ 0x16 ‖ tuple("klav/v1/item/password-record", account_id(16), vault_id(16), item_id(16))
plaintext = JSON UTF-8 {v: 1 | 2, history: [{field, value, from_ms, to_ms, unconfirmed?}], pending?: {field, value, created_at_ms, task_id?, rotation_id?}}
blob      = 0x01 ‖ 0x16 ‖ nonce(24) ‖ ct(n + 16)
```

- `field` es el `name` de un campo de tipo `password` o `concealed`; como mucho 100 entradas por campo, se descarta la más vieja.
- `pending` es la contraseña nueva de un cambio asistido aún sin confirmar (ADR 0022 §5). `klavd` la escribe antes de tocar la página; `rotation_id` es el ID del cambio en el servidor (`RotationInfo::id`), para que el `confirm` o `cancel` del agente solo cierre su propio cambio.
- **Versión 2** (cambio asistido): añade `unconfirmed: true` en una entrada del historial (una contraseña generada que nadie confirmó: el `cancel` del agente, «Mantener la actual», o una pendiente reemplazada por otro cambio; `from_ms` es su `created_at_ms` y `to_ms` el momento en que se descartó) y `rotation_id` en `pending`. Un registro sin ninguna de las dos claves se escribe como `v: 1`, byte a byte igual que antes. Los lectores aceptan `1` y `2` y rechazan otra versión, y también un `v: 1` con claves de la versión 2.
- Confirmar: la pendiente pasa al campo y el valor que reemplaza entra al historial con `to_ms` = ahora, como cualquier edición.
- La versión del elemento **no** va en el AAD: el registro se copia tal cual entre versiones cuando no cambia. Lo reescribe solo un cliente de la persona, con `PasswordRecord::note_changes` de `klav-core` (el elemento antes y después de la edición), nunca cada interfaz por su cuenta. Consecuencia aceptada (modelo de amenazas, riesgo 27, T97): un servidor puede servir el registro de otra versión del mismo elemento, nunca el de otro elemento. Si un agente cambió la contraseña, el cliente de la persona reconstruye el registro desde las versiones del servidor en su siguiente edición.
- `from_ms` es opcional: falta cuando no se sabe desde cuándo valía (un valor anterior al registro cuyas versiones ya borró el servidor).
- `history` va de la más vieja a la más nueva.

**Proyecto de sistema.** El historial del generador (`kind = generator_history`, ADR 0022 §2) vive en un proyecto de la bóveda personal con un ID fijo, derivado del de la bóveda, para que cualquier cliente lo reconozca sin leer su nombre y nunca lo meta en un grant:

```
project_id = SHA-256(tuple("klav/v1/id/system-project", vault_id(16)))[0..16], con la versión de UUID 8 (byte 6 = 0x8·) y la variante de RFC 9562 (byte 8 = 0b10······)
```

Los vectores están en `registro.json`: `password-record` (versión 1), `password-record-rotation` (versión 2, con una entrada no confirmada y una pendiente con `rotation_id`) y `system-project`.

**Preferencias de la cuenta** (ADR 0032 §7, ADR 0036 §3). Un elemento de sistema `kind = preferences`, título `Preferences`, en el proyecto de sistema de una bóveda de la cuenta (la por defecto al crearlo), sin campos. Sus *details* llevan `preferences`:

| Clave | Tipo | Obligatoria | Notas |
|---|---|---|---|
| `developer` | booleano | no | El interruptor «Desarrollo» (ADR 0032 §7). Sin la clave, encendido |
| `proxy` | objeto | no | `{mode, agent_id?}`. Sin la clave, `mode = none` |
| `proxy.mode` | texto | sí | `none`, `own` o `klav` |
| `proxy.agent_id` | UUID (texto) | con `own` | el agente que es el proxy propio; con `none` o `klav` no va |

- **Sin el elemento, valen los valores por defecto,** y un cliente solo escribe las claves que eligió la persona: crear el elemento para el proxy no escribe `developer`.
- **`klav`** es el proxy alojado y atestado (ADR 0036 §12), que no existe todavía: los clientes lo leen, lo tratan como no disponible y nunca lo escriben.
- **Leer falla cerrado.** Solo cuentan los elementos de las bóvedas de la propia cuenta. Si el proyecto de sistema de una de ellas tiene un elemento que este dispositivo no abre, o un elemento `preferences` escrito por un agente, leer las preferencias es un error, nunca «sin preferencias» (que se leería como «sin proxy»). De un elemento escrito por un agente no se usa nada: la lista de sandboxes lo marca (`security`, [klavd.md](klavd.md) `sandbox_list_flagged`) en vez de fallar, y solo `klav proxy use`, tras la presencia, lo reescribe con un cuerpo nuevo que lleva solo `proxy` (sin `developer`), sin usar ni conservar nada del contenido del agente. Reescribirlo sí descifra la versión actual, como toda actualización de un elemento, y la sincronización descifra su *overview*; nada de eso pasa al cuerpo nuevo. Dos dispositivos que lo crearon a la vez dejan dos: se leen los dos y, si no coinciden en `proxy`, es un error hasta que se vuelva a escribir el ajuste, que se escribe igual en todos; cada uno conserva sus demás claves.
- Un cliente anterior a esta versión no conoce el tipo y se salta el elemento con un aviso de que no se descifra (como un tipo desconocido cualquiera). No usa el ajuste, y por defecto no hay proxy.
- Ningún formato binario cambia, así que no hay vector: es una clave más del JSON de *details* (§7.1), como `generated`.

## 8. Compartir llaves con HPKE (`kind = 0x20, 0x21, 0x23`)

### 8.1 Suite
| Componente | Valor | Identificador RFC 9180 |
|---|---|---|
| KEM | DHKEM(X25519, HKDF-SHA256) | `0x0020` |
| KDF | HKDF-SHA256 | `0x0001` |
| AEAD | ChaCha20-Poly1305 | `0x0003` |
| Modo | `base` (`mode_base = 0x00`) | — |

La implementación se valida contra el vector oficial RFC 9180 A.2.1 (`docs/vectores/hpke-rfc9180.json`). La autenticidad de quien comparte no viene de HPKE (modo `base`). Viene de la firma Ed25519 del grant (§13.4), de la firma de la cuenta sobre su llave de bóveda (§8.3) y de la sesión autenticada con el servidor.

### 8.2 Formato
```
(enc, ct) = SealBase(pkR = x25519_pk del receptor, info, aad = header, pt = llave(32))
blob      = header(2) ‖ enc(32) ‖ ct(32 + 16)                                    (82 bytes)
```

| `kind` | Llave | `info` |
|---|---|---|
| `0x20` | bóveda | `tuple("klav/v1/share/vault-key", account_id, vault_id, fingerprint_receptor)` |
| `0x21` | proyecto | `tuple("klav/v1/share/project-key", account_id, vault_id, project_id, fingerprint_receptor)` |
| `0x23` | elemento | `tuple("klav/v1/share/item-key", account_id, vault_id, project_id, item_id, fingerprint_receptor)` |

- `account_id` es la cuenta dueña de la bóveda.
- `fingerprint_receptor` (§6.2) liga el blob a la identidad completa del receptor, incluida su llave de firma. El receptor calcula el `info` con su propia huella.
- HPKE de un solo disparo (*single-shot*): un blob por receptor y por llave, sin reutilizar contextos.
- El `0x23` lleva la llave de **un** elemento (ADR 0036 §2): el `info` incluye `project_id` e `item_id`, así que el blob no abre como llave de proyecto ni para otro elemento. La llave de un elemento no cambia al rotar su proyecto (§5.2); cambia cuando se revoca un grant que la compartía (§13.4).

### 8.3 Firma de la llave de bóveda

HPKE solo prueba que el blob `0x20` se cifró **para** la identidad de la cuenta, y esa identidad pública la conoce el servidor. Para que el servidor no pueda fabricar una llave de bóveda que el cliente use como propia, la cuenta dueña firma su blob (ADR [0030](decisiones/0030-ronda-de-seguridad-2026-11.md) §1):

```
mensaje = tuple("klav/v1/sig/vault-key", account_id(16), vault_id(16), shared_key(82))
firma   = Ed25519(identidad de la cuenta dueña, mensaje)                        (64 bytes, §9)
```

- `shared_key` son los bytes exactos del blob `0x20` (con su encabezado). Como su `info` ya lleva la huella del destinatario (§8.2), la firma también liga a quién va la llave.
- `account_id` es el de la cuenta dueña, el mismo del AAD de todo lo que hay dentro de la bóveda. El cliente arma el contexto con el `account_id` de su sesión, nunca con el `owner_account_id` que manda el servidor, y rechaza una bóveda cuyo dueño no sea su cuenta.
- El mensaje no lleva la versión de la bóveda: `version` es la de los metadatos (cambia con cada cambio de nombre), la llave de un miembro no cambia y el retroceso de los metadatos ya lo cubre su AAD (§7.2). Si algún día la llave de bóveda rota, se añadirá un número de generación o una etiqueta nueva.
- El cliente verifica la firma con la identidad de **su propia cuenta** (la que tiene sellada con la KEK, §6.3), no con una que le dé el servidor. Una bóveda cuya firma no verifica no se usa.
- Las bóvedas creadas antes de esta firma se firman una vez por dispositivo (TOFU), con las reglas del ADR 0030 §1: si la caché sellada del dispositivo ya tenía la bóveda, el `shared_key` listado debe ser el de la caché byte a byte; después, una versión sin firma se rechaza siempre.
- Vector: `llave-de-boveda.json` (§11).

## 9. Firmas

```
mensaje = tuple(label, campo1, …, campoN)        label empieza con "klav/v1/sig/" y no es solo el prefijo
firma   = Ed25519-Sign(ed25519_seed, mensaje)    (64 bytes: R ‖ S)
```

- Verificación **estricta** (`verify_strict` de `ed25519-dalek`): rechaza firmas maleables (S no canónico) y llaves de orden pequeño.
- Ninguna etiqueta de AEAD, HKDF o HPKE empieza con `klav/v1/sig/`, así que una firma no puede reinterpretarse como otra construcción.
- Las etiquetas concretas de cada objeto firmado se definen en la sección que lo introduce: la llave de bóveda (§8.3) y las peticiones de agentes, grants, aprobaciones, revocaciones, tareas y pausas (§13).

## 10. Adjuntos con STREAM (`kind = 0x30`)

Construcción STREAM (Hoang, Reyhanitabar, Rogaway, Vizár, *Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance*, 2015) en la variante `StreamBE32` de RustCrypto `aead-stream`, sobre XChaCha20-Poly1305 y con la llave de adjunto.

```
header  = 0x01 ‖ 0x30 ‖ u32_be(chunk_size) ‖ nonce_prefix(19)                    (25 bytes)
nonce_i = nonce_prefix(19) ‖ u32_be(i) ‖ last(1)          last = 0x01 en el último bloque, 0x00 en los demás
AAD     = header(25) ‖ tuple("klav/v1/attachment", account_id, vault_id, project_id, item_id, attachment_id)
bloque_i = XChaCha20-Poly1305-Encrypt(llave_adjunto, nonce_i, trozo_i, AAD)     (|trozo_i| + 16 bytes)
blob    = header ‖ bloque_0 ‖ bloque_1 ‖ … ‖ bloque_k
```

- `nonce_prefix`: 19 bytes aleatorios por adjunto. `i` empieza en 0.
- `chunk_size` por defecto: 65 536 bytes (64 KiB). El lector acepta valores en `[64, 1 048 576]`.
- Todos los trozos salvo el último tienen exactamente `chunk_size` bytes. El último tiene entre 1 y `chunk_size` bytes y se sella con `last = 0x01`. Un adjunto vacío produce un único bloque final de 16 bytes. Si el tamaño es múltiplo exacto de `chunk_size`, el último trozo completo es el final (no se añade un bloque vacío).
- Al leer, el cuerpo se corta en segmentos de `chunk_size + 16` bytes. El último segmento (que puede ser más corto, pero de al menos 16 bytes) se abre con `last = 0x01` y los demás con `last = 0x00`. Así se detectan reordenamientos, bloques eliminados o añadidos y truncamientos.
- Máximo: 2³² − 1 bloques (≈ 256 TiB con el tamaño por defecto).
- El descifrado por flujo entrega texto en claro bloque por bloque. Si al final devuelve error, el llamador **debe descartar** todo lo escrito.

## 11. Vectores de prueba

Están en [`docs/vectores/`](vectores/), uno por formato, en JSON (campos binarios en hexadecimal). Cada caso trae entradas (llaves, IDs, nonces, textos en claro) y salidas (AAD calculado, blob, etc.). La prueba `crypto::vectors::vectors_match_spec` de `klav-core` recalcula todas las salidas a partir de las entradas, abre o verifica cada blob guardado y, en el caso de HPKE, lo compara con los valores publicados en RFC 9180. Los nonces y la aleatoriedad de HPKE son fijos solo en estos vectores. En producción siempre vienen del CSPRNG.

| Archivo | Formato |
|---|---|
| `secret-key.json` | Secret Key: checksum y texto (§4.2) |
| `kdf.json` | KDF con parámetros reducidos, con NFKD y con parámetros de producción, incluida la entrada de OPAQUE (§4.3, §4.4) |
| `identidad.json` | identidad, huella y llaves privadas selladas (§6) |
| `envoltura.json` | llaves de proyecto, elemento y adjunto envueltas (§5.2) |
| `elemento.json` | secciones *overview* y *details* (§7) |
| `entorno.json` | entornos (ADR 0032): *overview* y *details* de un entorno con un valor y una referencia, documentos que hay que rechazar (variable repetida, valor y referencia a la vez, referencia a otro entorno, referencia por nombre, listas que no coinciden) y el conjunto protegido a partir de versiones de la persona y de agentes (§7.1) |
| `compartir.json` | llaves de bóveda y de proyecto con HPKE (§8) |
| `item-grant.json` | llave de un elemento con HPKE (`0x23`, §8.2), y un `GrantPayload` `v: 2` que la lleva, con su mensaje y la firma de la cuenta (§13.4) |
| `sandbox-grant.json` | dos `GrantPayload` `v: 3` (§13.4): el del proxy, con un emisor en `issuers`, y el del emisor, con `sandbox` y sin proyectos, cada uno con su mensaje y la firma de la cuenta |
| `llave-de-boveda.json` | blob `0x20`, mensaje y firma de la cuenta dueña sobre su llave de bóveda (§8.3) |
| `hpke-rfc9180.json` | vector oficial RFC 9180 A.2.1 (§8.1) |
| `adjunto.json` | adjuntos de 0, 64 y 150 bytes con `chunk_size = 64` (§10) |
| `firma.json` | firma con separación de dominio (§9) |
| `metadatos.json` | metadatos de bóveda y de proyecto (§7.2) |
| `local.json` | llave local, identidad local y datos locales (§12.2) |
| `llavero.json` | llave local envuelta por el almacén de la plataforma (§12.3) |
| `sandbox-events.json` | las tres peticiones firmadas del proxy para la vida de un sandbox (`sandbox.issued`, `sandbox.claimed`, `sandbox.revoked`, §13.7): el cuerpo, su mensaje de §13.3 y la firma, y el resumen de la llave del canal (§13.10) |
| `sandbox-revoke.json` | la revocación de sandboxes por la persona, firmada por la cuenta: un sandbox y `all`, con su mensaje y su firma (§13.11) |
| `sandbox-heartbeat.json` | las dos peticiones firmadas del proxy para su almacén: `sandbox.store_reset` y el latido, con la misma época; el cuerpo, su mensaje de §13.3 y la firma (§13.12) |
| `sandbox.json` | paquete de un sandbox (`ksb1_`), su SPKI y la huella fijada del proxy, el resumen del secreto y paquetes que hay que rechazar (§13.10) |
| `agentes.json` | código de emparejamiento, llave privada de agente (`0x07`), nombres del grant (`0x14`), firmas de peticiones, grants, aprobaciones y revocaciones, la cadena de la bitácora con su cabeza firmada, la solicitud, la decisión, la negativa y el fin de una tarea, y las pausas y la reanudación (§13) |
| `passkey.json` | llave privada de una passkey sellada (`0x15`), su llave pública (SEC1 y SPKI), una firma ES256 determinista, y un registro y una aserción de Klav (COSE, `authData`, `attestationObject` y `clientDataJSON`) (§14) |
| `webauthn-l3.json` | vector oficial de WebAuthn nivel 3, «ES256 Credential with No Attestation», transcrito del texto: con la misma llave, AAGUID, `credential_id` y banderas, `klav-core` produce el mismo `attestationObject`, el mismo `authenticatorData`, el mismo `clientDataJSON` de la aserción y la misma firma (RFC 6979) (§14) |
| `invite.json` | códigos de invitación: escritura canónica, otras escrituras que dan los mismos bytes (minúsculas, sin prefijo ni guiones, con espacios, con `I`/`L`/`O`), resumen, y códigos que hay que rechazar (§4.7) |
| `mcp-gateway.json` | la pasarela MCP: tokens de cliente local (`klc1_`) con su resumen y tokens que hay que rechazar, el resumen de los argumentos (también reordenados y ausentes), la coincidencia de los patrones de herramienta con patrones inválidos, y la evaluación de una llamada con herramienta (§13.4, §13.16) |
| `nitro-attestation.json` | atestación de Nitro (ADR 0051): la raíz fijada, un documento real de un enclave en modo *debug*, una cadena sintética con un documento que verifica y documentos mutados que hay que rechazar, las llaves por cuenta, el vínculo, la inscripción y el `info` del traspaso (§15). Solo con `--features nitro-attestation` |
| `enclave-manifest.json` | manifiesto de los enclaves (ADR 0051): el mensaje firmado, manifiestos que se aceptan y que se rechazan, con llaves de prueba (§15.5). Solo con `--features nitro-attestation` |
| `hosted-proxy-registration.json` | la marca de la llave de servicio del proxy alojado sobre el registro de un agente, como la comprueba el servidor con su llave pública Ed25519, en dos generaciones, y una marca de otra generación que hay que rechazar (§15.8). Sin feature: corre con `cargo test -p klav-core` |
| `totp.json` | vectores oficiales de RFC 6238 (TOTP, SHA-1/256/512) y RFC 4226 (HOTP), transcritos de los RFC |

Para regenerarlos tras un cambio **intencional** de formato: `KLAV_REGEN_VECTORS=1 cargo test -p klav-core vectors` y, para los dos de §15, `KLAV_REGEN_VECTORS=1 cargo test -p klav-core --features nitro-attestation nitro_vectors`.

## 12. Secretos en el dispositivo

### 12.1 Manejo de secretos en el código

- Las llaves, la contraseña, el Secret Key y las identidades viven en `secrecy::SecretBox` o `zeroize::Zeroizing` y se borran al soltarse. Ninguno de esos tipos implementa `Debug`, `Display` ni `Clone`; pruebas de compilación (`static_assertions`) lo comprueban.
- Los bytes de las llaves no salen de `klav-core`: el acceso está en un rasgo sellado y privado del crate.
- Los errores de descifrado son opacos (§3.1) para no dar oráculos.
- `mlock` (impedir que la memoria vaya a swap) queda pospuesto (ADR 0013): requiere `unsafe` o una dependencia nueva y no protege contra el atacante relevante (otro proceso del mismo usuario puede leer la memoria igualmente).

### 12.2 Llave local y datos del dispositivo (`kind = 0x40, 0x41`)

Cada dispositivo deriva de la KEK una **llave local**, ligada a la cuenta y al dispositivo (el `device_id` que asigna el servidor al iniciar sesión):

```
llave_local = HKDF-SHA256(salt = ∅, ikm = KEK,
                          info = tuple("klav/v1/kdf/local-key", account_id, device_id), L = 32)
```

Con ella se sellan, con el sobre de §3.1:

| `kind` | Contenido | AAD |
|---|---|---|
| `0x40` | `x25519_sk(32) ‖ ed25519_seed(32)` (como §6.3) | `header ‖ tuple("klav/v1/local/identity", account_id, device_id, public_identity(66))` |
| `0x41` | datos locales (JSON) | `header ‖ tuple("klav/v1/local/data", account_id, device_id, propósito)` |

- `propósito` separa los usos (`[a-z0-9-]{1,64}`): hoy `session` (tokens de sesión), `cache` (copia de la sincronización y *high-water marks*), `deletion` (lo que el dispositivo sabe del borrado de la cuenta, `deletion.bin`: `{v: 1, deletion: {requested_at, delete_at, device_id, device_name}, deleted}`, aparte de `cache` para que un cliente anterior, que rechaza campos desconocidos en la caché, la siga abriendo; ADR 0037 §3, enmienda A3), `audit` (la copia de la cadena de la bitácora que descargó el dispositivo, `audit-chain.bin`: `{v: 1, account_id, entries: [{seq, event, hash}]}`, con `event` y `hash` en base64url como en `GET /v1/audit`; ADR 0033 §8.4), `revocations` (los cambios de llave que este dispositivo debe y lo que firmó para cada agente, `revocations.bin`, formato abajo; aparte de `cache` por la misma razón que `deletion`; ADR 0033, enmienda del 2026-11-10, F4) `presence` y `passkey-window` (la configuración de presencia y la ventana de las passkeys de `klavd`, `presence.bin` y `passkey-window.bin`: `{v: 1, window}`, con `window` uno de `always`, `5m` o `unlocked`; se leen solo con `v == 1` exacto y sin otros campos, y un blob que no abre, de otra versión o de otro formato se lee como `always`; ADR 0041 §2.4, capa 2) y `sandbox-marks` (la marca de agua del latido de cada proxy, `sandbox-marks.bin`: `{v: 1, marks: [{proxy, store_epoch, epoch_seq, seq}]}`, una por proxy, bajo su época actual, con `epoch_seq` la posición en la cadena del `sandbox.store_reset` de esa época, y si dos épocas distintas empatan en `epoch_seq` se queda la marca guardada; aparte de `cache` por la misma razón; ADR 0036 E3.3, §13.12. Se lee solo con `v == 1` exacto y sin otros campos; un formato posterior conserva el propósito, el sobre y un `v` entero en el nivel de arriba). y `protection` (el conjunto protegido de ADR 0032 §3.1, `protection.bin`: lo que cada entorno protegido aporta al conjunto, los entornos vistos, lo que protegen los grants vigentes, las bóvedas sin leer y la última versión de la persona de cada entorno; aparte de `cache` por la misma razón que `deletion`; se lee solo con `v == 1` exacto; un archivo que existe y no abre se lee como desconocido: todo valor pide presencia y no se firma un grant que conserve permisos hasta la siguiente sincronización; ADR 0032 §3.1, capa 3) y `hosted-proxy` (lo que este dispositivo sabe del proxy alojado de Klav Cloud, `hosted-proxy.bin`: `{v: 1, highest_seq?, seed_epoch?, generation, agents}`, con `highest_seq` el `seq` más alto de un manifiesto que verificó (la marca de agua del ADR 0051 §2.4), `seed_epoch` el más alto de esos manifiestos, `generation` la más alta en la que inscribió un agente (un `reset` pide la siguiente) y `agents` cada agente alojado que inscribió, para que un grant a cualquiera de ellos se vuelva a verificar aunque las preferencias ya nombren otro; los valores solo suben y `agents` solo crece. Se lee con `v == 1` y sin otros campos; uno que no abre se lee vacío y la siguiente verificación lo escribe otra vez con un aviso de que se perdió la marca de agua, y uno con un `v` posterior se lee vacío y nunca se escribe; ADR 0051 §17, capa 5). Un blob de un propósito no abre como otro.
- **`revocations.bin`** (`v: 1`; todo campo marcado `?` falta cuando está vacío o en falso, y un archivo sin él se lee con su valor por defecto):

  ```
  {v: 1,
   agents:   {<agent_id>: {name, rotate?, regrants?, unknown?, log_unchecked?, items?, last_error?}},
   narrowed?: {<agent_id>: {name, projects, rotated?, regrants?, last_error?}},
   signed?:   {<agent_id>: {projects?, items?, version}}}
  ```

  - `agents`: revocaciones con algo pendiente. `rotate` (por defecto `true`; se escribe solo `false`) dice si la persona pidió cambiar las llaves de sus proyectos; sin él solo quedan `items`, y ninguna llave de proyecto cambia. `regrants`: proyectos ya rotados cuyos otros agentes esperan su grant nuevo. `unknown`: este dispositivo no sabe qué proyectos tenía. `log_unchecked`: la bitácora no se pudo leer o no trae la última versión que este dispositivo firmó (`signed.version`); el cambio no termina hasta que un paso la lea. `items`: elementos compartidos uno por uno sin llave nueva o cuyos otros titulares esperan grant; también los que quedan fuera de alcance (su bóveda borrada o sin listar, o un elemento que este dispositivo ya no ve), que se quedan apuntados y cambian si vuelven. El formato no cambia, pero el significado se amplió (#308): los elementos cuya bóveda ya no está ya se quedaban; lo nuevo es que también se queda un elemento que este dispositivo ya no ve. Un lector anterior a ese cambio que abre un archivo así toma el elemento que ya no ve por pendiente, lo intenta una vez, no lo encuentra y lo quita de la lista. Un elemento purgado nunca vuelve (la sincronización rechaza uno purgado que reaparece), así que se queda en `items` hasta que la entrada se borre. Los proyectos de la revocación y los ya rotados siguen en `cache` (`revocations`), que además significa «nunca volver a otorgarle».
  - `narrowed`: cambios de llave de proyectos quitados a un agente que sigue activo (`rotate_removed`): `projects` quitados, `rotated` los ya cambiados. No es una revocación: no va en `cache`.
  - `signed`: lo que este dispositivo firmó para cada agente. `projects` e `items` (los elementos de un grant por elemento, ADR 0036 §18) se escriben antes de subir el grant; `version`, la mayor que el servidor aceptó, después. Una revocación con cambio de llaves cambia la llave de cada proyecto de `projects`, y toda revocación la de cada elemento de `items`, sirva el servidor el grant que sirva (uno anterior o ninguno) o corte la bitácora donde la corte.
  - **Cómo cambia el formato.** Todo cambio en esta disposición sube `v`. Dentro de una misma `v` el esquema es cerrado en todos los niveles: un campo desconocido es un error, nunca algo que se descarta al reescribir. El lector lee primero solo `v` (un objeto con ese único campo, sin cerrar) y después el resto:
    - una `v` mayor que la que conoce es un error propio, «lo escribió una versión más nueva de Klav; actualiza Klav», que no toca ni reescribe el archivo y nunca sugiere apartarlo: apartarlo perdería los cambios de llave pendientes y `signed`;
    - un archivo que no abre (otra llave), o que no se analiza en una `v` que conoce, es el otro error: se muestra, nunca es «nada pendiente», Klav no lo sobrescribe, y revocar con cambio de llaves o firmar un grant se detiene hasta que la persona lo aparte.

    La CLI de `~/.cargo/bin` y el `klavd` de la app pueden ser versiones distintas, así que un lector más viejo verá un día un archivo más nuevo: falla cerrado. Mantener los campos desconocidos al reescribir (un mapa `flatten`) no es mejor: un lector viejo haría su paso sin entender un campo nuevo que lo cambia, como `rotate: false` cambió qué se rota.
  - Vacío, el archivo se borra. La prueba `format_1_is_exactly_this_layout_and_closed` (`klav-client`, `revoke.rs`) fija la disposición completa de `v: 1`.
- Al abrir la identidad local se comprueban las llaves públicas igual que en §6.3.
- **Desbloqueo con contraseña:** contraseña + Secret Key → KEK → abre `sealed_identity` (§6.3) y recalcula la llave local.
- **Desbloqueo biométrico:** la llave local viene del almacén de llaves de la plataforma (§12.3) y abre la identidad local sin la KEK.
- Nada de esto sale del dispositivo: los tipos `0x40–0x4F` nunca se envían al servidor.
- La llave local es derivada (no aleatoria) para no tener que guardar otra envoltura en disco y para que no haya un ciclo KEK ↔ llave local. Cambiar la contraseña (fase futura) cambia la KEK y, con ella, la llave local: los clientes vuelven a sellar sus datos locales.

### 12.3 Llave local en el almacén de la plataforma (`kind = 0x42`)

Para el desbloqueo biométrico (diseño §4.3), el almacén de llaves de la plataforma guarda una llave P-256 no exportable que solo se usa tras Face ID o Touch ID. En Apple es el Secure Enclave, con el ACL `biometryCurrentSet` (ADR 0013). Esa llave protege la llave local de §12.2 sin que `klav-core` la vea nunca.

- **Envolver** (sin biometría): la plataforma crea un par efímero P-256 y calcula `ss = ECDH(efímera, pública_del_almacén)`, que son los 32 bytes de la coordenada x. Se descarta la privada efímera.
- **Desenvolver** (con biometría): el almacén calcula `ss = ECDH(privada_del_almacén, pública_efímera)`.

Con `ss`:

```
llave_envoltura = HKDF-SHA256(salt = ∅, ikm = ss,
                              info = tuple("klav/v1/kdf/keystore-wrap", account_id, device_id,
                                           pública_almacén(65), pública_efímera(65)), L = 32)
blob = sobre §3.1 (kind 0x42) de llave_local(32) con
       AAD = header ‖ tuple("klav/v1/local/keystore-wrap", account_id, device_id,
                            pública_almacén(65), pública_efímera(65),
                            u64_be(password_at_ms), u64_be(boot_time_s))
```

- Las llaves públicas van en SEC1 sin comprimir (`0x04 ‖ x ‖ y`, 65 bytes); otro formato se rechaza.
- `password_at_ms` es el último desbloqueo con contraseña (milisegundos Unix) y `boot_time_s` el arranque de la máquina en que se envolvió (segundos Unix). Están en el AAD para que la política "contraseña cada N días y tras reiniciar" no se pueda extender editando el archivo: un valor cambiado ya no abre. El cliente comprueba la política antes de pedir la biometría.
- Cada desbloqueo con contraseña vuelve a envolver con un par efímero nuevo y los valores de política actuales. Si la biometría registrada cambia, el almacén invalida su llave y hace falta la contraseña, que crea una llave nueva.

## 13. Agentes

Un agente tiene su propia identidad (§6), generada en su máquina (ADR [0014](decisiones/0014-agentes-fase-4.md)). Esta sección fija lo que el agente y la cuenta firman o se intercambian. El protocolo HTTP está en [`api.md`](api.md) §8.

Vectores en [`docs/vectores/agentes.json`](vectores/agentes.json). Además de las firmas, traen en `messages` los bytes exactos que cubre cada una (`tuple(etiqueta, campos…)`, §9) y en `labels_aad` el AAD del blob `0x14`, para comprobar la codificación antes que la firma, y en `negative` entradas que hay que rechazar: un blob `0x14` con otra versión, con otro `kind` o con el tag alterado, y un grant firmado con la etiqueta de aprobación.

### 13.1 Código de emparejamiento

```
palabra_i = EFF[u32_be(fingerprint[4i .. 4i+4]) mod 7776]      i = 0 … 5
código    = palabra_0 ␠ palabra_1 ␠ … ␠ palabra_5
```

- `fingerprint` es la huella de §6.2 y `EFF` la *EFF Large Wordlist* (7776 palabras, en el orden del archivo, índice desde 0; licencia CC BY 3.0 US en `crates/klav-core/src/generator/WORDLIST-NOTICE.md`).
- Seis palabras dan unos 77,5 bits. El sesgo de `mod 7776` sobre 2³² es menor que 2⁻¹⁹ por palabra.
- Al compararlas se ignoran las mayúsculas y los separadores (espacios, guiones, comas). Las palabras esperadas se separan igual: cuatro palabras de la lista llevan guion (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`), así que `t-shirt` y `t shirt` valen lo mismo.
- La persona compara el código del agente en ambas pantallas antes de aprobarlo (T10). El de la cuenta se calcula igual y sirve para que el agente compruebe la identidad que fijó (TOFU).

### 13.2 Llave privada de un agente (`kind = 0x07`)

```
blob  = 0x01 ‖ 0x07 ‖ x25519_sk(32) ‖ ed25519_seed(32)          (66 bytes)
texto = "kag1_" ‖ BASE64URL-SIN-RELLENO(blob)
```

- No va cifrada, porque quien la tiene *es* el agente. Por eso los grants tienen alcance y caducidad y se pueden revocar (T23). Vive en el llavero de macOS, en un archivo 0600 o en la variable `KLAV_AGENT_KEY`.
- Al decodificar se rechaza: otro prefijo, base64url inválido, longitud distinta de 66, encabezado incorrecto. Las llaves públicas se recalculan como en §6.3.
- No se envía nunca al servidor.

### 13.3 Petición firmada

```
mensaje = tuple("klav/v1/sig/agent-request", agent_id(16), método, ruta, u64_be(ts_ms), nonce(16), SHA-256(cuerpo))
```

- `método` en mayúsculas (`GET`, `POST`…).
- `ruta`: la ruta con su *query*, tal como se envió (`/v1/agent/me`).
- `ts_ms`: hora del agente en milisegundos Unix.
- `nonce`: 16 bytes aleatorios nuevos.
- `cuerpo`: los bytes exactos del cuerpo; vacío si no hay.
- Cabeceras:
  - `Klav-Agent`: el ID en texto;
  - `Klav-Timestamp`: `ts_ms` en decimal;
  - `Klav-Nonce` y `Klav-Signature`: base64url sin relleno.
- El servidor rechaza con `401`:
  - una firma que no verifica con la identidad registrada del agente;
  - `|ahora − ts_ms| > 5 min`;
  - un nonce ya visto por ese agente en los últimos 10 minutos (T25).
- `klavd` verifica también la petición que el agente le reenvía en un cambio asistido (`AgentRequestProof`: método, ruta, `ts_ms`, nonce, cuerpo y firma; ADR 0022 §5): la identidad sale del grant firmado por la cuenta, exige `POST`, la ruta exacta, la misma ventana de 5 min y un nonce no visto en la sesión desbloqueada, y lee el elemento, la tarea y el host del cuerpo firmado.

### 13.4 Grant

```
payload = JSON de GrantPayload (klav-proto): { v: 1, account_id, agent_id, version, issued_at, policy, projects: [ { vault_id, owner_account_id, project_id, shared_key, labels } ] }
mensaje = tuple("klav/v1/sig/agent-grant", account_id(16), agent_id(16), identidad_pública_del_agente(66), payload)
```

- `shared_key` es la llave del proyecto compartida con el agente por HPKE (tipo `0x21`, §8), con `account` = dueño de la bóveda.
- `labels` (tipo `0x14`) lleva los nombres de la bóveda y del proyecto, para que el agente pueda resolver referencias `klav://Bóveda/Proyecto/…`. El nombre de la bóveda está sellado con su llave, que el agente nunca recibe. Usa el sobre de §3.1 con la llave del proyecto:
  ```
  AAD = header ‖ tuple("klav/v1/agent/labels", account_id, vault_id, project_id, agent_id)
  texto en claro = {"vault": "…", "project": "…"}
  ```
  Los nombres son los del momento de la aprobación: un cambio de nombre posterior llega con el grant siguiente.
- El payload se firma y se guarda **byte por byte**: nadie lo vuelve a serializar, así que no hace falta una forma canónica.
- `version` empieza en 1 y cada grant nuevo usa la siguiente. El agente guarda la mayor que aceptó y rechaza una menor.
- La política solo puede nombrar bóvedas y proyectos por ID.

**Versión 2: grant por elemento (ADR 0036 §2).** El agente recibe llaves de elementos sueltos, nunca de un proyecto: es el grant del proxy de credenciales.

```
payload v2 = { v: 2, account_id, agent_id, version, issued_at, policy,
               projects: [],
               items: [ { vault_id, owner_account_id, project_id, item_id, shared_key } ],
               profiles: [ { name, item_id, field?, header, prefix?, upstream, rate_per_minute? } ] }
```

- `items[].shared_key` es la llave del elemento compartida por HPKE (tipo `0x23`, §8.2). El grant no lleva `labels`: el agente no resuelve referencias por nombre.
- Un grant con `items` no lleva `projects`. Los IDs de `items` y los nombres de `profiles` no se repiten, y **dos perfiles nunca usan el mismo elemento**: las reglas se atan a elementos, no a perfiles, así que dos perfiles sobre un mismo token compartirían los hosts, métodos y rutas que las reglas le permiten (ADR 0036 §8 quiere listas por perfil). Un formato posterior puede permitirlo; los clientes de ahora lo rechazan, que es fallar cerrado.
- Un **perfil**:
  - `name`: de 1 a 32 caracteres, letras minúsculas ASCII, dígitos o `-`, empezando por una letra. En el modo (a) es el primer segmento de la URL local.
  - `item_id`: un elemento del grant.
  - `field`: el campo con el valor, por nombre o ID, de 1 a 64 caracteres, sin caracteres de control, formato o separación (Unicode `Cc`, `Cf`, `Zl`, `Zp`) y no solo espacios. Sin `field`, el secreto principal del elemento: `password` en un `login` y `api_key` en un `api_key`; con otro tipo, el perfil tiene que nombrar el campo. El proxy nunca pone en una cabecera una semilla TOTP ni un campo vacío.
  - `header`: de 1 a 64 caracteres, letras minúsculas ASCII, dígitos o `-`. No puede ser ninguna de estas 12: `host`, `content-length`, `transfer-encoding`, `connection`, `keep-alive`, `te`, `trailer`, `upgrade`, `expect`, `forwarded`, `proxy-authorization`, `proxy-connection`; ni empezar por `proxy-` ni por `klav-`.
  - `prefix`: el texto delante del valor, hasta 64 bytes de ASCII imprimible (`0x20`–`0x7e`), sin saltos de línea.
  - `upstream`: `https://host` o `https://host:puerto` (puerto de 1 a 65535), sin ruta, usuario, consulta ni fragmento. El host ya está normalizado (minúsculas ASCII, sin punto final, etiquetas de `[a-z0-9-]`) y es un nombre, nunca una dirección IP: se rechaza un host cuya última etiqueta es un número (`10.0.0.1`, `127.1`, `2130706433`, `0x7f.1`), como lo leería un analizador de URL, y los literales IPv6 no pasan la normalización.
  - `rate_per_minute`: de 1 a 6000; 60 si falta.
- La política gana el permiso `proxy` y, en `Scope`, `items`, `methods` y `path_prefixes`, que solo pueden aparecer en reglas de `proxy`. Una regla de `proxy` que no es `deny` nombra sus elementos (todos del grant) y sus hosts; ninguno es `*` ni una dirección IP (la misma regla que en `upstream`). Si alguna regla puede permitir `proxy`, `reveal`, `inject` y `fill` llevan al menos una regla y todas son `deny`: el valor nunca sale del proxy por Klav, salvo hacia los hosts del perfil, que pueden devolverlo (un servicio que repite las cabeceras, T149 del modelo de amenazas). En la respuesta, el proxy reemplaza solo el valor entero, tal cual o en base64, hex, URL o JSON, nunca un trozo; los trozos de 12 caracteres o más los cuenta para la persona, sin que lo note un sandbox, que llama por el canal (un programa de la misma máquina y el mismo usuario puede leer las cuentas). Es una red para ecos accidentales, no una barrera.
- Cada perfil apunta a un elemento del grant, y alguna regla de `proxy` que no es `deny` deja a ese elemento llegar al host de su `upstream`.
- **Métodos:** de 1 a 16 letras mayúsculas ASCII (`A`–`Z`), comparados exactos; `get` se rechaza, no se pasa a mayúsculas. Una petición de `proxy` con un método que no cumple esto, o con `CONNECT` o `TRACE`, se deniega siempre, diga lo que diga una regla (una regla sin `methods` no mira el método).
- **Rutas:** cada byte se escribe de **una sola manera**, para que una regla `deny` o `ask` más estrecha no se esquive escribiendo la misma ruta de otra forma (`/v1/%63harges` por `/v1/charges`):
  - empieza con `/` y tiene como mucho 2048 bytes;
  - un byte ASCII visible (`0x21`–`0x7e`) que no sea `?`, `#`, `\`, `;` ni `%` va tal cual: su escape (`%63`, `%3A`) se rechaza;
  - un espacio, `?` o `#` va solo escapado y en hexadecimal mayúscula: `%20`, `%3F`, `%23`;
  - nada más se acepta: ni `;` (parámetros de ruta), ni `\`, ni otro escape (`%2F`, `%5C`, `%25`, `%3B`, hexadecimal en minúscula, caracteres de control, bytes de `0x80` en adelante, escapes mal formados), ni bytes fuera de ASCII;
  - sin segmentos vacíos (`//`) salvo una `/` final, y sin segmentos `.` ni `..`.

  Una ruta así se rechaza, no se normaliza. La de una petición puede terminar en `/`; un prefijo no (salvo `/`). Un prefijo coincide consigo mismo y en un límite de segmento (`/graphql` cubre `/graphql`, `/graphql/` y `/graphql/v2`, no `/graphqlx`). La comparación es **byte a byte y distingue mayúsculas**, y el proxy manda al proveedor exactamente los bytes que comprobó, sin volver a codificar ni normalizar nada entre la comprobación y el envío.
- **Límite:** un `deny` bajo un `allow` amplio vale lo que valga el enrutado del proveedor. Si el proveedor no distingue mayúsculas, o decodifica algo que el formato deja pasar tal cual, `/V1/Charges` puede llegar donde `deny /v1/charges` no alcanza. El formato no puede resolverlo; conviene que los `allow` sean estrechos. Lo mismo con un proveedor que lee `+` como espacio en la ruta, que recorta un `%20` final o los segmentos de solo puntos, o que decodifica y vuelve a analizar (`%3F`, `%23`): puede ver dos formas como una.
- **Escapes del cliente:** un cliente HTTP que escapa él mismo caracteres reservados dentro de un segmento (`%2C`, `%3A`, `%40`, `%2F` dentro de un ID, como hacen por defecto `PathEscape` de Go o `encodeURIComponent` de JavaScript) queda rechazado **a propósito**: esos escapes son otra forma de escribir la misma ruta. El proxy lo dice con el carácter rechazado y el motivo.
- **El servidor no impide que un grant por elemento se escriba sobre uno por proyecto, ni al revés.** Lo rechaza el cliente de la persona. Como todo grant lleva la firma de la cuenta, solo uno de los dispositivos de la persona podría hacerlo.
- Un elemento en la papelera puede seguir en un grant (el servidor solo rechaza los purgados): un grant que se vuelve a emitir tras un cambio de llave conserva todos sus elementos. Un grant **nuevo** no incluye elementos de la papelera, y `POST /v1/agent/access` nunca los entrega.
- `v: 1` sigue siendo el de arriba, byte por byte: `items` y `profiles` vacíos no se escriben. Un grant `v: 1` con algo de la versión 2, o un `v` que el cliente no conoce, se rechaza (falla cerrado), igual en el servidor, en los clientes de la persona y en el agente. Los clientes solo escriben `v: 2` cuando hace falta, y al volver a emitir un grant nunca bajan de `v: 2` a `v: 1` ni quitan sus `items` o `profiles` (`v: 3`, abajo).
- **Cambio de llave de un elemento.** Al revocar un grant que compartía un elemento, o al quitarlo de un grant por elemento, el cliente de la persona le da una llave nueva: sella sus secciones como la versión siguiente, envuelve la llave nueva con la del proyecto y vuelve a envolver con ella cada llave de adjunto (`0x04`) en la misma escritura (`attachment_keys` en `api.md`). Las versiones anteriores conservan sus llaves. Un elemento en la papelera también recibe la llave nueva y sigue en la papelera: el servidor acepta en él esa escritura y ninguna otra. Los demás agentes que tenían el elemento reciben un grant nuevo con la llave nueva; si uno falla, los demás siguen y el informe dice cuáles no la recibieron. Al quitar elementos de un grant por elemento, sus llaves cambian **antes** de subir el grant nuevo: si eso falla, el agente se queda con el grant anterior (cuyos elementos quitados ya no abre con la llave nueva) y repetir la operación la termina.
- **Adjuntos durante un cambio de llave.** `POST …/attachments` lleva `item_version`, la versión del elemento cuya llave envolvió la del adjunto. Si no es la actual, el servidor responde `409`, y lo comprueba con el candado de la bóveda que también toma el cambio de llave: o el adjunto se declara antes y el cambio de llave lo encuentra en curso (`409`), o el cambio de llave va antes y el adjunto ve una versión más nueva (`409`). Sin `item_version` (clientes anteriores) no se comprueba. La comprobación solo protege ante un servidor que conoce el campo: uno anterior rechaza el campo desconocido con un `400` que lo nombra, y el cliente vuelve a declarar el adjunto sin él. Eso no abre nada: un servidor que se salta la comprobación ya podía aceptar una subida con la llave vieja.

**Versión 3: emisores de sandboxes (ADR 0036 §3–§4).** Dos campos nuevos, cada uno en un grant distinto: `issuers` en el del proxy de credenciales y `sandbox` en el del agente que crea sandboxes (el **emisor**).

```
payload v3 del proxy  = payload v2 + { issuers: [ { agent_id, public_identity, profiles, max_ttl_secs, max_live } ] }
payload v3 del emisor = { v: 3, account_id, agent_id, version, issued_at, policy, projects,
                          sandbox: { proxy: { agent_id, public_identity, url } | null } }
```

- `issuers[]` solo va en un grant con `profiles`. `agent_id` no se repite ni es el propio proxy; `public_identity` (66 bytes, tipo `0x05`) es la que la persona aprobó, y es con la que el proxy verifica las peticiones del emisor, nunca una que le dé el servidor. `profiles`: de 1 a 6 nombres de perfiles de este grant, sin repetir. `max_ttl_secs`: de 300 a 86 400. `max_live`: de 1 a 50.
- `sandbox` va en el grant del emisor, nunca en uno con `items`, `profiles` o `issuers`: un proxy no es emisor. `proxy.public_identity` es la del proxy, de la que sale la huella del paquete (§13.10), y `proxy.url` es la dirección del paquete (`tls://host:puerto`, como mucho 255 bytes). `proxy` es `null` cuando la cuenta cambió de proxy (`klav proxy use`) o la persona quitó al emisor y el grant no tiene proyectos: un grant tiene que llevar algo. Con `sandbox`, el grant puede no llevar ni proyectos ni elementos: un emisor no necesita llaves (ADR 0036 §4).
- El servidor comprueba además que los agentes de `issuers` y `sandbox.proxy` son de la cuenta.
- **`v: 3` solo con `issuers` o `sandbox`**, y siempre con ellos: un grant `v: 2` no se reetiqueta `3`, y un grant `v: 1` o `v: 2` con alguno de los dos se rechaza. Al volver a emitir un grant, el cliente escribe el `v` que necesita lo que lleva, sin bajar nunca de 2 a 1: el grant del proxy vuelve a `v: 2` al quitar su último emisor, y el del emisor sigue en `v: 3` mientras lleve `sandbox`, también con `proxy: null`.
- Los clientes, `klavd`, el verificador de la bitácora y los `klav-proxy` anteriores rechazan `v: 3` («the grant is not readable»): el primer `klav proxy issuer add` de la cuenta pide `--every-device-is-updated`.

**Versión 4: la pasarela MCP (ADR [0049](decisiones/0049-mcp-gateway.md) §2–§3).** Un superconjunto de `v: 3` con tres cosas nuevas, todas en el grant del proxy:

```
perfil MCP      = perfil + { mcp: { endpoint, headers?: [ { name, value } ] } }
regla de proxy  = regla + { scope: { …, mcp_tools: [ patrón ] } }
payload v4      = payload v3 del proxy + { local_clients: [ { name, token_digest, profiles } ] }
```

- **`mcp.endpoint`:** la ruta del *endpoint* MCP en `upstream`, canónica (como las rutas de arriba) y de 64 bytes como mucho. Alguna regla de `proxy` que no es `deny` deja al elemento del perfil llegar al host de `upstream` con un prefijo que cubre el *endpoint*. **`mcp.headers`:** hasta 4 cabeceras fijas y no secretas; cada nombre sigue la regla de `header` de arriba, no es la del propio perfil ni una de estas: `authorization`, `cookie`, `www-authenticate`, `mcp-session-id`, `mcp-protocol-version`, `last-event-id`, `content-type`, `content-encoding`, `accept`, `accept-encoding`, `origin`; no se repite; y su valor tiene hasta 128 bytes de ASCII imprimible. `headers` vacío no se escribe.
- **`mcp_tools`:** patrones de herramienta, solo en reglas de `proxy` (`ToolPattern`). Un patrón es un nombre exacto en la gramática de herramientas (de 1 a 128 bytes de `A-Z a-z 0-9 _ - .`), ese nombre seguido de un `*` final (un prefijo), o `*` solo. Se compara byte a byte y distingue mayúsculas; un nombre fuera de la gramática no coincide con nada. Una regla con `mcp_tools` nombra al menos un elemento, y todos sus elementos son de perfiles MCP.
- **La evaluación** (ADR 0049 §5.3, Q3): una petición con herramienta (`mcp_tool`) solo la alcanzan las reglas sin `mcp_tools` que deniegan, como las peticiones que no se pueden juzgar; ningún valor por defecto deja pasar una herramienta (sin reglas para el permiso, `deny`); y una herramienta fuera de la gramática, o con un permiso que no es `proxy`, no se puede juzgar. Sin herramienta, la evaluación es la de siempre. Los vectores de `mcp-gateway.json` lo fijan.
- **`local_clients`:** solo en un grant con `profiles` (un proxy), como mucho 16. `name` tiene de 1 a 32 bytes de `a-z 0-9 -` y no se repite; `token_digest` son los 32 bytes de §13.16, sin repetir; `profiles` nombra uno o más perfiles **MCP** de este grant, sin repetir.
- **`v: 4` solo con algo de lo anterior**, y siempre con ello: un `v` menor con un perfil MCP, una regla con `mcp_tools` o `local_clients` se rechaza, y un `v: 4` sin nada de eso también. Al volver a emitir el grant, el cliente escribe el `v` que necesita lo que lleva, sin bajar de 2: vuelve a 3 o a 2 al quitar lo último de la pasarela.
- Los clientes, `klavd`, el verificador de la bitácora, los servidores y los `klav-proxy` anteriores rechazan `v: 4` (`deny_unknown_fields`, versión desconocida): fallan cerrados. Un `klav-proxy` de las capas 1–3 lo lee pero **no sirve** ningún perfil MCP hasta la capa 4.

**Entornos (ADR [0032](decisiones/0032-entornos-por-repositorio.md) §3.1 y §4), en cualquier versión.** Tres claves nuevas en la política y una en el payload, que no se escriben vacías o en falso, así que los grants sin ellas no cambian ni un byte:

```
regla           = regla + { once?: true, origin?: "protected" }
scope de regla  = scope + { items: [ item_id ] }      ← ahora en cualquier permiso
payload         = payload + { released?: [ item_id ] }
```

- **`Scope.items` en cualquier regla** (§4.1), por ID: el servidor ve el elemento de cada petición. AND entre dimensiones, OR dentro de la lista. Ya no exige `v: 2`: solo las reglas de `proxy` siguen nombrando únicamente elementos del grant, y una regla de otro permiso nombra elementos de los proyectos compartidos. Los lectores anteriores rechazan `items` fuera de `proxy`, así que fallan cerrados.
- **`once`** (§4.2) solo con `ask`: una aprobación bajo esa regla no lleva arrendamiento, se gasta en un uso y nunca va en una tarea. Entre las reglas que aplican, el orden es `deny` > `ask once` > `ask` > `allow`, y `Decision::once` dice si el `ask` ganador es `once`.
- **`origin: "protected"`** (§3.1): una regla **heredada** del conjunto protegido. Es `ask once`, su alcance son solo sus elementos (ninguna otra dimensión: una etiqueta, un host o unas horas la dejarían sin aplicar aunque siguiera escrita), no caduca y solo puede ser de `fill`, `inject`, `reveal`, `totp`, `update` o `delete` (`Policy::check_once`). Cuenta como regla de su permiso, así que el valor por defecto deja de aplicar, pero nunca sube una petición por encima de lo que dan las demás reglas: si aplica, un `allow` o un `ask` pasa a `ask once`, y un `deny` sigue siendo `deny`. Añadir una no hace más permisiva ninguna decisión (*proptests* en `klav-core::policy`).
- **`released`**: los elementos cuya protección heredada el grant deja a propósito, porque el cliente de la persona vio su versión del entorno que los quitó. Sin repetir, hasta 1024, y ninguno nombrado aún por una regla heredada.
- El cliente de la persona no firma, y el servidor responde `400`, a un grant con `once` fuera de `ask` o una regla heredada mal formada. El servidor responde **`409`** a un grant nuevo que pierde un par `(permiso, elemento)` heredado del grant en vigor sin nombrar el elemento en `released` (`GrantPayload::lost_protection`).
- Para el servidor, un destino «pide cada vez» si `evaluate` dice `ask once` o, sin fiarse de las etiquetas, el host, el método, la ruta ni la herramienta que declara el agente, si alguna regla `once` viva de ese permiso coincide con la bóveda, el proyecto, las horas y el elemento (`Policy::may_require_once`). `passkey` y `rotate` sobre un elemento protegido se deniegan siempre, también dentro de una tarea.

### 13.5 Decisión sobre una aprobación

```
mensaje = tuple("klav/v1/sig/approval", approval_id(16), agent_id(16), petición, "approve" | "deny", u64_be(lease_until_ms), u64_be(decided_at_ms))
```

- `petición` son los bytes JSON de la petición pendiente, tal como los guarda el servidor y se le muestran a la persona.
- `lease_until_ms` es el fin del arrendamiento ("aprobar 15 min"), o `0` para "solo esta vez" y para las negativas.
- **Un entorno y sus elementos protegidos** (ADR [0032](decisiones/0032-entornos-por-repositorio.md) §3.1). Un `inject` sobre un entorno puede nombrar en `items` los demás elementos que resuelve la misma llamada. La petición pendiente gana entonces `items`, con sus IDs ordenados, y la aprobación vale **un** acceso a `item_id` y uno a cada elemento de la lista, cada uno con su propio `access` que nombra la aprobación. Nunca lleva arrendamiento ni va a una tarea. Se gasta cuando se usan todos o cuando pasa la ventana de una sola vez. Sin `items`, la petición es la de siempre byte a byte; un dispositivo anterior la rechaza (`deny_unknown_fields`) y no muestra la tarjeta.
- **Sin arrendamiento ni tarea en lo que pide cada vez** (ADR 0032 §4.2): el servidor responde `400` a una decisión con `lease_until_ms > 0`, o con «Añadir a la tarea», sobre un destino que pide cada vez (§13.4) o una petición con `items`.
- **La pasarela MCP** (ADR [0049](decisiones/0049-mcp-gateway.md) §5.4). Con el interruptor `mcp_gateway` de la cuenta encendido, la petición gana `caller`, `{"sandbox_id": …}` o `{"local_client": …}` (exactamente uno), cuando la llamada es de un sandbox o de un cliente local, y sus `claims` pueden traer `mcp_tool` y `mcp_args` (§13.16). Con el interruptor apagado no aparecen, y la petición es la de siempre byte a byte. El dispositivo comprueba la gramática de la herramienta y del cliente antes de mostrar nada; si falla, muestra una tarjeta de seguridad y no firma nada.

### 13.6 Revocación

```
mensaje = tuple("klav/v1/sig/agent-revocation", account_id(16), agent_id(16), u64_be(revoked_at_ms))
```

### 13.7 Bitácora

Cada cuenta tiene una sola cadena de eventos (diseño §6, ADR 0014 §6). El protocolo está en [`api.md`](api.md) §9.

```
hash_0 = 32 bytes en cero
hash_n = SHA-256(tuple("klav/v1/audit/event", u64_be(n), hash_{n-1}, evento_n))
cabeza = Ed25519 sobre tuple("klav/v1/sig/audit-head", account_id(16), u64_be(n), hash_n)
```

- `evento_n` son los bytes JSON exactos del `AuditEvent` (klav-proto) que guardó el servidor, con `seq = n`. Nadie lo vuelve a serializar.
- `n` empieza en 1 y no tiene huecos. Incluir `n` en el hash impide mover un evento de lugar.
- Lo que cada evento prueba por sí mismo lo fija una tabla cerrada por `action` (ADR 0030 §4). El verificador no se fía del `actor` que escribe el servidor: lo compara con la tabla, y una acción que no está en ella hace fallar la verificación.

  | `action` | `actor` | Lo respalda | Método y ruta firmados |
  |---|---|---|---|
  | `agent.access` | `agent` | petición del agente, **con cuerpo** (en `proxy`, también `method` y `path` de `claims`, y el `sandbox` para el que es la llamada, si lo nombra; el verificador rechaza un `sandbox` con otro permiso) | `POST /v1/agent/access` |
  | `agent.create` | `agent` | petición del agente | `POST /v1/agent/items` |
  | `agent.update` | `agent` | petición del agente | `PUT /v1/agent/items/{item_id}` |
  | `agent.trash` | `agent` | petición del agente | `POST /v1/agent/items/{item_id}/trash` |
  | `agent.ask` | `agent` | petición del agente, **con cuerpo** | `POST /v1/agent/approvals` |
  | `task.requested` | `agent` | petición del agente, **con cuerpo** | `POST /v1/agent/tasks` |
  | `task.ended` (`outcome = agent`) | `agent` | petición del agente, **con cuerpo** | `POST /v1/agent/tasks/{task_id}/end` |
  | `rotate.started` | `agent` | petición del agente, **con cuerpo** | `POST /v1/agent/rotations` |
  | `rotate.confirmed`, `rotate.cancelled` | `agent` | petición del agente, **con cuerpo**, y un `rotate.started` anterior | `POST /v1/agent/rotations/{rotation_id}/confirm` (o `/cancel`) |
  | `rotate.confirmed`, `rotate.cancelled` | `person` | solo el servidor, y un `rotate.started` anterior | — |
  | `agent.granted`, `approval.decided`, `task.decided`, `agent.revoked` | `person` | firma de la cuenta (§13.4–§13.6, §13.8) | — |
  | `agents.paused`, `agents.resumed` | `person` | firma de la cuenta (`agent-pause`, §13.9) | — |
  | `task.ended` (`outcome = person`) | `person` | firma de la cuenta (`task-end`, §13.8) | — |
  | `sandbox.issued` | `agent` | petición del proxy, **con cuerpo** | `POST /v1/agent/sandboxes` |
  | `sandbox.claimed` | `agent` | petición del proxy, **con cuerpo**, y un `sandbox.issued` anterior | `POST /v1/agent/sandboxes/{sandbox_id}/claimed` |
  | `sandbox.revoked` | `agent` | petición del proxy, **con cuerpo**, y un `sandbox.issued` anterior | `POST /v1/agent/sandboxes/{sandbox_id}/revoked` |
  | `sandbox.revoke_requested` | `person` | firma de la cuenta (`sandbox-revoke`, §13.11) | — |
  | `sandbox.store_reset` | `agent` | petición del proxy, **con cuerpo** (`{store_epoch}`, §13.12) | `POST /v1/agent/sandboxes/epochs` |
  | `task.ended` (`outcome = revocation`), `agent.denied`, `item.created`, `item.updated`, `item.trashed`, `item.restored`, `item.purged`, `project.rotated`, `passkey.used` | `person` | solo el servidor | — |
  | `task.ended` (`outcome = expiry`), `agent.registered` | `agent` | solo el servidor | — |

- Eventos de un agente. Llevan su petición firmada (§13.3), con el cuerpo si mide hasta 16 KiB (`MAX_PROOF_BODY`). El servidor rechaza con `400` un cuerpo mayor en las rutas marcadas **con cuerpo**, así que en ellas el cuerpo es obligatorio. El verificador comprueba:
  - que el método y la ruta firmados sean los de la acción, y que el `item_id` o el `task_id` de la ruta sean los del evento;
  - que el cuerpo coincida con su resumen y se lea como la petición de esa ruta;
  - que el elemento, el permiso, la razón (sin espacios a los lados) y el host (`claims.domain`) del evento sean los firmados. En `agent.create`, la bóveda y el proyecto también; el permiso de `agent.create`, `agent.update` y `agent.trash` es `create`, `update` y `delete`. En `agent.ask`, la bóveda y el proyecto también, y el permiso firmado tiene que ser `create`, `update` o `delete`. `task.requested` y el fin por el agente no llevan elemento, permiso ni host. Los pasos de un cambio asistido (ADR 0022 §5) llevan el permiso `rotate`; el host de `rotate.started` es el `claims.domain` firmado, normalizado;
  - que el par `(agent_id, nonce)` no se repita en la cadena, y que `|timestamp − at| ≤ 5 min` (T25);
  - la firma, con la identidad del agente que da `GET /v1/agents`, pero solo si antes, en la cadena, un `agent.granted` verificó con esa misma identidad (el mensaje del grant la incluye, §13.4). Una identidad listada sin ese aval hace fallar la verificación. Un agente que el servidor ya no lista no hace fallar nada: queda como aviso y su firma no se comprueba, pero el resto de las reglas sí.

- La vida de un sandbox (ADR 0036 §9, E3.3). El proxy de credenciales firma cada paso; el evento solo dice el proxy (`agent_id`) y, en `sandbox.revoked`, el motivo firmado en `outcome`, sin elemento, permiso, razón, host, tarea ni aprobación. Lo demás (el emisor, la etiqueta, los perfiles, `expires_at`, la llave del canal) queda en el cuerpo firmado. El verificador exige:
  - en `sandbox.issued`, un cuerpo `{sandbox_id, issuer_id, label, profiles, expires_at}` con una etiqueta de 1 a 64 caracteres sin espacios a los lados ni caracteres ocultos (`klav_core::text::is_hidden`), de 1 a 6 perfiles sin repetir cuyos nombres siguen la regla del grant (de 1 a 32 minúsculas, dígitos o `-`, empezando por una letra; `klav_proto::agent::profile_name_ok`), un emisor que no es el proxy y un `sandbox_id` que la cadena no emitió antes;
  - en `sandbox.claimed`, `{channel_key_sha256}` de 32 bytes (§13.10), y en `sandbox.revoked`, `{reason}`, uno de `stop`, `ttl`, `inactivity`, `theft`, `released` o `issuer_removed`;
  - que el reclamo y el fin nombren en su ruta un sandbox que **el mismo proxy** emitió antes en la cadena, cada uno una sola vez, ninguno después del fin, y `theft` o `released` solo después del reclamo.

  Avisa (sin error) de un `sandbox.issued` o un `sandbox.claimed` con el proxy o el emisor en pausa. El fin nunca avisa: solo quita acceso. Un `klav log verify` anterior a estas acciones falla ante la primera (la tabla es cerrada).

  La revocación de la persona (capa 5a, §13.11) añade a la tabla `sandbox.revoke_requested` y a los motivos `person` (con el `at` de la revocación que responde) y `person_local`. `sandbox.revoke_requested` solo puede pedirlo la persona, con la firma de la cuenta. El servidor acepta un fin `person` solo si tiene registrada una revocación de ese proxy con ese `at` que cubre el sandbox. `person_local` (la persona por el *socket* local del proxy, E3.5) no responde a ninguna; el servidor lo acepta desde la capa 11 (la que lo manda), solo como `{"reason":"person_local"}`, y antes lo rechazaba con `400`: solo lo firma la llave del proxy (riesgo residual 64). Todo verificador publicado ya lo comprueba (este, de la capa 5a). El verificador acepta los tres y comprueba: la firma de la cuenta; que el `at` firmado de cada proxy y alcance crezca; que un sandbox nombrado lo haya emitido antes ese proxy; que el evento se haya registrado a no más de 5 min del `at` firmado (§13.11); que la lista de un `all` sea exactamente la que rehace de la cadena y del `at` firmado (§13.11); y que un fin `person` venga después de una revocación de ese proxy que cubre su sandbox, con ese `at`. Un fin con `person` o `person_local` solo vale como objeto JSON (el servidor rechaza la forma de arreglo de cualquier fin; el verificador sigue aceptándola en los motivos anteriores, como antes). Un `sandbox_id` o `sandbox_ids` en cualquier otra acción es un error. Avisa, sin error, como con la pausa (ADR 0033 §7.6), de una llamada permitida o de un reclamo de un sandbox después de su revocación por la persona. Un `klav log verify` anterior a esta capa falla ante el primero de los tres.

  El almacén nuevo del proxy (capa 5a, latido, §13.12) añade `sandbox.store_reset`. El verificador exige un cuerpo `{store_epoch}` de 16 bytes, que sea un objeto JSON (la forma de arreglo `["…"]` no vale) y sin otros campos, y sin `outcome` en el evento, y que ese proxy no haya nombrado antes esa época en la cadena; otro proxy puede tener los mismos bytes. La época del último `sandbox.store_reset` de cada proxy cuya firma comprobó (un proxy avalado por un grant, como en el resto de la tabla) sale en el informe (`VerifyReport::store_epochs`, con su posición), y es la única con la que un dispositivo acepta un latido. Un proxy que el servidor ya no lista no tiene época en el informe. Avisa, sin error, de un `sandbox.store_reset` con el proxy en pausa, porque el servidor rechaza toda petición firmada de un agente en pausa salvo `me`. Un `klav log verify` anterior a esta capa falla ante el primero.
- Pasos de un cambio asistido. La confirmación o la cancelación (del agente o de la persona desde la tarjeta del elemento) no firman el host. El verificador exige que su agente, su elemento, su host y, si lo nombra, su tarea sean los de un `rotate.started` permitido que vino antes en la cadena; un `rotate.started` permitido sin tarea, elemento o host hace fallar la verificación. El paso de la persona no lleva permiso ni razón.

  En `agent.create` y `agent.update` con un cuerpo mayor de 16 KiB (el elemento cifrado), la ruta sigue fijando el elemento y el permiso; la razón y el host solo los atestigua el servidor. La bóveda y el proyecto de los demás eventos de agente, el `approval_id`, el `task_id` de la tarea que dejó pasar un uso, el `outcome` y las alertas los escribe el servidor.
- Grants, decisiones, revocaciones y pausas. Llevan los bytes firmados (o, en la revocación, el fin de una tarea y las pausas, los campos de los que se rehace la tupla) y la firma de la cuenta (§13.4–§13.6, §13.8, §13.9). Lo que el evento dice debe salir de esos bytes:
  - en `agent.granted`, la cuenta y el agente del payload deben ser los del evento;
  - en `approval.decided`, la aprobación, el agente, la bóveda, el proyecto, el elemento y el permiso deben ser los de la petición firmada, y la razón y el host, si el evento los lleva, también;
  - los demás no llevan elemento, permiso, razón ni host.
- Lo que solo atestigua el servidor no puede llevar permiso, razón, host, petición de agente ni firma de la cuenta. El contenido de los cambios de la persona ya lo protege el AEAD; el evento solo dice cuándo ocurrió.
- Al leer la cadena, cada página de `GET /v1/audit?after=` debe empezar en `after + 1` y seguir sin huecos. Una página vacía antes de `head_seq` es un error.
- Un dispositivo de confianza que verificó la cadena hasta `n` firma la cabeza `(n, hash_n)` con la identidad de la cuenta y la sube. También la guarda en `audit-head.json` en su directorio local, con el `account_id` de la cuenta: un archivo de otra cuenta no se usa, y uno sin `account_id` (anterior a la capa 05) se toma como propio y se reescribe. Si no hay archivo y la cadena tiene eventos, el verificador avisa de que es la primera verificación en ese dispositivo. En adelante, una cadena que ya no llegue a ese hash (evento editado, borrado o reordenado) o que sea más corta se rechaza.
- El servidor guarda una cabeza por dispositivo y posición (una que el dispositivo ya subió, o una anterior a su última, no se guarda otra vez) y lista las 100 más recientes de la cuenta más la última de cada dispositivo (la de `n` más alto), para 1 000 dispositivos como mucho ([`api.md`](api.md) §9). La lista es decisión del servidor: puede omitir cabezas (T12, riesgo residual 10).
- El servidor puede **omitir** eventos posteriores a la última cabeza firmada (no los puede probar nadie más que él). Es el riesgo residual de T12. También puede **reordenarlos**, encadenándolos de nuevo, mientras ninguna cabeza firmada los cubra: por ejemplo, poner un `all` antes del `sandbox.issued` de un sandbox, que entonces no lo cubre.

### 13.8 Decisión sobre una solicitud de tarea

ADR [0021](decisiones/0021-solicitudes-de-tarea.md) §4. Tipos `TaskRequest` y `TaskDecision` en `klav-core::task`; vectores en `agentes.json`.

```
mensaje = tuple("klav/v1/sig/task-decision", task_id(16), agent_id(16), solicitud, decisión, "approve" | "deny", u64_be(decided_at_ms))
fin     = tuple("klav/v1/sig/task-end", account_id(16), task_id(16), agent_id(16), u64_be(ended_at_ms))
```

- `solicitud` son los bytes JSON de la solicitud del agente, tal como los guarda el servidor; vacía en una tarea ofrecida por la persona (ADR 0022 §6). Es el cuerpo exacto del `POST /v1/agent/tasks` del agente, que ya va firmado por él (§13.3), así que su resumen coincide con el de la petición firmada:
  ```
  {v: 1, task, reason, duration_secs, access: [{vault_id, project_id, item_id, permissions, domain?}]}
  ```
  - `task` (1–120 caracteres) y `reason` (1–500) sin caracteres de control, de formato (`Cf`: *bidi* como U+202A–U+202E y U+2066–U+2069, de ancho cero) ni separadores de línea o párrafo (`Zl`, `Zp`), desde la capa 06 de la ronda 2026-11 (`klav_core::text::is_hidden`). Lo comprueban el cliente, el runtime y el servidor. Van en claro (T20).
  - `duration_secs` entre 300 y 86 400.
  - `access`: de 1 a 50, un elemento una sola vez; `permissions` sin repetir, entre `fill`, `totp`, `inject`, `update`, `passkey` y `rotate` (nunca `reveal`, `delete`, `list` ni `create`); `domain` es un host.
- `decisión` son los bytes JSON de la decisión, también guardados tal cual:
  ```
  {v: 1, task_id, agent_id, revision, expires_at_ms, access: [{vault_id, project_id, item_id, permissions, domains, added_by_klav}], offer?: {task, reason}}
  ```
  - `revision` empieza en 1. Cada «Añadir a la tarea» firma una decisión nueva con `revision + 1`, el mismo `expires_at_ms` y sin quitar nada de la anterior.
  - `domains` son los hosts aprobados, en minúsculas; vacío para elementos sin sitio (tarjetas, llaves de API).
  - `added_by_klav` es la lista de permisos que añadió el cliente de la persona (`totp`, `passkey`), un subconjunto de `permissions`. Es una lista y no un booleano porque Klav añade `totp` a un acceso que ya tiene el `fill` que pidió el agente.
  - En la primera decisión, cada elemento aprobado está en la solicitud y cada permiso lo pidió el agente o está en `added_by_klav`; `expires_at_ms` es posterior a `decided_at_ms` y no pasa de `decided_at_ms + min(duration_secs, 86 400) · 1000`.
  - Una negativa lleva `revision = 1`, `access` vacío y `expires_at_ms = 0`.
  - `rotate` exige al menos un host en `domains` (T99): sin sitio no hay página de cambio que comprobar.
  - `offer` solo existe en una **tarea ofrecida** (ADR 0022 §6): la persona la firma sin solicitud del agente, así que `solicitud` va vacía y el título y el motivo los escribe ella (`task` de 1–120 caracteres y `reason` de 1–500, sin caracteres de control). La primera decisión de una tarea ofrecida lleva `revision = 1`, vence después de `decided_at_ms` y no más de 24 h después, y `added_by_klav` solo contiene `totp` o `passkey`. Cada «Añadir a la tarea» conserva el mismo `offer`. Una decisión sobre una solicitud del agente no lleva `offer`; si falta, el campo no se serializa y los bytes de una decisión anterior no cambian. Vector: `task_offer` y `task_offer_signature` en `agentes.json`.
- `fin` lo firma la persona al terminar una tarea, con la misma forma que la revocación (§13.6). El agente que termina su propia tarea no firma nada más: su petición ya va firmada (§13.3).

### 13.9 Pausa y reanudación de los agentes

ADR [0033](decisiones/0033-agentes-desde-la-app-de-mac.md) §7. Funciones `sign_pause` y `verify_pause` en `klav-core::crypto::agent`; vectores en `agentes.json`.

```
mensaje = tuple("klav/v1/sig/agent-pause", account_id(16), alcance, estado, u64_be(at_ms), u64_be(until_ms))
```

- `alcance`: los 3 bytes ASCII `all` (todos los agentes de la cuenta, también los que se aprueben después), o los 16 bytes crudos del `agent_id` (un agente). Como las longitudes son distintas, un alcance no se puede leer como el otro.
- `estado`: `pause` o `resume`, en ASCII.
- `at_ms`: cuándo decidió la persona, en milisegundos Unix.
- `until_ms`: fin de la pausa en milisegundos Unix, o `0` si no tiene fin. Una reanudación lleva siempre `0`. El fin de una pausa con duración no necesita otra firma: `until_ms` ya va firmado.
- El servidor rechaza una decisión con `|ahora − at_ms| > 5 min`, como la revocación, y una cuyo `at_ms` no sea mayor que el de la última decisión del mismo alcance. Así no se puede repetir una reanudación vieja.
- En la bitácora, `agents.paused` y `agents.resumed` (§13.7) llevan la firma de la cuenta y los campos de los que se rehace el mensaje: el agente (ninguno si el alcance es `all`), `decided_at` = `at_ms` y, en una pausa con fin, `until` = `until_ms`. No llevan `signed`, igual que la revocación: el mensaje es solo la tupla.
- El servidor responde ese `409` con `last_at` = el `at_ms` de la última decisión del alcance. El cliente vuelve a firmar una **pausa** (nunca una reanudación) en `max(ahora, last_at + 1)` si eso queda a 5 minutos o menos de su reloj y antes de `until_ms`; es otra firma sobre otra tupla, no se reutiliza la anterior.
- El verificador comprueba además que el `at_ms` de cada alcance crezca a lo largo de la cadena. Avisa (sin error) de cada `agent.access`, `agent.create`, `agent.update`, `agent.trash`, `rotate.started`, `rotate.confirmed` o `rotate.cancelled` con `outcome = allow` y firmado por un agente en pausa: después de una pausa firmada de su alcance o de `all`, y antes de la reanudación firmada de ese alcance o de que `at` llegue a `until_ms`. Un `rotate.*` de la persona (`actor = person`, sin firma del agente) no avisa: cerrar un cambio es suyo. Una cancelación del agente sí, porque el servidor rechaza toda petición firmada de un agente en pausa.

### 13.10 Paquete de un sandbox (`ksb1_`)

ADR [0036](decisiones/0036-sandboxes-de-agentes.md) §4 y §5. Funciones en `klav-core::crypto::sandbox`; vectores en [`docs/vectores/sandbox.json`](vectores/sandbox.json).

El **paquete** es lo que el emisor le da a un sandbox para que su reenviador lo reclame ante el proxy. **No es una llave de Klav:** no descifra nada ni firma nada ante el servidor. Su secreto se gasta con el primer reclamo (ADR 0036 §5).

```
paquete = 0x01 ‖ sandbox_id(16) ‖ secreto(32) ‖ u64_be(vence_ms) ‖ huella(32) ‖ lp(url)
texto   = "ksb1_" ‖ BASE64URL-SIN-RELLENO(paquete)
spki    = 30 2a 30 05 06 03 2b 65 70 03 21 00 ‖ ed25519_pk(32)          (44 bytes, RFC 8410)
huella  = SHA-256(spki)
resumen = SHA-256(tuple("klav/v1/sandbox/secret", sandbox_id(16), secreto(32)))
```

- **El primer byte es la versión** (`0x01`). No lleva byte de tipo: no es un blob de §3, y el prefijo `ksb1_` ya dice qué es.
- `sandbox_id`: 16 bytes que elige el proxy al crear el sandbox.
- `secreto`: 32 bytes aleatorios nuevos del proxy. El proxy no lo guarda: guarda el `resumen`, que lleva el `sandbox_id` dentro para que el resumen de un sandbox nunca sirva para otro, y lo compara en tiempo constante.
- `vence_ms`: cuándo vence el sandbox, en milisegundos Unix; nunca `0`.
- `huella`: el SHA-256 del `SubjectPublicKeyInfo` DER de la llave Ed25519 de la **identidad del proxy** (§6.2), la misma que la persona comparó con las 6 palabras al emparejarlo. Es lo que el reenviador fija en el canal TLS (ADR 0036 §6): el proxy la presenta como llave pública en bruto (RFC 7250) o dentro de un certificado autofirmado, y la huella es la misma en los dos casos. Las firmas de Klav sobre esa llave no se confunden con la de TLS 1.3: todo mensaje de Klav empieza con `lp(etiqueta)`, cuyos 4 primeros bytes son una longitud corta, y el de `CertificateVerify` de TLS 1.3 empieza con 64 bytes `0x20` (RFC 8446 §4.4.3).
- `url`: dónde el reenviador llega al proxy, `tls://HOST:PUERTO`, como mucho 255 bytes. `HOST` es un nombre DNS en minúsculas (etiquetas de `[a-z0-9-]`, de 1 a 63 bytes, sin `-` al principio ni al final), una IPv4 con cuatro decimales o una IPv6 entre corchetes en minúsculas; `PUERTO` va de 1 a 65535, en decimal y sin ceros a la izquierda. En esta versión no hay otro esquema.
- **El emisor arma el paquete** con lo que le responde el proxy (`sandbox_id`, `secreto`, `vence_ms`) y con la huella y la `url` de **su propio grant**, firmado por la cuenta (§13.4). Así, un proceso que se haga pasar por el proxy no puede mandar el sandbox a otro sitio: el proxy de verdad no conoce su secreto.
- Al decodificar se ignoran los espacios en blanco alrededor del texto y se rechaza: otro prefijo, base64url inválido, otra versión, un paquete más corto que su parte fija, `vence_ms = 0`, una longitud de `url` que no coincide con lo que sigue (ni bytes de más ni de menos) y una `url` que no cumple la regla de arriba.
- El paquete y el secreto nunca van a un registro, a un mensaje de error ni a la salida `--json` de `klav sandbox start` (ADR 0036 E6.1).
- **La llave de Tailscale de un sandbox nunca va en el paquete:** viaja aparte, en `KLAV_TAILNET_KEY` (ADR [0042](decisiones/0042-sandboxes-for-daily-use.md) §4).
- **La llave del canal.** El reenviador presenta en el canal una llave Ed25519 suya, nueva en cada arranque (ADR 0036 §5). El proxy registra el reclamo con `channel_key_sha256 = SHA-256(spki)` de esa llave, con el mismo `spki` de arriba: los dos extremos del canal fijado se nombran igual. Vectores de las tres peticiones del proxy (§13.3, §13.7) en [`docs/vectores/sandbox-events.json`](vectores/sandbox-events.json).
- **El canal** (ADR 0036 §6, capa 6). Es TLS 1.3 con `rustls` y el proveedor `aws-lc-rs`, y nada de lo que sigue es criptografía propia: TLS hace el intercambio y las firmas del *handshake* las verifica `rustls` (`verify_tls13_signature_with_raw_key`).
  - **Llaves en bruto (RFC 7250) en los dos extremos,** sin certificados: el proxy presenta el `spki` de la llave Ed25519 de su identidad, y el reenviador el de su llave del canal. El esquema de firma es solo `ed25519`.
  - **Solo TLS 1.3,** sin reanudación de sesión: cada conexión vuelve a probar su llave. TLS 1.2 se rechaza en los dos lados.
  - **El reenviador acepta al proxy** solo si presenta exactamente una llave, es un `spki` Ed25519 y `SHA-256(spki) = huella`, comparado en tiempo constante. No mira el nombre del servidor (la huella nombra al proxy, no el DNS) ni la fecha (una llave en bruto no vence).
  - **El proxy exige una llave al reenviador,** exactamente una y Ed25519, y no decide en el *handshake* si esa llave puede algo: una llave nueva es como empieza todo reclamo. Lo decide después, por `SHA-256(spki)` de la llave que el *handshake* probó, nunca por algo que diga la petición.
  - **Lo que firma cada llave.** La identidad del proxy firma en el canal solo el contenido de un `CertificateVerify` de servidor de TLS 1.3 (64 bytes `0x20`, `"TLS 1.3, server CertificateVerify"`, un `0x00` y un *hash* de 32 o 48 bytes). La llave del canal firma solo el de cliente. `klav-core` (`crypto::channel::TlsSigner`) rechaza cualquier otro mensaje, así que la llave de la identidad nunca sale de `klav-core` y el canal no la puede usar para firmar un mensaje de Klav.

### 13.11 La persona revoca sandboxes

ADR [0036](decisiones/0036-sandboxes-de-agentes.md) E3.3 (capa 5a). Funciones `sign_revoke` y `verify_revoke` en `klav-core::crypto::sandbox`; vectores en [`docs/vectores/sandbox-revoke.json`](vectores/sandbox-revoke.json).

```
mensaje = tuple("klav/v1/sig/sandbox-revoke", account_id(16), proxy_id(16), alcance, u64_be(at_ms))
```

- `proxy_id`: el agente que es el proxy de credenciales de esos sandboxes.
- `alcance`: los 3 bytes ASCII `all` (todos los sandboxes de ese proxy que la bitácora emitió antes de esta revocación), o los 16 bytes crudos del `sandbox_id` (uno). Como en la pausa (§13.9), las longitudes distintas impiden leer un alcance como el otro.
- `at_ms`: cuándo revocó la persona, en milisegundos Unix. Sirve contra la repetición: el servidor rechaza un `at_ms` a más de 5 min de su reloj y uno que no sea mayor que el de la última revocación del mismo proxy y alcance (`409` con `last_at`, como la pausa). Qué sandboxes cubre `all` lo decide el orden de la bitácora (los emitidos antes del evento); `at_ms` solo deja fuera los que ya vencieron, con la ventana del reloj (abajo).
- En la bitácora, `sandbox.revoke_requested` (§13.7) lleva la firma de la cuenta y los campos de los que se rehace el mensaje: el proxy (`agent_id`), `decided_at` = `at_ms` y, con un sandbox, `sandbox_id`; sin él, el alcance es `all`. Con `all`, `sandbox_ids` lista, ordenados por sus 16 bytes, los sandboxes de ese proxy que el servidor leyó con el cerrojo de la cuenta: los que tienen su `sandbox.issued` antes en la cadena, ningún `sandbox.revoked` antes y `expires_at > at_ms − 5 min`, con el `at_ms` firmado (`klav_proto::sandbox::all_covers`, la misma regla en el servidor y en el verificador). Incluye los que la persona ya revocó y el proxy aún no terminó, y los que vencieron hace menos de 5 min: la ventana del reloj hace la regla más amplia, no más estrecha, para que un dispositivo con el reloj hasta 5 min adelantado no deje fuera un sandbox que el servidor todavía cuenta como vivo (uno ya vencido queda bloqueado igual). Así, ninguna hora que ponga el servidor decide qué cubre `all`. El `at` del propio evento, que nadie firma, debe estar a no más de 5 min (`CLOCK_SKEW_MS`) del `at_ms` firmado: el servidor rechaza un `at_ms` más lejos de su reloj y registra el evento con esa misma lectura del reloj, así que una cadena honesta siempre pasa. Ya no decide la lista, así que es solo una comprobación de cordura. Lo que el servidor sí decide es la posición del evento en la cadena, y con ella qué sandboxes se emitieron antes: eso lo cubre lo que §13.7 dice de omitir y reordenar tras la última cabeza firmada. La lista no la firma la cuenta, pero se rehace byte a byte de la cadena y del `at_ms` firmado, y el verificador la compara así. No lleva `signed`: el mensaje es solo la tupla.
- La posición `seq` de ese evento es el cursor con el que el proxy lee las revocaciones (`api.md` §8.8).

### 13.12 Época del almacén y latido del proxy

ADR [0036](decisiones/0036-sandboxes-de-agentes.md) E3.3 (capa 5a, latido). Tipos `SandboxStoreReset` y `SandboxHeartbeat` en `klav-proto::sandbox`; comprobación del dispositivo en `klav-client::sandbox_state::check_heartbeat`; vectores en [`docs/vectores/sandbox-heartbeat.json`](vectores/sandbox-heartbeat.json). Las dos son peticiones firmadas del proxy (§13.3), sin etiqueta nueva. Las rutas, lo que el servidor rechaza y quién puede llamarlas están en `api.md` §8.8 desde la capa 5a (latido, rutas); el proxy las manda desde esa misma capa.

- **La época del almacén.** Cada almacén nuevo del proxy, también el primero, crea una época de 16 bytes al azar, y el proxy la registra antes de su primer latido con `POST /v1/agent/sandboxes/epochs` (la ruta, decidida por Omar el 2026-11-13) y el cuerpo `{"store_epoch": <16 bytes en base64url sin relleno>}`, un objeto JSON sin otros campos. En la bitácora es `sandbox.store_reset` (§13.7). Un proxy nunca usa una época dos veces: el verificador rechaza una que ese proxy ya nombró en la cadena, y el servidor la guarda en `sandbox_store_epochs` (migración 0019), y contesta `409` a una repetida y `400` a un cuerpo que no es un objeto JSON, sin registrar nada.
- **El latido.** `PUT /v1/agent/sandboxes/state` con el cuerpo:

  ```
  {"v": 1, "store_epoch": <16 bytes>, "seq": u64, "sent_at_ms": i64,
   "sandboxes": [{"id": <sandbox_id>, "connected": bool, "last_seen_at": i64 opcional}]}
  ```

  Sin otros campos en ningún nivel, y el cuerpo es un objeto JSON: el servidor contesta `400` a la forma de arreglo y no la guarda. `v` es 1. `seq` empieza en 1 y crece con cada latido de esa época; el proxy lo guarda antes de mandarlo, junto con la época, en su propio archivo junto al almacén (`<nombre>.sandbox-heartbeat`, 0600, con versión; `api.md` §8.9), así que el formato del almacén no cambia (decidido por Omar el 2026-11-13; el ADR, E3.3, pone `seq` en el almacén del proxy). Un latido que el servidor rechaza en pausa se guarda ahí y sale tal cual al reanudarse; si entonces el servidor lo rechaza con un `400`, se descarta y sale uno nuevo. Un archivo que falta o no se lee empieza una época nueva. `sent_at_ms` es la hora del proxy al firmar el latido (mayor que 0); la edad sale de ahí, no del `timestamp` de la petición, que el proxy firma de nuevo cada vez que lo manda (también el latido que guardó durante una pausa, al reanudarse). Como mucho 100 sandboxes (`MAX_HEARTBEAT_SANDBOXES`, decidido por Omar el 2026-11-13; subirlo después es caro, porque un dispositivo que lee más rechaza el latido en el paso 3, como error de seguridad), sin repetir; un proxy con más nombra primero los conectados y luego los vistos más recientemente. Así el cuerpo cabe siempre entero en los 16 KiB de `MAX_PROOF_BODY`. `last_seen_at` falta si el proxy nunca supo de ese sandbox, y si está, es mayor que 0 y no posterior a `sent_at_ms`. El latido no va a la bitácora: el servidor guarda solo el último de cada proxy (`sandbox_heartbeats`, migración 0019) y lo devuelve tal como se firmó.
- **Lo que comprueba el dispositivo** (`check_heartbeat`), con la identidad del proxy que avala un grant verificado:
  1. el método y la ruta firmados son `PUT /v1/agent/sandboxes/state`, con el cuerpo, que coincide con su resumen;
  2. la firma de §13.3, con el nonce de 16 bytes;
  3. el cuerpo es un latido con la forma de arriba.

  Si algo de esto falla, es un error de seguridad. Después:
  4. la época es la del último `sandbox.store_reset` de ese proxy en la cadena verificada. Si no hay ninguno, o es otra, el latido no cuenta y la app dice que el proxy no da señales;
  5. un `sent_at_ms` más de 5 min por delante del reloj del dispositivo tampoco cuenta;
  6. dentro de esa época, un `seq` menor que el mayor que el dispositivo ya aceptó es un *rollback* (T7, T168), con el mismo error que las demás marcas de agua.

  La edad del latido se mide desde `sent_at_ms`, nunca desde el servidor. Un latido solo dice cuándo se conectó cada sandbox: no hace vivo, terminado ni revocado a ninguno. Eso sale solo de la cadena, y un sandbox que el latido nombra y la cadena no muestra vivo se ignora.
- **Riesgo residual: el orden de las épocas.** La cadena no ordena los `sandbox.store_reset` por su hora. Un servidor deshonesto que tenga dos que el proxy firmó con menos de 5 min de diferencia puede registrarlos al revés, y entonces la época vieja queda como la actual y los latidos vivos se descartan como de otra época: la app dice que el proxy no da señales. Solo puede hacer que un proxy vivo parezca callado, como ya puede reteniendo latidos; no puede hacer que uno muerto parezca vivo ni que un sandbox vivo parezca terminado. No hay regla de horas crecientes porque fallaría con cadenas honestas cuando el reloj del proxy retrocede.
- **La marca de agua de `seq`.** La comprobación la recibe del llamador, una por proxy y época. La lista de sandboxes de la persona (`klav-client::sandboxes`) la guarda en `sandbox-marks.bin` (§12.2) y la sube con cada latido que cuenta. La lee, con el cerrojo del directorio, antes de pedir `GET /v1/sync`, y compara el latido con esa: así otro proceso del mismo dispositivo (la CLI y `klavd`) que guardó una mayor entretanto no provoca un *rollback* falso. La guarda con el cerrojo, leyendo el archivo otra vez: para el mismo proxy y la misma época se queda el `seq` mayor; la marca de otra época la reemplaza, salvo que la guardada sea de una época posterior en la cadena o empate con ella (`epoch_seq` mayor o igual). Así un proceso que listó con la época anterior y guarda tarde nunca devuelve la marca a esa época (decidido por Omar el 2026-11-15). Un latido de la época actual con un `seq` menor que esa marca es un *rollback*: no cuenta (la app dice que el proxy no da señales, con un aviso), la marca no se mueve, y la lista, que sale de la cadena, se muestra igual. Un archivo que no abre, o que no se lee con este formato (también uno sin `epoch_seq`) sin tener un `v` mayor, se lee como vacío, con un aviso, y se escribe de nuevo. Uno con un `v` mayor (de una versión más nueva) se lee como vacío, con un aviso, y nunca se escribe.
- **Un proxy que el servidor no lista.** Si el proxy que nombra el ajuste cifrado no está entre los agentes que lista el servidor (un servidor honesto los lista todos, también los revocados), la lista falla con un error de seguridad (decidido por Omar el 2026-11-13, ADR 0036): si no, el servidor podría esconder todos los sandboxes de ese proxy. No solo el servidor los puede desacordar: otro dispositivo de la cuenta puede guardar un ajuste que nombra un agente que el servidor no tiene, así que el error nombra las dos causas.
- **Preferencias que no se leen.** Si el dispositivo no puede leer las preferencias, o dos elementos no coinciden en el proxy, la lista no falla: muestra las filas de la cadena de todos los proxies, sin proxy ni latido y con un aviso (decidido por Omar el 2026-11-15, ADR 0036). Un error de seguridad sigue haciéndola fallar, como antes: una cadena alterada y también unas preferencias que escribió un agente.
- **Una versión que el dispositivo no conoce.** Antes de leer el cuerpo entero, el dispositivo lee su `v`. Un latido firmado con otro `v` (de un proxy más nuevo) no cuenta, como si no diera señales, y nunca es un error de seguridad.

### 13.14 Solicitudes de secreto por un agente (`kind = 0x25`, ADR 0046)

*(§13.13 queda reservada para `klav/v1/sig/agent-egress` del ADR 0044.)*

Un agente propone crear un elemento o actualizar un campo secreto enviando solo metadatos cifrados con HPKE para la identidad pública de la cuenta, con la misma suite de §8 (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20-Poly1305`, modo `base`):

```
blob = header(2) ‖ enc(32) ‖ ciphertext(n) ‖ tag(16)
header = 0x01 ‖ 0x25
info = tuple("klav/v1/agent/secret-request", account_id, agent_id, request_id, fingerprint(cuenta))
AAD  = header
```

- `plaintext` es el JSON UTF-8 de `SecretRequestProposal` (`v = 1`, `deny_unknown_fields`: no existe campo de valor). No puede estar vacío y el `blob` total mide como mucho 8 192 bytes (sobrecarga fija de 50 bytes).
- El servidor guarda `proposal_digest = SHA-256(plaintext)` en claro junto con `reason` y el `blob` hasta que se decida o venza; nunca lee el contenido de la propuesta.
- La persona completa la solicitud en su dispositivo (cifrando el elemento con el flujo normal de §7) y firma su decisión con la identidad Ed25519 de la cuenta:

```
firma = Ed25519(cuenta, tuple(
  "klav/v1/sig/secret-request-decision",
  request_id(16),
  agent_id(16),
  proposal_digest(32),
  decision_bytes,
  u64_be(decided_at_ms)
))
```

- `decision_bytes` son los bytes JSON exactos de `SecretRequestDecision` (`v = 1`, `status: "fulfilled" | "denied"`, `in_grant`). Si `status = "fulfilled"` y `in_grant = false` (guardado fuera del grant del agente), `vault_id`, `project_id` e `item_id` se omiten (T236). Si `status = "denied"`, todos los campos de elemento y proxy se omiten.
- El agente verifica la firma con la identidad fijada de la cuenta (TOFU) y comprueba que `request_id`, `agent_id` y `proposal_digest` coinciden con su propuesta (T237).
- Vectores en [`docs/vectores/secret-request.json`](vectores/secret-request.json).

Todas las firmas de esta sección son Ed25519 según §9: las del agente con su identidad, y las de la persona con la identidad de la cuenta.

### 13.16 La pasarela MCP: token de cliente local y resumen de los argumentos (ADR 0049)

*(§13.15 queda reservada para el blob `0x27` `mcp-call`, los argumentos sellados de una capa posterior del ADR 0049.)*

**Token de cliente local.** Lo genera el dispositivo de la persona, uno por cliente MCP de su Mac, y va en la configuración del cliente como `Authorization: Bearer …` hacia el proxy en *loopback* (ADR 0049 §3.2). Versionado desde el primer byte, como `kag1_` (§13.2):

```
blob  = 0x01 ‖ token(32)                                   (33 bytes)
texto = "klc1_" ‖ BASE64URL-SIN-RELLENO(blob)               (49 caracteres)
token_digest = SHA-256(tuple("klav/v1/proxy/local-client", agent_id(16), token(32)))
```

- `agent_id` es el del proxy; `token` son los 32 bytes aleatorios, sin el byte de versión.
- Al decodificar se rechaza: otro prefijo (también `KLC1_`), espacios alrededor, un base64url que no es el canónico sin relleno (`=`, `+`, `/`), una longitud distinta de 33 bytes y otro byte de versión. 33 bytes son exactamente 44 símbolos, así que cada token tiene una sola escritura.
- El grant del proxy lleva solo `token_digest` (§13.4, `local_clients`); el proxy lo compara en tiempo constante. El token va en un `SecretString` (`klav_core::crypto::mcp::LocalClientToken`), sin `Debug` que lo muestre ni `Display`, y el servidor de Klav nunca lo ve.

**Resumen de los argumentos** (`claims.mcp_args`, ADR 0049 §5.4):

```
mcp_args = SHA-256(tuple("klav/v1/proxy/mcp-args", agent_id(16), item_id(16), herramienta, argumentos))
```

- Cada campo lleva su propio prefijo de longitud, como en toda `tuple` (§2.3): `herramienta` son los bytes UTF-8 del nombre (el `lp(tool)` del ADR 0049 §5.4 es este campo, no un segundo prefijo) y `argumentos` los bytes exactos de `params.arguments` tal como llegaron, sin reserializar; vacío cuando falta (que no es `{}`). `agent_id` es el del proxy e `item_id` el elemento del perfil.
- Su forma de texto es base64url sin relleno, 43 caracteres, con una sola escritura (los 2 bits que sobran son cero): el servidor rechaza cualquier otra con `400`.
- Los mismos argumentos escritos de otra manera (otro orden de claves, otros espacios) dan otro resumen y piden otra aprobación «una vez»: falla cerrado (ADR 0049 §5.4).

Vectores: `mcp-gateway.json` (tokens, sus resúmenes y tokens que hay que rechazar; resúmenes de argumentos, también reordenados y ausentes; coincidencia de patrones y patrones inválidos; y la evaluación del ejemplo de Maple de ADR 0049 §5.3).

## 14. Passkeys

> **ADR [0020](decisiones/0020-passkeys.md), en implementación.** Están en `klav-core` las primitivas (§14.1), la llave sellada `0x15` (§14.3, `crypto::passkey`), `authData`, COSE, `attestationObject` y `clientDataJSON` (§14.4–§14.6, `passkey::webauthn`), el AAGUID (§14.8), la validación del rpId (§14.9, `passkey::rp`) y la cola `0x43` del escritorio y de iOS (§14.7, `klav-client::passkey_outbox`), con vectores en [`docs/vectores/passkey.json`](vectores/passkey.json) y [`docs/vectores/webauthn-l3.json`](vectores/webauthn-l3.json). La passkey dentro de un login (§14.2) está en `model::passkey`.

Klav actúa como autenticador WebAuthn (nivel 3) para credenciales descubribles ES256. Esta sección fija los bytes que produce `klav-core`; el flujo entre la extensión, `klavd` e iOS está en el ADR 0020.

### 14.1 Primitivas
- **ES256** (`alg = -7`): ECDSA sobre P-256 con SHA-256, de `p256` 0.14 y `ecdsa` 0.17 (RustCrypto, ADR 0020 §6). Nonce determinista RFC 6979. Firma codificada en DER (ASN.1 `SEQUENCE { r, s }`), como pide WebAuthn para ES256.
- **Llave privada:** el escalar P-256 de 32 bytes en big-endian, generado con el CSPRNG (§1). Al abrirla (§14.3), un escalar fuera de `[1, n−1]` se rechaza.
- **Llave pública:** SEC1 sin comprimir (`0x04 ‖ x(32) ‖ y(32)`, 65 bytes) dentro del núcleo; en COSE (§14.5) hacia el RP; en SPKI DER para `getPublicKey()`.
- **Separación de usos (§9):** la regla «toda firma lleva `klav/v1/sig/`» vale para las llaves Ed25519 de identidad. Las llaves P-256 de passkey son de otro tipo, se generan una por credencial y solo firman mensajes WebAuthn (`authData ‖ clientDataHash`, §14.6). Ninguna otra construcción de Klav firma con ellas, así que no hay confusión entre protocolos.

### 14.2 La passkey dentro de *details* (§7.1)
Clave `passkey` de *details*, solo con `kind = login`:

| Clave | Tipo | Notas |
|---|---|---|
| `credential_id` | base64url sin relleno | 16 bytes aleatorios; inmutable |
| `rp_id` | texto | dominio ASCII (punycode) en minúsculas, sin puerto; inmutable |
| `rp_name` | texto | opcional, solo para mostrar |
| `user_handle` | base64url sin relleno | de 1 a 64 bytes, lo da el RP; inmutable |
| `user_name` | texto | `user.name` |
| `user_display_name` | texto | opcional, `user.displayName` |
| `alg` | entero | `-7`; otro valor se rechaza |
| `created_at` | entero | milisegundos Unix |
| `key` | base64url sin relleno | blob `0x15` de 74 bytes (§14.3) |

El resumen del *overview* (`{rp_id, credential_id, user_name}`) debe coincidir con estos valores (`SectionMismatch` si no). `v` sigue en 1: un lector anterior rechaza la clave desconocida y salta el elemento.

- `credential_id` tiene 16 bytes cuando la crea Klav; una passkey importada conserva el suyo (de 1 a 1023 bytes, §14.3).
- `rp_name`, `user_name` y `user_display_name` tienen hasta 256 caracteres, sin caracteres de control; `user_name` puede ir vacío (lo trae así alguna exportación).
- Un lector rechaza un `alg` distinto de `-7`, claves desconocidas dentro de `passkey`, un `key` que no sea un blob `0x15` de 74 bytes y una `passkey` en un elemento que no sea `login`.
- Al poner una passkey en un login (`Item::set_passkey`), si ninguna URL del login tiene el `rp_id` como host, se añade `https://<rp_id>`. Al leer no se añade nada.
- Las ediciones del login conservan la passkey tal cual; solo `Item::set_passkey` e `Item::remove_passkey` la cambian.

### 14.3 Llave privada sellada (`kind = 0x15`)
Sobre de §3.1 con la **llave de bóveda** (no la de elemento), para que ningún agente pueda abrirla aunque reciba los *details* (ADR 0020 §4):

```
plaintext = escalar(32)
AAD       = 0x01 ‖ 0x15 ‖ tuple("klav/v1/passkey/private-key", account_id(16), vault_id(16), item_id(16),
                                credential_id(16), rp_id(ASCII), user_handle(1..64))
blob      = 0x01 ‖ 0x15 ‖ nonce(24) ‖ ct(32 + 16)                                          (74 bytes)
```

- `account_id` es la cuenta dueña de la bóveda.
- `project_id` no entra en el AAD: mover el elemento a otro proyecto de la misma bóveda no obliga a volver a sellar. Moverlo a otra bóveda sí.
- `rp_id`, `credential_id` y `user_handle` están en el AAD: no se puede pasar la llave a otro sitio, otra credencial u otro usuario. Van con su prefijo de longitud (§2.3): una passkey creada por Klav tiene un `credential_id` de 16 bytes; el formato acepta de 1 a 1023 (el máximo de WebAuthn), y `user_handle` de 1 a 64.
- `rp_id` debe ser ASCII en minúsculas (letras, dígitos, `-` y `.`), sin punto al principio ni al final y de hasta 253 bytes; si no, el sellado y la apertura se niegan antes de cifrar.
- El escalar sellado se comprueba al abrir: fuera de `[1, n−1]` da `Malformed`, aunque el tag sea válido.
- Cualquier fallo de autenticación da el error opaco `Decryption` (§3.1).

### 14.4 Datos del autenticador (`authData`)
```
authData = rpIdHash(32) ‖ flags(1) ‖ u32_be(signCount)(4) ‖ [ attestedCredentialData ]
rpIdHash = SHA-256(rp_id en ASCII)
attestedCredentialData = aaguid(16) ‖ u16_be(len(credential_id)) ‖ credential_id(16) ‖ credentialPublicKey (COSE, §14.5)
```

| Campo | Valor |
|---|---|
| `flags` al crear | UP (`0x01`) · UV (`0x04`) · BE (`0x08`) · BS (`0x10`) · AT (`0x40`) = `0x5D`; sin UV, `0x59` |
| `flags` al firmar | UP · UV · BE · BS = `0x1D`; sin UV, `0x19` |
| `signCount` | siempre `0` |
| ED (`0x80`) | nunca: no hay extensiones del autenticador en v1 |

- UV solo vale 1 si hubo una verificación real (Touch ID, la contraseña maestra en un marco de Klav o el desbloqueo) dentro de la ventana que eligió la persona: «Siempre», «Cada 5 min» o «Mientras Klav esté desbloqueado» (ADR 0020 §8). En el uso de un agente dentro de una tarea, la verificación es la aprobación firmada de la tarea, con Touch ID o Face ID, y vale hasta que la tarea vence (ADR 0020 §9). En los dos casos los bytes son los mismos: solo cambia cuándo se pone la bandera.
- Tamaño: 148 bytes al crear (37 + 16 + 2 + 16 + 77) y 37 al firmar.

### 14.5 Llave pública COSE
Mapa CBOR de 5 entradas, en el orden canónico de CTAP2 (claves enteras ordenadas por su codificación):

```
{ 1: 2,            kty = EC2
  3: -7,           alg = ES256
 -1: 1,            crv = P-256
 -2: bstr(x, 32),
 -3: bstr(y, 32) }
= A5 01 02 03 26 20 01 21 58 20 ‖ x ‖ 22 58 20 ‖ y                                   (77 bytes)
```

`attestationObject` = mapa CBOR `{ "fmt": "none", "attStmt": {}, "authData": bstr(authData) }`, en ese orden (canónico de CTAP2: por largo de la clave y luego por bytes). Siempre `fmt = "none"`, aunque el RP pida `direct`. El codificador de `klav-core` solo produce enteros, `bstr`, `tstr` y mapas de largo definido, con la forma más corta de cada largo.

### 14.6 `clientDataJSON` y firma
Lo construye `klavd` con el origen que da el navegador, nunca la página. En iOS, el sistema entrega `clientDataHash` y Klav no ve el JSON.

```
clientDataJSON = {"type":"webauthn.create"|"webauthn.get","challenge":"<b64url>","origin":"<origen>","crossOrigin":false}
clientDataHash = SHA-256(clientDataJSON)
firma          = ECDSA-P256-SHA256-DER(escalar, authData ‖ clientDataHash)
```

- Las claves van en ese orden, sin espacios, con el escape de cadenas JSON que define WebAuthn L3 para serializar `CollectedClientData`.
- `challenge` es base64url sin relleno de los bytes que dio el RP.
- `crossOrigin` siempre es `false`: en v1 un marco de otro origen pasa al navegador, así que nunca hay `topOrigin`.
- Al crear, la firma no se usa (`fmt = "none"`). Al iniciar sesión, la firma va en `AuthenticatorAssertionResponse.signature`, junto a `authenticatorData` y `userHandle`.

### 14.7 Cola de salida de iOS (`kind = 0x43`)
Sobre de §3.1 con la **llave local** del dispositivo (§12.2):

```
AAD = 0x01 ‖ 0x43 ‖ tuple("klav/v1/local/outbox", account_id(16), device_id(16))
plaintext = JSON UTF-8 con las altas pendientes (llave de elemento envuelta, secciones selladas y blob 0x15) y los eventos passkey.used pendientes
```

- Como todo `0x40–0x4F`, nunca sale del dispositivo: la app envía su contenido como operaciones normales de la API, no el blob.
- **iOS (ADR 0020 §11):** `outbox.bin` en el *home* compartido de la app y su extensión. Implementado en `klav-client` (`passkey_outbox`) y expuesto por `klav-ffi`. El texto plano:

```
plaintext = {"v":1,
             "passkeys":[{"vault","project","item","base_version"?,"wrapped_key","overview","details","created_at"}],
             "used":[{"id","item","at"}]}
```

  - `passkeys`: el elemento tal como se subirá. `wrapped_key` es la llave del elemento envuelta con la del proyecto (`0x03`); `overview` y `details` son las secciones selladas (`0x10`, `0x11`) con la versión `base_version + 1`, o 1 sin `base_version` (un login nuevo); la llave `0x15` va dentro de *details*. Los tres en base64url.
  - `used`: los inicios de sesión pendientes de `passkey.used`; `id` son 16 bytes aleatorios en base64url, para borrar exactamente lo enviado.
  - Al leer, cada alta se superpone a la caché si todavía aplica: un login que la caché no tiene, o la versión siguiente de uno que la caché tiene en `base_version`.
  - La app la vacía con las operaciones normales (`POST` con el ID que eligió el dispositivo, o `PUT`); si el login cambió mientras tanto, pone la passkey sobre la versión nueva.
  - Las dos colas usan el mismo sobre y el mismo AAD; las distingue el nombre del archivo y el texto plano (`deny_unknown_fields`: una no se lee como la otra). El sobre es el del caso `local-outbox` de `local.json`; el texto plano no cambia ningún byte del formato.
- El AAD lo fijó el ADR 0020 (el plan no lo hacía), por simetría con `0x41`.
- **Escritorio (ADR 0022 §2):** `klavd` y la CLI en modo directo usan el mismo sobre y el mismo AAD para la cola del historial del generador, en `generator-outbox.bin` del *home*. Implementado en `klav-core` (`crypto::local::seal_local_outbox`) con el caso `local-outbox` de [`local.json`](vectores/local.json). Su texto plano es otro:

```
plaintext = {"v":1,"generated":[{"value","created_at","host"?,"saved_in"?}]}
```

  Cada contraseña generada se escribe ahí, y el archivo se sincroniza a disco antes de devolverla, para que nunca se pierda aunque el equipo esté sin red. `klavd` vacía la cola en el elemento `generator_history` del proyecto del sistema (§7.3) en cuanto puede, y la reintenta cada 30 s si falla.

### 14.8 AAGUID
Un UUID v4 fijo de Klav, constante en `klav-core` (`crypto::passkey::AAGUID`) y el mismo en todas las plataformas: **`a36a6cd0-200d-411f-a41d-b964cce16689`**. Se registra en la lista comunitaria `passkey-authenticator-aaguids` (pregunta P2 del ADR). **Por comprobar:** si Chromium lo pone a cero con `attestation: "none"` (ADR 0020, «Verificaciones pendientes»).

### 14.9 Validación del rpId
`klav_core::passkey::rp::validate(origen, rp_id?)`, detrás de la feature `rp-id` (ADR 0020 §7), que activa `klav-client` y no compila `klav-wasm`:

- El origen es el que da el navegador del remitente. Debe ser `https:`, o `http:` en `localhost` o en un nombre bajo `.localhost` (RFC 6761); el origen opaco (`null`, `data:`, `file:`) y los hosts que son una IP se rechazan.
- El `rp_id` pedido (por defecto, el host) se pasa a ASCII en minúsculas con punycode (`url::Host`); con puerto, punto final, `/`, `:` o `@` se rechaza.
- Debe valer `host == rp_id` o `host` termina en `"." + rp_id`.
- No puede ser un sufijo público conocido de la PSL (`psl` 2.1, secciones ICANN y privada), ni tener una sola etiqueta salvo `localhost`.
- Si falla, la llamada pasa al autenticador del navegador; no hay error propio de Klav.

## 15. Proxy alojado de Klav Cloud: atestación de Nitro, manifiesto y llaves por cuenta (ADR 0051)

Todo esto vive en `klav_core::nitro`, detrás de la feature `nitro-attestation`, que no está activada por defecto. `klav-wasm` nunca la compila: la extensión nunca envuelve llaves para un proxy. En esta capa ningún binario la activa todavía; la CLI, `klavd`, `klav-ffi` y el enclave la activan en sus capas del ADR [0051](decisiones/0051-hosted-nitro-enclave-proxy.md).

### 15.1 Primitivas y dependencias

| Uso | Primitiva | Crate |
|---|---|---|
| Firma del documento y de la cadena | ECDSA P-384 con SHA-384, solo verificación | `p384` 0.14 (`ecdsa`, que trae `sha384`) |
| Certificados | X.509 v3 en DER, solo lectura | `x509-cert` 0.3, `der` 0.8, `spki` 0.8 |
| CBOR del documento | lector estricto propio (§15.2), no criptografía | — |
| Manifiesto | Ed25519, verificación estricta (§9) | `ed25519-dalek` 3 |
| Llaves por cuenta | HKDF-SHA256 | `hkdf` 0.13, `sha2` 0.11 |

`ciborium` sigue siendo solo dependencia de desarrollo: su `Value` acepta longitudes indefinidas y enteros en forma larga sin dejar rastro, así que no se puede hacer estricto. Ninguna llave privada toca `p384`.

### 15.2 El documento de atestación

Un `COSE_Sign1` (RFC 9052) que firma el Nitro Secure Module. El NSM lo emite **sin** la etiqueta CBOR 18; la documentación de AWS la muestra, así que se aceptan las dos formas y ninguna otra etiqueta. El documento entero cabe en 16 KiB.

```
COSE_Sign1 = [ protected: bstr, unprotected: {}, payload: bstr, signature: bstr(96) ]
protected  = a1 01 38 22                    ({1: -35}, ES384, exactamente estos 4 bytes)
signature  = r(48) ‖ s(48)
```

**Lector CBOR estricto** (`nitro::cbor`), para el `COSE_Sign1` y para el `payload`. Rechaza:

- longitudes indefinidas y el byte `break`;
- una longitud o un entero que no está en su forma más corta;
- claves repetidas en un mapa (se comparan los bytes de la clave, que son únicos porque todo va en forma corta) y claves que no son enteros ni texto;
- *floats*, `undefined` y valores simples que no sean `false`, `true` o `null`;
- texto que no es UTF-8, anidamiento de más de 8 niveles y bytes después del objeto.

El orden de las claves no se comprueba: el NSM escribe su mapa en un orden fijo que no es el canónico.

**`payload`**: un mapa con exactamente estas claves de texto; cualquier otra se rechaza.

| Clave | Tipo | Regla |
|---|---|---|
| `module_id` | texto | no vacío |
| `digest` | texto | `"SHA384"` |
| `timestamp` | entero sin signo | milisegundos Unix |
| `pcrs` | mapa `índice → bstr` | índices < 32, cada valor de 48 bytes, con 0, 1 y 2 presentes (los documentos reales traen 16) |
| `certificate` | bstr | el certificado hoja, DER |
| `cabundle` | arreglo de bstr | la raíz y luego cada intermedio |
| `public_key`, `user_data`, `nonce` | bstr de hasta 1024 bytes, `null` o ausente | el NSM escribe `null` cuando faltan |

**Firma** (RFC 9052 §4.4), verificada con la llave P-384 de la hoja:

```
Sig_structure = ["Signature1", protected, h'', payload]   (CBOR: 84 6a "Signature1" bstr(protected) 40 bstr(payload))
```

### 15.3 La cadena de certificados

`cabundle[0]` tiene que ser, byte a byte, la raíz fijada en `klav-core`: AWS Nitro Enclaves Root-G1 (`CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`, válida de 2019-10-28 a 2049-10-28), de `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`, con SHA-256 `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b` (una prueba lo comprueba). La cadena es `[cabundle[0], …, cabundle[n], certificate]`, de 2 a 8 certificados de 1 a 1024 bytes. Para cada uno:

1. DER estricto: el certificado se decodifica sin bytes de más y vuelve a codificarse en los mismos bytes. X.509 v3.
2. Algoritmo `ecdsa-with-SHA384` (1.2.840.10045.4.3.3, sin parámetros) en el certificado y en el TBS; llave `id-ecPublicKey` en `secp384r1`.
3. Desde el segundo: su `issuer` es el `subject` del anterior (comparados en DER) y la firma del anterior verifica sobre los bytes del `TBSCertificate` **tal como llegaron**.
4. Dentro de su validez en el reloj del dispositivo (`notBefore ≤ ahora ≤ notAfter`, en segundos).
5. Extensiones: `basicConstraints` y `keyUsage` se leen; cualquier otra extensión crítica, o una extensión repetida, se rechaza. No hay CRL (AWS dice que se desactive).
6. Los de `cabundle`: `cA = TRUE`, `keyUsage` con `keyCertSign`, y su `pathLenConstraint`, si lo hay, no menor que el número de intermedios que quedan debajo (sin contar la hoja).
7. La hoja: no es CA y, si trae `keyUsage`, incluye `digitalSignature`.

Los documentos reales de 2022 y 2023 (§15.7) traen tres intermedios (`pathLenConstraint` 2, 1 y 0), todos ECDSA P-384 con SHA-384.

### 15.4 Lo que comprueba el dispositivo, y lo que comprueba un enclave en un traspaso

`nitro::verify_hosted_proxy` (ADR 0051 §2.2, pasos 2 a 6), antes de envolver cualquier llave para el proxy alojado:

1. §15.2 y §15.3, y la firma del documento.
2. `nonce` igual al que mandó el dispositivo con `GET /v1/attest`.
3. `|timestamp − ahora| ≤ 5 minutos`.
4. `user_data` igual al vínculo de §15.6 para el agente que el servidor muestra como proxy alojado de la cuenta. `public_key` se ignora.
5. PCR0, PCR1 y PCR2 distintos de cero (un enclave en modo *debug* los reporta en cero y se rechaza).
6. PCR0–2 iguales a los de una imagen del manifiesto (§15.5) con estado `current` o `draining`; `revoked` se rechaza.

`nitro::verify_handoff_peer` (ADR 0051 §4.2, paso 2), lo que el enclave que tiene la semilla comprueba del que la pide: los pasos 1–3, 5 y 6 (con el `nonce` del que la tiene), y además que PCR3 esté en `parent_roles`, que la imagen del otro no sea más vieja que la propia (por `version`) y que `public_key` sea una llave X25519 de 32 bytes. Que el manifiesto sea el publicado en el repositorio lo comprueba quien llama.

`nitro::verify_handoff_holder` (ADR 0051 §4.2, paso 3), lo que el enclave que se une comprueba del que tiene la semilla antes de aceptarla: los pasos 1–3, 5 y 6 (con su propio `nonce`) y que PCR3 esté en `parent_roles`. No pide `public_key` ni rechaza una imagen más vieja: en una actualización escalonada el que tiene la semilla corre la imagen anterior, y es él quien rechaza un *downgrade*.

Cada rechazo tiene su variante de `NitroError` y un código estable (`NitroError::code`), el que usan los vectores.

### 15.5 Manifiesto de transparencia de los enclaves

`manifest.json`, JSON en UTF-8 con estos campos y ningún otro (un campo desconocido o repetido se rechaza):

```json
{"v":1,"seq":7,"seed_epoch":0,"issued_at_ms":…,"expires_at_ms":…,
 "endpoint":"proxy.klav.dev","server":"api.klav.dev",
 "images":[{"version":"0.12.0","commit":"<40 hex>","arch":"aarch64",
            "pcr0":"<96 hex>","pcr1":"<96 hex>","pcr2":"<96 hex>","status":"current"}],
 "parent_roles":["<96 hex>"],"egress":["203.0.113.10/32"]}
```

- `v = 1`; `0 < expires_at_ms − issued_at_ms ≤ 30 días`; `endpoint` y `server` son nombres de host en minúsculas.
- Al menos una imagen. `version` es `MAYOR.MENOR.PARCHE` sin ceros a la izquierda; `commit` 40 hexadecimales en minúsculas; `arch` `aarch64` o `x86_64`; cada PCR 96 hexadecimales en minúsculas, ninguno en cero; dos imágenes no repiten PCR0–2; `status` es `current`, `draining` o `revoked`.
- `parent_roles`: valores de PCR3 (96 hexadecimales, no cero). `egress`: hasta 16 bloques CIDR, con la dirección escrita en su forma canónica.

**Firma**, Ed25519 (§9) sobre los bytes exactos que se recibieron:

```
mensaje = tuple("klav/v1/sig/enclave-manifest", SHA-256(manifest_bytes))
```

con cualquiera de las llaves públicas de la autoridad de publicación fijadas en `klav-core` (`RELEASE_AUTHORITY_KEYS`: la activa y una de respaldo). **En esta versión la lista está vacía**: esas llaves aún no existen, así que todo manifiesto se rechaza con `no_release_key` hasta que una capa posterior las fije.

El dispositivo verifica la firma antes de leer el JSON, y después rechaza: un `seq` menor que el más alto que ya verificó (el mismo `seq` se acepta), un manifiesto con `ahora ≥ expires_at_ms` y uno con `issued_at_ms > ahora + 5 minutos`.

### 15.6 Llaves por cuenta, vínculo, inscripción y traspaso

Una semilla de 32 bytes que vive solo en la memoria del enclave (`HostedSeed`, sin `Debug`, `Display` ni `Clone`, borrada al soltarse). Las llaves del agente proxy de cada cuenta:

```
okm         = HKDF-SHA256(ikm = semilla, sal = vacía,
                          info = tuple("klav/v1/proxy/hosted-account", account_id(16), u32_be(generation)), L = 64)
x25519_sk   = okm[0..32]          ed25519_seed = okm[32..64]
```

forman un par de identidad normal (§6.1), el de un agente (§13).

**Vínculo** que lleva `user_data` (ADR 0051 §2.2, paso 5):

```
binding = SHA-256(tuple("klav/v1/proxy/enclave-binding", account_id(16), agent_id(16),
                        agent_ed25519_pub(32), agent_x25519_pub(32), u32_be(generation)))
```

**Inscripción** (ADR 0051 §6.1, paso 2), firmada con la identidad de la cuenta (§9); el enclave comprueba además que `at_ms` esté a ±5 minutos:

```
tuple("klav/v1/sig/hosted-proxy-enroll", account_id(16), u32_be(generation), u64_be(at_ms))
```

**`info` de HPKE del traspaso de la semilla** del enclave que la tiene (H) al que se une (J) (ADR 0051 §4.2, paso 4); el `nonce` de cada documento tal como aparece en él (el del documento de J vino de H, y al revés):

```
info = tuple("klav/v1/proxy/enclave-handoff", pcr0_H(48), pcr0_J(48), nonce_del_documento_de_H, nonce_del_documento_de_J)
```

**Traspaso sellado** (tipo `0x28`, capa 3 del ADR 0051). El que se une genera una llave X25519 de un solo uso (`HandoffKey`) y la atestigua en `public_key`; el que tiene la semilla, tras `verify_handoff_peer`, sella:

```
blob = 0x01 ‖ 0x28 ‖ enc(32) ‖ HPKE(semilla(32) ‖ estado(n)) ‖ tag(16)      aad = 0x01 ‖ 0x28
```

con la suite de §8 en modo base, el `info` de arriba, y `n ≤ 8 MiB`. El estado son las inscripciones y los almacenes en memoria del enclave, en JSON; su forma la fija `klav-proxy`, no este formato. Un blob más corto que 82 bytes, de otro tipo o que no abre se rechaza.

El JSON lleva su versión en `v`. La 1 (capa 3) son solo las inscripciones. La 2 (capa 3b) añade `accounts`, a lo sumo uno por inscripción: el almacén de sandboxes de la cuenta (cada uno con el SHA-256 de su secreto, nunca el secreto), sus llaves de canal (el SHA-256 de cada una), la época del latido con su último `seq`, el cursor de revocaciones y si la persona ya aprobó el agente. El que se une lee la 1 y la 2, y rechaza otra versión, un campo desconocido, el estado de una cuenta sin inscripción o una cuenta repetida. El blob y el `info` no cambian, ni los vectores.

**Semilla nueva** (el primer enclave, o tras una pérdida total). Ninguna de las dos fuentes decide sola:

```
semilla = HKDF-SHA256(ikm = aleatorio_del_SO(32) ‖ entropía_del_NSM, sal = vacía,
                      info = tuple("klav/v1/proxy/hosted-seed"), L = 32)
```

**Llave de servicio** (ADR 0051 §8). Igual para todas las cuentas; `klav-server`, configurado con su mitad pública, distingue así el registro de un agente alojado. No es una frontera de seguridad:

```
okm = HKDF-SHA256(semilla, info = tuple("klav/v1/proxy/hosted-service"), L = 64)      // se parte como las llaves por cuenta
```

Con ella el enclave marca el registro del agente de cada cuenta; la marca, dónde va y cómo la comprueba el servidor están en §15.8, y su definición vive solo en `klav_core::crypto::hosted` (`nitro::sign_hosted_registration` y `nitro::verify_hosted_registration` llaman a ese módulo).

### 15.7 Vectores

`nitro-attestation.json` y `enclave-manifest.json` (§11). Se comprueban con `cargo test -p klav-core --features nitro-attestation nitro_vectors`; `cargo test --workspace` no los compila.

- **Un documento real**, de un enclave en modo *debug* en `us-east-1` del 2023-09-18, tomado de las pruebas de `evervault/attestation-doc-validation` (Apache-2.0, `crates/klav-core/src/nitro/testdata/README.md`): su cadena llega a la raíz fijada, su firma verifica, y sus PCR0–2 en cero lo hacen rechazar como `debug_enclave`.
- **Una cadena sintética** con la forma de la de AWS (raíz, dos intermedios y hoja, ECDSA P-384 con SHA-384 y llaves deterministas), **que no es de AWS**: un documento que verifica, también con la etiqueta 18, y documentos mutados, cada uno vuelto a firmar para que llegue a la comprobación que nombra (un bit en el *payload* o en la firma, un PCR cambiado, la cadena fuera de orden, una clave de más, una clave repetida, una longitud indefinida, un certificado vencido, otra raíz, PCR en cero, un `timestamp` viejo, otro `nonce`, otro `user_data` y una imagen revocada).
- Las llaves por cuenta en dos generaciones, sus vínculos, la firma de inscripción y el `info` del traspaso; un traspaso sellado (`0x28`) con la llave del que se une, su `ikm_e` y el estado; la mezcla de una semilla nueva; la llave de servicio y la marca de un registro.
- Manifiestos firmados con llaves de prueba (la activa y la de respaldo) que se aceptan, y otros que se rechazan: otra llave, *rollback*, vencido, emitido en el futuro, un campo desconocido o repetido, más de 30 días y un PCR en cero.

El documento del enclave propio de Klav se captura en la capa 6 del ADR 0051.

### 15.8 La marca del registro del agente alojado, en el servidor

El enclave registra el agente proxy de cada cuenta en el servidor con el `POST /v1/agents/register` de siempre ([api.md](api.md) §8.15), con la marca en el campo `hosted: { account_id, generation, signature }` del cuerpo (`RegisterHostedAgent`), firmada con su **llave de servicio**, una identidad derivada de su semilla e igual para todas las cuentas. La derivación y la firma son del enclave (capa 3 del ADR 0051, en `nitro`):

```
okm   = HKDF-SHA256(semilla, info = tuple("klav/v1/proxy/hosted-service"), L = 64)      // se parte como las llaves por cuenta (§15.6)
firma = Ed25519(tuple("klav/v1/sig/hosted-proxy-registration", account_id(16), agent_id(16),
                      agent_ed25519_pub(32), agent_x25519_pub(32), u32_be(generation)))
```

- El servidor la comprueba con la llave pública Ed25519 de esa identidad (`KLAV_HOSTED_PROXY_SERVICE_KEY`, 64 dígitos hexadecimales; rechaza un punto fuera de la curva y uno de orden pequeño) con `verify_strict`, como `sign::verify`, y marca el agente `hosted`. El correo no va firmado: el servidor exige que sea el de `account_id`. No es una frontera de seguridad: lo que protege las llaves es la atestación que verifica cada dispositivo (§15.4).
- Una semilla nueva (tras una pérdida total, ADR 0051 §4.4) da otra llave de servicio, y la configuración del servidor cambia con ella.
- La comprobación del servidor vive en `klav_core::crypto::hosted`, sin feature, para que el servidor no compile las dependencias de la atestación.
- Vectores en `hosted-proxy-registration.json` (§11), que corren con `cargo test -p klav-core`.

## 16. Registro de cambios

| Fecha | Cambio |
|---|---|
| 2026-11-02 | Versión inicial del formato v1. |
| 2026-11-02 | §7.1: esquema JSON v1 de las secciones de un elemento; vectores TOTP/HOTP. |
| 2026-11-02 | §4.3: entrada de OPAQUE `O`; §4.5: suite `klav-opaque-v1`; §4.6: tokens de sesión. `kdf.json` gana el campo `opaque_input` (los demás valores no cambian). |
| 2026-11-02 | §4.4: el servidor también rechaza parámetros fuera de rango al registrar (sin cambios de formato). |
| 2026-11-02 | §7.2: metadatos de bóvedas y proyectos (tipos `0x12`, `0x13`); §12.2: llave local, identidad local y datos locales (tipos `0x40`, `0x41`). Vectores nuevos `metadatos.json` y `local.json`; los demás no cambian. |
| 2026-11-02 | §12.3: llave local envuelta por el almacén de la plataforma (tipo `0x42`); vector nuevo `llavero.json`. §12.1: `mlock` pospuesto (ADR 0013). |
| 2026-11-02 | §13: agentes (código de emparejamiento, tipos `0x07` y `0x14`, peticiones firmadas, grants, aprobaciones y revocaciones); vector nuevo `agentes.json`. El registro de cambios pasa a §14. |
| 2026-11-02 | §13.7: cadena de la bitácora y cabezas firmadas. `agentes.json` gana `audit_events`, `audit_hashes` y `audit_head_signature` (los demás valores no cambian). |
| 2026-11-03 | §13.1: la comparación del código separa también las palabras esperadas que llevan guion (antes un código con `t-shirt` nunca coincidía). Sin cambios de formato ni de vectores. |
| 2026-11-03 | Cambio de nombre a Klav (ADR 0019), solo nombres: etiquetas `lacre/v1/…` → `klav/v1/…`, suite `lacre-opaque-v1` → `klav-opaque-v1`, Secret Key `L1` → `K1` (§4.2), tokens `lat_`/`lrt_` → `kat_`/`krt_` (§4.6), llave del agente `lak1_` → `kag1_` (§13.2) y cabeceras `Lacre-*` → `Klav-*` (§13.3). Ningún algoritmo, parámetro ni disposición cambia; todos los vectores se regeneran (en `hpke-rfc9180.json` solo la descripción). |
| 2026-11-04 | **Propuesto (ADR 0020, pendiente de aceptación):** passkeys. §2.3: etiquetas `klav/v1/passkey/private-key` y `klav/v1/local/outbox`; §3: tipos `0x15` (passkey-key) y `0x43` (local-outbox); §7.1: clave `passkey` en *overview* y *details* (`v` sigue en 1); §14 nueva: authData, COSE, `clientDataJSON`, AAGUID y los dos blobs. El registro de cambios pasa a §15 (la cita «especificación §14» del ADR 0019 se refiere a él). §14.4 recoge las respuestas de Omar sobre la UV (ventana elegida y aprobación de tareas de agentes), sin cambiar bytes. Ningún formato existente cambia; sin vectores hasta que haya código. |
| 2026-11-04 | **Propuesto (ADR 0021 y ADR 0022, pendientes de aceptación):** §2.3: etiquetas `klav/v1/sig/task-decision` y `klav/v1/item/password-record`; §3: tipo `0x16` (password-record) y `0x43` también en el escritorio; §7.1: tipo `generator_history` y claves `password_record` y `generated` (`v` sigue en 1); §7.3 nueva: registro de contraseñas; §13.8 nueva: decisión sobre una tarea. Ningún formato existente cambia; sin vectores hasta que haya código. |
| 2026-11-04 | **ADR 0022 en código:** §7.3: registro de contraseñas (`0x16`) e ID del proyecto del sistema; §14.7: la cola `0x43` también para el historial del generador en el escritorio. Vectores nuevos: `registro.json` y el caso `local-outbox` de `local.json`; los demás no cambian. |
| 2026-11-04 | ADR 0020, 0021, 0022 y 0023 aceptados. Lo del ADR 0022 (`0x16`, `0x43` en el escritorio, `generator_history`, `password_record`, `generated`, §7.3) pasa a vigente; lo de los ADR 0020 y 0021 (`0x15`, `0x43` en iOS, `passkey`, §13.8 y §14) queda como «aceptado, pendiente de implementar». Los rangos reservados de §3 pasan a `0x17–0x1F` y `0x44–0xFF`. Ningún byte ni vector cambia. |
| 2026-11-04 | **ADR 0021 en código:** §13.8: la solicitud y la decisión de una tarea quedan fijadas byte a byte (`added_by_klav` es una lista de permisos) y se añade la etiqueta `klav/v1/sig/task-end` (§2.3), con la forma de la revocación. `agentes.json` gana `task_*` (los demás valores no cambian). |
| 2026-11-05 | **ADR 0022 §4 en código** (salud de la bóveda): §1 lista SHA-1 (`sha1` 0.11, feature `breach-check`), solo para el prefijo de 5 caracteres que se envía a Have I Been Pwned. La comparación de reutilizadas, `SHA-256(sal ‖ valor)` con una sal aleatoria por corrida, vive solo en memoria. Ningún formato ni vector cambia. |
| 2026-11-05 | **ADR 0022 §5–6 en código, mitad del servidor:** §13.8: la decisión gana el campo opcional `offer` (`{task, reason}`) para las tareas que ofrece la persona, firmadas con `solicitud` vacía, y `rotate` exige al menos un host aprobado. Las decisiones sin `offer` no cambian ni un byte. `agentes.json` gana `task_offer`, `task_offer_decided_at_ms` y `task_offer_signature` (los demás valores no cambian). |
| 2026-11-05 | **ADR 0022 §5 en código, mitad de `klavd`:** §7.3: el registro `0x16` gana la versión 2 (`unconfirmed` en el historial, `rotation_id` en la pendiente); un registro sin esas claves sigue siendo `v: 1` byte a byte. §13.3: `klavd` verifica la petición firmada que le reenvía el agente. Vector nuevo: caso `password-record-rotation` en `registro.json`; los demás no cambian. |
| 2026-11-05 | **ADR 0030 en código (capa 02):** §8.3 nueva: la cuenta dueña firma su llave de bóveda compartida con la etiqueta `klav/v1/sig/vault-key` (§2.3). Vector nuevo `llave-de-boveda.json`; ningún formato cifrado ni vector existente cambia. |
| 2026-11-05 | **ADR 0030 en código (capa 05):** §13.7: tabla cerrada de acciones con su prueba, su método y su ruta; reglas del verificador (campos sacados de lo firmado, llaves de agente avaladas por un `agent.granted` de la cadena, nonce único, ventana de ±5 min, páginas sin huecos) y `account_id` en `audit-head.json`. Ningún formato firmado ni vector cambia. |
| 2026-11-05 | **ADR 0030 en código (capa 10):** §13: `agentes.json` añade `messages` (los bytes firmados de petición, grant, aprobación, revocación, decisión y denegación de tarea, fin de tarea y cabeza de la bitácora), `labels_aad` y casos `negative`. §7.3: el registro `0x16` sin versión del elemento en el AAD queda documentado como residual (riesgo 27). Ningún formato ni byte cambia; los demás vectores no cambian. |
| 2026-11-05 | **ADR 0020 en código, capa 1:** §14.1 y §14.3: llave privada de passkey (`0x15`, `crypto::passkey`) con `p256` 0.14 y `ecdsa` 0.17; §14.3 fija los largos que acepta el AAD (`credential_id` de 1 a 1023 bytes, 16 al crear) y la forma del `rp_id`; §14.8: AAGUID `a36a6cd0-200d-411f-a41d-b964cce16689`. Vector nuevo `passkey.json`; los demás no cambian. |
| 2026-11-05 | **ADR 0020 en código, capa 2:** §14.4–§14.6: `authData`, la llave COSE, `attestationObject` y `clientDataJSON` en `passkey::webauthn`, con un codificador CBOR mínimo; §14.9 nueva: validación del rpId con la PSL (`passkey::rp`, feature `rp-id`). `passkey.json` gana el caso `webauthn`; vector nuevo `webauthn-l3.json`, transcrito de WebAuthn nivel 3. Los demás no cambian. |
| 2026-11-05 | **ADR 0020 en código, capa 3:** §7.1 y §14.2: la clave `passkey` en *overview* y *details* (`model::passkey`), con la comprobación del resumen (`SectionMismatch`) y las reglas de lectura y edición. Ningún formato ni vector cambia. |
| 2026-11-05 | **ADR 0020 en código, capa 5:** §13.7: `passkey.used` entra en la tabla cerrada del verificador, con `person` y solo el servidor (lo envía un dispositivo de la persona por `POST /v1/audit/person`; lleva el elemento y, si lo usó un agente en una tarea, el agente y la tarea, nunca un host). Ningún formato ni vector cambia. |
| 2026-11-05 | **ADR 0020 en código, capa 8:** §14.7: la cola `0x43` de iOS (`outbox.bin`) y su texto plano. Mismo sobre y AAD que la del escritorio; ningún vector cambia. |
| 2026-11-06 | **ADR 0033 en código, capa 3:** §13.9 nueva: pausa y reanudación de los agentes, firmadas por la cuenta con la etiqueta `klav/v1/sig/agent-pause` (§2.3). §13.7: `agents.paused` y `agents.resumed` entran en la tabla cerrada del verificador, con la firma de la cuenta, el `at_ms` creciente por alcance y el aviso de los accesos durante una pausa. `agentes.json` gana `pause_at_ms`, `pause_until_ms`, `resume_at_ms`, las firmas `pause_all_signature`, `pause_agent_signature` y `resume_signature`, sus mensajes y un caso `negative`; los demás valores y vectores no cambian. |
| 2026-11-06 | **ADR 0033 en código, capa 4:** §12.2: el propósito `audit` de los datos locales (`0x41`), para la copia de la cadena de la bitácora en el dispositivo. El sobre y la AAD no cambian; ningún vector cambia. |
| 2026-11-09 | **ADR 0037 en código, capa 3 (revisión):** §12.2: el propósito `deletion` de los datos locales (`0x41`), para `deletion.bin`, lo que el dispositivo sabe del borrado de la cuenta; antes iba en la caché, y un cliente anterior no abría esa caché. El sobre y la AAD no cambian; ningún vector cambia. |
| 2026-11-10 | **ADR 0036 en código, capa 2** (grants por elemento): §3 y §8: tipo `0x23` (shared-item-key) y etiqueta `klav/v1/share/item-key` (§2.3); §13.4: `GrantPayload` `v: 2` con `items` y `profiles`, el permiso `proxy` y `items`, `methods` y `path_prefixes` en `Scope`, y el cambio de llave de un elemento al revocar; §13.7: `method` y `path` en `agent.access`. Vector nuevo `item-grant.json`; los demás no cambian. Tras la revisión: una sola forma de escribir cada ruta, un perfil por elemento, hosts que no son IP, `CONNECT` y `TRACE` siempre denegados en `proxy`, `item_version` al declarar un adjunto, la llave nueva también en la papelera. |
| 2026-11-10 | §13.4: el límite de los proveedores que leen `+` como espacio, recortan `%20` o segmentos de puntos, o decodifican y vuelven a analizar; los escapes de reservados que hace el cliente se rechazan a propósito; `item_version` solo protege ante un servidor que conoce el campo, y el cliente lo vuelve a declarar sin él ante el `400` de un servidor anterior. |
| 2026-11-10 | **ADR 0036 en código, capa 3** (`klav-proxy`): §13.4: el secreto principal de un perfil sin `field` (`password` en un `login`, `api_key` en un `api_key`; otro tipo tiene que nombrar el campo) y nunca una semilla TOTP ni un campo vacío. Ningún formato ni vector cambia. |
| 2026-11-10 | **ADR 0036 en código, capa 4a** (preferencias de la cuenta, ADR 0032 §7): §7.1: el tipo `preferences` y la clave `preferences` de *details*; §7.3: «Preferencias de la cuenta», con `developer` y `proxy` opcionales, `klav` reservado y la lectura que falla cerrada. Ningún formato binario ni vector cambia. |
| 2026-11-10 | **ADR 0036 en código, capa 5** (el paquete de un sandbox): §13.10: el paquete `ksb1_`, la huella del proxy (SHA-256 del SPKI de su llave Ed25519) y el resumen del secreto con la etiqueta `klav/v1/sandbox/secret` (§2.3). Vectores nuevos en `sandbox.json`; ninguno de los anteriores cambia. |
| 2026-11-10 | **ADR 0036 en código, capa 5** (emisores de sandboxes): §13.4: `GrantPayload` `v: 3` con `issuers` en el grant del proxy y `sandbox` en el del emisor; `v: 3` solo con alguno de los dos, y un grant de emisor sin proyectos ni elementos. Vector nuevo `sandbox-grant.json`; los demás no cambian. |
| 2026-11-10 | **ADR 0033, enmienda del 2026-11-10, capa 2** (cambiar el grant de un agente y revocarlo desde las apps): §2.3: la etiqueta `klav/v1/grant-change`, de un resumen local que no es firma ni sale del dispositivo; §12.2: el propósito `revocations` de los datos locales (`0x41`), para `revocations.bin`. Ningún formato firmado cambia; `docs/vectores/agentes.json` gana `grant_change` y `grant_change_digest`. |
| 2026-11-10 | **ADR 0033, enmienda del 2026-11-10, correcciones de la capa 4**: §12.2: formato completo de `revocations.bin` (`rotate`, `log_unchecked`, `items`, `narrowed`, `signed` con sus `items`) y la regla de cómo cambia: toda modificación sube `v`, el esquema es cerrado dentro de una `v`, y una `v` más nueva da su propio error («actualiza Klav») sin tocar el archivo. Es un formato local que esta misma pila introduce; ningún formato firmado ni del servidor cambia. |
| 2026-11-10 | **ADR 0036 en código, capa 5** (la vida de un sandbox en el servidor): §13.7: `sandbox.issued`, `sandbox.claimed` y `sandbox.revoked` en la tabla cerrada, con la petición del proxy y su cuerpo, el orden emitir → reclamar → terminar y los motivos `stop`, `ttl`, `inactivity`, `theft`, `released` e `issuer_removed`; §13.10: el resumen de la llave del canal. Vector nuevo `sandbox-events.json`; los demás no cambian. |
| 2026-11-10 | **ADR 0036 en código, capa 5a** (primera parte): §13.7: el cuerpo de `agent.access` puede nombrar un `sandbox`, solo con `proxy`. Ningún vector cambia. El cuerpo firmado admite un campo más: un `klav log verify` anterior a esta capa rechaza como alterado un acceso que lo lleve, y desde la capa 6 el proxy lo manda en cada llamada de un sandbox (ruptura aceptada por Omar el 2026-11-10, ADR 0036 E9). |
| 2026-11-10 | **ADR 0036 en código, capa 6** (el canal): §13.10: el canal fijado, TLS 1.3 con llaves Ed25519 en bruto en los dos extremos, lo que comprueba cada lado y lo único que firman la identidad del proxy y la llave del canal. §13.7: desde esta capa el proxy nombra el `sandbox` en el cuerpo de cada `agent.access` que hace por una llamada de un sandbox, que es lo que la fila de la capa 5a anunciaba. Ningún formato binario ni vector cambia. |
| 2026-11-10 | **ADR 0036 en código, capa 6** (redacción, T149): §13.4: el proxy reemplaza en las respuestas solo el valor entero, en las codificaciones de siempre, nunca un trozo (respuesta de Omar, ADR 0036 E9); cuenta los trozos para la persona. Ningún formato ni vector cambia. |
| 2026-11-12 | **ADR 0036 en código, capa 5a** (la revocación de la persona, mitad del servidor): §13.11 nueva, etiqueta `klav/v1/sig/sandbox-revoke`; §13.7: `sandbox.revoke_requested` en la tabla cerrada, los motivos `person` (con `at`) y `person_local`, y los campos `sandbox_id` y `sandbox_ids` del evento. El servidor rechaza todavía esos dos motivos con `400`, y el verificador los tres; los acepta la capa siguiente de la pila. Vector nuevo `sandbox-revoke.json`; los demás no cambian. |
| 2026-11-12 | **ADR 0036 en código, capa 5a** (la revocación de la persona, verificación): §13.7: el verificador acepta `sandbox.revoke_requested` y los motivos `person` y `person_local`, y el servidor acepta `person` (`person_local` sigue siendo un `400` hasta la capa que lo manda); lo que comprueba cada uno. §13.11: la lista de un `all` sale del `at_ms` firmado, con la ventana del reloj (`expires_at > at_ms − 5 min`), en el servidor y en el verificador, y el `at` del evento queda a no más de 5 min del firmado como comprobación de cordura; §13.7: un servidor puede reordenar lo que sigue a la última cabeza firmada. No cambia ningún formato ni vector. |
| 2026-11-13 | **ADR 0036 en código, capa 5a** (el latido, verificación): §13.12 nueva: la época del almacén (`sandbox.store_reset`, `POST /v1/agent/sandboxes/epochs`) y el latido (`PUT /v1/agent/sandboxes/state`), y lo que comprueba el dispositivo. §13.7: `sandbox.store_reset` en la tabla cerrada; el verificador rechaza una época repetida de un proxy y da la última de cada proxy avalado. Ningún servidor tiene aún las dos rutas. Vector nuevo `sandbox-heartbeat.json`; los demás no cambian. |
| 2026-11-13 | **ADR 0036 en código, capa 5a** (el latido, verificación, corrección antes de publicar): §13.7 y §13.12: el cuerpo de `sandbox.store_reset` solo vale como objeto JSON; el verificador rechaza la forma de arreglo (`["…"]`), que antes leía igual que el objeto. Ningún servidor tiene aún la ruta ni ha registrado ese evento. Los vectores no cambian. |
| 2026-11-13 | **ADR 0036 en código, capa 5a** (el latido, rutas): §13.12: el servidor sirve las dos rutas y `GET /v1/sync` trae `sandbox_state` (solo de proxies activos); el proxy guarda la época y `seq` en `<nombre>.sandbox-heartbeat`, guarda el latido que rechaza una pausa y lo descarta si el servidor lo rechaza con un `400`. Las dos rutas exigen la ruta exacta, sin consulta, y un cuerpo que sea un objeto JSON. La ruta de la época, su cuerpo y el tope de 100 sandboxes los decidió Omar el 2026-11-13; dónde vive `seq` (su propio archivo, apartándose de E3.3) y quién llama a las dos rutas los decidió el 2026-11-13. Ningún formato ni vector cambia. |
| 2026-11-13 | **ADR 0036 en código, capa 5a** (la lista de la persona): §12.2: el propósito `sandbox-marks` de los datos locales (`0x41`), para `sandbox-marks.bin`, la marca de agua del latido; §13.12: la marca se guarda, y un latido de otra versión no cuenta y no es un error. El sobre y la AAD no cambian; ningún vector cambia. |
| 2026-11-15 | **ADR 0036 en código, capa 5a** (la lista de la persona, revisión): §12.2: cada marca de `sandbox-marks.bin` lleva `epoch_seq` y el archivo sigue en `v: 1`, porque ninguna versión publicada lo escribió; un formato posterior conserva el propósito, el sobre y un `v` entero arriba. §13.12: la marca nunca vuelve a una época anterior, y unas preferencias que no se leen dejan la lista sin proxy y con un aviso. El sobre y la AAD no cambian; ningún vector cambia. |
| 2026-11-16 | §13.7: el servidor guarda una cabeza por dispositivo y posición, y `GET /v1/audit/heads` lista, además de las 100 más recientes, la última de cada dispositivo (la de `n` más alto), para 1 000 dispositivos como mucho. Ningún formato cambia. |
| 2026-11-16 | **ADR 0036 en código, capa 5a** (preferencias que escribió un agente): §7.3: de un elemento `preferences` cuya versión actual es de un agente no se usa nada; la lista de sandboxes lo marca en vez de fallar, y `klav proxy use`, tras la presencia, lo reescribe con un cuerpo nuevo que lleva solo `proxy`. Ningún formato binario ni vector cambia: el cuerpo es el JSON de *details* de siempre. |
| 2026-11-16 | **ADR 0036 en código, capa 5a** (la marca del latido, empates): §13.12 ya lo decía y esta tabla no lo recogía. Para el mismo proxy y la misma época se guarda el `seq` mayor; un latido con el mismo `seq` que la marca cuenta y no la mueve, y solo uno menor es un *rollback*. Entre épocas, en un empate de `epoch_seq` se queda la marca guardada. Un latido que retrocede es un aviso, no un fallo: la lista no sale con 3 por él (decidido por Omar el 2026-11-16, ADR 0036). Ningún formato ni vector cambia. |
| 2026-11-19 | **ADR 0041 en código, capa 2** (la puerta de presencia, apagada): §12.2: los propósitos `presence` y `passkey-window` de los datos locales (`0x41`). El sobre y la AAD no cambian; ningún vector cambia. |
| 2026-11-23 | **ADR 0046 en código, capa 1** (solicitudes de secreto por un agente): §2.3, §3 y §13.14 nueva: tipo `0x25` (`secret-request-proposal`, HPKE con `klav/v1/agent/secret-request`), firma `klav/v1/sig/secret-request-decision`, tipos `SecretRequestProposal`/`SecretRequestDecision` y validador de `setup_url` en `klav-core`. Vector nuevo `secret-request.json`; los demás no cambian. |
| 2026-11-25 | **ADR 0048 en código, capa 1** (invitaciones al registro): §2.3: etiqueta `klav/v1/server/invite`; §4.7 nueva: el código de invitación (128 bits en Crockford base32 tras `KLAV-`), su forma canónica y su resumen, en `klav_core::crypto::invite`. Vector nuevo `invite.json`; los demás no cambian. |
| 2026-11-25 | **ADR 0049 aceptado y en código, capas 1–3** (la pasarela MCP): §2.3: etiquetas `klav/v1/proxy/local-client` y `klav/v1/proxy/mcp-args`; §13.4: grant `v: 4` (perfiles MCP, `mcp_tools`, `local_clients`) y la regla de evaluación de las herramientas; §13.5: `caller` y las *claims* de la pasarela, solo con el interruptor de la cuenta encendido; §13.16 nueva: el token de cliente local (`klc1_`) y el resumen de los argumentos, en `klav_core::crypto::mcp`. §13.15 queda reservada para `0x27`. Vector nuevo `mcp-gateway.json`; los demás no cambian. |
| 2026-11-25 | **ADR 0049 en código, capa 4** (el proxy): §2.3: etiqueta `klav/v1/proxy/tool-definition`, solo local, sin formato en el cable ni vectores. Nada más cambia: el proxy calcula `mcp_args` y compara `token_digest` con las funciones de §13.16. |
| 2026-11-25 | **ADR 0032 en código, capas 1–2** (entornos por repositorio): §7.1: el tipo `environment`, la clave `environment` del *overview* y `variables` de *details*, con sus reglas, la marca efectiva, el conjunto protegido y el error `UnknownKind`; §7.2: `repos` en los metadatos de proyecto (ya en código); §11: `entorno.json`; §13.4: `Scope.items` en cualquier regla sin `v: 2`, `once`, `origin: "protected"` y `released`, en cualquier versión, con el `400` y el `409` del servidor; §13.5: `items` en la petición de aprobación y sin arrendamiento ni tarea en lo que pide cada vez. Ningún formato binario, etiqueta ni AAD cambia; los vectores existentes no cambian. |
| 2026-11-25 | **ADR 0036 en código, capa 11** (el proxy en el Mac): §13.7: el servidor acepta el fin `person_local` (solo `{"reason":"person_local"}`), que el *socket* local del proxy manda sin firma de la persona; el verificador no cambia. Sin formatos nuevos: el *socket* habla líneas JSON con versión (`v: 1`), en [api.md](api.md) §8.14. |
| 2026-11-25 | **ADR 0032 en código, capa 3** (CLI y `klavd`): §12.2: el propósito `protection` de los datos locales (`0x41`), para `protection.bin`. Ningún formato firmado, del servidor ni binario cambia; los vectores no cambian. |
| 2026-11-26 | **ADR 0051 aceptado y en código, capas 1–2** (el proxy alojado de Klav Cloud): §1: `p384`, `x509-cert`, `der` y `spki`, detrás de la feature `nitro-attestation`; §2.3: etiquetas `klav/v1/proxy/hosted-account`, `klav/v1/proxy/enclave-binding`, `klav/v1/proxy/enclave-handoff`, `klav/v1/sig/hosted-proxy-enroll` y `klav/v1/sig/enclave-manifest`; §15 nueva: el documento de atestación con su lector CBOR estricto, la cadena hasta AWS Nitro Enclaves Root-G1, lo que comprueban el dispositivo y el enclave en un traspaso, el manifiesto, las llaves por cuenta, el vínculo, la inscripción y el `info` del traspaso, en `klav_core::nitro`. El registro de cambios pasa a §16 (la cita «§15» del ADR 0020 se refiere a él). Vectores nuevos `nitro-attestation.json` y `enclave-manifest.json`; los demás no cambian. |
| 2026-11-26 | **ADR 0051 en código, capa 4** (el servidor): §2.3: etiqueta `klav/v1/sig/hosted-proxy-registration`, la misma de la capa 3; §15.8 nueva: cómo comprueba el servidor la marca de la llave de servicio en el registro del agente alojado, en `klav_core::crypto::hosted` (sin feature). Vector nuevo `hosted-proxy-registration.json`; los demás no cambian. |
| 2026-11-26 | **ADR 0051 en código, capa 3** (el enclave): §2.3: etiquetas `klav/v1/proxy/hosted-seed`, `klav/v1/proxy/hosted-service` y `klav/v1/sig/hosted-proxy-registration`; §3: tipo `0x28` (`enclave-handoff`), y la nota de reservados nombra el `0x26` del ADR 0047 y el `0x27` de §13.15; §15.4: `verify_handoff_holder`; §15.6: el traspaso sellado, la mezcla de la semilla y la llave de servicio; §15.8: la marca va en el campo `hosted` del registro, y su único verificador es el de `klav_core::crypto::hosted`. `nitro-attestation.json` gana `handoff.sealed` y sus entradas, `seed_mix` y `service`; los demás valores no cambian. |
| 2026-11-26 | **ADR 0051 en código, capa 3b** (el traspaso con los sandboxes vivos): §15.6: el estado sellado pasa a la versión 2, con el almacén, las llaves de canal, el latido y el cursor de cada cuenta; el que se une lee también la 1. El blob `0x28`, su `info` y los vectores no cambian. |
| 2026-11-26 | **ADR 0051 en código, capa 5** (los clientes): §12.2: el propósito `hosted-proxy` de los datos locales (`0x41`), para `hosted-proxy.bin`. Ningún formato firmado, del servidor ni binario cambia: los clientes verifican con §15 (atestación, manifiesto y enlace) y firman la inscripción con la etiqueta `klav/v1/sig/hosted-proxy-enroll` que ya estaba; el ajuste `proxy` de §7.3 acepta `mode: "klav"` con `agent_id`. |
