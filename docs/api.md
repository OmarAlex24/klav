# API de `klav-server` (v1)

Referencia de la API HTTP del servidor. Los tipos exactos están en el crate
[`klav-proto`](../crates/klav-proto/src) (ADR
[0007](decisiones/0007-crate-klav-proto.md)): si este documento y
`klav-proto` difieren, manda el código. La instalación está en
[`self-hosting.md`](self-hosting.md).

El servidor **no descifra nada**. Todo lo que dice "blob" lo cifró el cliente
con `klav-core` según la [especificación criptográfica](especificacion-cripto.md),
y el servidor lo guarda y lo devuelve byte por byte. Solo comprueba la forma
del blob: el encabezado `versión ‖ tipo`, la longitud y el tamaño máximo.

## 1. Convenciones

- Todas las rutas empiezan por `/v1`. Cuerpos en JSON (`application/json`),
  salvo el contenido de los adjuntos (`application/octet-stream`).
- **Blobs:** base64url sin relleno (`Blob` en `klav-proto`).
- **IDs:** UUID v4 en texto (`AccountId`, `VaultId`, `ProjectId`, `ItemId`,
  `AttachmentId`, `DeviceId`). **El cliente genera los IDs de bóvedas,
  proyectos, elementos y adjuntos**, porque van en el AAD de lo que cifra
  (§7 de la especificación). Un ID repetido devuelve `409`.
- **Fechas:** milisegundos desde la época Unix (`i64`).
- **Autenticación:** `Authorization: Bearer kat_…` con el token de acceso de
  la sesión (§3). Los agentes no usan tokens: firman cada petición (§8.2).
- Los campos desconocidos en un cuerpo JSON son un error `400`.

### 1.1 Errores

Todo error tiene la misma forma, y nunca incluye detalles internos (consultas
SQL, rutas de archivos, trazas):

```json
{ "error": "conflict", "message": "stale version: fetch the latest version and retry", "current_version": 7 }
```

| Código HTTP | `error` | Cuándo |
|---|---|---|
| 400 | `bad_request` | JSON inválido, blob con encabezado o tamaño incorrecto, valores fuera de rango |
| 401 | `unauthorized` | Falta el token, está vencido o revocado, o falló el login |
| 403 | `forbidden` | Registro cerrado, o la operación es solo del dueño de la bóveda |
| 403 | `agents_paused` | La persona pausó a ese agente o a todos (§8.1, Pausa) |
| 403 | `reauth_failed` | La contraseña maestra para borrar la cuenta no es correcta, o el `handle` venció, ya se usó, es de otra sesión o de un inicio de sesión (§2.4). Nunca `401`: la sesión sigue valiendo |
| 403 | `account_deleting` | La persona pidió borrar la cuenta: a sus agentes (§2.4, §8.2) |
| 403 | `not_issuer` | El emisor que nombra el proxy de credenciales no está en su grant, o ya no es un agente activo cuyo grant nombra a ese proxy (§8.8) |
| 403 | `profile_not_allowed` | El sandbox pide un perfil que su emisor no tiene (§8.8) |
| 403 | `sandbox_revoked` | El sandbox está revocado o vencido, o su emisor ya no lo es; también al registrar su fin por segunda vez (§8.8) |
| 403 | `invite_invalid` | Servidor en modo `invite`: el código no sirve para ese correo ahora (no existe, está revocado, venció, se agotó o está ligado a otro correo). Una sola respuesta para todos los motivos, que nunca dice si el correo tiene cuenta (§2.2, ADR [0048](decisiones/0048-invite-beta-and-distribution.md) §1.3) |
| 403 | `quota_exceeded` | La escritura pasaría a la cuenta por encima de una cuota (adjuntos, datos de la bóveda, elementos o bóvedas); el mensaje dice cuál, cuánto se usa y el máximo (§7, ADR 0048 §3.2). No es `413`: aquí `413` es un cuerpo demasiado grande |
| 404 | `not_found` | No existe **o no eres miembro** (no se distingue a propósito) |
| 404 | `sandbox_not_found` | Las rutas de §8.8 no conocen ese sandbox: este proxy nunca registró su `sandbox.issued`. Solo este código le dice al proxy que puede olvidar el fin pendiente de un sandbox; el `not_found` genérico de una ruta que el servidor no tiene no dice nada de él. Los servidores anteriores responden `not_found` |
| 409 | `conflict` | Versión vieja, ID repetido, estado incompatible (p. ej. editar algo en la papelera) |
| 409 | `too_many_sandboxes` | El emisor ya tiene tantos sandboxes vivos como le permite el grant del proxy (§8.8) |
| 409 | `sandbox_claimed` | El sandbox ya se reclamó (§8.8) |
| 413 | `payload_too_large` | Cuerpo mayor que el límite |
| 429 | `too_many_requests` | *Rate limit*; trae `Retry-After` en segundos |
| 500 | `internal` | Error interno (el detalle queda solo en el log) |
| 503 | `unavailable` | Saturación temporal (p. ej. demasiados logins a medio hacer) |

`current_version` solo aparece en los `409` por versión vieja (§4.4). Un
`agents_paused` trae además `scope` (`all` · `agent`), `since` y, si la pausa
tiene fin, `until` (milisegundos Unix). `last_at` solo aparece en el `409` de
una pausa o reanudación que no es posterior a la última decisión de su
alcance (§8.1, Pausa). Un `account_deleting` trae `delete_at`, cuándo se
borra la cuenta (milisegundos Unix, §2.4).

### 1.2 Cabeceras de seguridad

Todas las respuestas llevan `Strict-Transport-Security`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'…`,
`Cross-Origin-Resource-Policy: same-origin`, `Cache-Control: no-store` y
`Server: klav`.

### 1.3 Salud

`GET /v1/health` → `200 {"status":"ok","version":"…","registration_open":true,"account_deletion":true,"registration_mode":"open"}`.
Si la base no responde, devuelve `503`. No requiere sesión.

`registration_mode` (ADR [0048](decisiones/0048-invite-beta-and-distribution.md)
§1.2) dice cómo acepta cuentas nuevas el servidor: `open` (cualquiera),
`invite` (con un código de invitación, §2.2) o `closed` (nadie). Sale de
`registration_mode` / `KLAV_REGISTRATION_MODE` y del ajuste anterior
`allow_registration` / `KLAV_ALLOW_REGISTRATION`: `true` es `open`, `false` es
`closed`, y sin ninguno de los dos, `open`. Con los dos puestos tienen que
concordar (`true` solo con `open`; `false` con `closed` y con `invite`), o el
servidor no arranca. Los clientes nuevos lo leen primero; si falta (un
servidor anterior), usan `registration_open`. Un valor que no conocen (un
servidor más nuevo) lo tratan como `closed`.

`registration_open` dice si el servidor acepta cuentas nuevas
(`KLAV_ALLOW_REGISTRATION`, [`self-hosting.md`](self-hosting.md)). Los
clientes lo consultan antes de pedir la contraseña del registro y, si es
`false`, lo dicen sin crear nada (ADR
[0028](decisiones/0028-servidor-por-defecto-klav-dev.md) §3). Es opcional: un
servidor anterior no lo manda y el cliente intenta el registro, que responde
`403` si está cerrado (§2.2). En modo `invite` es `false`: así un cliente
anterior a `registration_mode` se detiene antes de escribir el kit de
emergencia o derivar llaves, con el mensaje de «registro no abierto».

`account_deletion` dice que el servidor sabe borrar una cuenta desde las apps
y la CLI (§2.4). Todo servidor con esta versión lo manda en `true`, sin un
ajuste para apagarlo. Los clientes lo consultan **antes** de pedir Face ID,
Touch ID o la contraseña; si falta, dicen «Este servidor no permite borrar la
cuenta desde la app. Pídeselo a quien lo opera.» (ADR
[0037](decisiones/0037-borrar-la-cuenta.md) §4).

## 2. Cuenta: registro e inicio de sesión (OPAQUE)

El cliente deriva de la contraseña maestra y el Secret Key dos valores
independientes (§4.3 de la especificación): la **KEK**, que nunca sale del
dispositivo, y la **entrada de OPAQUE** `O`, que solo se usa dentro del
protocolo. El servidor guarda un registro de OPAQUE que no permite atacar la
contraseña fuera de línea (§4.5; suite `klav-opaque-v1`, ADR
[0009](decisiones/0009-opaque.md)).

Los mensajes de OPAQUE (`registration_request`, `credential_request`, etc.) son
los bytes de `opaque-ke` en base64url, sin encabezado de Klav.

El correo se normaliza (sin espacios alrededor, en minúsculas) y es el
identificador de la credencial en OPAQUE.

### 2.1 Prelogin

`POST /v1/auth/prelogin` `{ "email" }` → `{ "kdf_params": Blob }`

Devuelve los parámetros de Argon2id de la cuenta (tipo `0x06`). Para un correo
desconocido devuelve parámetros **señuelo**, deterministas y con una sal
derivada de un secreto del servidor, así que no revela si la cuenta existe. El
cliente debe rechazar parámetros por debajo del mínimo de v1 (T3).

### 2.2 Registro

1. `POST /v1/auth/register/start` `{ "email", "registration_request" }` →
   `{ "registration_response" }`
2. `POST /v1/auth/register/finish` →
   `201 { "account_id" }`

```json
{
  "email": "ana@example.com",
  "account_id": "…",
  "registration_upload": "…",
  "kdf_params": "…",
  "public_identity": "…",
  "sealed_identity": "…"
}
```

`public_identity` son las llaves públicas X25519 y Ed25519 (tipo `0x05`).
`sealed_identity` son las privadas selladas con la KEK (tipo `0x01`, §6.3).
`kdf_params` debe llevar exactamente los costos por defecto de v1 (m = 256
MiB, t = 3, p = 4; especificación §4.4) con cualquier sal; si no, `400`
(defensa en profundidad para T3, ADR
[0010](decisiones/0010-decisiones-fase-3-y-plan-alojado.md)). No basta con
estar dentro del rango: `prelogin` responde esos mismos costos para los
correos desconocidos, y una cuenta con otros se distinguiría de un correo
que no existe.
Si el registro está cerrado responde `403`. Si el correo ya existe, `409`
(la verificación por correo que lo oculta llega con el plan alojado, fase 8).

**Con invitación** (`registration_mode = "invite"`, ADR
[0048](decisiones/0048-invite-beta-and-distribution.md) §1.3):

- `POST /v1/auth/invite/check` `{ "email", "invite" }` → `204` si el código
  sirve ahora para ese correo, o `403 invite_invalid` con el mismo mensaje
  por cualquier motivo. No lee las cuentas: responde igual tenga o no cuenta
  el correo. No reserva nada: dos personas con el último uso de un código de
  grupo pueden pasarlo, y solo una termina. En `open` y `closed` responde
  `404`. Los clientes lo llaman antes de pedir la contraseña y de entregar el
  kit.
- `register/start` y `register/finish` aceptan un campo opcional `invite`. En
  modo `invite` es obligatorio: `start` hace la misma comprobación antes del
  trabajo de OPAQUE, y `finish`, en una sola transacción y con la escritura
  primero, gasta un uso del código (un `UPDATE` condicional), crea la cuenta
  y anota qué cuenta lo usó. Si el correo ya existe, la transacción se
  deshace (el uso no se gasta) y la respuesta es el `409` de siempre. Dos
  `finish` por el último uso no pueden confirmarse los dos. En `open` el
  campo se ignora. Los clientes solo lo mandan cuando `health` dijo
  `invite`: un servidor anterior rechaza campos desconocidos.
- El código es `KLAV-` y 26 caracteres de Crockford base32 (128 bits), en
  grupos; se aceptan minúsculas, sin prefijo, sin guiones o con espacios, y
  `I`/`L` valen `1` y `O` vale `0` (especificación §4.7). El servidor guarda
  solo su resumen.
- Límite propio por IP (§7): cada `invite/check` y cada fallo de invitación
  en `start` o `finish` gastan una ficha; con el cubo vacío, también un
  código bueno espera (`429`). Cada fallo deja una línea `warn` con la IP y
  sin el código ni el correo.
- Los códigos los crea quien opera el servidor con `klav-server invite
  create|ls|revoke` (ADR 0048 §1.4), no hay API HTTP de administración.

### 2.3 Login

1. `POST /v1/auth/login/start` `{ "email", "credential_request" }` →
   `{ "login_id", "credential_response" }`. El `login_id` vale 2 minutos y
   un solo uso.
2. `POST /v1/auth/login/finish`:

```json
{
  "login_id": "…",
  "credential_finalization": "…",
  "device": { "id": null, "name": "MacBook de Ana", "kind": "cli" }
}
```

→ `200 { "account": AccountKeyset, "device_id", "session": SessionTokens }`

`kind` ∈ `cli`, `daemon`, `browser`, `ios`, `android`, `other`. Si `device.id`
es un dispositivo vigente de la cuenta, se reutiliza; si no, se registra uno
nuevo. Una contraseña equivocada y una cuenta inexistente fallan igual, con
`401`.

`AccountKeyset` trae `kdf_params`, `public_identity` y `sealed_identity`: el
cliente abre `sealed_identity` con su KEK y comprueba que las llaves públicas
coinciden (T9). `GET /v1/account` devuelve lo mismo a una sesión activa y,
si la persona pidió borrar la cuenta, `deletion` (§2.4). Un cliente anterior
lo ignora.

### 2.4 Borrar la cuenta

La persona borra su cuenta desde la app de iPhone, la de Mac o la CLI (ADR
[0037](decisiones/0037-borrar-la-cuenta.md)). Hacen falta su sesión y su
contraseña maestra: el cliente vuelve a hacer el intercambio OPAQUE completo
del login, con `O` calculado con la contraseña y el Secret Key del
dispositivo, en rutas propias. Si sale bien, en esa misma petición queda
**programado** el borrado para dentro de 7 días; hasta entonces, cualquier
dispositivo con sesión lo cancela.

| Ruta | Cuerpo | Respuesta |
|---|---|---|
| `POST /v1/account/delete/start` | `{ "credential_request" }` | `{ "handle", "credential_response" }` |
| `POST /v1/account/delete/finish` | `{ "handle", "credential_finalization" }` | `202 AccountDeletion` |
| `POST /v1/account/delete/cancel` | — | `204`; `404` si no hay borrado pedido |

`AccountDeletion` es `{ "requested_at", "delete_at", "device_id",
"device_name" }`: cuándo se pidió, cuándo se borra (`requested_at` + 7
días, en milisegundos Unix) y desde qué dispositivo.

- **Las tres rutas exigen la sesión de la persona** (`Authorization: Bearer
  kat_…`). Una petición firmada de un agente nunca llega: no lleva token
  (`401`). No hay permiso, herramienta de `klav mcp`, función del SDK ni
  operación de `klavd` que borre la cuenta.
- **El correo es el de la cuenta de la sesión**, nunca uno que mande el
  cliente.
- **El `handle` vale 2 minutos, un solo uso, solo para esa sesión y solo para
  borrar.** Un `login_id` no termina un borrado, ni un `handle` un inicio de
  sesión (`401` en `login/finish`); el que se usa mal queda gastado igual.
- **Una contraseña equivocada responde `403 reauth_failed`, nunca `401`**,
  porque los clientes toman cualquier `401` por el fin de la sesión. También
  un `handle` vencido, usado, de otra sesión o de un inicio de sesión.
- **Un borrado a la vez.** Con uno pedido, `start` y `finish` responden
  `409 conflict` (`start` antes de cualquier trabajo de OPAQUE en el
  servidor). El cliente ya gastó su Argon2id, del que sale el KE1: para
  ahorrárselo, los clientes miran antes `deletion` en `GET /v1/account` o
  `GET /v1/sync`.
- **Límites:** `start` cuenta en los de autenticación por IP y por correo e
  IP (§7), con el correo de la cuenta, y como mucho **5 por cuenta y hora**,
  salgan bien o mal. Como mucho **3 borrados pedidos por cuenta cada 7
  días** (`429` desde `start`). Cancelar solo cuenta en el límite por cuenta.
  Estos dos contadores viven en memoria, como los demás límites: un
  reinicio del servidor los vacía.
- **Mientras tanto todo sigue igual para la persona:** leer, editar,
  sincronizar e iniciar sesión en otro dispositivo, para cancelar desde uno
  nuevo. El correo no se puede volver a registrar (`409`), porque la cuenta
  existe.
- **Los demás dispositivos lo saben** por `deletion` en `GET /v1/account` y
  en `GET /v1/sync` (§5.2), y por los avisos de *push* (§3).
- **Los agentes se cortan al momento** (§8.2): toda petición firmada recibe
  `403 account_deleting` con `delete_at`, salvo `GET /v1/agent/me`, que trae
  `account_delete_at`. El servidor lo vuelve a mirar con el cerrojo de la
  cuenta al registrar en la bitácora un uso permitido, así que una petición
  en vuelo tampoco pasa, y otra vez antes de las escrituras que van después
  del evento, salvo la que cierra un cambio de contraseña (§8.2). Un
  registro nuevo de agente recibe el `202` de
  siempre, sin guardar nada ni avisar: no revela que la cuenta se va (§8.1).
  Al cancelar, vuelven.
- **Ni el pedido ni la cancelación ni el borrado entran en la bitácora**
  (ADR 0037 §5.3): la cadena se borra con la cuenta, y una acción nueva
  rompería los `klav log verify` anteriores.

**Al llegar `delete_at`,** la limpieza de cada hora borra la cuenta en una
transacción, con el mismo cerrojo que toma «Cancelar»: una cancelación de un
segundo antes gana.

1. Borra las filas de `vault_members` que nombran a la cuenta como miembro
   (`member_id` no tiene llave foránea).
2. Borra la fila de `accounts`, que se lleva en cascada todo lo demás:
   dispositivos, sesiones y *tokens* de *push*; bóvedas, proyectos,
   elementos, versiones y adjuntos; agentes, sus proyectos y nonces,
   aprobaciones, tareas, cambios asistidos y pausas; la bitácora y el
   propio pedido.
3. Después del *commit*, borra del disco los archivos de sus bóvedas (la
   limpieza de huérfanos queda de respaldo), cierra sus flujos SSE, olvida
   sus logins a medio hacer, manda el aviso final y escribe en el log
   `account deleted` con el `account_id`, sin el correo
   ([`self-hosting.md`](self-hosting.md) §4.3).

Después, sus sesiones y sus agentes reciben `401`, como una sesión revocada
o un agente que el servidor no conoce: el servidor no guarda nada de la
cuenta para responder otra cosa. El correo queda libre: con el registro
abierto, se puede crear con él otra cuenta, sin nada de la anterior.
**Ninguna respuesta del servidor borra una copia local**, ni un `401` ni
`deletion` ni el aviso final (T165): cada dispositivo ofrece borrar la suya.

## 3. Sesiones y dispositivos

```json
{
  "access_token": "kat_…",
  "access_expires_at": 1767225600000,
  "refresh_token": "krt_…",
  "refresh_expires_at": 1769817600000
}
```

- El **token de acceso** dura 15 minutos.
- El **token de renovación** dura 30 días, con plazo deslizante, y es de un
  solo uso. `POST /v1/auth/refresh` `{ "refresh_token" }` devuelve un par
  nuevo. Si alguien presenta el token de renovación **inmediatamente
  anterior** (el que se acaba de cambiar por el actual), **se revoca la
  sesión entera** (señal de robo). El servidor solo recuerda esa generación:
  un token de dos o más renovaciones atrás recibe `401` sin revocar nada.
  Quien robe un token y lo use primero hace que la siguiente renovación del
  dueño presente el anterior, y eso sí revoca.
- `POST /v1/auth/logout` revoca la sesión actual (`204`).
- El servidor guarda solo `SHA-256` de los tokens (§4.6 de la especificación).

Dispositivos:

- `GET /v1/devices` → `{ "devices": [ { "id", "name", "kind", "created_at", "last_seen_at", "revoked_at"?, "current" } ] }`
- `DELETE /v1/devices/{device_id}` → `204`. Revoca el dispositivo y todas sus
  sesiones. Sus flujos SSE se cierran en menos de 30 s. También borra su token
  de *push*.

*Push* del dispositivo actual (aprobaciones en el teléfono, ADR 0018 §5):

- `PUT /v1/devices/current/push` `{ "token", "environment" }` → `204`. `token`
  es el *device token* de APNs en hexadecimal (32 a 200 caracteres; `400` si
  no) y `environment` es `sandbox` o `production`. Un token que tenía otro
  dispositivo de la misma cuenta (la app se reinstaló) o un dispositivo
  revocado pasa a este. Si lo tiene un dispositivo **activo de otra
  cuenta**, `409`: esa cuenta debe cerrar la sesión allí (o revocar el
  dispositivo) antes.
- `DELETE /v1/devices/current/push` → `204`. `POST /v1/auth/logout` también lo
  borra.
- Con APNs configurado (`self-hosting.md` §2.4), el servidor avisa a los
  teléfonos de la cuenta cuando un agente pide registrarse (como mucho 5 avisos
  por cuenta y hora), cuando se crea una aprobación `ask` nueva (repetir la
  misma solicitud pendiente no vuelve a avisar; como mucho 60 por cuenta y
  hora) y cuando un agente pide una tarea (§8.5; como mucho 30 por cuenta y
  hora). Pasado el presupuesto, la solicitud se crea igual, sin aviso. El *payload* no lleva texto
  del servidor ni datos de la solicitud:

  ```json
  { "aps": { "alert": { "title-loc-key": "PUSH_APPROVAL_TITLE", "loc-key": "PUSH_APPROVAL_BODY" },
             "sound": "default", "thread-id": "approval" },
    "klav": { "type": "approval", "id": "<approval_id>" } }
  ```

  `type` es `approval` (el ID es el de la aprobación), `agent` (el del
  agente) o `task` (el de la tarea, con `PUSH_TASK_TITLE`/`PUSH_TASK_BODY`).
  La app pide los detalles con `GET /v1/approvals/{id}`, `GET /v1/agents` o
  `GET /v1/tasks`. El aviso caduca en APNs (`apns-expiration`) cuando
  caduca lo que anuncia: 10 minutos para aprobaciones y tareas, una hora
  para registros. Un `410` o un `BadDeviceToken` de Apple borra el token.
- El borrado de la cuenta (§2.4) avisa tres veces: al pedirlo
  (`PUSH_ACCOUNT_DELETION_TITLE`/`_BODY`), al cancelarlo
  (`PUSH_ACCOUNT_CANCELED_…`) y al terminar (`PUSH_ACCOUNT_DELETED_…`). Van
  con `"klav": { "type": "account" }`, sin ID, sin `apns-collapse-id` (un
  aviso no tapa al otro) y caducan a los 7 días. El aviso final se manda a
  los *tokens* leídos antes del borrado, que se los lleva, y solo si el
  borrado se confirmó. Como mucho 10 de cada uno por cuenta y hora.

## 4. Bóvedas, proyectos y elementos

Jerarquía de llaves (§5 de la especificación): la llave de bóveda se comparte
con cada miembro por HPKE (`shared_key`), cada proyecto tiene su llave
envuelta con la de la bóveda, y cada elemento la suya envuelta con la del
proyecto.

### 4.1 Bóvedas

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `GET /v1/vaults` | — | `{ "vaults": [Vault] }` (sin las borradas; esas aparecen en `/v1/sync`) |
| `POST /v1/vaults` | `{ "id", "meta", "shared_key", "shared_key_signature" }` | `201 Vault`; `400` sin firma o si no verifica |
| `GET /v1/vaults/{id}` | — | `Vault` |
| `PUT /v1/vaults/{id}` | `{ "version", "meta" }` | `Vault` (solo el dueño) |
| `DELETE /v1/vaults/{id}` | — | `204` (solo el dueño; se puede restaurar durante `trash_days`) |
| `POST /v1/vaults/{id}/restore` | — | `Vault` (solo el dueño); `404` si ya se purgó |
| `PUT /v1/vaults/{id}/signature` | `{ "shared_key_signature" }` | `Vault` (solo el dueño): firma una bóveda anterior a la firma; `409` si ya tiene otra |
| `GET /v1/vaults/{id}/members` | — | `{ "members": [Member] }` |

`Vault` = `{ id, owner_account_id, role, revision, version, meta, shared_key,
shared_key_signature?, created_at, updated_at, deleted_at? }`. `shared_key` es
la copia del que pregunta: la llave de bóveda sellada con HPKE para su
identidad, con contexto `(owner_account_id, vault_id)`.

`shared_key_signature` es la firma Ed25519 de la cuenta dueña sobre
`shared_key` (64 bytes, etiqueta `klav/v1/sig/vault-key`, §8.3 de la
especificación, ADR [0030](decisiones/0030-ronda-de-seguridad-2026-11.md) §1).
HPKE solo prueba que la llave se cifró *para* la cuenta, y el servidor conoce
su identidad pública; la firma prueba que la eligió la cuenta. El servidor la
verifica al crear la bóveda, pero quien decide es el cliente: no usa una
bóveda cuya firma no verifique con la identidad de su propia cuenta, ni una
cuyo `owner_account_id` no sea su cuenta.

Solo falta en las bóvedas creadas antes de la firma. La primera sincronización
de cada dispositivo actualizado las firma y sube la firma con `PUT
/v1/vaults/{id}/signature` (TOFU): si el dispositivo ya tenía la bóveda en su
caché, el `shared_key` listado debe ser byte a byte el de la caché. Después,
ese dispositivo rechaza cualquier bóveda sin firma. La ruta acepta también
bóvedas en la papelera, verifica la firma, no hace nada si recibe la misma
que ya tiene (Ed25519 es determinista) y responde `409` si tiene otra.
Guardarla sube la revisión de la bóveda, así que los demás dispositivos la
reciben en su siguiente `changes`. Si el servidor no la guarda, la
sincronización del cliente falla: los servidores se actualizan antes que los
clientes. `meta` es el nombre de la bóveda sellado con su
llave (tipo `0x12`, §7.2 de la especificación); el servidor solo lo trata como
blob. Los proyectos usan el mismo formato con su propia llave (tipo `0x13`).

Quien crea una bóveda es su dueño (`owner`). Compartir con otras cuentas y con
agentes llega en la fase 4. El esquema ya tiene la tabla de miembros con
`member_type` (`account`/`agent`) y `role`.

### 4.2 Proyectos

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `GET /v1/vaults/{v}/projects` | — | `{ "projects": [Project] }` |
| `POST /v1/vaults/{v}/projects` | `{ "id", "wrapped_key", "meta" }` | `201 Project` |
| `PUT /v1/vaults/{v}/projects/{p}` | `{ "version", "wrapped_key", "meta" }` | `Project` |
| `DELETE /v1/vaults/{v}/projects/{p}` | — | `204`; `409` si aún tiene elementos (incluidos los de la papelera) |
| `GET /v1/vaults/{v}/projects/{p}/keys` | — | `{ version, keys: [ { item_id, version?, wrapped_key } ] }` (solo el dueño) |
| `POST /v1/vaults/{v}/projects/{p}/rotate` | `{ version, wrapped_key, meta, keys }` | `Project` (solo el dueño) |

Un proyecto que no existe y uno de otra bóveda dan el mismo `404`: un miembro
no puede sondear IDs fuera de sus bóvedas.

- `PUT` acepta una `wrapped_key` nueva, pero sin tocar las llaves de los
  elementos: para rotar la llave de un proyecto con elementos se usa
  `rotate`.
- **Rotar la llave de un proyecto** (ADR 0014 §7):
  - solo el dueño de la bóveda lee `keys` y rota (`403` para cualquier otro
    miembro). Hoy no hay miembros ajenos; la regla queda puesta para cuando
    exista compartir con personas;
  - `keys` lista todas las llaves de elemento envueltas con la llave del
    proyecto: la de cada elemento no purgado (`version` ausente) y la de
    cada versión guardada (`version`);
  - el cliente las abre con la llave vieja, genera una nueva, las vuelve a
    envolver y manda en `rotate` exactamente las mismas entradas, junto con
    la llave nueva envuelta con la de la bóveda (`0x02`) y los metadatos
    sellados con ella para `version` = actual + 1;
  - el servidor lo aplica en una sola transacción. Responde `409` si la
    versión no es la siguiente o si el conjunto de llaves cambió entre
    medias (alguien editó o creó un elemento): basta con repetir;
  - los elementos cambian de revisión para que los demás dispositivos
    descarguen las llaves nuevas. El cuerpo admite hasta 64 MiB;
  - queda el evento `project.rotated` en la bitácora del dueño;
  - el cliente no se fía de la lista: comprueba que trae todos los elementos
    vivos del proyecto que tiene en su caché, con la misma `wrapped_key`, y
    si falta o cambia alguno no rota (error de seguridad). Las versiones
    guardadas no las puede comprobar: su caché no guarda el historial;
  - una escritura de elemento hecha con la llave vieja después de rotar
    recibe `409` (`project_version`, §4.4).

### 4.3 Elementos

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `GET /v1/vaults/{v}/items?project_id=&trash=` | — | `{ "items": [Item] }` **sin `details`** |
| `POST /v1/vaults/{v}/items` | `{ "id", "project_id", "version": 1, "wrapped_key", "project_version", "overview", "details" }` | `201 Item` |
| `GET /v1/vaults/{v}/items/{i}` | — | `Item` con `details` |
| `PUT /v1/vaults/{v}/items/{i}` | `{ "version", "wrapped_key", "project_version", "overview", "details", "attachment_keys"? }` | `Item` |
| `DELETE /v1/vaults/{v}/items/{i}` | — | `204`: a la papelera |
| `POST /v1/vaults/{v}/items/{i}/restore` | — | `Item`: sale de la papelera |
| `POST /v1/vaults/{v}/items/{i}/purge` | — | `204`: borrado definitivo (solo desde la papelera) |
| `GET /v1/vaults/{v}/items/{i}/versions` | — | `{ "versions": [ { "version", "created_at", "author_agent_id"? } ] }`, de la más nueva a la más vieja |
| `GET /v1/vaults/{v}/items/{i}/versions/{n}` | — | `ItemVersion` con los blobs de esa versión |
| `DELETE /v1/vaults/{v}/items/{i}/versions` | — | `204`: borra las versiones anteriores guardadas; la actual queda (permiso de escritura en la bóveda) |

`trash` ∈ `exclude` (por defecto), `only`, `include`. La lista lleva `overview`
para mostrar títulos sin bajar los secretos. `details` se pide elemento por
elemento o llega por sincronización.

**Autoría** (ADR [0030](decisiones/0030-ronda-de-seguridad-2026-11.md) §7). `Item`, cada entrada de
`versions` e `ItemVersion` llevan `author_agent_id` cuando esa versión la
escribió un agente (por las rutas de §8.3); sin él, la escribió la persona.
Las versiones anteriores a la capa 06 no tienen autor y cuentan como de la
persona. Los **hosts confirmados** de un elemento son los de las URLs de la
última versión que escribió la persona. El cliente de la persona solo usa
esos para sugerir, autollenar y en el Credential Provider. Los demás los
muestra como «añadidos por *agente*», con confirmar (una edición normal de
la persona) y quitar. Si la versión actual es de un agente, el cliente busca
al sincronizar la última de la persona en `versions` y la baja; si no puede,
esos hosts quedan pendientes (falla cerrado).

Un elemento no se puede mover de proyecto: su AAD incluye el proyecto. Para
moverlo, el cliente lo crea de nuevo en el destino y purga el original.

**Llave nueva de un elemento** ([ADR 0036](decisiones/0036-sandboxes-de-agentes.md)
§18, especificación §13.4). Al revocar un grant que compartía el elemento, el
cliente de la persona escribe la versión siguiente con una llave de elemento
nueva y manda `attachment_keys`: `[ { attachment_id, wrapped_key } ]`, cada
adjunto completo y no borrado del elemento con su llave envuelta de nuevo
(tipo `0x04`), o `[]` si no tiene. El servidor guarda la versión y las llaves
de los adjuntos en la misma transacción y revisión, o nada:
- `409` si la lista no es exactamente esos adjuntos (falta uno, sobra uno o
  se repite) o si hay una subida en curso del elemento, que lleva una llave
  envuelta con la llave vieja: el cliente sincroniza y lo intenta otra vez;
- `400` si una llave no es un blob `0x04`.

Esta escritura también vale para un elemento en la papelera, que sigue ahí
con su `trashed_at` intacto: revocar no deja un elemento que el agente
revocado podría abrir tras una restauración. Cualquier otra escritura a un
elemento en la papelera sigue dando `409`.

Sin `attachment_keys`, la escritura conserva la llave (lo de siempre). Un
servidor anterior rechaza el campo (`400`): falla cerrado. Un agente nunca lo
manda (`400` en `PUT /v1/agent/items/{id}`).

### 4.4 Versiones y el contrato del `409`

- Cada elemento tiene una **versión** que empieza en 1 y sube de uno en uno.
  Va dentro del AAD de sus blobs (§7, T6).
- Para editar, el cliente envía `version = actual + 1` con los blobs sellados
  para esa versión. Si otra escritura llegó antes, el servidor responde
  `409` con `current_version`. El cliente baja la versión actual, combina los
  cambios y reintenta con `current_version + 1`. El servidor nunca sobrescribe
  en silencio.
- Lo mismo aplica a `PUT` de bóvedas y proyectos, con su propio `version`.
- **`project_version`.** Toda escritura de elemento (`POST` y `PUT`, de
  personas y de agentes) dice con qué versión del proyecto envolvió su
  `wrapped_key`. El servidor la compara con la versión actual del proyecto
  dentro de la misma transacción de la escritura, que toma el mismo cerrojo
  de la bóveda que una rotación. Si no es la actual, responde `409` **sin**
  `current_version` (ese campo es el del elemento). Así, una llave de
  elemento envuelta con una llave de proyecto que acaba de rotar nunca se
  guarda donde la llave nueva no la abre.
  - El cliente de la persona sincroniza y, si el proyecto cambió de
    versión, vuelve a envolver con la llave nueva y reintenta **una vez**.
  - La versión del proyecto sube también al renombrarlo: ese `409` es
    espurio pero inofensivo (el reintento lo resuelve).
  - El runtime del agente toma `project_version` de `GET /v1/agent/items`
    solo si los metadatos del proyecto abren con la llave de su grant para
    esa versión (va en su AAD). Si no abren, la llave rotó después del grant
    y no escribe nada en ese proyecto hasta recibir uno nuevo. Ante un `409`
    recarga la sesión (y el grant nuevo, si lo hay) y devuelve el error para
    que se reintente.
- Cada edición guarda la versión anterior en el historial (hasta
  `max_item_versions`, 50 por defecto), con su autor. La última versión que
  escribió la persona no se borra al recortar el historial: sus hosts son
  los confirmados (§4.3). `DELETE …/versions` sí la borra; con la versión
  actual de un agente, ningún host queda confirmado hasta que la persona
  vuelva a escribir el elemento.
- **Purgar las versiones** (`DELETE …/versions`) borra todo ese historial
  sin tocar la versión actual. El cliente lo usa al borrar entradas del
  historial del generador (ADR 0022 §2): si no, las versiones viejas
  seguirían guardando, cifradas, las contraseñas borradas.
- **Restaurar una versión vieja lo hace el cliente.** Baja la versión `n`,
  la descifra con su número `n`, la vuelve a sellar como `actual + 1` y la
  envía con `PUT`. El historial no se reescribe.
- La papelera conserva los elementos `trash_days` días (30 por defecto). La
  purga automática los convierte en *tombstones*: sin blobs, con `purged_at`,
  para que la sincronización propague el borrado. También borra su historial
  y sus adjuntos.

## 5. Sincronización

### 5.1 Revisiones

Cada bóveda tiene una **revisión** que sube en 1 con cada cambio confirmado
en ella: bóveda, miembros, proyectos, elementos y adjuntos. Cada fila guarda
la revisión del último cambio que la tocó. Las escrituras de una misma bóveda
se serializan, así que las revisiones se asignan en orden de confirmación.

### 5.2 Endpoints

- `GET /v1/sync` → `{ "vaults": [ { "vault_id", "revision", "deleted_at"? } ], "agent_pauses"?, "deletion"?, "sandbox_state"? }`:
  todas las bóvedas a las que perteneces. Si una desaparece de la lista, se
  purgó o perdiste el acceso: bórrala de la copia local. `agent_pauses` son
  las pausas de agentes en vigor, firmadas por la cuenta (§8.1, Pausa); el
  cliente se queda solo con las que verifican. `deletion` es el borrado de
  la cuenta que pidió la persona (`AccountDeletion`, §2.4): cada cliente
  guarda la fecha y muestra el aviso, y la quita cuando ya no viene.
  `sandbox_state` es el último latido de cada proxy de credenciales activo
  de la cuenta, firmado por él (§8.8, La época del almacén y el latido).
- `GET /v1/vaults/{v}/changes?since=<rev>` → `Changes`:

```json
{
  "vault_id": "…",
  "since": 41,
  "revision": 44,
  "vault": { … },
  "members": [ … ],
  "projects": [ … ],
  "items": [ … ],
  "attachments": [ … ]
}
```

Trae todo lo que cambió con `since < revisión ≤ revision`: los elementos
completos (con `details`), los proyectos borrados como *tombstone*
(`deleted_at`, sin blobs), los elementos purgados (`purged_at`) y los
adjuntos completados o borrados. `vault` solo aparece si cambiaron sus
metadatos o su estado. Con `since=0` se baja la bóveda entera.

El servidor lee la revisión actual **antes** que las filas. Así, todo lo que
tiene revisión `≤ revision` ya está a la vista y no se pierde nada: lo que se
confirme mientras tanto llega en la siguiente llamada. Hoy no hay paginación:
la respuesta incluye todos los cambios.

### 5.3 *High-water marks* y rollback (T7)

El cliente guarda, por bóveda, la última `revision` que aplicó, y por
elemento, la última `version` que vio. Si el servidor devuelve una revisión
menor que la guardada, o un elemento con una versión menor que la conocida,
el cliente debe tratarlo como *rollback* y rechazarlo (T7). El servidor solo
garantiza que ambos números son monótonos. La comprobación es del cliente:
`klav-client` (ADR [0011](decisiones/0011-cliente-tls-y-jerarquia-local.md))
guarda esas marcas en su caché cifrada, comprueba también las versiones de
bóvedas y proyectos, que `changes` responda el `since` pedido y que lo purgado
no reaparezca, y si algo retrocede aborta la sincronización entera sin tocar
la caché.

Además, un cambio nunca pisa una copia buena con una que no abre: si al
aplicar los cambios de una bóveda deja de descifrarse algo que se descifraba
(la bóveda, un proyecto o un elemento, aunque llegue con la misma versión, o
una llave de bóveda firmada que vuelve sin firma), el cliente descarta los
cambios de esa bóveda, conserva su copia y su revisión y avisa. La siguiente
sincronización lo vuelve a intentar. Los adjuntos de `changes` deben ser de
esa bóveda y estar completos (`completed_at`, `wrapped_key` y `received =
size`) o borrados; si no, también es *rollback*.

### 5.4 Avisos en vivo (SSE)

`GET /v1/events` (con `Authorization`) abre un flujo `text/event-stream`:

| Evento | `data` | Qué hacer |
|---|---|---|
| `ready` | `{}` | Ya estás suscrito: sincroniza ahora (`/v1/sync` + `changes`) para no perder lo ocurrido antes de suscribirte |
| `change` | `{ "vault_id", "revision" }` | Si `revision` es mayor que tu marca, pide `changes?since=<tu marca>` |
| `resync` | `{}` | Te quedaste atrás y se descartaron avisos: sincroniza todo |

Solo recibes avisos de bóvedas de las que eres miembro. Los avisos llevan IDs
y revisiones, nunca contenido. Cada 15 s llega un comentario para mantener
viva la conexión. El flujo se cierra cuando vence el token de acceso o se
revoca la sesión o el dispositivo: reconecta con un token nuevo.

## 6. Adjuntos

Los adjuntos se cifran en el cliente con STREAM (§8 de la especificación) y su
llave va envuelta con la del elemento. El servidor guarda el ciphertext en
disco (`<data_dir>/attachments/<bóveda>/<adjunto>`).

1. **Crear:** `POST /v1/vaults/{v}/items/{i}/attachments`
   `{ "id", "size", "wrapped_key", "item_version"? }` → `201 Attachment`.
   `item_version` es la versión del elemento cuya llave envolvió
   `wrapped_key`: si no es la actual, `409` con `current_version` (el
   cliente sincroniza y vuelve a empezar). Se comprueba con el candado de la
   bóveda, el mismo que toma una llave nueva del elemento (§4.3), así que un
   adjunto nunca queda envuelto con la llave vieja. Los clientes de Klav
   siempre lo mandan; sin él no se comprueba, como antes. Solo protege ante
   un servidor que conoce el campo: uno anterior responde `400` nombrando
   `item_version` (campo desconocido), y el cliente declara otra vez sin él.
   Eso no abre nada, porque un servidor que se salta la comprobación ya
   podía aceptar la subida igual. `size` es el tamaño
   del ciphertext, como máximo `max_attachment_bytes` (100 MiB). Las subidas
   sin completar de todas las bóvedas del dueño suman como mucho
   `max_pending_upload_bytes` (1 GiB, contando el `size` declarado); pasarse
   da `409`. Una subida sin trozos nuevos durante un día se borra (fila y
   archivo).
2. **Subir por trozos:** `PUT /v1/vaults/{v}/attachments/{a}/content?offset=<n>`
   con el cuerpo en binario → `{ "received", "size" }`. Cada trozo mide como
   máximo `max_attachment_chunk_bytes` (8 MiB). `offset` debe ser igual a lo
   ya recibido; si no, `409` (para reanudar, consulta `received` con
   `GET /v1/vaults/{v}/attachments/{a}`). Pasarse de `size` da `400`. El
   primer trozo debe empezar con el encabezado de adjunto (`0x01 0x30`).
3. **Completar:** `POST /v1/vaults/{v}/attachments/{a}/complete` →
   `Attachment`. Exige que haya llegado todo (`409` si no) y asigna la
   revisión: hasta entonces el adjunto no aparece en la sincronización.
4. **Bajar:** `GET /v1/vaults/{v}/attachments/{a}/content` →
   `application/octet-stream`. Acepta `Range`, así que una descarga cortada
   se puede reanudar.
5. **Borrar:** `DELETE /v1/vaults/{v}/attachments/{a}` → `204`. Deja un
   *tombstone* (`deleted_at`) en la sincronización y borra el archivo. Si en
   ese momento se está escribiendo un trozo, `409` (reintenta).

No se pueden añadir adjuntos a un elemento en la papelera (`409`). En una
bóveda borrada no se crean, suben ni completan adjuntos (`404`).

## 7. Límites

| Límite | Por defecto | Error |
|---|---|---|
| Cuerpo JSON | 4 MiB | 413 |
| `meta` de bóveda o proyecto | 64 KiB | 400 |
| `overview` | 64 KiB | 400 |
| `details` | 1 MiB | 400 |
| Versiones guardadas por elemento | 50 | se descartan las más viejas |
| Adjunto | 100 MiB | 400 |
| Trozo de subida | 8 MiB | 413 |
| Subidas sin completar por cuenta | 1 GiB | 409 |
| Adjuntos de la cuenta (`max_account_attachment_bytes`, `KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES`) | 10 GiB | 403 `quota_exceeded` |
| Datos de la bóveda de la cuenta (`max_account_vault_bytes`, `KLAV_MAX_ACCOUNT_VAULT_BYTES`) | 1 GiB | 403 `quota_exceeded` |
| Elementos de la cuenta (`max_items_per_account`, `KLAV_MAX_ITEMS_PER_ACCOUNT`) | 100 000 | 403 `quota_exceeded` |
| Bóvedas de la cuenta (`max_vaults_per_account`, `KLAV_MAX_VAULTS_PER_ACCOUNT`) | 1 000 | 403 `quota_exceeded` |
| Peticiones por IP | 600/min, ráfaga 120 | 429 |
| Autenticación por IP | 30/min, ráfaga 10 | 429 |
| Autenticación por correo e IP | 10/min, ráfaga 5 | 429 |
| Peticiones por cuenta | 1200/min, ráfaga 300 | 429 |
| Invitaciones por IP (`invite/check` y fallos de invitación, §2.2) | 1/min, ráfaga 10 | 429 |
| Reautenticaciones para borrar la cuenta (`account/delete/start`) | 5 por cuenta y hora | 429 |
| Borrados de la cuenta pedidos | 3 por cuenta cada 7 días | 429 |

**Cuotas por cuenta** (ADR [0048](decisiones/0048-invite-beta-and-distribution.md)
§3). Cuentan todo lo de las bóvedas de las que la cuenta es dueña (paga la
dueña), y `0` es sin límite:

- **Adjuntos:** el tamaño declarado de cada adjunto no purgado: terminados,
  pendientes y los de elementos en la papelera. Se comprueba al declararlo
  (`POST …/attachments`); su tamaño queda fijo ahí. Una cuota distinta de `0`
  tiene que ser al menos `max_attachment_bytes`.
- **Datos de la bóveda:** `overview`, `details` y `wrapped_key` de cada
  elemento no purgado **y de sus versiones guardadas**, más el `meta` de cada
  bóveda y proyecto. Una versión nueva cuenta lo que de verdad añade: su
  tamaño, menos las versiones viejas que descarta (la anterior pasa a la
  historia y sigue contando).
- **Elementos:** los no purgados (la papelera cuenta).
- **Bóvedas:** las de la cuenta, también las borradas hasta que se purgan.

Cada escritura que suma a una cuenta comprueba su cuota dentro de su
transacción, bajo el candado de la cuenta dueña, así que dos escrituras a la
vez no caben las dos en el último hueco: crear una bóveda toma ese candado, y
también crear o cambiar un proyecto o el `meta` de una bóveda. Nunca se
rechaza una escritura que no hace crecer la cuenta, ni borrar, ni mover a la
papelera, ni leer: una cuenta por encima de una cuota que se bajó después lo
conserva todo y puede limpiar.

Todos se pueden cambiar en la configuración (ver
[`self-hosting.md`](self-hosting.md) §2), salvo los dos del borrado de la
cuenta (§2.4), que son fijos. Los límites por IP agrupan IPv6 por
`/64` y, detrás de un proxy, usan la cabecera de IP que se configure
(`self-hosting.md` §3.2).

## 8. Agentes

Un agente tiene su propia identidad y nunca conoce la contraseña ni el Secret
Key de la persona (diseño §5, ADR [0014](decisiones/0014-agentes-fase-4.md)).
Los formatos firmados están en la especificación §13.

### 8.1 Registro y aprobación

| Método y ruta | Quién | Cuerpo | Respuesta |
|---|---|---|---|
| `POST /v1/agents/register` | el agente, sin sesión | `{ id, email, name, public_identity, note? }` | `202 { id, status: "pending", expires_at }` |
| `GET /v1/agents` | la persona | — | `{ agents: [AgentInfo] }` |
| `GET /v1/agents/{id}` | la persona | — | `AgentInfo` |
| `POST /v1/agents/{id}/grant` | la persona | `SignedGrant { payload, signature }` | `AgentInfo` (estado `active`) |
| `POST /v1/agents/{id}/deny` | la persona | — | `204` |
| `POST /v1/agents/{id}/revoke` | la persona | `{ revoked_at, signature }` | `AgentInfo` (estado `revoked`) |
| `POST /v1/agents/pause` | la persona | `{ state, at, until?, signature }` | `{ pauses: [AgentPause] }` |
| `POST /v1/agents/{id}/pause` | la persona | `{ state, at, until?, signature }` | `{ pauses: [AgentPause] }` |

- **El registro no revela cuentas.** Responde siempre `202` con la misma
  forma, exista o no el correo. Con un correo desconocido no se guarda nada.
  - Un `id` repetido devuelve `409`, sea cual sea el correo.
  - Hay como máximo 20 solicitudes pendientes por cuenta; las demás se
    descartan en silencio (el tope se cuenta e inserta en un solo paso).
  - `name` (1 a 64 caracteres) y `note` (hasta 500) no admiten caracteres de
    control, de formato (bidi, ancho cero) ni separadores de línea o párrafo
    (`400`). `name` tampoco puede ser `you`, en mayúsculas o minúsculas, que
    es como la bitácora llama a la persona (`400`, ADR 0033 §8.1); un agente
    registrado antes con ese nombre lo conserva.
  - Una solicitud pendiente caduca a la hora y pasa a `denied`.
  - Con el borrado de la cuenta pedido (§2.4), la solicitud se descarta en
    silencio, como un correo desconocido: `202`, nada guardado y sin aviso.
  - Usa el *rate limit* de autenticación por IP.
- `AgentInfo`:
  - `id`, `name`, `note?`, `public_identity` (tipo `0x05`) y `status`
    (`pending` · `active` · `denied` · `revoked`);
  - las fechas `created_at`, `expires_at`, `approved_at?`, `revoked_at?` y
    `last_seen_at?` (precisión de un minuto);
  - el `grant?` vigente;
  - `paused?`: `{ scope, since, until? }` si una pausa lo detiene ahora (la
    suya o la de todos; con las dos, la que dura más).
- **Grant** (especificación §13.4). El servidor comprueba:
  - la firma con la identidad de la cuenta;
  - que `version` sea la actual + 1 (si no, `409` con `current_version`);
  - que los proyectos existan, sean de bóvedas de las que la cuenta es
    miembro y traigan una `shared_key` de tipo `0x21`;
  - que la política nombre bóvedas y proyectos solo por ID (`400` si no);
  - que el payload sea `v: 1`, o `v: 2` con sus reglas (especificación
    §13.4, `400` si no): un grant por elemento lleva `items` y ningún
    proyecto; cada elemento existe, no está en la papelera, está en el
    proyecto y la bóveda que dice, de las que la cuenta es miembro, y trae
    una `shared_key` de tipo `0x23`; los perfiles y las reglas de `proxy`
    solo nombran elementos del grant; y con `proxy`, `reveal`, `inject` y
    `fill` siempre en `deny`. Un `v` desconocido da `400`.

  Guarda el payload byte por byte. Un agente `denied` o `revoked` no puede
  recibir grants (`409`): tiene que registrarse otra vez.
- **Revocación** (especificación §13.6): la firma de la cuenta sobre
  `revoked_at`, que no puede alejarse más de 5 minutos del reloj del
  servidor. Solo se revocan agentes `active` (`409` si no; un registro
  pendiente se deniega). Desde ese momento:
  - toda petición firmada del agente recibe `403`, salvo `GET /v1/agent/me`,
    que le dice que fue revocado;
  - sus solicitudes pendientes pasan a `denied`;
  - queda el evento `agent.revoked` con la firma.
- **Pausa** ([ADR 0033](decisiones/0033-agentes-desde-la-app-de-mac.md) §7,
  especificación §13.9): detiene a todos los agentes (`/v1/agents/pause`) o
  a uno (`/v1/agents/{id}/pause`) sin tocar su grant, sus llaves, sus
  solicitudes ni sus tareas. Una sola ruta por alcance: `state` es `pause`
  o `resume`.
  - `at` es la hora de la decisión (milisegundos Unix) y `until` el fin de
    la pausa (`0` o ausente: hasta que la persona reanude). La firma de la
    cuenta cubre el alcance, el estado, `at` y `until`.
  - El servidor exige que `at` esté a ±5 minutos de su reloj, que una
    reanudación no traiga `until`, que el `until` de una pausa sea
    posterior a `at` y a ahora (`400` si no), y que `at` sea **mayor** que
    el de la última decisión del mismo alcance (`409` si no): una
    reanudación vieja no se puede repetir. Ese `409` trae `last_at`, el
    `at` de esa última decisión: el dispositivo que pausó mientras otro,
    con el reloj adelantado, decidía después, vuelve a firmar la pausa en
    `last_at + 1` si cae dentro de los ±5 minutos (nunca una reanudación:
    fechada después de la pausa de otro, la levantaría).
  - Un servidor anterior a las pausas no tiene estas rutas: responde `405`
    a la de todos (la lee como `/v1/agents/{id}` con el ID `pause`, que
    solo tiene `GET`) y `404` a la de uno. El cliente lo dice: «this
    server does not support pausing agents: update it».
  - Se pausan agentes `pending` o `active`; uno `denied` o `revoked` da
    `409`.
  - Reanudar un alcance que no estaba en pausa se acepta (mueve su reloj y
    queda en la bitácora). Reanudar a todos no levanta las pausas de un
    agente.
  - Guarda la última decisión de cada alcance y escribe el evento
    `agents.paused` o `agents.resumed` en la misma transacción, con el
    cerrojo de la cuenta. Responde con las pausas en vigor de la cuenta
    (`AgentPause`: `agent_id?` (ninguno: todos), `at`, `until`, `signature`),
    las mismas que da `GET /v1/sync`.
  - Mientras dure, toda petición firmada del agente recibe `403`
    `agents_paused`, salvo `GET /v1/agent/me`, que dice desde cuándo y hasta
    cuándo. El servidor vuelve a mirarla con el cerrojo de la cuenta al
    escribir el evento de un uso permitido: una petición en vuelo cuando
    llega la pausa también recibe `403`, y si gastaba una aprobación de un
    solo uso, la aprobación vuelve a quedar sin usar. Si la pausa llega
    después del evento y antes de la escritura que lo sigue (§8.2), la
    escritura recibe el `403` y no se hace, pero el evento ya está en la
    bitácora y la aprobación queda gastada. El cierre de un cambio de
    contraseña es la excepción: se escribe igual (§8.2).
  - Una pausa con `until` termina sola, sin otra firma.

### 8.2 Peticiones del agente

Toda ruta bajo `/v1/agent/` exige estas cabeceras (especificación §13.3):

| Cabecera | Valor |
|---|---|
| `Klav-Agent` | ID del agente |
| `Klav-Timestamp` | hora del agente, milisegundos Unix |
| `Klav-Nonce` | 16 bytes aleatorios, base64url |
| `Klav-Signature` | firma Ed25519, base64url |

El servidor responde `401` en estos casos:

- la firma no verifica;
- la hora se aleja más de 5 minutos;
- el nonce se repite (el servidor los recuerda 10 minutos y 1 segundo, más
  que la ventana de la hora);
- el agente no existe.

La ruta firmada es la que envió el cliente: un proxy inverso no debe
reescribirla ([`self-hosting.md`](self-hosting.md) §3). Cada agente tiene su
propio *rate limit*, con los valores del límite por cuenta. Se aplica después
de guardar el nonce: una petición firmada que recibe `429` ya gastó su nonce
y no se puede repetir más tarde.

| Método y ruta | Respuesta |
|---|---|
| `GET /v1/agent/me` | `{ id, name, status, lapsed?, account_id, account_public_identity, grant?, paused?, account_delete_at?, gone_issuers? }` |

Un agente pendiente, denegado o revocado solo puede consultar `me`, para
saber en qué estado está. Una solicitud pendiente que caducó sale como
`denied` con `lapsed: true`: nadie la aprobó ni la denegó, y el agente
puede pedir otra (ADR 0033 E2.2). El campo solo aparece cuando es `true`;
un servidor anterior no lo manda. El resto de rutas responde `403` si el agente no
está `active`: la revocación tiene efecto en la petición siguiente. Una
petición que ya pasó esa comprobación y llega a registrar su evento después
de la revocación también recibe `403` `forbidden`: el servidor vuelve a
mirar el estado del agente con el cerrojo de la cuenta al registrar el
evento (con cualquier resultado: permitido, denegado o `ask`), el mismo
cerrojo que toma la revocación, así que la bitácora no muestra ninguna
petición del agente detrás de `agent.revoked`, y lo que la ruta escribe en
la transacción del evento se deshace con él. Si la petición gastaba una
aprobación de un solo uso, la aprobación vuelve a quedar sin usar, como en
una pausa (§8.1), y lo mismo si la persona pidió borrar la cuenta mientras
la petición esperaba (`403` `account_deleting`). Una consulta previa
(`POST /v1/agent/approvals`) solo mira la aprobación, sin gastarla, así que
no devuelve ninguna. Crear, editar o mandar a la
papelera un elemento, y empezar o cerrar un cambio de contraseña, escriben
después de registrar su evento y fuera de su transacción; esa escritura
vuelve a tomar el cerrojo de la cuenta y a mirar el estado del agente, así
que si la revocación llega entre el evento y la escritura, la escritura
recibe el mismo `403` `forbidden` y no se hace. Las escrituras de un
elemento y el inicio de un cambio de contraseña miran además, en el mismo
orden que al registrar el evento, el borrado pedido y la pausa: si llegan
entre el evento y la escritura, la escritura recibe `403`
`account_deleting` o `agents_paused` y no se hace. En los dos casos, el
evento `allow` sí queda, sin su escritura (antes de `agent.revoked` si fue
una revocación), como ya puede quedar el de una escritura que después
recibe `409`, y la aprobación de un solo uso que gastó queda gastada: el
evento la nombra.

El cierre de un cambio de contraseña (`rotate_confirm`, `rotate_cancel`)
no se detiene por una pausa ni por un borrado pedido que lleguen entre el
evento y la escritura: el evento está en la bitácora y, con un cliente
anterior, `klavd` ya aplicó el paso en el elemento antes de mandarlo aquí,
así que el servidor cierra el cambio. Un cliente actual manda el paso aquí
primero y a `klavd` solo después (§8.6). Solo la revocación lo detiene.
Entonces el evento queda y el cambio sigue `started`. Con un cliente
actual, la contraseña sigue pendiente en el elemento y la persona lo cierra
desde su ficha. Con uno anterior ya no hay nada pendiente en él, así que la
persona no puede cerrarlo; como la revocación terminó las tareas del
agente, el servidor lo marca `abandoned` en el siguiente inicio de un
cambio de ese elemento.

Un agente `active` en pausa recibe `403` `agents_paused` en todas las
rutas salvo `me`, también al cerrar un cambio de contraseña (§8.1), y `me` trae
`paused: { scope, since, until? }`. Si la persona pidió borrar la cuenta,
todos sus agentes reciben `403` `account_deleting` con `delete_at` (§2.4),
antes que la pausa, y `me` trae `account_delete_at`. Cuando la cuenta ya se
borró, el agente recibe `401`, como uno que el servidor no conoce.

### 8.3 Uso de la bóveda por un agente

El servidor evalúa la política firmada del grant en cada ruta (ADR
[0014](decisiones/0014-agentes-fase-4.md) §4). No puede leer etiquetas ni
URLs, así que el agente declara las del elemento en `claims`
(`{ tags, domain?, method?, path? }`). Su runtime vuelve a evaluar la política con los datos
descifrados. Toda acción exige un `reason` no vacío, de 500 caracteres como
máximo y sin caracteres de control, de formato (bidi, ancho cero) ni
separadores de línea o párrafo. Los `claims` también se acotan (`400`):

- `domain` es un nombre de host tal como lo compara la política: en
  minúsculas, sin esquema, puerto ni punto final (`github.com`, no
  `GitHub.com.` ni `https://github.com`);
- `tags`: como mucho 64, cada una no vacía, de hasta 128 caracteres y sin
  esos caracteres;
- `method` y `path`, solo con `proxy`: en cualquier otro permiso y en
  cualquier ruta de agente (`access`, crear, editar, papelera, aprobaciones,
  cambios de contraseña) dan `400` antes de evaluar, guardar o registrar
  nada. El método son de 1 a 16 letras `A`–`Z`. La ruta es la de la petición
  que arma el proxy, sin consulta, escrita de **una sola manera**
  (especificación §13.4): ASCII visible tal cual, solo `%20`, `%3F` y `%23`
  escapados (hexadecimal mayúscula), sin `;`, `\`, segmentos vacíos, `.` ni
  `..`, hasta 2048 bytes. Cualquier otra forma da `400`: no se normaliza.
  Un cliente que escapa él mismo caracteres reservados dentro de un segmento
  (`%2C`, `%3A`, `%40`, `%2F` dentro de un ID, como `PathEscape` de Go o
  `encodeURIComponent` de JavaScript) queda rechazado a propósito.
  Además, el servidor rechaza con `400` una ruta con `"`, aunque la
  especificación la dé por canónica: la clave de la aprobación es JSON, donde
  cada `"` ocupa dos bytes, y en Postgres una ruta larga llena de ellas pasaba
  del límite del índice de aprobaciones (2704 bytes) y daba `500`. Los
  prefijos firmados no cambian: un prefijo con `"` sigue siendo válido, pero
  ninguna llamada bajo él pasa.

**`proxy`** ([ADR 0036](decisiones/0036-sandboxes-de-agentes.md) §2): el
proxy de credenciales pide un elemento por cada petición que inyecta, con
`claims.domain`, `claims.method` y `claims.path` obligatorios (`400` sin
ellos) y sin `include_attachments` (`400`). Solo llega a los elementos de su
grant por elemento, en el proyecto y la bóveda que el grant dice (`404` para
cualquier otro, también si el elemento se movió o está en la papelera); esos
elementos no se listan en `GET /v1/agent/items` ni se alcanzan con otro
permiso (`404`). La política decide con el elemento, el host, el método y la
ruta: una regla de `proxy` solo cubre los elementos que nombra, y
`CONNECT` y `TRACE` se deniegan siempre. Las rutas se comparan byte a byte,
distinguiendo mayúsculas; un `deny` bajo un `allow` amplio vale lo que valga
el enrutado del proveedor. Una aprobación de `proxy` vale para el mismo
método y la misma ruta, además del elemento y el host. El evento
`agent.access` lleva `method` y `path`, sin redactar: un token dentro de la
ruta quedaría en la bitácora, así que un perfil para una API que pone
credenciales en la ruta no está soportado.

Los elementos de una bóveda borrada no existen para el agente (no se listan,
`404` al usarlos) hasta que la persona la restaure. Una política vencida
deniega todo, también `passkey` y `rotate` dentro de una tarea.

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `GET /v1/agent/items` | — | `{ grant_version, projects: [ { vault_id, project_id, project_version, project_meta, items: [Item sin details], attachments?: [Attachment] } ] }` |
| `POST /v1/agent/access` | `{ item_id, permission, reason, claims?, approval_id?, task_id?, include_attachments?, sandbox? }` | `200 { item, attachments?, approval_id?, person_version?, sole_author? }` con `details` · `202` pendiente |
| `POST /v1/agent/items` | `{ vault_id, item: CreateItem, reason, claims?, approval_id?, task_id? }` | `201 Item` con `approval_id?` · `202` |
| `PUT /v1/agent/items/{id}` | `{ item: UpdateItem, reason, claims?, approval_id?, task_id? }` | `200 Item` con `approval_id?` · `202` · `409` versión vieja o `project_version` vieja |
| `POST /v1/agent/items/{id}/trash` | `{ reason, claims?, approval_id?, task_id? }` | `200 { approval_id? }` · `202` |
| `POST /v1/agent/approvals` | `{ permission, vault_id, project_id, item_id?, reason, claims?, task_id? }` | `200 { approval_id?, task_id? }` · `202` pendiente · `403` |
| `GET /v1/agent/approvals/{id}?wait=N` | — | `ApprovalInfo` (con `wait`, *long-poll*) |

- **`person_version`** (ADR [0030](decisiones/0030-ronda-de-seguridad-2026-11.md) §7): si un agente escribió la versión actual
  (`item.author_agent_id`), `access` manda también `{ version, wrapped_key,
  overview }` de la última versión que escribió la persona. El runtime la
  abre con su llave de proyecto (la versión va en el AAD) y solo rellena en
  los hosts de esas URLs: un host que añadió un agente queda fuera hasta que
  la persona lo confirma. Sin `person_version` (lo creó un agente), ningún
  host está confirmado.
- **`sole_author`** (ADR 0030 §7, excepción del alta de ADR 0022 §7):
  `true` si el agente que pide escribió la versión actual y todas las
  guardadas, la persona ninguna, y no falta ninguna del historial. Solo
  entonces su runtime rellena en los hosts de las URLs del elemento que
  creó. Si falta, vale `false`.
- **`items`** solo lista los proyectos del grant cuyo `list` sale `allow`
  para alguna combinación de etiquetas (`evaluate_upper_bound`). Nunca
  incluye `details`: los secretos solo llegan por `access`, de uno en uno.
  Cada proyecto trae su versión actual (`project_version`) y sus metadatos
  sellados con su llave actual (`project_meta`, tipo `0x13`), para que el
  runtime sepa si su llave es la vigente (§4.4).
- **`access`** acepta `list` (solo metadatos: la respuesta no trae
  `details`), `fill`, `inject`, `totp`, `reveal` y `update` (para leer el
  elemento antes de escribir la versión siguiente). Las escrituras usan sus
  propias rutas con `create`, `update` y `delete`.
- **Adjuntos** (ADR [0016](decisiones/0016-adjuntos-para-agentes.md)): con
  `inject` e `include_attachments: true`, un `200` trae también
  `attachments: [{ attachment, content }]`, todos los adjuntos completados
  del elemento con su llave envuelta y su *ciphertext* en base64. Es la
  misma decisión que la del elemento. Con otro permiso, `400`; más de
  16 MiB en total, `400`. El evento `agent.access` lista en `attachments`
  los que entregó.
- **Respuestas de la política:**
  - `deny`: `403` con el motivo, por ejemplo "the policy denies `reveal` here".
  - Un elemento o proyecto fuera del grant: `404`.
  - `ask`: `202 { pending_approval_id, expires_at }`. El agente repite la
    petición cuando la persona decide, con `approval_id` o sin él (§8.4).
- **Mismo destino** (ADR [0015](decisiones/0015-aprobaciones-reutilizables-y-espera.md)):
  mismo agente y versión del grant, mismo permiso, bóveda, proyecto y
  elemento, y mismo `claims.domain`; para `proxy`, también el método y la
  ruta (sin la consulta), y el `sandbox` cuando la petición lo nombra
  (§8.8): la aprobación de un sandbox no sirve a otro ni a una llamada sin
  sandbox. El motivo y las etiquetas no cuentan.
- **Con `ask` y sin `approval_id`**, el servidor prueba en este orden:
  1. una tarea vigente que cubre la acción (§8.5): pasa;
  1. un arrendamiento vigente con el mismo destino: pasa;
  1. una aprobación de un solo uso sin gastar, con el mismo destino y
     decidida hace menos de 10 minutos: la gasta y pasa. Nunca una ligada a
     una tarea por «Añadir a la tarea» (§8.4): esa solo pasa nombrada;
  1. la solicitud pendiente con el mismo destino: devuelve **su** ID (`202`),
     sin crear otra;
  1. si no hay nada, crea una solicitud nueva.

  Dos peticiones simultáneas con el mismo destino reciben la misma
  solicitud, y una aprobación de un solo uso deja pasar solo a una.
- **Un `approval_id`** sirve si:
  - es de ese agente (si no, `404`);
  - el grant no cambió desde entonces (`409`);
  - es para el mismo destino (`400`);
  - está aprobado (`409` si sigue pendiente o venció; `403` si la persona lo
    denegó);
  - no ha vencido su arrendamiento, o era de un solo uso, no se ha usado y
    se decidió hace menos de 10 minutos (`409`).
- Cada agente puede tener como máximo 10 solicitudes pendientes; las demás
  reciben `429`. Un reintento que reutiliza su pendiente no cuenta.
- La bitácora registra cada petición: `ask` con el ID de la solicitud
  (nueva o reutilizada) y `allow` con el ID de la aprobación que la dejó
  pasar.
- **`approval_id` en la respuesta** (ADR [0030](decisiones/0030-ronda-de-seguridad-2026-11.md) §3):
  `200`/`201` de `access`, de crear, editar y mandar a la papelera llevan
  `approval_id` cuando una aprobación dejó pasar la petición (la nombrada o
  una reutilizada). El runtime del agente, si su política local dice `ask`,
  pide esa aprobación y verifica la firma de la cuenta antes de usar la
  respuesta; sin aprobación válida ni tarea verificada que cubra la acción,
  la trata como un fallo de seguridad. La papelera de agentes responde
  `200 {}` (antes `204`).
- **`POST /v1/agent/approvals`, preguntar antes de escribir** (ADR [0030](decisiones/0030-ronda-de-seguridad-2026-11.md) §3, riesgo residual 35):
  el runtime pide así la aprobación de una escritura **antes** de mandar su
  cuerpo, cuando su política local dice `ask` y ninguna tarea que verificó
  la cubre. Solo acepta `create` (sin `item_id`), `update` y `delete` (con
  `item_id`, del proyecto indicado); otro permiso, `400`. El servidor hace
  las mismas comprobaciones que la escritura, **sin gastar nada**:
  - `202 { pending_approval_id, expires_at }`: la solicitud de la persona
    (nueva, o la pendiente con el mismo destino);
  - `200 { approval_id }`: un arrendamiento vigente, o una aprobación de un
    solo uso sin gastar, con el mismo destino. No la gasta: la gasta la
    escritura que la nombra;
  - `200 { task_id }`: una tarea vigente que cubre la escritura;
  - `200 {}`: la política del servidor la deja pasar;
  - `403`: la política la niega.

  El runtime verifica la firma de la cuenta y que la aprobación sea para
  esa misma escritura antes de mandar el cuerpo con su `approval_id`. Si el
  servidor dice que no hace falta aprobación (`200 {}`, o una tarea que el
  runtime no puede verificar), no le cree: no manda nada y lo trata como un
  fallo de seguridad. Se registra como `agent.ask` con su cuerpo (como
  `access`, hasta 16 KiB): `ask` con el ID de la solicitud, `allow` si algo
  ya la cubre (sin que eso sea un uso) o `deny`.
- **`GET /v1/agent/approvals/{id}?wait=N`** espera hasta `N` segundos (30
  como máximo) mientras la solicitud siga pendiente. Responde en cuanto la
  persona decide, cuando la solicitud vence (`expired`) o al acabarse `N`.
  Sin `wait`, responde al momento.

- **`passkey` y `rotate`** (ADR [0021](decisiones/0021-solicitudes-de-tarea.md) §5): solo
  pasan dentro de una tarea vigente que los cubre; fuera, `403` con la
  indicación de pedir una tarea (`request_task`). Se usan a través de
  `klavd`, nunca entregando el elemento al agente:
  - **`passkey`** ([ADR 0020](decisiones/0020-passkeys.md) §9, paso 1):
    `claims.domain` es obligatorio (`400` sin él) y es el host de la pestaña
    de la persona, ya en forma normal: en minúsculas, sin esquema, puerto ni
    punto final (`400` si no lo está). El servidor lo registra tal como se
    firmó, porque el verificador de la bitácora lo compara con la firma.
    Si la tarea cubre el elemento con `passkey` en ese host,
    el servidor registra el uso (`agent.access`, con la tarea) **antes** de
    responder `200` con `PasskeyAccess { task_id, item_id, domain }`, sin
    el elemento. El agente entrega esa petición firmada a `klavd`
    (`agent_passkey_arm`, [`klavd.md`](klavd.md) §3), que la vuelve a
    comprobar.
  - **`rotate`**: `access` responde `400`; va por `/v1/agent/rotations`
    (§8.6).

### 8.4 Aprobaciones (la persona)

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `GET /v1/approvals` | — | `{ approvals: [ApprovalInfo] }` (las 100 más recientes) |
| `GET /v1/approvals/{id}` | — | `ApprovalInfo` |
| `POST /v1/approvals/{id}/decide` | `{ approve, lease_until, decided_at, signature, task_id? }` | `ApprovalInfo` |

- **`ApprovalInfo`:**
  - `id`, `agent_id` y `status` (`pending` · `approved` · `denied` · `expired`);
  - `request`: bytes JSON de `ApprovalRequest`, que el servidor construye al
    crear la solicitud;
  - `created_at`, `expires_at` (10 minutos después), `decided_at?`,
    `lease_until?`, `signature?` y `used_at?` (cuándo se gastó una
    aprobación de un solo uso).
- **`ApprovalRequest`:** `{ v, approval_id, agent_id, agent_name, permission,
  vault_id, project_id, item_id?, reason, claims, grant_version, requested_at }`.
- **`task_id`** («Añadir a la tarea», ADR [0021](decisiones/0021-solicitudes-de-tarea.md) §6): la tarea vigente
  del agente que la persona acaba de revisar para cubrir esta petición. No
  va firmado (lo firmado es la revisión de la tarea). El servidor exige que
  sea una aprobación (`approve`) y que esa tarea la cubra (`400` si no), y
  la liga a ella: nunca la reutiliza sin su ID, por su ID solo pasa
  mientras la tarea siga vigente (`409` después), y el evento
  `approval.decided` lleva el `task_id`.
- **La decisión va firmada** por la identidad de la cuenta sobre esos bytes
  exactos (especificación §13.5). El servidor la rechaza (`400`) si:
  - la firma no verifica;
  - `decided_at` se aleja más de 5 minutos;
  - `lease_until` no es `0` ni está entre `decided_at` y 24 horas después;
  - hay arrendamiento en una negativa.
- Si el agente ya no está activo o su grant cambió, la solicitud pasa a
  `expired` (`409`). Un grant nuevo también vence las pendientes.

### 8.5 Solicitudes de tarea

ADR [0021](decisiones/0021-solicitudes-de-tarea.md): el agente pide de una vez los elementos y permisos de un trabajo, la persona aprueba una sola tarjeta y el agente usa ese conjunto de destinos hasta que la tarea vence. Formatos y firmas en la especificación §13.8.

**El agente** (peticiones firmadas, §8.2):

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `POST /v1/agent/tasks` | `TaskRequest` `{ v: 1, task, reason, duration_secs, access: [{ vault_id, project_id, item_id, permissions, domain? }] }` | `202 { pending_task_id, expires_at }` · `400` · `429` |
| `GET /v1/agent/tasks` | — | `{ tasks: [TaskInfo] }` (las suyas, 100 más recientes) |
| `GET /v1/agent/tasks/{id}?wait=N` | — | `TaskInfo` (con `wait`, *long-poll* de hasta 30 s, como §8.3) |
| `POST /v1/agent/tasks/{id}/end` | `{ reason }` | `TaskInfo` · `409` si ya no está pendiente ni vigente |

- El servidor guarda **los bytes exactos del cuerpo** como solicitud (los mismos que firmó el agente) y genera el ID.
- `400` si la solicitud no cumple los límites (1–50 accesos, de 5 min a 24 h, `task` de hasta 120 caracteres, `reason` de hasta 500), si pide `reveal`, `delete`, `list` o `create`, si repite un elemento o si un elemento no está en los proyectos del grant.
- `429` con 5 solicitudes pendientes o 10 tareas vigentes del agente.
- La persona tiene 10 minutos para decidir; después, `expired`.
- Con APNs, cada solicitud nueva avisa a los teléfonos de la cuenta con `type: "task"` y el ID de la tarea, sin título, motivo ni nombre del agente (§3).

**La persona:**

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `GET /v1/tasks` | — | `{ tasks: [TaskInfo] }` (las 100 más recientes) |
| `POST /v1/tasks` | `{ task_id, agent_id, decision, decided_at, signature }` | `201 TaskInfo` (tarea ofrecida) |
| `GET /v1/tasks/{id}` | — | `TaskInfo` |
| `POST /v1/tasks/{id}/decide` | `{ approve, decision, decided_at, signature }` | `TaskInfo` |
| `POST /v1/tasks/{id}/end` | `{ ended_at, signature }` | `TaskInfo` |

- **`TaskInfo`:** `id`, `agent_id`, `agent_name`, `status` (`pending` · `approved` · `denied` · `expired` · `ended`), `request` (bytes de la solicitud), `created_at`, `decide_by`, `decided_at?`, `decision?` y `signature?` (la decisión vigente y su firma), `revision` (0 mientras está pendiente), `expires_at?`, `ended_at?` y `ended_by?` (`person` · `agent` · `expiry` · `revocation`).
- **`decide`** sobre una pendiente: la primera decisión (`revision = 1`) o la negativa. Sobre una vigente: «Añadir a la tarea», que solo acepta la revisión siguiente (`409` si no), con el mismo `expires_at_ms` y sin quitar nada (`400`). El servidor rechaza (`400`) una firma que no verifica, un `decided_at` a más de 5 minutos, una decisión para otra tarea o agente, un elemento que no se pidió, un permiso que no pidió el agente ni añadió Klav, y un vencimiento posterior a lo pedido. `409` si el agente ya no está activo o ya tiene 10 tareas vigentes.
- **`end`** va firmado por la cuenta (`klav/v1/sig/task-end`) y solo termina una tarea vigente.
- **`POST /v1/tasks`** crea una **tarea ofrecida** (ADR 0022 §6): la persona la propone sin que el agente la pida, por ejemplo «arreglar mis contraseñas repetidas».
  - El cliente genera `task_id` y firma la decisión con la solicitud vacía. La decisión lleva `offer: { task, reason }`, con el título y el motivo de la persona, y dura hasta 24 h (especificación §13.8).
  - El servidor la guarda ya aprobada, con `request` vacío, y registra `task.decided` (`approve`) con la firma y `task_request` vacío. El agente la ve en `GET /v1/agent/tasks` (MCP `list_tasks`), con `offered: true` y el motivo de la persona.
  - `400` por una firma que no verifica, un `decided_at` a más de 5 minutos, una decisión sin `offer`, de otra tarea o de otro agente, o un elemento que no está vivo en los proyectos del grant.
  - `404` si el agente no es de la cuenta. `409` si el agente no está activo o no tiene grant, si ya tiene 10 tareas vigentes o si el `task_id` ya existe.
  - «Añadir a la tarea» funciona igual que en las demás tareas, y cada revisión conserva el mismo `offer`.
- **`rotate`** exige al menos un host aprobado en el elemento (`400` si no; T99).
- Al aprobar, el servidor guarda una fila por `(elemento, permiso)` en `task_targets`, con el destino del ADR 0015 sin dominio ni versión del grant y la lista de hosts aprobados.

**En cada uso** (§8.3), una tarea cubre la acción si está aprobada, antes de `expires_at`, sin terminar, con el agente vigente, y su decisión firmada incluye el elemento y el permiso; para `fill`, `passkey` y `rotate`, además, el `claims.domain` es uno de los hosts aprobados o un subdominio. Sin hosts aprobados, la tarea no cubre esos permisos (ADR 0030 §6), y el servidor rechaza al decidir una tarea que los lleve con la lista vacía (`400`). Las peticiones aceptan `task_id`: con él, solo cuenta esa tarea. La tarea **no** amplía la política: con `deny` sigue siendo `deny`, y cada uso evalúa el grant actual. Un grant nuevo no termina las tareas; la revocación sí, y deniega las pendientes. Una tarea vencida pasa a `ended` (`expiry`) la primera vez que el servidor la ve, en una consulta o en la limpieza periódica.

### 8.6 Cambio asistido de contraseñas

ADR [0022](decisiones/0022-generador-historial-y-cambio-asistido.md) §5. Esta es la mitad del servidor. `klavd` genera la contraseña nueva, la guarda como pendiente en el registro sellado del elemento y rellena el formulario: por estas rutas no pasa ningún valor. Cada paso es una petición firmada del agente (§8.2) que pasa por la misma evaluación que un uso (§8.3) con el permiso `rotate`.

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `POST /v1/agent/rotations` | `{ item_id, reason, claims: { domain }, task_id? }` | `201 { rotation: RotationInfo, task: TaskInfo }` |
| `POST /v1/agent/rotations/{id}/confirm` | `{ item_id, reason }` | `RotationInfo` |
| `POST /v1/agent/rotations/{id}/cancel` | `{ item_id, reason }` | `RotationInfo` |
| `POST /v1/rotations/{id}/confirm` | — (sesión de la persona) | `RotationInfo` |
| `POST /v1/rotations/{id}/cancel` | — (sesión de la persona) | `RotationInfo` |

- **`RotationInfo`:** `id` (el `pending_id` del agente), `task_id`, `vault_id`, `project_id`, `item_id`, `host`, `status` (`started` · `confirmed` · `cancelled` · `abandoned`), `started_at` y `finished_at?`.
- **Empezar** (`rotate_password`):
  - `claims.domain` es obligatorio (`400`): es el host de la página de cambio.
  - Hace falta una tarea vigente que cubra `rotate` en ese elemento y ese host. Si no la hay, `403` y un evento `deny`; nunca pasa a `ask`. El permiso no existe fuera de una tarea, y `access` responde `400` a `rotate`.
  - Solo un cambio por elemento a la vez (`409`, con el ID del que está en curso).
  - La respuesta incluye la tarea con su decisión firmada, para que `klavd` la verifique antes de rellenar.
- **Confirmar o cancelar** (`rotate_confirm` y `rotate_cancel`):
  - Solo el agente que empezó el cambio puede cerrarlo (`404` para los demás). El `item_id` debe ser el del cambio (`400`).
  - Se vuelve a comprobar la misma tarea con el host guardado: si terminó o venció, `403` y un evento `deny`.
  - Un cambio ya cerrado responde `409`.
- **La persona cierra el cambio** (`/v1/rotations/{id}/confirm` o `/cancel`, con su sesión): su `klavd` lo manda cuando ella decide en la tarjeta «Cambio pendiente» («Usar la nueva» confirma, «Mantener la actual» cancela). Solo en un cambio `started` de su cuenta (`404` si no es suyo, `409` si ya está cerrado). Deja `rotate.confirmed` o `rotate.cancelled` con `actor: person`, su `device_id`, el agente, la tarea, el elemento y el host; sin `permission` ni petición firmada. Después, el cierre del agente responde `409` y no deja evento.
- **Un cambio que se queda en `started`** cuando su tarea termina pasa a `abandoned` la próxima vez que empieza un cambio de ese elemento. La contraseña pendiente sigue en el elemento y la resuelve la persona en su ficha (T100).
- **En la bitácora** (§9): `rotate.started`, `rotate.confirmed` y `rotate.cancelled`. Los del agente llevan `permission: rotate`, el `item_id`, el host en `domain`, el `task_id` y la petición firmada. Los de la persona (su cierre desde la tarjeta) llevan su `device_id`, el agente, el `item_id`, el host y el `task_id`, sin `permission` ni petición. Nunca llevan valores.
- **Del lado de `klavd`** ([`klavd.md`](klavd.md) §3, «Cambio asistido de contraseña»): el agente le da la misma petición firmada (`AgentRequestProof`) con `agent_rotate_begin`, `agent_rotate_confirm` o `agent_rotate_cancel`. `klavd` la verifica por su cuenta, junto con la decisión de la tarea, antes de tocar el elemento o la página.
  - **Empezar:** primero el servidor y después `klavd` (en el SDK, `Agent::call_proved` devuelve la respuesta y la prueba): `klavd` rellena con la tarea que devolvió el servidor.
  - **Confirmar o cancelar:** tres llamadas.
    1. El agente le pregunta a `klavd` si la contraseña pendiente del elemento es la de este cambio (`agent_rotate_pending`, solo lectura), con una petición firmada propia para `POST /v1/agent/rotations/{id}/pending`, una ruta que este servidor no tiene. Si no lo es (la persona ya decidió desde la ficha, un cliente anterior ya lo aplicó, o `klavd` nunca la guardó), no se manda nada al servidor. La excepción es el `cancel` que el propio runtime manda cuando `klavd` no rellenó: el servidor lo cierra igual.
    2. El servidor registra el paso (en el SDK, `Agent::sign_post` y `Agent::send_proved`). Si lo rechaza (pausa, revocación, borrado pedido, firma vieja), en el elemento no cambia nada: la ficha y un reintento siguen sirviendo. Su `409` «already confirmed» (o «cancelled») para el mismo paso quiere decir que una llamada anterior ya lo registró: el agente sigue al paso 3. Un `409` con el otro resultado detiene todo, sin tocar el elemento.
    3. `klavd` aplica el paso con la misma petición firmada. Si falla (bloqueado, detenido) o su respuesta se pierde, el elemento y la bitácora pueden no coincidir hasta que se aplique: el agente lo dice, y lo termina reintentando el mismo paso (que responde «no pendiente» si `klavd` ya lo había aplicado) o la persona desde la ficha. Mientras el elemento tenga la pendiente de un cambio de la tarea, `klavd` rechaza empezar otro en él con la misma tarea, y el runtime cancela el nuevo en el acto: la bitácora muestra un par `rotate.started` y `rotate.cancelled` de ese cambio rechazado, que nunca tocó el elemento.
    - Un SDK anterior manda primero a `klavd` y después aquí; `klavd` acepta los dos órdenes. Si la persona decide en la ficha lo contrario de lo que el agente ya registró, `klavd` responde con un aviso (la bitácora dice una cosa y el elemento otra, y la otra contraseña está en el historial).
- **Del lado del agente:** las herramientas MCP `change_password_url`, `rotate_password`, `rotate_confirm` y `rotate_cancel`, y en Rust `klav_sdk::rotate`, hacen las llamadas de cada etapa ([`cli.md`](cli.md), `klav mcp`). Si `klavd` no rellena y no se pidió `submit`, o se pidió pero `klavd` no guardó la pendiente, el runtime cancela en el acto el cambio que acaba de empezar, para no dejar el elemento ocupado con un `409`, y el error dice hasta dónde llegó esa cancelación: hecha, registrada sin respuesta de `klavd`, innecesaria porque el servidor ya tenía el cambio cerrado (un `409` con el otro resultado), quizá no llegó (sin respuesta del servidor), o rechazada. Si no llegó y `klavd` no tiene pendiente, el cambio sigue `started` hasta que la tarea termine (`end_task` libera el elemento, pero termina también los otros sitios de la tarea, y seguir con ellos pide una tarea nueva a la persona).

### 8.7 Proxy de credenciales (`klav-proxy`)

`klav-proxy` (ADR [0036](decisiones/0036-sandboxes-de-agentes.md), capa 3) es un agente con un grant por elemento (especificación §13.4) que pone la credencial de un perfil en cada petición sin devolverla a quien llama, y la redacta si el proveedor la repite (la redacción es una red para ecos accidentales, no una barrera: modelo de amenazas, T149). Su interfaz no es la de este servidor: escucha solo en `127.0.0.1` (puerto 8790 por defecto) y la usan las herramientas de la misma máquina. Cómo emparejarlo y servirlo: [self-hosting.md](self-hosting.md) §9.

- **Modo (a), URL base:** `METODO http://127.0.0.1:8790/<perfil>/<ruta>[?consulta]` se manda como `METODO https://<upstream del perfil>/<ruta>[?consulta]`, con la credencial en la cabecera del perfil (`prefix` + valor). La consulta va tal cual, byte a byte, y no entra en la política ni en la aprobación; se rechaza una que nombra el método (`_method`, `x-http-method-override`, `x-http-method`, `x-method-override`, con el nombre decodificado hasta tres veces solo para esta comprobación, también como base de un arreglo, `_method[]`, o como última clave entre corchetes, `a[_method]`, y un nombre que sigue escapado tras tres decodificaciones). Un `_method` en un cuerpo de formulario no se revisa.
- **El valor que se inyecta:** el campo `field` del perfil. Sin `field`, el secreto principal: `password` en un elemento de tipo `login` y `api_key` en uno de tipo `api_key`; en cualquier otro tipo, el perfil tiene que nombrar el campo. Nunca una semilla TOTP ni un campo vacío.
- **Por cada petición**, el proxy hace `POST /v1/agent/access` (§8.3) con `permission: proxy`, el elemento del perfil, el host del `upstream`, el método y la ruta, y no guarda la autorización. Un `ask` deja la aprobación en el servidor (§8.4); el reintento del mismo método, host y ruta usa la decisión.
- **Solo programas de la máquina:** una petición que lleva el `Origin` o el `Sec-Fetch-Site` de un navegador, o cuyo `Host` no es exactamente `127.0.0.1:<puerto>` o `localhost:<puerto>`, recibe `403 klav_not_allowed` antes de todo lo demás. `Sec-Fetch-Mode` solo, que manda el `fetch` de Node, pasa.
- **Con `--no-local-calls`** ([self-hosting.md](self-hosting.md) §9.2, ADR [0042](decisiones/0042-sandboxes-for-daily-use.md) §3), toda llamada de modo (a) al *listener* de `127.0.0.1` recibe `403 klav_not_allowed` antes de todo lo demás, también antes de la comprobación del navegador y del `Host`, y sin preguntar al servidor. La API firmada del emisor (§8.9) y el canal de los sandboxes (§8.10) no cambian.
- **Antes de preguntar al servidor** rechaza, con `403 klav_not_allowed`: un perfil que el grant no tiene, un método que no sea de 1 a 16 letras mayúsculas, `CONNECT`, `TRACE`, una URI absoluta, y una ruta que no esté en su única forma canónica (§13.4) o que lleve `"`, que el servidor rechaza (§8.3). En ese caso, el `message` dice qué escape o carácter rechazó y por qué (`%2C` escapa `,`, que una ruta lleva tal cual), sin repetir el resto de la ruta, y no se registra. El proxy manda exactamente los bytes de ruta que comprobó.
- **Las peticiones** pierden `Authorization`, `Cookie`, `Proxy-Authorization`, la cabecera del perfil, `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, `Host`, las de salto a salto (y las que nombra `Connection`), `Forwarded`, `X-Forwarded` y todas las `X-Forwarded-*`, `X-Original-URL`, `X-Original-URI`, `X-Original-Host`, `X-Host`, `X-Rewrite-URL`, `Via`, las de la IP del cliente (`X-Real-IP`, `Client-IP`, `X-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`, `X-Cluster-Client-IP`), todas las `X-Envoy-*`, `Proxy-*` y `Klav-*`, y llevan `Accept-Encoding: identity`. El cuerpo se lee entero, hasta `--max-body` (10 MiB por defecto), con cada trozo en 10 s y todo dentro del tiempo de espera de la petición (si no, `403 klav_not_allowed`, sin preguntar al servidor), con 16 peticiones a la vez como mucho (la siguiente recibe `429`) y 64 conexiones abiertas.
- **Las respuestas** no siguen redirecciones (un `304` pasa, sin cuerpo), y bloquean un `Content-Encoding` que no sea `identity` y un `Transfer-Encoding` que no sea un solo `chunked` (`chunked, chunked` también se bloquea). Pierden las cabeceras de salto a salto, las `Klav-*` del proveedor y las `Access-Control-*`. El proxy espera como mucho 60 s cada trozo del proveedor y que quien llama tome el anterior; después, o si el proveedor la corta a medias, la respuesta termina en un error: la transferencia queda rota y nunca parece completa. El valor inyectado **entero**, tal cual o en sus codificaciones (base64, hex, URL, JSON), se reemplaza en las cabeceras y en el cuerpo, también cuando llega partido entre dos trozos de la respuesta. Un pedazo del valor no se reemplaza: así la respuesta a «¿esto es un pedazo del token?» es la misma con una adivinanza buena que con una mala. Eso vale para los pedazos: una adivinanza del valor **entero** sí se nota (se reemplaza), así que un valor corto o fácil de adivinar se puede confirmar adivinándolo entero; el proxy es para valores de mucha entropía (modelo de amenazas, T149). El proxy cuenta por perfil los pedazos de 12 caracteres o más que deja pasar; la persona los ve en el registro y en `klav-proxy status` (`redactions` en `--json`). Un sandbox, que llama por el canal y no puede leer el *home* ni el registro del proxy, no lo nota de ninguna forma. Un programa de la misma máquina, con el mismo usuario que el proxy, sí puede leer esas cuentas (el archivo `<home>/agents/<nombre>.redactions`, `klav-proxy status` o el registro) y usarlas como el oráculo que esto le quita a un sandbox.

- **Su memoria** (ADR [0044](decisiones/0044-proxy-key-at-rest.md) §3, con las decisiones de Omar del 2026-11-19): antes de leer o crear su llave, el proxy apaga los volcados de memoria (`RLIMIT_CORE` a `(0, 0)`), en Linux se vuelve no volcable (`PR_SET_DUMPABLE` a 0) y no arranca si falla cualquiera de los dos. Después, solo si el límite de `memlock` no tiene tope o puede quitárselo, bloquea su memoria al tocarla con `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)` (Linux 4.4 o posterior) y lo comprueba leyendo `VmLck`; si no, arranca sin bloquearla y lo avisa, salvo con `--require-memory-lock` o `KLAV_PROXY_REQUIRE_MEMORY_LOCK=1`. Un bloqueo que tomó, no se lee de vuelta y `munlockall` no puede deshacer no impide arrancar: queda `locked: false` con `lock_not_undone: true` y el motivo, y con el requisito no arranca (ADR 0044, decisión 19). Esa forma del campo es la elección propia L21, que Omar aceptó el 2026-11-19 (decisión 28), y con ella, que un registro que dice a la vez `locked: true` y `lock_not_undone: true` se lea como ese estado, con `locked: false`. `--no-memory-lock` o `KLAV_PROXY_MEMORY_LOCK=off` arranca sin intentarlo, y con el requisito no arranca. La cabecera con el valor se construye sobre un búfer que se borra cuando se suelta la última copia (`Bytes::from_owner` y `HeaderValue::from_maybe_shared`, sin la copia de `from_bytes`). `klav-proxy status --json` lo muestra en `memory`: `{core_dumps: "off", dumpable: false|null, locked, lock_turned_off?, vm_lck_kib?, why?, lock_not_undone?, since}`, lo que registró el `klav-proxy serve` que escribió el registro por última vez (`<home>/agents/<nombre>.memory`, 0600, `v: 1`, que un `serve` escribe en cuanto escucha y quita al pararse si sigue siendo el suyo; uno que falla antes de escuchar, o que escucha y no logra escribirlo, deja el de antes), y `memory_error` si no se puede leer; sin `memory` cuando no hay registro. `status` no sabe si ese `serve` sigue corriendo. En Linux, `status` escribe además en stderr una línea sobre la memoria de su propio proceso, nunca de un `serve` (decisión 26; que en macOS no la escriba y que vaya antes de leer el agente o llamar al servidor son las elecciones propias L25 y L26 de la capa, que Omar aceptó el mismo día, decisión 30); su salida estándar, en texto y en `--json`, no cambia ([self-hosting.md](self-hosting.md) §9.2).

Los errores llevan la cabecera `Klav-Error: <error>` y un JSON `{ "error", "message", "next" }`, con los códigos del ADR 0036 §10. Ninguno contiene un valor, una cabecera ni la ruta pedida:

| `error` | HTTP | Cuándo |
|---|---|---|
| `klav_server_unreachable` | 503 | El proxy no llega al servidor de Klav |
| `klav_agents_paused` | 423 | La persona pausó los agentes |
| `klav_not_allowed` | 403 | Una llamada local con el proxy arrancado con `--no-local-calls`; una petición de una página web o para otro host; perfil desconocido; método, ruta o consulta que la política no puede juzgar; el servidor lo deniega (su política o un proxy revocado, que el servidor responde igual) o no acepta la firma del proxy (`401`); o lo que devolvió no se puede verificar (firma o *rollback*) |
| `klav_approval_pending` | 409 | `ask`: con `approval_id` y `expires_at`; el reintento de la misma petición recibe la decisión |
| `klav_approval_denied` | 403 | La persona dijo que no |
| `klav_rate_limited` | 429 | Pasó el `rate_per_minute` del perfil o el de su sandbox, o ya hay 16 peticiones en curso (o 4 de su sandbox): con `retry_after` en segundos y la cabecera `Retry-After` |
| `klav_upstream_blocked` | 502 | Una dirección que no es pública, una redirección (salvo `304`), una respuesta comprimida, un proveedor que no responde o un cuerpo que no se puede revisar |
| `klav_sandbox_revoked` | 401 | Solo por el canal (§8.10): el servidor rechaza el sandbox (terminado, vencido, o su emisor ya no lo es), o terminó mientras la llamada esperaba al servidor |
| `klav_sandbox_expired` | 401 | Solo por el canal (§8.10): el sandbox venció, también mientras la llamada esperaba al servidor |

**Una llamada que el servidor deniega** recibe `403 klav_not_allowed` con el mensaje general («outside what the person allowed»), salvo cuando el proxy sabe qué parte quedó fuera por la política del grant: si hay reglas `proxy` vigentes que permiten o preguntan para ese elemento y ese host, y ninguna cubre a la vez el método y la ruta, el `message` dice si quedó fuera la ruta («This call's path…»), el método («This call's method…») o ese método en esa ruta («This call's method on this path…»). Nunca nombra las reglas, lo que sí se permite ni la ruta pedida. Sin una regla para ese host, o si una lo cubre (el servidor denegó por otra cosa, como un proxy revocado), el mensaje es el general.

**Lo que queda abierto.** El servidor guarda una aprobación de `proxy` por elemento, host, método y ruta, sin la consulta, y reutiliza una aprobada para el mismo destino: una petición con otra consulta puede gastar una aprobación de una sola vez (el proxy solo recuerda la suya con la consulta exacta). Una API que nombra la acción en la consulta, o GraphQL por `GET`, no queda limitada por `ask`, y la tarjeta de la aprobación muestra la ruta sin la consulta. Un pedazo real del valor que un servicio devuelva por accidente pasa sin redactar, y un eco en una forma que la redacción no cubre pasa entero (modelo de amenazas, T149).

### 8.8 La vida de un sandbox (el proxy de credenciales)

ADR [0036](decisiones/0036-sandboxes-de-agentes.md) §4, §9 y E3.3. El proxy de credenciales registra cada paso de un sandbox con una petición firmada (§8.2) **con cuerpo**, que la bitácora guarda (§9). Ninguna de estas rutas recibe el secreto del sandbox, su resumen ni el paquete. Las cinco escrituras del proxy (emitir, reclamar, terminar, la época y el latido) vuelven a mirar bajo el cerrojo de la cuenta que el proxy sigue activo, así que una petición que pasó la comprobación de §8.2 antes de que la persona revocara el proxy, y llega al cerrojo después, recibe el mismo `403 forbidden`, y la ruta no escribe ni registra nada detrás de `agent.revoked`.

| Método y ruta | Cuerpo | Respuesta | Evento |
|---|---|---|---|
| `POST /v1/agent/sandboxes` | `{ sandbox_id, issuer_id, label, profiles, expires_at }` | `204` | `sandbox.issued` |
| `POST /v1/agent/sandboxes/{id}/claimed` | `{ channel_key_sha256 }` | `204` | `sandbox.claimed` |
| `POST /v1/agent/sandboxes/{id}/revoked` | `{ reason, at? }` | `204` | `sandbox.revoked` (`outcome` = `reason`) |
| `GET /v1/agent/sandboxes/revocations?since=` | — | `{ revocations: [{ seq, proxy_id, scope, at, signature, sandbox_ids }], more }` | — |

- **Emitir** (antes de que el proxy le dé el paquete al emisor; si el servidor lo rechaza, no hay paquete):
  - `label` de 1 a 64 caracteres, sin espacios a los lados ni caracteres de control o invisibles; `profiles`, de 1 a 6, sin repetir; `issuer_id` distinto del proxy (`400`);
  - el emisor está en `issuers` del grant del proxy, firmado por la cuenta, y su propio grant nombra a este proxy en `sandbox.proxy`; es un agente activo de la cuenta (`403 not_issuer`) y no está en pausa (`403 agents_paused`);
  - cada perfil está entre los del emisor (`403 profile_not_allowed`);
  - `expires_at` es posterior a ahora y no pasa de `max_ttl_secs` del emisor más la ventana de reloj de 5 min (`400`);
  - el emisor tiene menos sandboxes vivos (sin fin registrado, sin vencer y sin revocar por la persona) que su `max_live` en este proxy (`409 too_many_sandboxes`);
  - el `sandbox_id` no se usó antes (`409`).
- **Reclamar** (antes de que el proxy dé el secreto por gastado; el reenviador que lo llama llega con la capa 6): `channel_key_sha256` es el SHA-256 del SPKI de la llave Ed25519 del canal (especificación §13.10). Solo un sandbox que emitió este proxy (`404` para cualquier otro, también para el de otro proxy), sin fin registrado, sin vencer y sin revocar por la persona, con su emisor todavía emisor (`403 sandbox_revoked`) y sin pausa (`403 agents_paused`), y una sola vez (`409 sandbox_claimed`).
- **Terminar:** `reason` es `stop` (lo paró el emisor), `ttl`, `inactivity`, `theft`, `released` o `issuer_removed`; otro valor es un `400`. Los motivos de la persona: `person` (responde a una revocación de la persona y lleva su `at`) se acepta desde la capa 5a, y necesita una revocación de la persona registrada para ese proxy, con ese `at`, que cubra el sandbox (otra, `409`; sin `at`, `400`). `person_local` (la persona por el socket local del proxy, E3.5) sigue siendo un `400`, con cualquier forma de cuerpo y el mismo mensaje, sin registrar nada: solo lo firma la llave del proxy, y los `klav log verify` publicados lo rechazan. Lo acepta la capa que lo manda (el socket local del proxy en el Mac), cuando todos los dispositivos tengan el verificador que ya lo comprueba (especificación §13.7). `at` va solo con `person` y es un número (`null` o `1.0` son un `400`), así que los cuerpos de los demás motivos no cambian. El cuerpo es un objeto JSON: la forma de arreglo (`["stop"]`), que el lector de JSON también acepta, es un `400` con cualquier motivo. `theft` y `released` solo tras un reclamo (`409`). Una sola vez: el segundo recibe `403 sandbox_revoked`, para que el proxy deje de reintentarlo. Terminar solo quita acceso, así que vale con el sandbox vencido y con el emisor quitado o en pausa.
- **Todas las comprobaciones** se hacen con el cerrojo de la cuenta, el mismo que toman la bitácora y la pausa, así que una pausa o una revocación escrita antes se ve.
- **Un sandbox desconocido** en `claimed` o `revoked` (que este proxy no emitió, también el de otro proxy) recibe `404 sandbox_not_found`, no el `not_found` genérico.
- **La segunda barrera** (E3.3, capa 5a): un `POST /v1/agent/access` con `permission: proxy` puede nombrar el sandbox para el que es la llamada (`sandbox`, fuera de `claims`, así que la solicitud que firma la persona no cambia, aunque el sandbox sí cuenta en el mismo destino, §8.3; con otro permiso, `400`). Antes de evaluar nada ni registrar nada, y con el cerrojo de la cuenta, el servidor lo rechaza con `403 sandbox_revoked` si este proxy no lo emitió, si su fin ya está registrado, si la persona lo revocó, si venció, o si su emisor ya no está en el grant del proxy o ya no es emisor (revocado, denegado, vencido, o su grant ya no nombra a este proxy); y con `403 agents_paused` si su emisor está en pausa, que al reanudarse vuelve a dejarlo pasar. Una llamada permitida lo comprueba **otra vez** en la transacción que la registra, con el cerrojo de la cuenta tomado antes (capa 5a): un fin o una revocación de la persona confirmados antes de ese cerrojo se ven, así que la bitácora nunca muestra una llamada permitida de un sandbox después de su revocación, y el proxy no recibe el valor (`403 sandbox_revoked`, sin evento). Sin `sandbox`, el acceso es el de siempre.
- **Los emisores que ya no lo son:** el `GET /v1/agent/me` de un proxy trae `gone_issuers`, los emisores de su grant que el servidor ya no cuenta como emisores de ese proxy (por las mismas razones; uno en pausa no está). El proxy termina sus sandboxes vivos con `issuer_removed` (Q-C; T156). Falta en la respuesta de cualquier otro agente, y los servidores anteriores no lo mandan.
- **Leer las revocaciones de la persona** (capa 5a): `GET /v1/agent/sandboxes/revocations?since=` trae las de este proxy (de ningún otro agente) cuya posición `seq` es mayor que `since` (por defecto `0`), de la más vieja a la más nueva, como mucho 100; `more` dice si hay más, y se pide otra vez desde el `seq` de la última. `seq` es la posición de su `sandbox.revoke_requested` en la bitácora de la cuenta. El servidor da esa posición y confirma la revocación con el cerrojo de la cuenta, así que se confirman en orden y una lectura nunca ve una sin las anteriores: el cursor no salta ninguna. `signature` es la de la cuenta (especificación §13.11), que el proxy comprueba con la identidad de la cuenta que fijó en su primer `GET /v1/agent/me` (cada `me` después debe traer la misma), nunca una que trae otra respuesta; `sandbox_ids` son los sandboxes que cubre (el servidor los lee del registro para `all`, sin firma de la cuenta). Un proxy en pausa no las lee (como toda ruta salvo `me`), pero el servidor ya bloquea sus sandboxes. Un `since` que no es un número es un `400`.
- **Cómo las lee el proxy** (capa 5a): antes de servir, en un barrido que espera como mucho 15 s (si el servidor responde a `me` pero no a las revocaciones, sirve igual, porque sin ese servidor sus sandboxes no reciben acceso; sin servidor el proxy no arranca), y después en cada barrido (cada 30 s), mientras tenga sandboxes vivos o arranques en curso, pide las que siguen a su cursor, de página en página (hasta 10 por barrido). Comprueba cada una con la identidad de la cuenta que fijó en su primer `me` (la firma de §13.11 de la especificación, que sea suya, que esté después del cursor, que un sandbox nombrado sea el que se firmó y que la lista de un `all` esté ordenada y sin repetidos); una que no pasa (lo registra como error, sin el texto de la página), o un error del servidor (también la pausa), deja el cursor donde estaba y no termina nada más. La página se lee con un límite de 16 MiB. Una página mayor deja el cursor donde estaba en cada barrido y tras reiniciar (retener, como el `seq` enorme). Termina cada sandbox vivo que cubren con `person` y el `at` de la primera que lo cubre. Si una cubre un sandbox cuyo arranque aún espera al servidor, termina los vivos que cubre y el cursor se detiene antes de ella hasta el barrido siguiente. Desde que el barrido lo termina (al acabar su lectura), el proxy no sirve ese sandbox, aunque el servidor aún no haya tomado su fin. El cursor avanza solo después de terminar lo que cubren: un barrido cortado a medias (el límite de 15 s, con una página que no llega) no avanza nada, y el siguiente las vuelve a leer. Los fines de ese primer barrido se mandan después, sin retrasar el arranque. El cursor vive en memoria: tras reiniciarse las lee todas otra vez y salta las de sandboxes que ya no tiene.
- **Lo que el servidor puede hacer con ellas** (T168, T169): la lista de un `all` no la firma la cuenta, y el proxy termina lo que nombra sin compararla con su almacén, así que el servidor puede añadir sandboxes vivos a la lista (el proxy los termina) o dejar fuera alguno (el proxy no lo termina, y un servidor que miente así puede seguir dándole acceso). `klav log verify` rehace la lista de la cadena y rechaza una alterada. `seq` tampoco va firmado: una revocación válida con un `seq` enorme lleva el cursor ahí y esconde las siguientes hasta que el proxy se reinicie. No hay un límite barato, porque la posición crece con cada evento de la bitácora; es retener, que el servidor ya puede hacer, y que dura hasta el reinicio.
- **Lo que no hace todavía** (capa 5a): no hay latido, ni `sandbox.store_reset`, ni avisos de la persona sobre sandboxes; el proxy no recibe la revocación por su *socket* local (`person_local`, E3.5), ni la app ni la CLI revocan todavía (las capas siguientes de la pila).

#### La persona revoca sandboxes

| Método y ruta | Cuerpo | Respuesta | Evento |
|---|---|---|---|
| `POST /v1/sandboxes/revoke` | `{ proxy_id, scope, at, signature }` | `200 { seq, proxy_id, scope, at, signature, sandbox_ids }` | `sandbox.revoke_requested` |

Con la sesión de la persona (§3). `scope` es un `sandbox_id` o `all`; `signature`, la de la cuenta sobre `klav/v1/sig/sandbox-revoke` (especificación §13.11).

- `at` a 5 min o menos del reloj del servidor (`400`), y la firma tiene que verificar con la identidad de la cuenta (`400`).
- `proxy_id` es un agente de la cuenta, en cualquier estado y aunque esté en pausa (`404 not_found` para el de otra cuenta, igual que para uno que no existe). Con un `sandbox_id`, un sandbox que ese proxy emitió, terminado o no (`404 sandbox_not_found` para cualquier otro).
- `at` mayor que el de la última revocación del mismo proxy y alcance; si no, `409` con `last_at`, el de esa última, y el dispositivo firma otra con un `at` posterior. Así no se puede repetir un `all` viejo sobre sandboxes emitidos después.
- `all` cubre los sandboxes de ese proxy emitidos antes, sin fin registrado y con `expires_at > at − 5 min` (el `at` firmado, con la ventana del reloj, no la hora del servidor; especificación §13.11), leídos con el cerrojo de la cuenta y ordenados; también los que la persona ya revocó y el proxy aún no terminó, y los que vencieron dentro de esa ventana. Así un dispositivo con el reloj adelantado hasta 5 min no deja fuera ninguno que el servidor cuente como vivo. Uno emitido después no queda cubierto. Una revocación de un sandbox ya revocado o ya terminado se acepta y se registra: solo quita acceso.
- La comprobación, el evento, la revocación y las filas de la barrera van en una transacción, con el cerrojo de la cuenta. Desde que se confirma, el servidor rechaza el acceso y el reclamo, y los sandboxes cubiertos dejan de contar para `max_live`. El proxy los terminará con `person` al leerlos (capas siguientes).

#### La época del almacén y el latido

Desde la capa 5a (latido): los formatos y la comprobación del dispositivo con la primera mitad, las dos rutas y `sandbox_state` con la segunda. La forma exacta y lo que comprueba cada dispositivo (la época del último `sandbox.store_reset` de ese proxy en la cadena verificada, un `seq` que no baja dentro de ella y la edad desde `sent_at_ms`) están en la especificación, §13.12.

| Método y ruta | Cuerpo | Respuesta | Evento |
|---|---|---|---|
| `POST /v1/agent/sandboxes/epochs` | `{ store_epoch }` | `204` | `sandbox.store_reset` |
| `PUT /v1/agent/sandboxes/state` | `{ v, store_epoch, seq, sent_at_ms, sandboxes: [{ id, connected, last_seen_at? }] }` | `204` | ninguno: el servidor guarda solo el último de cada proxy |

- Las dos son peticiones firmadas del proxy (§8.2) **con cuerpo**, bajo el cerrojo de la cuenta. `store_epoch` son 16 bytes al azar, uno por almacén del proxy, también el primero, registrado antes de su primer latido y nunca dos veces. El latido nombra como mucho 100 sandboxes (decidido por Omar el 2026-11-13 (ADR 0036, «El latido de la capa 5a (2026-11-13)»)): subir el tope después es caro, porque un dispositivo que lee un latido con más lo rechaza como error de seguridad («no es un latido»).
- **La ruta de la época** (decidido por Omar el 2026-11-13 (ADR 0036, «El latido de la capa 5a (2026-11-13)»)): `POST /v1/agent/sandboxes/epochs`, con el cuerpo exacto `{store_epoch}`, y `sandbox.store_reset` sin `outcome`.
- **Firmadas para la ruta exacta:** con una consulta, aunque sea un `?` solo, son un `400` y no se registra ni se guarda nada, porque el verificador exige la ruta exacta. Una época cuya firma queda a más de 5 min de la hora que llevaría su evento (un cuerpo que tardó en llegar) es un `401` y tampoco se registra: el verificador la rechazaría.
- **Quién las llama** (decidido por Omar el 2026-11-13, ADR 0036, «Las preguntas abiertas de la capa 5a (2026-11-13)»; una declaración firmada que nombre al proxy queda para después de la primera prueba real): un agente activo de la cuenta cuyo grant, firmado por la cuenta, tiene perfiles del proxy o emisores; si no, `403 forbidden`. En pausa no (`403 agents_paused`), como toda ruta salvo `me`: el proxy guarda su último latido y lo manda al reanudarse. La elección de proxy de la cuenta es una preferencia cifrada que el servidor no lee, así que no puede exigir más; cada dispositivo mira solo el proxy que nombra esa preferencia.
- **La época:** una que este proxy ya usó es un `409`; si no, el servidor registra `sandbox.store_reset` y guarda la época con la posición de su evento. Un cuerpo con otro campo, o una época que no mide 16 bytes, es un `400`. El cuerpo es un objeto JSON: la forma de arreglo (`["<época>"]`), que el lector de JSON también acepta, es un `400` antes de guardar o registrar nada, porque el verificador la rechaza.
- **El latido:** un cuerpo que no es un objeto JSON (la forma de arreglo, como en la época), que no pasa la forma de §13.12, un `seq` mayor que 2⁶³ − 1 o un `sent_at_ms` más de 5 min por delante del reloj del servidor es un `400`. Una época que no es la del último `sandbox.store_reset` de este proxy (o ninguno todavía), o un `seq` que no crece dentro de ella, es un `409`. Si no, sustituye al anterior de ese proxy, con su petición firmada tal cual. No va a la bitácora.
- **Ante un `409`** (valor por defecto aceptado por Omar el 2026-11-15, ADR 0036, «Las preguntas abiertas de la capa 5a»): el proxy empieza una época nueva y nunca repite un `seq`. Un intento manda como mucho dos `sandbox.store_reset` y un latido, y los intentos van a un minuto o más uno de otro (salvo si el reloj del proxy retrocede más allá del último intento: entonces toca uno enseguida), así que nunca entra en un bucle. Dos procesos con la misma identidad de proxy se quitan la época uno al otro y registran un `sandbox.store_reset` en cada intento: corre uno solo por proxy.
- **En pausa**, el servidor rechaza el latido (`403 agents_paused`) y el proxy lo guarda en su archivo; al reanudarse lo manda tal cual, con su `seq` y su `sent_at_ms`, y uno nuevo un minuto después. Si el servidor rechaza ese guardado con un `400` (su `sent_at_ms` quedó adelantado, por ejemplo), el proxy lo descarta y el siguiente intento manda uno nuevo.
- **`GET /v1/sync`** trae `sandbox_state`: `[{ proxy_id, proof, received_at }]`, el último latido de cada proxy activo de la cuenta (no los revocados, denegados ni pendientes; el de un proxy en pausa sigue saliendo y envejece), con la petición firmada (`proof`, con el cuerpo) para que el dispositivo la compruebe. `received_at` es la hora del servidor y no está firmada. Falta si no hay ninguno.

### 8.9 La API del emisor en el proxy (`/_klav/sandboxes`)

ADR [0036](decisiones/0036-sandboxes-de-agentes.md) §4, E1.3 y E3.3. No es una ruta del servidor: la sirve `klav-proxy serve` en su escucha local, `http://127.0.0.1:<puerto>/_klav/sandboxes`, y solo para programas de la misma máquina (las reglas de origen y `Host` de §8.7). Con `klav-proxy serve --no-local-calls` sigue igual, aunque el proxy rechace toda llamada local a un perfil (ADR [0042](decisiones/0042-sandboxes-for-daily-use.md) §3). Ningún perfil puede llamarse `_klav`: un nombre de perfil empieza por una minúscula. El emisor firma cada petición como una al servidor (§8.2: las mismas cabeceras y el mismo mensaje, con la ruta y la consulta tal como se mandan), y el proxy la comprueba con la identidad del emisor que dice **su propio grant** (`issuers[].public_identity`, firmado por la cuenta), nunca con una que le dé el servidor.

**Cada ruta lleva la consulta `?port=<puerto>`**, el puerto en el que el emisor espera al proxy, y va dentro de lo firmado. El proxy rechaza otro puerto, o ninguno, con `403 klav_not_allowed`. Así, lo que escuche en un puerto no puede pasarle la petición a un proxy en otro: puede cambiar `Host`, pero no la consulta firmada.

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `POST /_klav/sandboxes` | `{ label, profiles, ttl_secs? }` | `200 { sandbox_id, secret, expires_at }` (`Cache-Control: no-store`) |
| `GET /_klav/sandboxes` | — | `200 { sandboxes: [ { sandbox_id, label, profiles, issued_at, expires_at, claimed } ] }`, solo los del emisor que firma |
| `POST /_klav/sandboxes/{id}/stop` | — | `200 { logged }`: `logged` dice si el servidor ya tiene el fin |

- **Firma:** un agente que el grant del proxy no lista recibe el mismo `401 klav_not_allowed` que una firma mala, así que nadie sin llave averigua quién es emisor; la marca de tiempo a ±5 min del reloj del proxy y no anterior a su arranque (los *nonces* vistos viven en memoria, así que una petición firmada antes de un reinicio no vale); cada *nonce* una sola vez por emisor, guardado solo tras comprobar la firma, y como mucho 4096 a la vez y 1024 de un mismo emisor, para que uno solo no llene la memoria de los demás (`429 klav_rate_limited` si no cabe otro). Cuerpo de 4 KiB como mucho.
- **Empezar:** cada perfil es del emisor y el proxy lo tiene (`403 klav_profile_not_allowed`); `ttl_secs` no pasa del `max_ttl_secs` del emisor, y sin él vale 8 h o ese máximo (`400 klav_bad_request`); el emisor tiene menos sandboxes vivos que su `max_live` (`409 klav_too_many_sandboxes`), contando los arranques que esperan al servidor, así que dos a la vez no pasan de `max_live`; el emisor que el servidor ya no cuenta como tal (`gone_issuers`, §8.8) recibe `403 klav_not_issuer`. Cada emisor pide como mucho 30 arranques por minuto, contados tras comprobar la firma y antes de escribir nada (`429 klav_rate_limited`). Con 256 fines esperando al servidor, ningún sandbox empieza (`503 klav_proxy_backlog`; hasta la capa 6 era `klav_server_unreachable`, y una CLI anterior muestra el mensaje y el `next` del proxy y sale con 1 igual que antes): ningún fin se descarta para hacer sitio. El cerrojo del almacén solo se toma para leerlo o cambiarlo, nunca mientras se espera al servidor: `GET`, `stop` y el barrido no esperan a un arranque.
  - **Antes de preguntar al servidor,** guarda en el almacén el fin (`stop`) de ese sandbox. Si no puede, responde `500 klav_proxy_store` y el servidor no se entera.
  - **Después registra `sandbox.issued`** (§8.8). Si el servidor lo rechaza, no hay sandbox ni secreto y el fin se borra (`423 klav_agents_paused`, o el código del servidor). Si no responde, o responde 5xx o `429`, el proxy no sabe si lo registró: responde `503 klav_server_unreachable` y deja el fin, que el barrido manda cuando el servidor vuelva (el `404 sandbox_not_found` del servidor que nunca lo tuvo lo descarta). Mientras el arranque espera, su fin pendiente no se manda. Lo mismo si el proceso muere entre la respuesta del servidor y el guardado.
  - **Guarda el sandbox** con el resumen del secreto (especificación §13.10), nunca el secreto, y quita el fin pendiente. Si no puede guardarlo, el fin sigue en el archivo: termina el sandbox en el servidor con `stop` y responde `500 klav_proxy_store` sin secreto.
- **`secret`** es el secreto de un solo uso en base64url. El emisor arma el paquete `ksb1_` con él y con la dirección y el pin del proxy que dice **su** grant (§13.10), no con lo que diga la respuesta.
- **Parar** surte efecto en cuanto el proxy guarda el fin, también en pausa y también mientras otro arranque espera al servidor. Si no puede guardarlo, el sandbox sigue vivo y responde `500 klav_proxy_store`. Un sandbox de otro emisor, o que no existe, recibe el mismo `404 klav_sandbox_not_found`.
- **El barrido** (cada 30 s, y al arrancar) termina un sandbox vencido (`ttl`), uno sin reclamar una hora después de empezar, o reclamado y sin ninguna llamada por su canal durante una hora (`inactivity`; la hora de un sandbox reclamado cuenta desde su última llamada, su reclamo o el arranque del proxy, lo último), y, con `issuer_removed`, uno cuyo emisor dejó el grant del proxy, perdió uno de los perfiles del sandbox o está en `gone_issuers` del último `GET /v1/agent/me` del proxy (revocado, o su grant ya no nombra a este proxy; el proxy lo pregunta cada 30 s mientras su grant tiene emisores).
- **Los fines que el servidor no tomó** esperan en el almacén, en orden, y salen en el barrido siguiente, mandados de uno en uno y sin tener el cerrojo. Sin red, en pausa, con un 5xx, un `429`, un `401` (un reloj desfasado) o un `403 forbidden`, el envío para y sigue en el barrido siguiente. Si el servidor rechaza solo ese fin (un `404` genérico, que da un servidor sin estas rutas o una dirección equivocada, o un `400`), lo guarda y sigue con los demás. Solo se descarta uno que el servidor ya tiene (`403 sandbox_revoked`), uno de un sandbox que nunca tuvo (`404 sandbox_not_found`, nunca un `404` genérico) o uno cuyo motivo nunca tomará (`409`). Un proxy así necesita un servidor con `sandbox_not_found`: con uno anterior, el fin de un arranque que el servidor nunca registró se queda esperando.
- **El almacén** es un archivo 0600 del usuario del proxy junto a su registro (`<home>/agents/<nombre>.sandbox-store`, con `v: 1`; no termina en `.json`, que es lo que la CLI lista como agentes), reemplazado de forma atómica. El proxy no arranca con uno que no puede leer, de otra versión o más abierto que 0600: no empieza de cero solo, porque olvidaría sandboxes que todavía tiene que terminar. `klav-proxy status` lo lee con las mismas comprobaciones y muestra los sandboxes vivos (ID, etiqueta, perfiles, emisor, vencimiento y si se reclamó, nunca el resumen del secreto) y cuántos fines esperan al servidor. Un fin `person` pendiente guarda además el `at` de la revocación a la que responde; un proxy anterior a la capa 5a (segunda parte) no lee un almacén que tenga uno: hay que esperar a que el servidor lo tome o mover el almacén y parar los sandboxes a mano.
- **Los fines `theft` y `released`** necesitan el reclamo registrado (§8.8). Si el proxy tiene en el archivo de canales un reclamo que el servidor quizá no registró, primero lo manda, con su llave, y después el fin.

### 8.10 El canal de los sandboxes (`klav-proxy serve --channel`)

ADR [0036](decisiones/0036-sandboxes-de-agentes.md) §5, §6, §10 y E3.3. Tampoco es una ruta del servidor: la sirve `klav-proxy serve --channel HOST:PUERTO`, la dirección a la que apunta el `tls://` que la persona firmó para el emisor (`klav proxy issuer add --url`). Es TLS 1.3 con llaves Ed25519 en bruto en los dos extremos (especificación §13.10): el proxy presenta la de su identidad, que el paquete fija, y el reenviador una llave del canal suya. Una conexión sin llave de cliente, con TLS 1.2 o con otra llave que no firma lo que presenta no termina el *handshake*. **Quién llama lo dice la llave que probó el *handshake*** (`SHA-256` de su SPKI), nunca la petición.

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `POST /_klav/claim` | `{ sandbox_id, secret }` | `200 { sandbox_id, label, profiles, expires_at }` |
| `GET /_klav/status` | — | `200` con lo mismo, si la llave reclamó un sandbox vivo |
| `POST /_klav/release` | — | `200 { logged }`: termina el sandbox con `released`; `logged` dice si el servidor ya tiene el fin |

- **`status` y `release` no aceptan una página web.** El puerto local del reenviador no tiene TLS y lo alcanza cualquier página que abra un navegador dentro del sandbox: sin esta regla, un formulario de otro sitio (`POST` sin *preflight*) terminaría el sandbox, y una página con *DNS rebinding* leería su estado (ID, etiqueta, perfiles y vencimiento). Por eso las dos rutas rechazan con `403 klav_not_allowed` una petición con el `Origin` o el `Sec-Fetch-Site` de un navegador, o con un `Host` que no sea exactamente `klav-proxy` (el que mandan el reenviador y `klav-forward status`), `127.0.0.1:<puerto>` o `localhost:<puerto>`. Una página que cambia su nombre a `127.0.0.1` sigue mandando su nombre en el `Host`, también en un motor que no manda `Origin` en un `GET` del mismo origen. El rechazo llega antes de mirar el sandbox: no lo termina, no gasta nada y no cuenta como actividad. `claim` no lo necesita: sin el secreto, que la página no tiene, un reclamo no tiene efecto (`401 klav_sandbox_revoked`, o `400` con un cuerpo de formulario). **Lo que queda abierto:** un motor anterior a *Fetch Metadata* que además no mande `Origin` en el `POST` de un formulario de otro sitio no trae ninguna de las dos cabeceras, y contra `127.0.0.1:<puerto>` su `Host` es válido: esa página puede terminar el sandbox, y su `GET` a ciegas a `status` cuenta como actividad (el mismo hueco que la nota de `modelo-de-amenazas.md` §5.17 nombra para el puerto local). Y si `klav-proxy` resuelve a una dirección local dentro del sandbox y el reenviador escucha en el puerto 80, un `GET` a ciegas de otro sitio a `http://klav-proxy/_klav/status` pasa también en un navegador actual, porque ese nombre no es un origen de confianza y no lleva `Sec-Fetch-Site`: no lee la respuesta ni termina el sandbox, pero cuenta como actividad y lo mantiene vivo hasta su vencimiento.

- **Por qué terminó un sandbox.** A la llave que lo reclamó, `status` y las llamadas le responden el `401` con un `message` que dice el motivo que el proxy ya conoce: lo paró su emisor, se acabó su tiempo (`klav_sandbox_expired`), pasó una hora sin una conexión suya, la señal de robo, su reenviador lo soltó (`klav-forward down`), la persona quitó o revocó a su emisor, o la persona lo revocó. El código es `klav_sandbox_revoked` salvo con el tiempo acabado. El `next` es el mismo de siempre. El motivo vive en la memoria del proxy (los 1024 últimos fines): tras reiniciarlo, y para cualquier llave que no reclamó ese sandbox, la respuesta es la general, la misma que recibe un sandbox que no existe o un secreto equivocado, así que el motivo no le dice nada a quien no tiene la llave. `claim` no mira la llave de un sandbox terminado: responde siempre el texto general, salvo en la señal de robo, donde las dos llaves reciben el mismo texto, que dice que fue un segundo reclamo y no dice cuál reclamó primero.
- **`status` con los agentes en pausa.** Si la última respuesta del servidor al refresco del grant del proxy (cada 30 s) fue `agents_paused`, `status` de un sandbox vivo responde `423 klav_agents_paused`, y vuelve a `200` con el primer refresco bueno. Solo ese refresco lo decide: no nombra a ningún emisor, así que dice si el proxy mismo está en pausa (todos los agentes, o el proxy). La pausa de **un** emisor la recibe solo en sus llamadas, del servidor, y su `status` sigue diciendo que está vivo (pendiente). La pausa no termina el sandbox, y `status` cuenta como actividad también entonces, así que una pausa larga no lo termina por inactividad.
- **El reclamo** (`secret` en base64url, 1 KiB de cuerpo como mucho):
  - un sandbox que no existe, ya terminado o un secreto equivocado reciben el mismo `401 klav_sandbox_revoked`; uno vencido, `401 klav_sandbox_expired`;
  - el proxy anota la llave en el archivo de canales **antes** de pedir al servidor `sandbox.claimed` (§8.8) con su `channel_key_sha256`, y solo con la respuesta da el secreto por gastado y liga el sandbox a la llave;
  - si el servidor rechaza el **primer** intento, no registró nada: la llave se olvida y el secreto no se gasta (`423 klav_agents_paused`, `401 klav_sandbox_revoked` o `403 klav_not_allowed`). Un `404` sin código, de un servidor sin esta ruta, es `403 klav_not_allowed` con el mensaje de que el servidor es más viejo que el proxy;
  - si no responde, o responde 5xx o `429`, el proxy no sabe si lo registró: responde `503 klav_server_unreachable`, deja la llave anotada y **solo esa llave** puede volver a reclamar. Desde ahí la llave sigue anotada hasta que el sandbox termine, **aunque el servidor rechace un reintento**: el rechazo de un reintento (una pausa, que el servidor mira antes que el reclamo) no dice nada del intento cuya respuesta se perdió;
  - un `409 sandbox_claimed` del servidor para una llave que ya estaba anotada cuenta como registrado: solo esa llave se le mandó para ese sandbox. Para una llave que este mismo intento anotó, el servidor tiene el reclamo de una llave de la que el proxy no sabe nada: es la señal de robo;
  - una llave ya anotada para **otro** sandbox no puede reclamar este: recibe `401 klav_sandbox_revoked` y el secreto no se gasta. Cada reenviador tiene una llave del canal y un sandbox (ADR 0036 §5), y una llamada corre siempre como el sandbox para el que el servidor la autorizó: si al mirarlo otra vez (abajo) la llave resulta ser de otro, recibe `401 klav_sandbox_revoked`;
  - la misma llave otra vez, con el sandbox ya ligado, recibe el mismo `200` sin registrar nada nuevo; otro reclamo del mismo sandbox mientras uno espera al servidor recibe `429 klav_rate_limited` con `Retry-After: 1`.
- **La señal de robo:** el secreto correcto desde **otra** llave, cuando ya hay una anotada, termina el sandbox con `theft` al momento, y las dos llaves reciben desde ahí `401 klav_sandbox_revoked` con el mismo mensaje, que dice que fue la señal de robo, sin saber cuál perdió. Lo mismo si el almacén dice que el sandbox se reclamó pero el archivo de canales no tiene su llave (se perdió), y si el servidor responde `409 sandbox_claimed` a una llave recién anotada: no se sabe qué llave registró el servidor. El aviso a la persona (*push* `sandbox_theft`) llega con la migración 0019 (capa 5a).
- **Un robo que el proxy no puede confirmar:** el fin `theft` sale después del reclamo pendiente. Si el servidor rechaza uno de los dos porque el sandbox ya acabó para él (venció, su emisor ya no lo es, ya tiene un fin) o no lo conoce, el proxy no sabe si el robo llegó a la bitácora: esa respuesta es la misma cuando el servidor nunca recibió el fin que cuando lo registró y la respuesta se perdió. El proxy no lo descarta en silencio: lo deja en el archivo de canales (los 32 últimos), lo escribe en su registro como aviso y `klav-proxy status` lo muestra (en `--json`, `unconfirmed_thefts`) para que la persona mire su bitácora.
- **Las llamadas a los perfiles** van por el canal como el modo (a) en la escucha local (§8.7): `METODO /<perfil>/<ruta>[?consulta]`, con las mismas reglas y límites. Además:
  - quién llama lo dice la llave, y que no es una página web lo dicen las cabeceras, como en la escucha local: con el `Origin` o el `Sec-Fetch-Site` de un navegador, o con un `Host` que no sea exactamente `127.0.0.1:<puerto>` o `localhost:<puerto>`, recibe `403 klav_not_allowed` antes de todo lo demás, sin gastar nada ni terminar el sandbox. El proxy no sabe en qué puerto escucha el reenviador, así que vale cualquiera; sin `Host`, con dos, sin puerto o con `[::1]` (el reenviador solo escucha en `127.0.0.1`) se rechaza. El reenviador pasa los bytes sin mirarlos, así que esta comprobación es del proxy, en cada petición de una conexión que sigue abierta. Así una página en un navegador que un agente maneja dentro del sandbox no usa los perfiles, tampoco cambiando su nombre a `127.0.0.1` (*DNS rebinding*);
  - solo una llave ligada a un sandbox vivo llama (`401 klav_sandbox_revoked`, o `401 klav_sandbox_expired`), y solo a los perfiles con que empezó el sandbox (otro recibe `403 klav_not_allowed`, como un perfil que el proxy no tiene);
  - cada sandbox tiene su propio ritmo, 60 llamadas por minuto entre todos sus perfiles, además del de cada perfil (`429 klav_rate_limited` con `retry_after`). Una llamada que pasa de uno de los dos no cuenta en ninguno: un sandbox sobre su ritmo no gasta el del perfil, que comparten los demás. Los ritmos se miran después de tomar sitio y leer el cuerpo, así que una llamada rechazada por falta de sitio o por un cuerpo que se detiene tampoco los gasta;
  - un sandbox ocupa como mucho 4 de las 16 peticiones a la vez (la siguiente recibe `429` con `retry_after: 1`). Al terminar el sandbox se cierran sus conexiones (ver **Límites**) y sus peticiones en curso sueltan lo que ocupan;
  - la respuesta pierde además `Set-Cookie` y `Set-Cookie2`: una cookie del proveedor es una credencial suya, que serviría sin el proxy y después del sandbox. Un programa de este Mac las sigue recibiendo;
  - cada `POST /v1/agent/access` lleva `sandbox` (§8.3), y el servidor lo rechaza si el sandbox terminó, venció o su emisor ya no lo es o está en pausa. El proxy responde entonces `401 klav_sandbox_revoked` (o `423 klav_agents_paused`) sin descifrar nada. Si el emisor ya no lo es, o el sandbox terminó en el servidor, el proxy lo termina en su barrido siguiente; una pausa no lo termina, y al reanudarse el sandbox vuelve a llamar;
  - una llamada en `ask` recibe `409 klav_approval_pending` con su aprobación, y el proxy la recuerda por sandbox. El servidor identifica la aprobación por su **mismo destino** (§8.3), que para `proxy` incluye el método, el host, la ruta sin la consulta y el `sandbox`: la solicitud del sandbox A, pendiente o aprobada, nunca sirve al sandbox B ni a una llamada de este Mac, y cada uno pide la suya;
  - si el sandbox termina o vence mientras su llamada espera al servidor, el proxy lo mira otra vez antes de poner la credencial y responde `401 klav_sandbox_revoked` o `401 klav_sandbox_expired`, sin llamar al proveedor.
- **Toda llamada por el canal** de una llave ligada cuenta para la inactividad (§8.9).
- **El archivo de canales** es `<home>/agents/<nombre>.sandbox-channels` (0600, `v: 1`, reemplazado de forma atómica), junto al almacén y aparte de él, para que el almacén siga en el formato que lee un proxy anterior. Guarda el `SHA-256` de cada llave del canal y si el servidor ya registró el reclamo, y los robos que no pudo confirmar (el ID del sandbox y cuándo); nunca una llave ni un secreto. El proxy no arranca con uno que no puede leer. Una llave se borra cuando su sandbox terminó y el servidor tiene el fin.
- **El archivo del latido** (decidido por Omar el 2026-11-13, ADR 0036, «Las preguntas abiertas de la capa 5a (2026-11-13)»; se aparta de E3.3, que pone `seq` en el almacén del proxy) es `<home>/agents/<nombre>.sandbox-heartbeat` (0600, `v: 1`, reemplazado de forma atómica), junto al almacén y aparte de él por la misma razón: `{ v, store_epoch, logged, seq, kept? }`, la época del almacén, si el servidor ya tomó su `sandbox.store_reset`, el último `seq` usado (guardado antes de mandarlo) y el latido que una pausa retuvo, que sale tal cual al reanudarse (§8.8). Uno que falta, no se lee o es de otra versión no impide arrancar: empieza una época nueva, que solo registra otro `sandbox.store_reset`.
- **Límites.** Cualquiera que llegue al puerto puede terminar un *handshake* con una llave desechable, así que nada de lo que haga antes de ligarse a un sandbox retiene al proxy mucho tiempo:
  - 3 s por *handshake*, cada uno aparte, y 64 a la vez (el siguiente espera en la cola del sistema);
  - 256 conexiones abiertas en total y 16 por llave: un sandbox no puede ocupar las de los demás. La que pasa del límite de su llave se cierra tras el *handshake*;
  - de ellas, 32 como mucho con una llave sin sandbox (reclamos en curso, sondeos). Cuando están todas, la más vieja se cierra para dejar sitio a la nueva (con los 5 s de gracia del apagado, para que salga una respuesta en camino), así que retenerlas pide un chorro constante de conexiones, y un reclamo nuevo entra igual. Una conexión que aún no mandó ni un byte se cierra al momento, sin gracia: un chorro de 32 *handshakes* o más entre el de un reenviador y la cabecera de su reclamo hace fallar el reclamo mientras dure, y el reenviador reintenta. Un reclamo en curso de la conexión cerrada termina igual: corre aparte, con el plazo del cliente HTTP de Klav para llegar al servidor (10 s para conectar, 60 s en total), y un reintento con la misma llave recibe entretanto `429` y después el `200`. Con el `200` de un reclamo, todas las conexiones de esa llave dejan de contar como sin sandbox en ese mismo momento, así que ninguna se puede cerrar para hacer sitio;
  - la cabecera de cada petición debe llegar en 20 s, y una conexión ociosa se cierra a los 20 s; una respuesta en la que el proxy sigue trabajando (una aprobación que espera) no cuenta;
  - el canal acepta el semicierre (`half_close`), para que el reenviador pase el fin de envío de quien llama y reciba igual la respuesta. A cambio, el proxy ya no nota que quien llama se fue a mitad de una petición: la llamada al proveedor sigue hasta su fin, ocupando uno de los 4 sitios del sandbox y un turno del reenviador hasta los 120 s del plazo del proveedor;
  - una conexión cuya llave no se liga a ningún sandbox en 30 s se cierra, aunque siga pidiendo cosas;
  - una conexión ligada comprueba cada 5 s que su sandbox sigue vivo: al pararlo, revocarlo o vencer, sus conexiones se cierran, aunque sigan pidiendo cosas. Una conexión nueva de esa llave recibe `401` con las reglas de una sin sandbox;
  - lo que queda: los *handshakes* se comparten, y quien llegue al puerto puede retrasar los de todos abriendo conexiones TCP calladas. Por eso el puerto del canal no debería estar abierto a internet si se puede evitar (§9.2 de `self-hosting.md`);
  - el cuerpo de un reclamo, 1 KiB como mucho (`413 klav_bad_request`, sin leer el resto) y en 10 s;
  - al apagarse, cada conexión tiene 5 s para terminar y luego se corta.
- **Registro:** los rechazos que puede causar cualquiera (secreto equivocado, sandbox desconocido o vencido, cuerpo inválido) van a nivel `debug`, para que nadie llene el registro desde fuera; los que solo causa quien tiene el secreto, a `info`.

### 8.11 El reenviador (`klav-forward`)

ADR [0036](decisiones/0036-sandboxes-de-agentes.md) §5, §7 modo (a) y §10. Corre dentro del sandbox y no tiene código de la bóveda: no descifra nada ni firma como agente. Solo el modo (a), con URL base; `HTTPS_PROXY` (modo b) y la puerta MCP (modo c) llegan en capas posteriores.

- **`klav-forward up [--daemon] [--port 8790] [--state-dir DIR] [--profile-file RUTA] [--no-skill] [--json]`:**
  1. lee el paquete de `KLAV_SANDBOX`, mira si ya hay algo que hacer con él (**Antes de arrancar**, abajo) y se lo pasa a un proceso hijo suyo por una tubería, nunca por sus argumentos ni su entorno (el hijo arranca sin `KLAV_SANDBOX`);
  2. el hijo abre `127.0.0.1:PUERTO` (un puerto ocupado falla con `klav_forward_port_in_use` antes de enviar el reclamo. Para decir quién lo tiene, pregunta antes `GET /_klav/status` en ese puerto: otro reenviador, `klav-proxy` (cuyo puerto por defecto también es 8790), otro programa, o no se sabe. Con otro reenviador, el `next` manda a `klav-forward status`, nunca a otro `up` con el mismo paquete ni a otro puerto: puede ser el reenviador de este mismo sandbox, y otro reclamo el proxy lo tomaría por un robo. Con `klav-proxy` u otro programa, dice que esta ejecución no reclamó nada, así que no gastó el paquete, y manda a `up --port <un puerto libre>` o a mover el otro programa, `klav-proxy serve --port <otro puerto>`. Con uno que no respondió a tiempo, que podría ser un reenviador de este mismo sandbox, manda a `klav-forward status` y a decir a la persona qué tiene el puerto, nunca a otro puerto. Ningún `next` manda a reintentar en bucle), escribe la **marca de reclamo** (abajo) antes del primer byte del reclamo, genera en memoria la llave del canal y reclama el sandbox por el canal (§8.10). Mientras el proxy o el servidor de Klav no respondan (`klav_proxy_unreachable`, `klav_server_unreachable`, `klav_rate_limited`), guarda el secreto en memoria y reintenta hasta 120 s; cualquier otro rechazo es definitivo;
  3. con el reclamo hecho o rechazado, olvida el secreto;
  4. escribe, sin secretos: su estado (`state.json`, 0600, `v: 1`, con su PID, su puerto y lo que el proxy dijo del sandbox; si el reenviador sale porque el proxy revocó el sandbox, el rechazo va aparte, en `ended.json`, abajo) en `$KLAV_FORWARD_HOME` o `~/.klav-forward` (0700 si `up` lo crea), y las líneas de *shell* con `KLAV_FORWARD_URL` y `KLAV_FORWARD_<PERFIL>_URL` en `/etc/profile.d/klav-forward.sh`, o en `~/.klav-forward/env.sh` si no puede escribir ahí (sin ser *root*), y lo dice. Reemplaza `/etc/profile.d/klav-forward.sh` aunque no lo haya escrito él: todavía no comprueba de quién es (pendiente);
  5. instala la skill de Klav en `~/.claude/skills/klav/` y `~/.agents/skills/klav/` si no hay una, o reemplaza una copia sin cambios de una versión publicada anterior; una editada, ajena, igual o más nueva no la toca (ADR 0036 E1.4);
  6. con `--daemon`, el hijo sigue en segundo plano, en su propio grupo de procesos, con su registro en `forward.log` (0600); sin él, `up` espera a que el hijo termine. `SIGTERM` (o Ctrl-C) lo para **sin soltar el sandbox**; `SIGHUP` no lo para. Solo `klav-forward down` (abajo) lo suelta en el proxy. Al vencer el sandbox, el reenviador tampoco sale solo: lo anota en su registro y sigue escuchando, y cada herramienta recibe `401 klav_sandbox_expired` con su `next` (las dos cosas, decididas por Omar el 2026-11-13, ADR 0036). Un sandbox revocado, en cambio, no vuelve: cuando el `GET /_klav/status` de cada 5 minutos (**El relevo**, abajo) responde `klav_sandbox_revoked` más de 10 minutos antes de su `expires_at` (más cerca, puede ser el fin por su tiempo de un proxy que se reinició o es anterior, que lo dice así), el reenviador lo anota en su registro, guarda el rechazo en `ended.json` si `state.json` sigue siendo suyo, cierra su *socket* de control, deja libre el puerto y sale con `5`. `state.json` no cambia: queda tal como lo lee cualquier versión de `v: 1`. `ended.json` (0600) es `{ "v": 1, "sandbox_id", "refusal": { "status", "error", "message", "next" } }`, sin secretos. Se lee así:
     - `status`, y `up` con el mismo paquete, primero preguntan en el puerto: si un reenviador responde, vale su respuesta y `ended.json` no cuenta. Si ninguno responde y `ended.json` es del sandbox de `state.json`, dicen su rechazo, con `5`;
     - un `ended.json` de otro sandbox no cuenta;
     - uno con otro `v`, o que no se puede leer, no cuenta para `up`, que sigue al paso de la marca de reclamo y responde `klav_forward_already_claimed`: nunca reclama otra vez. `status` responde `klav_forward_not_running` (`1`) diciendo que el reenviador paró y que el archivo es de otra versión o no se puede leer;
     - `down` no lo toca: no hay nada que parar. `down --if-other-package` con el mismo paquete tampoco. El reenviador de un paquete nuevo lo borra en cuanto escribe su `state.json`.

     Tras la salida, una herramienta que llama al puerto del reenviador recibe «conexión rechazada», sin `Klav-Error`: eso quiere decir correr `klav-forward status`, que dice por qué. Con los agentes en pausa (`423`) sigue corriendo. Al vencer, sigue preguntando cada 5 minutos, para que el proxy no lo termine por inactividad, pero lo anota en su registro una sola vez.
- **El relevo:** cada conexión local abre una conexión propia del canal y pasa los bytes tal cual, en los dos sentidos; el proxy lee la petición, aplica el perfil y responde cada rechazo con su `Klav-Error` (§8.10). Los límites (constantes de `klav_forward::forward`, también en `self-hosting.md` §9.2):
  - una conexión local no toma turno hasta su primer byte, que tiene que llegar en 20 s (`FIRST_BYTE`); una que no manda nada se cierra sin ocupar nada;
  - 12 turnos para llamadas (`MAX_RELAYED`, por debajo de las 16 conexiones por llave del proxy) y 2 aparte para `GET /_klav/status` (`STATUS_LANE`), así que `klav-forward status` nunca espera a una llamada;
  - una llamada espera un turno 10 s como mucho (`TURN_WAIT`), y como mucho 64 conexiones esperan a la vez (`MAX_WAITING`). Pasado eso, el reenviador responde él mismo `503` con `Klav-Error: klav_forward_busy` y `{error, message, next}`: nunca se queda colgada;
  - cuando el proxy cierra su lado (por ejemplo, tras sus 20 s sin petición en una conexión que un cliente guarda abierta), el reenviador cierra el lado local enseguida y el turno vuelve; si quien llama cierra su lado de envío, el proxy lo sabe, responde y cierra;
  - **al cerrar una conexión local** (tras la respuesta del proxy, tras su propio `503` o al pasar de `MAX_WAITING`), el reenviador termina su lado de envío y lee y descarta durante 1 s como mucho (`DRAIN`) lo que quien llama siga mandando, hasta que cierre el suyo. Un *socket* que se cierra con datos sin leer se reinicia (RST), y el reinicio puede llevarse una respuesta que quien llama aún no leyó. El turno y la conexión del canal vuelven antes de esa espera. Las conexiones que pasan de `MAX_WAITING` se cierran así hasta 64 a la vez; más allá, reciben el `503` sin esperar y su cierre puede reiniciarlas;
  - una conexión sin un byte en ninguno de los dos sentidos durante 240 s se cierra (`RELAY_IDLE`, más que los 60 s del servidor de Klav y los 120 s del proveedor que el proxy puede tardar). Una respuesta lenta que sigue llegando no se corta. Cada 5 minutos el reenviador pregunta `GET /_klav/status`, que cuenta como actividad, para que el proxy no termine por inactividad un sandbox que solo está callado. Si la respuesta es `klav_sandbox_revoked`, el reenviador sale (paso 6 de `up`).
- **Cuando no llega al proxy,** responde él mismo, después de leer la cabecera de la petición: `503` con `Klav-Error: klav_proxy_unreachable` y `{error, message, next}`, con el texto del ADR 0036 §10, y cierra la conexión.
- **Antes de arrancar,** `up` mira tres cosas, en este orden, sin conectarse al proxy por su cuenta:
  1. un reenviador de este directorio de estado que responda por este sandbox: `state.json` con el ID del paquete y, en su puerto, un `GET /_klav/status` que responde `200` con ese ID. Si lo hay, ya corre: `up` lo dice («already running… nothing to do»; con `--json`, `{"status": "running", sandbox, url}`) y sale con `0` sin reclamar. Si ese reenviador responde con un rechazo que lleva en `Klav-Error` un código de Klav (el sandbox revocado o vencido, los agentes en pausa, el proxy o el servidor sin responder, el reenviador ocupado), `up` lo dice como `status`, con su código. Cualquier otra cosa en ese puerto (una respuesta sin código de Klav, como el `404` de un servidor de desarrollo, una cortada o ninguna en 15 s, el plazo de conexión del reenviador más 5 s) no cuenta como reenviador: pasa al paso siguiente;
  2. si ningún reenviador responde, si el sandbox ya se reclamó desde aquí: su marca de reclamo (cualquier cosa salvo «sin archivo», también una que no se puede leer) o un `state.json` que lo nombra, que solo se escribe tras un reclamo con éxito. Así se ve también un directorio de antes de la marca, pero solo mientras su `state.json` siga ahí y se pueda leer: un reenviador que paró de forma normal lo borra, y uno que no se puede leer cuenta como ausente. Si es así, `up` responde `klav_forward_already_claimed` y sale con `1`: el paquete ya se usó desde aquí y otro reclamo terminaría el sandbox como un robo. El `next` manda a pedir un sandbox nuevo (`klav sandbox start`), nunca a otro `up`. El mensaje nombra el sandbox, nunca el paquete ni nada de su secreto. La marca se lee aunque el directorio no sea privado: una marca plantada solo puede hacer que `up` se niegue;
  3. solo de camino a un reclamo nuevo, que el directorio de estado, y `claimed/` si existe, sean privados de este usuario: suyos, y sin permiso de escritura para el grupo ni para otros. Si no, `up` responde `klav_forward_state_not_private` y sale con `1`, sin reclamar; el `next` dice cómo arreglar ese mismo directorio (`chmod 700` del que falla, el de estado o `claimed/`) y que esta ejecución no reclamó nada. Nunca dice que el paquete no se usó, porque no lo miró, ni manda al agente a otro directorio: otro `--state-dir` lo elige solo la persona, y solo si el paquete no se usó desde ningún sitio. Va después de los otros dos a propósito: un reenviador que ya corre en un directorio así no se rompe (`up` otra vez sigue diciendo que corre), y un paquete ya reclamado desde ahí, o desde un `claimed/` de otro usuario que este no puede leer, recibe `klav_forward_already_claimed`, nunca una invitación a reclamarlo desde otro directorio. Un directorio que `up` creó con #317 tiene el modo que daba la `umask` (0755 con la habitual, que pasa; 0775 con una `umask` de 002, que se rechaza).

  Solo cuenta como vivo un reenviador que responde, así que un `state.json` que quedó, un demonio muerto u otro programa en su puerto pasan al segundo paso: nada en el primero hace parecer sin reclamar un sandbox reclamado. Si `state.json` nombra a otro sandbox (otro `up` lo reescribió en el mismo directorio) o no se pudo guardar, un reenviador vivo de este sandbox no se ve desde aquí, y el mensaje lo dice así: ningún reenviador responde por él **desde este directorio de estado**.
- **La marca de reclamo** es `<estado>/claimed/<sandbox_id>`: JSON `{ "v": 1, "sandbox_id": "…", "at": <Unix ms> }`, con `at` el momento en que empezó a reclamar. No es secreta: nunca lleva el secreto, un *hash* de él ni el paquete. El archivo va con modo 0600, y `claimed/` y el directorio de estado con 0700 cuando `up` los crea; si ya existían, conservan su modo. **El directorio de estado tiene que ser privado de este usuario:** en uno donde otro usuario puede escribir, ese usuario puede borrar la marca (y un `up` posterior vuelve a reclamar, lo que el proxy toma por un robo) o plantar una para un ID de sandbox que conozca (y `up` se niega a arrancar). Por eso `up` rechaza uno que no lo es antes de un reclamo nuevo (paso 3), y el hijo lo vuelve a mirar antes de escribir la marca (`klav_forward_cannot_record` si no). La marca se escribe de una vez:
  - un archivo temporal nuevo (`O_EXCL`, con un nombre aleatorio, así que nada que estuviera ya en ese nombre se escribe a través), sincronizado, que se enlaza a su nombre solo si no hay otra marca. Donde el sistema de archivos no tiene enlaces duros, un `rename` tras comprobarlo; ahí dos `up` en el mismo instante (cada uno con su `--port`) pueden poner los dos su marca y reclamar los dos, porque un `rename` no ve el del otro. Un corte deja una marca entera o ninguna con ese nombre;
  - después se sincronizan `claimed/` y el directorio de estado, para que un apagón tras el reclamo no se lleve la marca ni `claimed/`. Si una de esas sincronizaciones falla, la marca puede no ser durable: el hijo no reclama (`klav_forward_cannot_record`) y quita la marca si la enlazó él. Si la marca queda (puesta con `rename`, o de otro intento), el `next` no dice que el paquete no se usó: dice dónde está y que solo la persona, si sabe que ningún otro `up` corrió con ese paquete, puede borrarla.

  Al leerla:
  - sin archivo, el sandbox no se reclamó desde aquí;
  - con `v: 1`, se reclamó;
  - con otro `v`, cuenta como reclamado y el mensaje dice el formato (de otra versión de `klav-forward`): nunca se lee como ausente;
  - un archivo que no se puede leer o no es una marca cuenta como reclamado.

  El hijo la escribe antes del primer byte del reclamo, porque una respuesta que no llega puede haber ligado ya la llave. Solo la borra si **ningún** intento escribió un byte de su petición (falló la conexión TCP o el *handshake* TLS en todos, o la dirección del paquete no sirve) y si la enlazó él: entonces el proxy no recibió nada, el paquete no se usó, y el `next` dice que `up` puede volver a correr cuando el proxy responda. Una marca puesta con el `rename` no se borra nunca: otro `up` en el mismo instante pudo poner la suya y estar reclamando con ella. Entonces el `next` dice que esta ejecución no usó el paquete, dónde queda la marca y que solo la persona, si sabe que ningún otro `up` corrió con él, puede borrarla; si no, hace falta `klav sandbox start`. Si algún intento llegó a escribir la petición, la marca queda para siempre. Un corte entre la marca y el reclamo (el hijo muere, la máquina se apaga) también la deja: el paquete queda gastado aunque no se haya reclamado, el lado prudente. Si no puede escribirla, no reclama: `klav_forward_cannot_record`, sale con `1` y el paquete sigue sin usar. La marca es del directorio de estado: otro usuario del sandbox, u otro `--state-dir`, no la ve.
- **`klav-forward status [--json]`** pregunta al proxy por el puerto local y sale con `0` si el sandbox está vivo, `5` si fue revocado, `6` si venció, `7` con los agentes en pausa y `1` en lo demás, con el `message` y el `next` del rechazo (`klav_forward_not_running` si no hay reenviador). Si ningún reenviador responde y el suyo salió porque el proxy revocó el sandbox, responde el rechazo que quedó en `ended.json`, con `5`.
- **`klav-forward env [--json]`** imprime las líneas de *shell* (solo URL de `127.0.0.1`). Con `--json`, una sola línea con lo mismo: `{"url": "http://127.0.0.1:PUERTO", "profiles": {"<perfil>": "<url>"…}, "env": {"KLAV_FORWARD_URL": …, "KLAV_FORWARD_<PERFIL>_URL": …}}` (`url` se llama igual que en `up --json`; un perfil cuyo nombre no da una variable falta en los tres, como en las líneas). Sin estado, sale con `1`: el texto de siempre en stderr, o con `--json` el JSON de `klav_forward_not_running` en stdout. La salida sin `--json` no cambió. Las variables no llevan valores de mentira; el único es el de la línea de `northflank login` que `klav sandbox start` da para un sandbox con el perfil `northflank`, después de `eval "$(klav-forward env)"` y con `--host "$KLAV_FORWARD_NORTHFLANK_URL"` ([cli.md](cli.md), `klav sandbox start`; ADR 0036 §5, decisión del 2026-11-16): el proxy quita ese token y pone el real, y el perfil tiene que dejar pasar `GET /v1/login` sin aprobación.
- **`klav-forward down [--state-dir DIR] [--json] [--if-other-package]`** suelta el sandbox en el proxy y para el reenviador de ese directorio de estado, que libera su puerto (nota del 2026-11-12 en el ADR 0036 §14):
  - **El socket de control.** Antes de responder a `up`, el hijo abre `<estado>/down.sock` (un *socket* Unix, 0600, en el directorio de estado, que tiene que ser privado de este usuario) y solo atiende a un proceso de su mismo uid, ni siquiera a *root*. `down` le manda una línea `{"v":1,"op":"down"}`, el reenviador responde `{"v":1,"op":"ready"}` y `down` confirma con `{"v":1,"op":"commit"}`. Solo con esa confirmación el reenviador deja de escuchar en su puerto, pide `POST /_klav/release` por el canal (§8.10) **una sola vez y con 10 s como mucho en total** (`RELEASE_TIMEOUT`, la conexión incluida, sin reintentos), borra su `state.json` y su *socket*, responde una línea con el resultado y sale. `down` nunca manda una señal ni confía en el PID de `state.json`, que tras un reinicio puede ser de otro proceso. El *socket* hace que parar el proceso pida el mismo usuario que una señal (un puerto de *loopback* lo dejaría a cualquier usuario del sandbox); soltar el sandbox, en cambio, ya lo puede pedir cualquier programa local por el puerto en claro (`POST /_klav/release`, arriba), y `down` no cambia eso. La confirmación hace que el resultado sea seguro en los dos lados: un `down` que se rinde antes de `ready` (5 s) nunca confirma, y una petición sin su confirmación nunca se atiende, aunque sus bytes sigan en el *socket* tras irse el cliente; una confirmada sí, aunque el cliente se vaya antes de la respuesta. Esto vale en Linux igual que en macOS. Tras confirmar, `down` espera la respuesta 20 s, más que los 10 s de la liberación. El reenviador lee cada conexión por separado, hasta 16 a la vez y hasta 10 s cada una (5 s para la petición y 5 s para la confirmación): unas pocas conexiones calladas no retienen a `down`. Con 16 abiertas a la vez, la siguiente se cierra en el acto; `down` vuelve a conectarse cada 100 ms durante 5 s y, si en ese tiempo no hay sitio, responde `klav_forward_cannot_stop` (código `1`), con un `next` que dice probar `down` otra vez en unos segundos. Un programa del mismo usuario que las mantenga ocupadas puede impedir `down` todo el tiempo que quiera, igual que podría parar el reenviador con una señal: el *socket* no protege contra el mismo usuario. El reenviador más nuevo de un directorio de estado toma el *socket*: uno anterior que siga vivo ahí ya no se para con `down`. Mientras el hijo todavía reclama, aún no hay *socket*, y `down` dice que no hay nada que parar. Si el hijo no puede abrir el *socket* (una ruta de más de 103 bytes en macOS o de 107 en Linux, por ejemplo), sigue sin él, lo dice en `forward.log` y `up` lo avisa en stderr: a ese reenviador `down` no lo puede parar ni soltar su sandbox, y responde `klav_forward_cannot_stop`; solo una señal lo para, sin soltarlo. Un `--state-dir` más corto lo evita.
  - **Lo que `down` comprueba.** Solo habla con un *socket* de un directorio de estado privado de su dueño, cuyo archivo y cuyo proceso son de ese mismo uid. Cuando el *socket* responde que el reenviador paró, `down` comprueba además que nada escucha ya en el puerto de la respuesta, ni el reenviador de `state.json` en el suyo; si alguno sigue ocupado, responde `klav_forward_cannot_stop` (código `1`) en vez de decir que el puerto quedó libre. Si quien lo ocupa es un reenviador más nuevo del mismo directorio de estado (otro `down` y otro `up` corrieron mientras tanto), lo dice, con su sandbox y con el resultado de la liberación del reenviador que sí paró. Si el reenviador cierra la conexión sin responder (otro `down` lo paró en ese mismo momento) o no confirma a tiempo, `down` mira el estado y el puerto como si no hubiera *socket*: dos `down` a la vez salen los dos con `0`, y el sandbox se suelta una sola vez. Solo si confirmó y no llegó respuesta en 20 s responde `klav_forward_cannot_stop` sin afirmar que el reenviador sigue vivo: puede estar parando o ya haber parado.
  - **El resultado** (`release` en `--json`): `released` (el proxy lo terminó con `released` y su plaza de `--max-live` queda libre; `logged` dice si el servidor de Klav ya lo tiene), `already_ended` (el proxy dijo `klav_sandbox_revoked` o `klav_sandbox_expired`: el emisor lo paró, venció o se revocó), `not_released` (el proxy no recibió la petición o la rechazó: el sandbox sigue vivo en el proxy, aunque nada lo puede usar, hasta `klav sandbox stop`, su TTL o 1 hora sin llamadas) o `unknown` (la petición salió y la respuesta no llegó a tiempo: el proxy termina el sandbox antes de avisar al servidor, así que lo más probable es que sí, y `klav sandbox ls` lo dice). En los cuatro el reenviador queda parado y el puerto libre. Con `--json`: `{"status": "stopped", "sandbox", "url", "release", "logged"?, "release_error"?}`, con el código y el mensaje del rechazo en `release_error` (`{"error", "message"}`), sin su `next`: era para una llamada que falló, y `down` no falló (un «para» ahí cortaría el *setup script* justo antes de su `up`).
  - **Sin reenviador** (sin directorio de estado, que no crea; uno vacío; un `state.json` cuyo PID murió o es de otro proceso; un *socket* que nadie atiende): sale con `0` y dice que no hay nada que parar (`{"status": "not_running", "message"}`), sin crear ni borrar nada. Un `state.json` que no se puede leer o no se entiende sale con `1` y `klav_forward_cannot_stop`: así no se sabe si algo corre. Para saber si el puerto lo tiene un reenviador sin *socket*, hace la misma comprobación que `up` (**Antes de arrancar**, paso 1): si en el puerto de `state.json` responde un reenviador, sale con `1` y `klav_forward_cannot_stop` (puede ser de otra versión de `klav-forward`), sin parar ni soltar nada; su `next` deja a la persona pararlo a mano. `klav_forward_cannot_stop` también sale si el reenviador recibió la petición y no respondió.
  - **Lo que queda después:** la marca de reclamo (el paquete ya se gastó: reclamarlo otra vez sería un robo para el proxy) y las líneas de *shell* (`/etc/profile.d/klav-forward.sh` o `env.sh`, sin secretos; el siguiente `up` las reescribe). Tras cualquier parada, con `down` o con una señal, el sandbox ya no se puede usar: la llave del canal solo vivía en la memoria del reenviador. **Un reenviador nuevo necesita siempre un paquete nuevo de `klav sandbox start`**, y `up` con ese paquete en el mismo puerto y el mismo directorio de estado funciona. Con el mismo paquete, `up` responde `klav_forward_already_claimed`.
  - **`--if-other-package`**, la primera línea del *setup script* de `klav sandbox start` desde el 2026-11-15 ([cli.md](cli.md), `klav sandbox start`; nota de esa fecha en el ADR 0036 §14), para solo el reenviador de **otro** paquete. Lee de `KLAV_SANDBOX` solo el ID del sandbox, igual que `up`, y nunca imprime, registra ni guarda nada más del paquete, tampoco en un error. Decide en este orden, sin contactar, soltar, escribir ni borrar nada antes: el paquete, el `state.json`, si este nombra el sandbox del paquete, la marca de reclamo de ese sandbox y, solo al final, lo de `down`:

    | Caso | Qué hace | Sale con | Línea (`status` en `--json`) |
    |---|---|---|---|
    | El `state.json` de este directorio de estado nombra el sandbox de `KLAV_SANDBOX` (el *script* corre otra vez con el mismo paquete) | Nada: ni el *socket*, ni la liberación, ni un archivo, esté su reenviador vivo, ocupado o muerto. El `up` siguiente hace lo mismo que sin esta línea: dice que ya corre; pasa el rechazo del proxy para ese sandbox con su código (`5` revocado o no permitido, `6` vencido, `7` con los agentes en pausa, `1` lo demás); o, si su reenviador murió, se niega con `klav_forward_already_claimed` (`1`) | `0` | «The forwarder of this state directory is for this package's sandbox «…» (…): left alone, nothing stopped.» (`same_package`, con `sandbox`) |
    | `KLAV_SANDBOX` no está, está vacía o no es un paquete | Nada: no sabe qué reenviador es el de este paquete. El `up` siguiente da su propio error | `0` | «KLAV_SANDBOX is not set, so …» o «KLAV_SANDBOX does not hold a Klav sandbox package, so … nothing stopped.» (`no_package`) |
    | El `state.json` no se puede leer | Nada, por lo mismo | `0` | «This state directory's state.json cannot be read (…), so … nothing stopped.» (`unreadable_state`) |
    | Ninguno de los anteriores, pero la marca de reclamo de este paquete está en este directorio de estado (cualquiera menos ninguna: una que no se lee o de otra versión cuenta, como en `up`). Es el caso de un paquete viejo repetido sobre el reenviador de uno más nuevo, o del reenviador de este paquete vivo sin `state.json` | Nada: el paquete ya se gastó aquí, así que el `up` siguiente se niega con `klav_forward_already_claimed` (`1`), igual que sin esta línea, y el reenviador que corre sigue | `0` | «This package's sandbox (…) was already claimed from this state directory: nothing stopped; `klav-forward up` says what to do.» (`already_claimed_here`) |
    | No hay `state.json`, o nombra otro sandbox, y este paquete no se reclamó aquí | Lo mismo que `down` sin la opción, en todos los casos de arriba: suelta ese sandbox y para su reenviador, o no hay nada que parar | lo de `down` | lo de `down` |

    En el último caso termina pronto (10 s como mucho si el proxy no responde, 15 s si otro programa tiene el puerto de un `state.json` viejo y no contesta) y, salvo `klav_forward_cannot_stop`, con `0`. Ese `1` viene del reenviador de otro paquete, que tiene el puerto: con `set -e` para el *script* antes de `up`, que con el puerto ocupado tampoco arrancaría. Sin la opción, `down` no mira `KLAV_SANDBOX` y para el reenviador de este mismo paquete: en un *setup script* que se repite, el `up` siguiente se negaría con `klav_forward_already_claimed`. Un `klav-forward` anterior a esta opción sale con `2` (`unexpected argument '--if-other-package' found`, o `unrecognized subcommand 'down'` si es anterior a `down`), sin tocar nada.
- **`up` sale** con `0` al reclamar o si su reenviador ya corre, `1` con `klav_forward_already_claimed`, `klav_forward_state_not_private` o `klav_forward_cannot_record`, `2` sin paquete o con uno que no es un paquete (sin repetirlo) o si no puede crear ni alcanzar su directorio de estado (el `next` no ofrece otro: puede ser donde otro usuario ya reclamó este paquete, y entonces hace falta `klav sandbox start`), y con los códigos de `status` si el proxy rechaza el reclamo.

### 8.12 Solicitudes de secreto

ADR [0046](decisiones/0046-agent-secret-requests.md). Un agente activo que no sea un proxy de credenciales pide a la persona que añada un elemento que falta (`mode: "create"`) o actualice un campo secreto de uno existente (`mode: "update"`). La propuesta viaja cifrada con HPKE a la identidad X25519 de la cuenta (`proposal_blob`, tipo `0x25`, especificación §13.14); por estas rutas nunca pasa un valor secreto.

**El agente** (peticiones firmadas, §8.2):

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `POST /v1/agent/secret-requests` | `{ id, mode, target_item_id?, reason, proposal_digest, proposal_blob }` | `202 { request_id, expires_at }` · `400` · `403` · `404` · `409` · `429` |
| `GET /v1/agent/secret-requests/{id}?wait=N` | — | `SecretRequestInfo` (sin `proposal_blob`; con `wait`, *long-poll* de hasta 30 s, como §8.3) |

- El agente elige `id` (`SecretRequestId`) antes de sellar `proposal_blob`, porque `id` va en el contexto HPKE (especificación §13.14). Un `id` ya usado responde `409`.
- Un agente cuyo grant lo hace proxy de credenciales (perfiles, emisores o reglas `proxy`) recibe `403`. Cualquier otro agente activo puede pedir secretos aunque su grant no tenga `create` ni `update`.
- `proposal_digest` mide 32 bytes; `proposal_blob` lleva la cabecera `0x01 0x25` y mide entre 51 bytes y 8 KiB (`400` si no). El cuerpo entero mide como mucho 16 KiB (`400`). `reason` es obligatorio (1–500 caracteres sin caracteres invisibles).
- Con `mode: "create"`, `target_item_id` debe faltar (`400`). Con `mode: "update"`, `target_item_id` es obligatorio (`400`) y debe ser un elemento vivo (sin papelera, sin purgar, en bóveda activa) dentro de un proyecto del grant del agente; fuera del grant o inexistente responden ambos `404` (T236).
- Como máximo 5 solicitudes pendientes por agente (`429`). Cada solicitud vence a la hora (`expires_at`).
- Con APNs, cada solicitud nueva avisa a los teléfonos con `type: "secret_request"` y el ID (sin texto ni motivo, §3), y `GET /v1/events` emite el evento SSE `secret_request` (`{ request_id, status }`).

**La persona:**

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `GET /v1/secret-requests` | — | `{ secret_requests: [SecretRequestInfo] }` (las 100 más recientes) |
| `GET /v1/secret-requests/{id}` | — | `SecretRequestInfo` |
| `POST /v1/secret-requests/{id}/decide` | `{ decision, signature, decided_at }` | `SecretRequestInfo` |

- **`SecretRequestInfo`:** `id`, `agent_id`, `agent_name`, `mode` (`create` · `update`), `target_item_id?`, `reason`, `proposal_digest`, `proposal_blob?` (presente solo mientras está `pending` para los dispositivos de la persona), `status` (`pending` · `fulfilled` · `denied` · `expired`), `created_at`, `expires_at`, `decided_at?`, `decision?` y `signature?`.
- **`decide`:** comprueba que la solicitud siga `pending` y sin vencer (`409`), que el agente siga activo (`409`), que `decided_at` esté a ±5 min (`400`), que `decision` sea un `SecretRequestDecision` válido para esa solicitud y ese agente (`400`), y que `signature` verifique con la identidad de la cuenta (especificación §13.14, `400`). Al guardar la decisión borra `proposal_blob` (`NULL`) en la misma transacción.
- **Limpieza y revocación:** al revocar el agente o al vencer el plazo de una hora (en consultas o en el barrido periódico), las solicitudes pendientes pasan a `expired` y pierden `proposal_blob`.
- **En la bitácora (§9):** `secret_request.created` (actor `agent`, con `secret_request_id`, `proposal_digest`, `item_id?`, `reason` y la petición firmada **sin cuerpo**, para no conservar `proposal_blob`) y `secret_request.decided` (actor `person`, con `device_id`, `agent_id`, `secret_request_id`, `proposal_digest`, `vault_id?`, `project_id?`, `item_id?`, `outcome` = `fulfilled` o `denied`, `decided_at`, `signed` = `decision` y `account_signature`).

## 9. Bitácora

Cada cuenta tiene una cadena de eventos con hash (especificación §13.7). El
servidor añade un evento por cada decisión sobre un agente **antes** de
responder, así que ningún agente recibe un secreto sin que quede
registrado.

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `GET /v1/audit?after=&limit=` | — | `{ entries: [ { seq, event, hash } ], head_seq }` (hasta 1000 por página, en orden) |
| `GET /v1/audit/heads` | — | `{ heads: [ { seq, hash, signature, device_id, signed_at } ] }` (las 100 más recientes y la última de cada dispositivo, de la más nueva a la más vieja; como mucho 1 100) |
| `POST /v1/audit/heads` | `{ seq, hash, signature }` | `204` (no guarda nada si el dispositivo ya tiene esa cabeza o una posterior) · `409` si no coincide con la cadena · `400` firma inválida |
| `POST /v1/audit/person` | `{ action, item_id, agent_id?, task_id? }` | `204` · `400` acción que no es de persona, campos de más, o `agent_id` sin `task_id` (o al revés, o de otro agente) · `404` elemento o tarea ajenos o inexistentes · `429` |

- **`event`** son los bytes JSON de un `AuditEvent`:
  - `v`, `seq`, `at`, `actor` (`person` · `agent`), `device_id?`, `agent_id?`;
  - `action`: `agent.registered`, `agent.granted`, `agent.denied`,
    `agent.revoked`, `agent.access`, `agent.create`, `agent.update`,
    `agent.trash`, `agent.ask`, `approval.decided`, `task.requested`,
    `task.decided`, `task.ended`, `rotate.started`, `rotate.confirmed`,
    `rotate.cancelled`, `item.created`, `item.updated`, `item.trashed`,
    `item.restored`, `item.purged`, `project.rotated`, `passkey.used`,
    `agents.paused`, `agents.resumed`, `sandbox.issued`, `sandbox.claimed`,
    `sandbox.revoked`, `sandbox.revoke_requested`, `sandbox.store_reset`,
    `secret_request.created` o `secret_request.decided`;
  - `vault_id?`, `project_id?`, `item_id?`, `permission?`;
  - `outcome?`: `allow`, `ask` o `deny` (la política), o `approve`/`deny`
    (una decisión);
  - `reason?` y `domain?` (lo que declaró el agente), `method?` y `path?`
    (solo en un `agent.access` de `proxy`, lo que firmó el agente),
    `approval_id?`,
    `task_id?` (la tarea del evento, o la que dejó pasar el uso),
    `lease_until?`, `decided_at?`, `until?`; en `task.ended`, `outcome` dice
    quién la terminó (`person`, `agent`, `expiry` o `revocation`). En
    `agents.paused` y `agents.resumed`, `agent_id` es el agente (ninguno:
    todos), `decided_at` el `at` firmado y `until` el fin firmado (solo en
    una pausa que lo tiene);
  - `alerts`: `first_use` (primer uso de los secretos de ese elemento por
    ese agente), `burst` (20 o más accesos en un minuto) y `denied`;
  - `agent_proof?`: la petición firmada del agente (§8.2), con su cuerpo si
    mide hasta 16 KiB. `POST /v1/agent/access`, `POST /v1/agent/tasks`,
    `POST /v1/agent/tasks/{id}/end`, `POST /v1/agent/rotations` y
    `POST /v1/agent/rotations/{id}/confirm` (y `/cancel`) y las tres rutas
    de §8.8 rechazan con `400` un cuerpo mayor, para que su evento siempre
    lo lleve (ADR 0030 §4);
  - `signed?` y `account_signature?`: los bytes que firmó la cuenta (grant,
    solicitud decidida, decisión de una tarea o revocación) y la firma. La
    revocación y la pausa no llevan `signed`: su mensaje se rehace con los
    campos del evento (especificación §13.6 y §13.9);
    `task_request?`, en `task.decided`, la solicitud de la tarea, para
    comprobar la firma con ese evento solo (vacía en una tarea ofrecida). El fin de una tarea por la
    persona lleva su firma (`task-end`); el vencimiento lo atestigua solo el
    servidor.
- Los lectores ignoran campos desconocidos: el hash cubre los bytes
  guardados.
- **`POST /v1/audit/person`** ([ADR 0020](decisiones/0020-passkeys.md) §10)
  registra lo que solo pasó en un dispositivo de la persona. Hoy la única
  acción es `passkey.used`: iniciar sesión con una passkey firma en el
  dispositivo y no escribe nada en el servidor.
  - Solo con la sesión de un dispositivo; un agente no llega (`401`).
  - El elemento tiene que estar en una bóveda de la cuenta y sin purgar. El
    servidor añade `vault_id`, `project_id` y `device_id`; `actor` es
    `person`.
  - `agent_id` y `task_id` van juntos, cuando un agente usó la passkey dentro
    de su tarea (§9 del ADR): la tarea es de la cuenta y de ese agente.
  - Sin sitio: el evento no lleva `rp_id` ni `domain`.
  - Además del límite de la cuenta, 60 por minuto por dispositivo (ráfaga de
    30).
  - Lo atestigua solo el servidor, como los cambios de la persona
    (modelo de amenazas, riesgo 23).
- La razón y el dominio van **en claro**: el servidor los necesita para
  mostrar la solicitud y calcular alertas (modelo de amenazas, T20).
- `klav log verify` recorre la cadena, comprueba las firmas y las cabezas
  firmadas y sube una cabeza nueva. Lo que exige a cada evento (la tabla de
  acciones, los campos sacados de lo firmado, las llaves de agente avaladas
  por la cadena, los nonces y la ventana de tiempo) está en la
  especificación §13.7. Cada página debe empezar en `after + 1`, sin huecos. Una cabeza solo se acepta si su hash es
  el guardado en esa posición y la firma verifica con la identidad de la
  cuenta.
- `GET /v1/audit/heads` trae las 100 cabezas más recientes de la cuenta y,
  además, la última de cada dispositivo (la de `seq` más alto, no la que
  subió al final), así que un dispositivo que verifica a menudo no saca de
  la lista la cabeza de otro. Una cuenta no tiene
  límite de dispositivos (cada instalación nueva suma uno, y los revocados
  se quedan), así que la respuesta lleva como mucho 1 100 cabezas: las 100
  más recientes y la última de los 1 000 dispositivos cuya última cabeza es
  más nueva. Si hay más, las que faltan son las de los dispositivos que
  llevan más tiempo sin firmar. Un servidor anterior trae solo las 100 más
  recientes.
- `POST /v1/audit/heads` responde `204` sin guardar nada si el dispositivo
  ya subió esa cabeza o una posterior: verificar en bucle no hace crecer la
  tabla. Una cabeza en la misma posición con otro hash no llega a ese
  punto: la ruta la compara antes con la cadena guardada (`409`). Dos
  subidas de la misma cabeza en el mismo instante pueden guardarse las dos,
  lo que solo deja una fila repetida. Las filas que un servidor anterior ya
  guardó repetidas no se borran.

## 10. Fuera de esta versión

Estas funciones llegan en fases posteriores (ver el [roadmap](roadmap.md)):

- compartir bóvedas con otras cuentas;
- cambio de contraseña y rotación del Secret Key;
- paginación de `changes`, cuotas por cuenta y almacenamiento S3.
