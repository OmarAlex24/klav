# Sitio web y lista de espera (`klav.dev`)

La página de Klav y la lista de espera viven en [`apps/web`](../apps/web).
La lista es la cola de invitaciones de la beta gratuita de `api.klav.dev`
([ADR 0048](decisiones/0048-invite-beta-and-distribution.md) §4): mientras
queden lugares, el sitio la manda sola por correo ([ADR
0050](decisiones/0050-auto-beta-invites.md), §3, «Invitaciones automáticas»);
si no, Omar la manda a mano (§3). Es un servicio aparte de `klav-server`: no toca la
bóveda, no comparte base de datos y no tiene dependencias de npm.

| Archivo | Qué es |
|---|---|
| `public/index.html` | La página: HTML, CSS y JS en línea; textos en inglés y español |
| `public/fonts/` | Geist, Geist Mono y Departure Mono, copiadas de la extensión (OFL) |
| `public/og.png` | La imagen para redes (1200×630); su fuente es `tools/og.html` |
| `public/privacy/index.html` | La política de privacidad, en inglés y español en la misma página y sin JavaScript, servida en `/privacy` y `/privacy/`. Su texto es el de [privacidad.md](privacidad.md) |
| `server.mjs` | Servidor: `node:http` y `node:sqlite` (Node ≥ 22.13) |
| `entrypoint.sh`, `Dockerfile` | La imagen para Railway |
| `test/server.test.mjs` | Pruebas con `node:test` |
| `test/auto-invite.test.mjs` | Pruebas de Turnstile y de las invitaciones automáticas, contra *mocks* locales de `klav-server`, Cloudflare Email Sending y `siteverify` |

El diseño sigue [`diseno-visual/README.md`](diseno-visual/README.md) §7,
«Sitio web». Qué afirma la página y de dónde sale cada cosa está en §6. Los
docs públicos son otro sitio, en [`apps/docs`](../apps/docs): §7.

## 1. En local

```sh
node --disable-warning=ExperimentalWarning apps/web/server.mjs
# klav-web on http://0.0.0.0:8080 · db apps/web/data/waitlist.db · export off · open nothing
```

- `PORT` (8080) y `HOST` (`0.0.0.0`) cambian dónde escucha.
- `KLAV_WEB_DB` es la ruta del SQLite. Por defecto, `apps/web/data/waitlist.db`.
  `apps/web/data/` está en `.gitignore`.
- `KLAV_WEB_ADMIN_TOKEN` activa la exportación y `mark-invited` (§3). Sin él,
  las dos responden `404`.
- `KLAV_WEB_TRUST_PROXY=1` toma la IP del cliente de `X-Real-IP` para el
  límite de intentos. Solo tiene sentido detrás de Railway; la imagen ya lo
  trae puesto.
- `KLAV_WEB_OPEN` enciende las descargas y los enlaces que hoy llevarían a
  un sitio privado (§2, «Descargas»): una lista separada por comas o espacios con `repo`
  (los enlaces al repositorio), `docs` (los enlaces a `docs.klav.dev`),
  `mac`, `chromium`, `firefox`, `linux` e `iphone`. Sin ella, todo está
  apagado.
- `KLAV_WEB_TESTFLIGHT_URL` es el enlace público de TestFlight
  (`https://testflight.apple.com/join/…`). `iphone` solo se enciende con él.
- `KLAV_TURNSTILE_SITE_KEY` y `KLAV_TURNSTILE_SECRET` encienden Cloudflare
  Turnstile en el formulario (§2); hacen falta los dos.
  `KLAV_TURNSTILE_VERIFY_URL` cambia la URL de `siteverify`, para pruebas.
- `KLAV_BETA_AUTO_CAP` (0 por defecto: solo lista de espera) y las variables
  de §3, «Invitaciones automáticas», encienden las invitaciones automáticas.

Un valor que falta o está mal escrito deja apagado lo suyo y lo dice una línea
del registro con el nombre de la variable, nunca su valor. La línea de
arranque termina en `turnstile on|off · auto invites on, cap N|off`.

Abrir `public/index.html` directamente (`file://`) también funciona, salvo el
formulario, que necesita el servidor. `?lang=es` y `?theme=dark` fuerzan el
idioma y el tema para capturas.

Pruebas:

```sh
node --test apps/web/test/*.test.mjs
```

En CI corren dentro de la tarea `extension`, que ya prepara Node 22.

## 2. La lista de espera

`POST /api/waitlist` con `{"email": "...", "lang": "en" | "es"}`.

- **Qué se guarda:** el correo (en minúsculas), el idioma de la página y la
  fecha. Al mandar la invitación, `mark-invited` (§3) o el envío automático
  añaden cuándo se mandó y una nota (`auto-beta` en el automático). Nada más:
  ni IP, ni navegador, ni cookies. La página no lleva analítica, y no carga
  nada de fuera salvo el *script* de Turnstile cuando está encendido.
- **Sin invitaciones automáticas, la misma respuesta para un correo nuevo y
  uno repetido** (`200 {"ok":true}`), para que el formulario no sirva para
  averiguar quién se apuntó.
- **Con ellas** (§3), la respuesta lleva `status`: `invited` (la invitación
  salió por correo), `already_invited` (a ese correo ya se le mandó una
  automática; no se llama al servidor ni se manda otra) o `waitlisted` (no
  quedan lugares, el límite por IP o un fallo de `klav-server` o de
  Cloudflare). `already_invited` revela que a ese correo ya se le mandó una:
  es el riesgo residual 106 del [modelo de amenazas](modelo-de-amenazas.md)
  (ADR 0050 §4).
- **Trampa para bots:** un campo `website` oculto. Si llega con algo, la
  respuesta es la misma que la de un correo que espera en la lista (`200
  {"ok":true}`, o con `"status":"waitlisted"` si las invitaciones
  automáticas están encendidas) y no se guarda nada.
- **Cloudflare Turnstile** (opcional, con `KLAV_TURNSTILE_SITE_KEY` y
  `KLAV_TURNSTILE_SECRET`): el servidor cambia el marcador `<!--turnstile-->`
  del formulario por el *widget* y su *script*, y la CSP de `/` gana
  `https://challenges.cloudflare.com` en `script-src` y en un `frame-src`
  nuevo; sin Turnstile, la CSP no cambia. La petición lleva
  `turnstile_token`, que se comprueba antes que la trampa: sin él, `400
  turnstile_required`; si no pasa, `403 turnstile_failed`; si `siteverify`
  falla o no responde, `503 turnstile_unavailable` (se cierra, no se guarda
  nada). No se le manda la IP del cliente. La página reinicia el *widget*
  tras cada intento, porque cada token sirve una vez.
- **Límites:** solo `application/json` (`415` si no), 2 KB por petición
  (`413`), 5 intentos cada 10 minutos por IP (`429` con `Retry-After`; la
  cuenta vive en memoria y nunca en disco) y nada desde otro origen (`403` si
  `Origin` no es el propio sitio).
- **Esquema 2:** una tabla `waitlist (id, email UNIQUE COLLATE NOCASE, lang,
  created_at, invited_at, note)` con `PRAGMA user_version = 2`. `invited_at`
  (fecha ISO 8601) y `note` son `NULL` hasta que `mark-invited` los pone; una
  fila sin `invited_at` está pendiente. El servidor se niega a abrir una base
  con un esquema más nuevo que el suyo.
  - **De 1 a 2:** al arrancar, en una sola transacción, `ALTER TABLE waitlist
    ADD COLUMN invited_at TEXT`, `ADD COLUMN note TEXT` y `PRAGMA user_version
    = 2`. Una base nueva pasa por el esquema 1 y llega al 2 en la misma
    apertura. Cada columna se añade solo si falta, así que volver a subir
    después de una vuelta atrás no falla.
  - **Volver a una versión anterior de `klav-web`:** la anterior se niega a
    abrir una base con el esquema 2. Las columnas son aditivas, así que basta
    con bajar el número a mano, dentro del contenedor (`railway ssh --service
    klav-web`), antes de desplegar la versión vieja:

    ```sh
    node --disable-warning=ExperimentalWarning -e '
    const { DatabaseSync } = require("node:sqlite");
    const db = new DatabaseSync("/data/waitlist.db");
    db.exec("PRAGMA user_version = 1");
    '
    ```

    Las columnas se quedan, con lo que tenían. La versión vieja no las lee ni
    las exporta, y la nueva, al volver, las encuentra y solo sube el número.

El resto de rutas: `GET /`, `GET /privacy` (y `/privacy/`), una lista fija de archivos (las tres fuentes y
`og.png`) y las descargas (abajo); cualquier otra cosa es `404`. `GET /healthz` responde `ok`.

**Descargas.** Los archivos son los de la última *release* de GitHub, con
los nombres fijos de [releasing.md](releasing.md) §1. El sitio no los sirve:
redirige con un `302` y `Cache-Control: no-store`, y solo lo que
`KLAV_WEB_OPEN` enciende. Así, mientras el repositorio sea privado, ninguna
de estas rutas de descarga lleva a GitHub. Los enlaces de la página al
repositorio van entre `<!--open:repo-->` y `<!--/open:repo-->`, así que,
con `repo` apagado, ningún enlace de `klav.dev` lleva a GitHub; una prueba
lo comprueba. Con `repo` apagado, el pie dice «Open source when it
launches» en lugar de «Open source», y el botón de la portada lleva a
«Downloads» en lugar de a GitHub. Otra prueba comprueba que cada marcador
nombra un interruptor de `OPENABLE`, tal como lo lee `renderPage`.

| Ruta | Se enciende con | Encendida, redirige a | Apagada |
|---|---|---|---|
| `/download/mac` | `mac` | `…/releases/latest/download/Klav.dmg` | `302` a `/#download` |
| `/releases/mac/appcast.xml` | `mac` | `…/releases/latest/download/appcast.xml` | `404` (es para Sparkle, no para personas) |
| `/download/extension/chromium` | `chromium` | `…/klav-extension-chromium.zip` | `302` a `/#download` |
| `/download/extension/firefox` | `firefox` | `…/klav-extension-firefox.xpi`, el `.xpi` que firmó Mozilla | `302` a `/#download` |
| `/download/linux` | `linux` | `…/klav-linux-x86_64.tar.gz` | `302` a `/#download` |
| `/download/checksums` | cualquiera de los cuatro anteriores | `…/SHA256SUMS` | `302` a `/#download` |
| `/download/iphone` | `iphone` y `KLAV_WEB_TESTFLIGHT_URL` | el enlace público de TestFlight | `302` a `/#download` |
| `/download`, `/download/` | — | `/#download` | `/#download` |

Solo una ruta de la tabla mira el método: con otro que no sea `GET` o `HEAD`
responde `405` (`Allow: GET, HEAD`). Cualquier otra ruta bajo `/download/` es
el mismo `404` que una ruta desconocida, con las mismas cabeceras, sea cual
sea el método. El `404` del *appcast* apagado lleva además `Cache-Control:
no-store`: un `404` se puede guardar en caché por defecto, y ninguna caché
debe seguir sirviéndolo el día que se enciende `mac`.

Cada build de la app de Mac trae `https://klav.dev/releases/mac/appcast.xml`
como `SUFeedURL` ([macos.md](macos.md) §6): esa ruta no puede cambiar.

- **Un valor mal escrito no tumba el sitio.** Un nombre que no se conoce, o
  `iphone` sin un enlace de TestFlight válido, se queda apagado y lo dice una
  línea del registro. La línea de arranque dice qué quedó encendido
  (`open mac,firefox` u `open nothing`).
- **La página sigue al interruptor.** Lo que va entre
  `<!--open:NOMBRE-->` y `<!--/open:NOMBRE-->` solo sale si `NOMBRE` está
  encendido; lo que va entre `<!--closed:NOMBRE-->` y `<!--/closed:NOMBRE-->`,
  solo si está apagado. El servidor lo resuelve al arrancar, antes de calcular
  la CSP. Los marcadores no van dentro del `<script>` ni del `<style>`, así
  que la CSP no cambia con el interruptor; las pruebas lo comprueban.

**Para encender las descargas,** el día de la primera *release*, en este
orden. Lo hace solo Omar ([releasing.md](releasing.md) §2, paso 9, y §4):

1. Publica la *release* de GitHub, no como *pre-release*: `releases/latest`
   se salta las *pre-releases*.
2. Haz público el repositorio.
3. Comprueba que GitHub ya sirve el archivo: `curl -sIL
   https://github.com/OmarAlex24/klav/releases/latest/download/appcast.xml`
   tiene que terminar en `200`.
4. Pon el dominio `docs.klav.dev` en el sitio de los docs (§7, «Poner
   `docs.klav.dev`») y comprueba que responde `200`: con `docs` encendido,
   la sección de descargas y los pasos de instalación enlazan ahí.
5. Solo entonces, en Railway, *Variables* del servicio `klav-web`: pon
   `KLAV_WEB_OPEN` (y `KLAV_WEB_TESTFLIGHT_URL` para el iPhone), guarda y
   despliega los cambios en espera (*staged changes*). Railway no aplica una
   variable hasta ese despliegue: *Adding, updating, or removing variables,
   results in a set of staged changes that you must review and deploy, in
   order to apply them.* Después, `curl -sI
   https://klav.dev/download/mac` tiene que responder `302` con la URL de
   GitHub.

Con `mac` encendido antes del paso 3, cada `/download/…` y cada app de Mac
instalada siguen un `302` hasta un `404` de GitHub, y la app de Mac no lo dice
(releasing.md §5).

**Cabeceras:** cada página HTML sale con su propia CSP sin `unsafe-inline`. El
servidor calcula al arrancar el `sha256` de los `<script>` (o `'none'` en
`/privacy`, que no lleva) y del `<style>` de cada página, así que editarla no
exige tocar la CSP. Por la misma razón, las páginas no pueden llevar atributos
`style="…"` ni manejadores `on…=`: las pruebas lo comprueban. Además: `nosniff`,
`Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`
y HSTS.

## 3. Exportar la lista y marcar las invitaciones

Las dos rutas piden `Authorization: Bearer $KLAV_WEB_ADMIN_TOKEN`. Sin
`KLAV_WEB_ADMIN_TOKEN` en el servicio responden `404`; sin token o con uno que
no coincide, `401` (la comparación es de tiempo constante).

### Exportar

```sh
curl -fsS -H "Authorization: Bearer $KLAV_WEB_ADMIN_TOKEN" \
  https://klav.dev/api/waitlist/export -o klav-waitlist.csv
```

Devuelve `email,lang,created_at,invited_at,note` en CSV, en el orden en que se
apuntaron. Con `?pending=1` (`/api/waitlist/export?pending=1`) solo salen las
filas sin `invited_at`; cualquier otro valor devuelve la lista entera. Una
celda que empiece por `=`, `+`, `-` o `@`, la nota incluida, sale con un `'`
delante para que una hoja de cálculo no la ejecute.

### Marcar como invitados

```sh
curl -fsS -X POST https://klav.dev/api/waitlist/mark-invited \
  -H "Authorization: Bearer $KLAV_WEB_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["ana@example.com", "bo@example.com"], "note": "waitlist"}'
# {"marked":2,"unknown":0}
```

- **Cuerpo:** `{"emails": [...], "note": "..."}`, solo `application/json`
  (`415` si no) y hasta 16 KB (`413`). Entre 1 y 200 correos (`400
  too_many_emails` con más, `400 emails_required` sin ninguno); todos tienen
  que ser correos (`400 invalid_email`, y no se marca ninguno). `note` es
  opcional, una cadena de hasta 200 caracteres (`400 invalid_note`).
- **Qué hace:** en una transacción, pone `invited_at` a la hora del servidor
  en cada fila de la lista con ese correo (sin distinguir mayúsculas ni
  espacios alrededor). Un correo repetido en la petición cuenta una vez. Una
  fila ya marcada se vuelve a marcar con la fecha nueva. Sin `note`, o con una
  vacía, la nota que hubiera se queda; con una, la reemplaza.
- **Respuesta:** `200 {"marked": n, "unknown": m}`. `unknown` son los correos
  que no están en la lista: no se añaden.
- **No mira `Origin`:** se llama con `curl`, y el token es la única
  autenticación. Por eso la ruta no existe sin token configurado.

### Mandar las invitaciones (a mano)

No hay infraestructura de correo: Omar manda cada invitación desde su propio
buzón ([ADR 0048](decisiones/0048-invite-beta-and-distribution.md) §4). Antes
de cada tanda, la regla de tamaño del ADR 0048 §3.3 dice cuántas plazas caben
en el volumen.

1. **Los pendientes:**

   ```sh
   curl -fsS -H "Authorization: Bearer $KLAV_WEB_ADMIN_TOKEN" \
     "https://klav.dev/api/waitlist/export?pending=1" -o pendientes.csv
   ```

2. **Un código por persona,** dentro del servidor (`railway ssh --service
   klav-server`):

   ```sh
   klav-server invite create --email ana@example.com --expires 30d --note waitlist
   ```

   Imprime el código una vez, solo en la salida estándar. Va ligado a ese
   correo, sirve una vez y caduca a los 30 días. No lo pegues en ningún otro
   sitio que el correo.
3. **El correo,** desde el buzón de Omar, con la plantilla de abajo en el
   idioma de la columna `lang` (inglés si está vacía).
4. **Marcarlos,** con los correos que de verdad salieron:

   ```sh
   curl -fsS -X POST https://klav.dev/api/waitlist/mark-invited \
     -H "Authorization: Bearer $KLAV_WEB_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"emails": ["ana@example.com"], "note": "waitlist"}'
   ```

   `unknown` tiene que ser `0`; si no, un correo está mal escrito.

Si alguien escribe que su código no funciona o caducó: `klav-server invite
ls` dice si se usó, y uno nuevo es repetir los pasos 2 a 4.

**Plantilla en inglés**

```text
Subject: Your invite to the Klav beta

Hi,

You asked for an invite to the Klav beta, and here it is. It works once, only
with this email address, until <date, 30 days from today>:

    <KLAV-…>

1. Install Klav for Mac from https://klav.dev/#download (on Linux, the
   command line from the same page).
2. Create your account on klav.dev: in the Mac app, "Set up this Mac" →
   "Create an account"; on the command line, `klav signup`. Use this email
   address, and paste the code when Klav asks for it.
3. The docs are at https://docs.klav.dev/.

Our server is free while the beta lasts. When it ends, it becomes a plan of
20 USD a year, and we'll tell you at least 60 days before you'd pay
anything. Running your own server stays free.

Just reply to this email if anything doesn't work.

Omar
```

**Plantilla en español**

```text
Asunto: Tu invitación a la beta de Klav

Hola:

Pediste una invitación a la beta de Klav, y aquí está. Sirve una vez, solo con
este correo, hasta el <fecha, a 30 días de hoy>:

    <KLAV-…>

1. Instala Klav para Mac desde https://klav.dev/#download (en Linux, la línea
   de comandos, desde la misma página).
2. Crea tu cuenta en klav.dev: en la app de Mac, «Configurar este Mac» →
   «Crear una cuenta»; en la línea de comandos, `klav signup`. Usa este
   correo y pega el código cuando Klav te lo pida.
3. Los docs están en https://docs.klav.dev/.

Nuestro servidor es gratis mientras dure la beta. Cuando termine pasa a ser un
plan de 20 USD al año, y te avisamos por lo menos 60 días antes de cobrarte
nada. Montar el tuyo sigue siendo gratis.

Si algo no funciona, contesta a este correo.

Omar
```

### Invitaciones automáticas

Mientras queden lugares, el sitio manda la invitación solo, en cuanto alguien
se apunta ([ADR 0050](decisiones/0050-auto-beta-invites.md)):

1. Pide a `klav-server` una invitación con `POST
   /v1/internal/invites/auto` (`{"email"}`, con `Authorization: Bearer
   $KLAV_AUTO_INVITE_TOKEN`), por la red privada de Railway. El servidor la
   crea ligada al correo, de un uso, de 14 días y con la nota `auto-beta`, y
   responde `201 {id, code, expires_at}` (`expires_at` en milisegundos Unix),
   `409 already_invited` o `409 cap_reached`.
2. La manda con Cloudflare Email Sending, en texto plano y en el idioma de la
   página: el código, que sirve una vez y solo con ese correo, la fecha en que
   caduca, la descarga para Mac, los pasos («Configurar este Mac» → «Crear una
   cuenta», o `klav signup`), los docs, las condiciones de la beta y
   `support@klav.dev`.
3. Si Cloudflare la acepta, pone `invited_at` y `note = 'auto-beta'` en la
   fila. Si no (un error, `success: false`, un rebote permanente o un
   destinatario suprimido), revoca la invitación con `POST
   /v1/internal/invites/auto/{id}/revoke`, que libera el lugar, y la fila
   queda pendiente para el ciclo a mano.

**Topes:** el sitio deja de pedir invitaciones cuando tiene
`KLAV_BETA_AUTO_CAP` filas `auto-beta` con `invited_at`, y el servidor tiene
su propio `KLAV_AUTO_INVITE_MAX`, que cuenta las invitaciones `auto-beta` no
revocadas. Además, cada IP recibe como mucho 2 invitaciones automáticas por
hora; las demás direcciones de esa IP esperan en la lista. Una invitación
automática que caduca sin usarse sigue ocupando su lugar hasta que Omar la
revoca (`klav-server invite ls`, `invite revoke`).

**Variables de `klav-web`** (todas, o se queda en solo lista de espera):

| Variable | Qué es |
|---|---|
| `KLAV_BETA_AUTO_CAP` | Cuántas invitaciones automáticas manda el sitio; `0` las apaga |
| `KLAV_AUTO_INVITE_URL` | `klav-server` por la red privada: `http://klav-server.railway.internal:8080` |
| `KLAV_AUTO_INVITE_TOKEN` | El mismo token que el de `klav-server`, de al menos 32 bytes |
| `KLAV_CF_ACCOUNT_ID` | El ID de la cuenta de Cloudflare (32 caracteres hexadecimales) |
| `KLAV_CF_EMAIL_TOKEN` | Un token de la API de Cloudflare con *Email Sending: Edit* |
| `KLAV_CF_EMAIL_FROM` | `invites@klav.dev` o `Klav <invites@klav.dev>`; el dominio, dado de alta en Email Sending |
| `KLAV_CF_EMAIL_API_BASE` | Opcional, para pruebas; por defecto `https://api.cloudflare.com/client/v4` |

**Variables de `klav-server`:** `KLAV_AUTO_INVITE_TOKEN` (el mismo) y
`KLAV_AUTO_INVITE_MAX` (50 en la primera ola), junto al modo `invite` que ya
tiene ([self-hosting.md](self-hosting.md) §2.5). Sin ellas, la ruta responde
`404`.

**Registro:** ni `klav-server` ni `klav-web` escriben el código ni los
tokens. El sitio escribe una línea por invitación enviada (`auto invite: sent
<id>`) y una por fallo, con el motivo y el código de estado.

### Sin token

**Si no quieres activar el token**, lee la lista desde dentro del contenedor. Entra
con `railway ssh --service klav-web` y, ya dentro:

```sh
node --disable-warning=ExperimentalWarning -e '
const { DatabaseSync } = require("node:sqlite");
const db = new DatabaseSync("/data/waitlist.db", { readOnly: true });
for (const r of db.prepare("SELECT email, lang, created_at, invited_at, note FROM waitlist ORDER BY id").all())
  console.log([r.email, r.lang ?? "", r.created_at, r.invited_at ?? "", r.note ?? ""].join(","));
'
```

## 4. Desplegar en Railway

Un servicio nuevo, `klav-web`, en el mismo proyecto `klav` que `klav-server`.

1. **Servicio.** En el proyecto: *New* → *GitHub Repo* → `klav`. En
   *Settings* → *Source*, **Root Directory** `apps/web`: Railway usa entonces
   `apps/web/Dockerfile` y solo sube esa carpeta. Opcional: *Watch Paths*
   `apps/web/**`, para que un cambio en Rust no vuelva a desplegar la página.
2. **Volumen.** Clic derecho en el servicio → *Attach Volume*, con la ruta de
   montaje `/data`. Railway lo monta como root; el *entrypoint* le da `/data`
   al usuario `node` y arranca el servidor como ese usuario, sin
   *capabilities* y con `no_new_privs`, igual que la imagen de
   `klav-server` ([self-hosting.md](self-hosting.md) §8). **No pongas
   `RAILWAY_RUN_UID`.**
3. **Variables.** La imagen ya fija `PORT=8080`,
   `KLAV_WEB_DB=/data/waitlist.db` y `KLAV_WEB_TRUST_PROXY=1`. Si quieres
   exportar por HTTP, `KLAV_WEB_ADMIN_TOKEN`; para Turnstile y las
   invitaciones automáticas, las de §2 y §3, «Invitaciones automáticas». Los
   tokens los creas en tu Mac (`openssl rand -base64 32`; el de las
   invitaciones, `openssl rand -base64 48`), los pegas en *Variables* y los
   guardas en Klav. No van en el repo ni en ningún chat.
4. **Despliegue** (*Settings* → *Deploy*): *Healthcheck Path* `/healthz` y
   *Restart Policy* `On Failure`. Sin *Custom Start Command*: Railway lo
   usaría en lugar del *entrypoint*.
5. **Dominio** (*Settings* → *Networking* → *Custom Domain*): `klav.dev`.
   Railway da el destino del `CNAME`. Un `CNAME` en la raíz del dominio
   necesita que el DNS lo permita (*CNAME flattening* o `ALIAS`; Cloudflare
   lo hace). Si quieres `www.klav.dev`, añádelo como segundo dominio: sirve
   lo mismo y la página declara `https://klav.dev/` como canónica.
   `api.klav.dev` sigue siendo de `klav-server` (ADR
   [0028](decisiones/0028-servidor-por-defecto-klav-dev.md) §1).
6. Comprueba `https://klav.dev/healthz`, abre la página y apúntate con un
   correo de prueba. Bórralo después con `railway ssh` si no lo quieres en la
   lista.

**Respaldos:** los del volumen de Railway. La lista es pequeña; una
exportación de vez en cuando (§3) también sirve de copia.

**Despliegues:** con volumen hay una caída breve en cada uno (el contenedor
viejo se para antes de que arranque el nuevo). Para una página estática y un
formulario no importa.

## 5. La imagen para redes

`public/og.png` se genera desde `tools/og.html` con el Chromium sin interfaz
de Playwright:

```sh
cd apps/web
CH=$(ls -d "$HOME"/Library/Caches/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-mac-arm64/chrome-headless-shell | tail -1)
"$CH" --hide-scrollbars --window-size=1200,630 --virtual-time-budget=3000 \
  --screenshot="$PWD/public/og.png" "file://$PWD/tools/og.html"
```

Cualquier Chromium sirve; la ruta de arriba es la que deja
`playwright install` (el número de la carpeta cambia con cada versión).

**Capturas de la página:** con `--screenshot`, el Chromium sin interfaz no
ejecuta `requestAnimationFrame`, así que las ilustraciones salen en su primer
fotograma. Para ver uno intermedio hace falta un navegador de verdad, o el
protocolo DevTools con una espera en tiempo real. Las capturas de
`docs/img/web/` se tomaron así.

## 6. Qué dice la página y de dónde sale

La página solo afirma lo que está en `main`. Lo que todavía no existe lleva
«Coming soon» / «Próximamente», sin fechas. Al cambiar un texto, revisa su
fuente aquí. La beta con invitación es la excepción en el otro sentido: no
basta con que esté en `main`, porque la página la ofrece solo después de que
Omar pone `api.klav.dev` en modo `invite` (ADR 0048 §8). El PR que la puso en
la página no se mezcla antes.

| Afirmación | Fuente |
|---|---|
| Cada agente tiene su identidad; se empareja con 6 palabras y se aprueba con Touch ID | [cli.md](cli.md) §9, «En la máquina del agente» y «En el dispositivo de la persona» |
| Permisos por proyecto, `allow`/`ask`/`deny` para `list`, `fill`, `inject`, `create`, `totp`, `update`, `reveal` y `delete`; `reveal` denegado por defecto | [cli.md](cli.md) §9 («Política»), [diseno.md](diseno.md) §5.2 |
| La petición del principio pide `inject` y la tarjeta de permisos lo tiene en `ask` | Política propia de ese agente (`--ask inject`), no la de por defecto, que deja `inject` en `allow` |
| Las solicitudes llegan como notificación al iPhone o a la Mac; el agente y el motivo se ven al abrirla | [ios.md](ios.md) §4 (APNs, el aviso solo lleva el tipo), [macos.md](macos.md) (avisos locales) |
| Aprobar una vez o por un tiempo, con Face ID o Touch ID | [cli.md](cli.md) §9, «Aprobaciones»; [ios.md](ios.md) §4 |
| Una tarea: una aprobación para varios elementos | [cli.md](cli.md) §9, «Solicitudes de tarea»; ADR [0021](decisiones/0021-solicitudes-de-tarea.md) |
| `klav agent run` pone los valores en el entorno y devuelve la salida al terminar, con `[redacted by klav]` también en base64, hex, URL y JSON escapado; no frena a un comando que cifre el valor a propósito | [cli.md](cli.md) §9, «Usar secretos sin verlos»; `crates/klav-sdk/src/actions.rs` (`REDACTED`); el aviso de stderr está en `crates/klav-cli/src/commands/agent_actions.rs` |
| `klav.toml` con referencias, que se puede subir al repo, y `klav run` | [cli.md](cli.md) §5 y §6 |
| Klav no bloquea un `cat .env`; con `klav.toml` no hay `.env` | No hay ningún bloqueo de comandos en el código; la página lo dice así |
| `klav inject --fifo`: una tubería que se lee una vez | [cli.md](cli.md) §7 |
| `klav mcp` con `fill_login` y `run_with_secrets`; la skill; `klav agent fill --extension` | [cli.md](cli.md) §9, «`klav mcp`»; [`skill/SKILL.md`](../skill/SKILL.md) |
| La bitácora verificable y el informe «qué vio» (`ITEM`, `PERMISSIONS`, `SECRET`, `USES`) | [cli.md](cli.md) §9, «Bitácora» y `show`; `crates/klav-cli/src/commands/agent.rs` (`print_exposure`) |
| Contraseñas, passkeys y códigos; extensión, iPhone y Mac; importar desde Bitwarden, 1Password o el navegador | [extension.md](extension.md), [ios.md](ios.md), [macos.md](macos.md), [cli.md](cli.md) §4 («Importar»), ADR [0020](decisiones/0020-passkeys.md) y [0024](decisiones/0024-importadores.md) |
| Un agente puede usar una passkey dentro de una tarea | [cli.md](cli.md) §9 (`passkey_sign_in`), ADR 0020 §9 |
| «Tu agente personal»: el agente que armaste pide el relleno con `fill_login` de `klav mcp` o con `klav agent fill`; Klav escribe los valores en la página de tu navegador y al agente le vuelven los nombres de los campos (y el origen), nunca los valores | [cli.md](cli.md) §9, «Usar secretos sin verlos» (`fill`) y «`klav mcp`»; [extension.md](extension.md) §8; `crates/klav-cli/src/mcp.rs` (`fill_login` devuelve `ok`, `filled` y `url`); `crates/klav-daemon/src/browser.rs` (`origins_only`). La ilustración pasa `url` en lugar de `ref`, que `fill_login` también acepta |
| El aviso «Klav filled this page for …» con el motivo del agente | [extension.md](extension.md) §8, paso 5; `apps/extension/_locales/*/messages.json` (`agent_filled`) |
| Con las passkeys, dentro de una tarea aprobada, Klav inicia la sesión y el agente no recibe la llave | [cli.md](cli.md) §9 (`passkey_sign_in`: solo por `klav mcp` o el SDK de Rust, con destino `extension`, una tarea con `passkey` y Klav desbloqueado; nunca devuelve la llave ni la aserción), ADR 0020 §9 |
| El agente tiene que correr en la computadora donde está el navegador | [cli.md](cli.md) §9 (`fill` «solo se conecta a navegadores en la propia máquina»; `klavd` es el del `KLAV_HOME` del agente o el de `KLAV_BROWSER_HOME`) |
| Un agente que además controla la página con scripts o DevTools puede leer el campo ya relleno | [modelo-de-amenazas.md](modelo-de-amenazas.md) T102; [extension.md](extension.md) §8 («Lo que Klav no puede evitar») |
| Descargas: la app de Mac pide macOS 15 y Apple silicon, se actualiza sola y «Configurar este Mac» instala la CLI y `klavd` y conecta los navegadores | [macos.md](macos.md) §3 y §6 (Sparkle); [releasing.md](releasing.md) §1 |
| Descargas: la CLI de Linux trae `klav`, `klavd` y `klav-native-host`, x86_64, y pide glibc 2.36 o posterior (Debian 12, Ubuntu 23.04 y posteriores; no Ubuntu 22.04); `ldd --version` dice cuál hay. En Linux no hay app: `klav unlock` arranca `klavd` y pide la contraseña maestra | [releasing.md](releasing.md) §1, §6 y §8 (decisión de Omar del 2026-11-13); [klavd.md](klavd.md) (Touch ID es solo de macOS); la imagen `rust:1.98.1-slim-bookworm` del `Dockerfile` (Debian 12, glibc 2.36) |
| Descargas: la extensión se instala a mano; en Chromium, como versión preliminar, con la compilación con llave y `--dev` (o «Extensión de desarrollo»), con su riesgo: cualquier extensión sin empaquetar que lleve la llave pública del repositorio llega a `klavd` (`default_allowed` en `crates/klav-daemon/src/native.rs` no la incluye, y `--dev` la añade); en Firefox, el `.xpi` que firmó Mozilla, desde «Instalar complemento desde archivo…», que se queda instalado pero no se actualiza solo. Mientras Mozilla no lo firme, Firefox dice «Próximamente» | [releasing.md](releasing.md) §3 y §8; [extension.md](extension.md) §3; [modelo-de-amenazas.md](modelo-de-amenazas.md) T64 y T122; las páginas de Mozilla citadas en releasing.md §3 |
| Descargas: la extensión necesita la app de Mac o, en Linux, la línea de comandos | `klavd` y `klav-native-host` vienen en los dos ([releasing.md](releasing.md) §1) |
| Descargas: el iPhone pide iOS 18, entra a una cuenta creada en la Mac o con la CLI, y sale por una beta pública de TestFlight | [ios.md](ios.md); [publicar-ios.md](publicar-ios.md) |
| Descargas: el servidor propio con `docker compose up`, SQLite o Postgres, detrás de tu TLS; el nuestro, gratis durante su beta con invitación | [self-hosting.md](self-hosting.md); la beta, [ADR 0048](decisiones/0048-invite-beta-and-distribution.md) §4 y Q1 |
| La beta de `api.klav.dev` («Request a free beta invite», la tarjeta «Hosted by us» en `#beta`): gratis mientras sea con invitación; después, un plan de 20 USD al año con al menos 60 días de aviso; el servidor propio, gratis siempre | [ADR 0048](decisiones/0048-invite-beta-and-distribution.md) §4, Q1 y Q5 (aceptado el 2026-11-25); el modo `invite` de `klav-server` y el código en `klav signup` y en la app de Mac (capas 1 y 2 del ADR). **Lo que la página no dice:** que la cuenta se pueda llevar a un servidor propio. ADR 0048 Q5 (a) nombra `klav account set-server`, pero hoy solo cambia la dirección de una cuenta que el servidor nuevo ya tiene ([cli.md](cli.md) §3, `set_server_cmd` en `crates/klav-cli/src/commands/account.rs`), y no hay forma de exportar una cuenta de `api.klav.dev` a un servidor propio vacío. Ni la página, ni los correos, ni los docs lo prometen hasta que exista ese camino; hace falta antes de que termine la beta. La página tampoco nombra las cuotas de la beta: dependen de las variables de producción |
| Mientras queden lugares, la invitación llega por correo; si no, se espera en la lista (la etiqueta del formulario, y los mensajes `invited`, `already_invited` y de la lista) | §3, «Invitaciones automáticas» y «Mandar las invitaciones»; [ADR 0050](decisiones/0050-auto-beta-invites.md) |

**Próximamente** (sin implementar en `main`). La lista sale de
[features.md](features.md), que decide dónde puede aparecer cada cosa (ADR
[0039](decisiones/0039-public-docs-site.md) §3, y su enmienda del 2026-11-13):
solo lo que está en «Accepted, not built», y los mismos elementos que «On the
way» en los docs. Quien cambie una lista cambia las otras dos en el mismo PR.

- **El proxy y `klav sandbox`** (la sección «Your tokens never enter the
  sandbox»), el propio primero y el gestionado en un enclave después; ADR
  [0036](decisiones/0036-sandboxes-de-agentes.md), aceptado. La comparativa
  (la tabla, «te toca» y «lo que ningún modo resuelve») sale de la nota de
  Omar del 2026-11-06 y del ADR. El precio del gestionado está por confirmar.
- **Entornos por repositorio** (`--env production`, importar un `.env`; ADR
  [0032](decisiones/0032-entornos-por-repositorio.md)).
- **Servicios desplegados** (ADR [0038](decisiones/0038-deployed-services.md)):
  la app guarda un ID de servicio y no sus secretos, y Klav detecta una
  instancia clonada.
- **Las tiendas:** la extensión en la Chrome Web Store y en
  addons.mozilla.org, y la app de iPhone en la App Store.
- **El servidor de Klav abierto a todos:** el registro en `api.klav.dev` sin
  invitación y el plan de 20 USD al año, cuando termine la beta (ADR
  [0010](decisiones/0010-decisiones-fase-3-y-plan-alojado.md); el precio,
  decisión de Omar del 2026-11-13; ADR
  [0048](decisiones/0048-invite-beta-and-distribution.md) Q1 y Q5). La beta
  con invitación ya no va aquí: la ofrece la tarjeta «Hosted by us» (`#beta`).

Fuera de la lista, a propósito:

- **Pausar agentes desde la app de Mac y el iPhone** y **conectar un agente
  desde la sección «Desarrollo» de la app de Mac** ya funcionan
  ([features.md](features.md), «Pause and revoke» y «Connect an agent»), así
  que dejaron de ser «Próximamente».
- **Agentes personales en la nube** (Muse, Grok Bot y Dots): son una idea sin
  ADR («Idea, no ADR» en features.md), y el ADR 0039 §3 no deja nombrar una
  idea en ningún sitio público.
- **Añadir un dispositivo con un QR** (ADR 0029) y **cambiar los permisos de
  un agente desde el iPhone** (enmienda del ADR 0033): están aceptados, pero
  ni el ADR 0039 ni su enmienda los nombran entre los elementos de «On the
  way». Añadirlos es decisión de Omar.
- **Los adjuntos en S3, la verificación del correo y el relé de push para
  servidores propios:** detalles del servidor, no algo que una persona busque
  en la página.

**La sección de descargas** sigue al interruptor (§2), no a esta lista: su
«Próximamente» marca lo que ya está en `main` y aún no tiene archivo
publicado, y desaparece al encender cada descarga. Lo que de verdad falta
(las tiendas y el registro abierto en nuestro servidor) lo nombran la lista de arriba y «On the
way» en los docs, y la sección de descargas enlaza ahí solo con `docs`
encendido.

**La CI** aparece solo como parte del problema: la página no promete ninguna
integración. Tampoco nombra a otros gestores para decir qué no hacen;
Bitwarden y 1Password salen solo como orígenes de la importación.

## 7. El sitio de documentación (`apps/docs`)

Los docs públicos de Klav, en inglés, para las personas que lo instalan y para
los agentes que los leen: lo que ya funciona y una sección «On the way» con lo
que tiene diseño aceptado y aún no está hecho, sin fechas (ADR
[0039](decisiones/0039-public-docs-site.md)). Es un sitio estático hecho con
Nimbus (Astro), servido como un Worker de Cloudflare con *static assets*. No
toca la bóveda ni `klav-server`, y Railway no interviene.

| Archivo | Qué es |
|---|---|
| `src/content/docs/` | Las páginas, en MDX. La carpeta es la URL y la barra lateral |
| `astro.config.ts` | La configuración de Nimbus: `site` (`https://docs.klav.dev`), la barra lateral y las reglas del lint |
| `public/_headers` | Las cabeceras de respuesta. Al construir, Nimbus añade las suyas: los tipos de los `.md` y de `llms.txt`, y los `Link` para agentes |
| `src/pages/robots.txt.ts` | `robots.txt`, cerrado a todos los rastreadores mientras el repo sea privado |
| `wrangler.jsonc` | El Worker `klav-docs`, que sirve `dist/` |
| `CLAUDE.md` | Cómo se trabaja en el sitio y cómo se actualiza Nimbus |

Además de cada página en HTML, el sitio publica su versión en Markdown
(`/<ruta>/index.md`), su fuente (`index.mdx`), `llms.txt` y `llms-full.txt`,
para que un agente lo lea sin HTML.

**Construir y comprobar.** Es un proyecto de pnpm aparte, con su propio
*lockfile*: el *workspace* de la raíz lo excluye. Desde `apps/docs`:

```sh
pnpm install --frozen-lockfile
pnpm audit --audit-level low
pnpm exec nimbus-docs check
pnpm exec astro check
pnpm build
pnpm exec nimbus-docs lint
```

Es lo mismo que corre la tarea `docs` de la CI. Para verlo como lo sirve
Cloudflare, con sus cabeceras, `pnpm run preview:cf` construye y lo levanta con
`wrangler dev`, en local y sin cuenta ni sesión; la dirección sale en la
terminal. Los
scripts apagan la telemetría (`ASTRO_TELEMETRY_DISABLED=1`,
`WRANGLER_SEND_METRICS=false`); si corres `astro` o `wrangler` a mano, ponlas
tú.

**Desplegar.** Se hace a mano desde la Mac de Omar: Omar, o el agente que trabaja
en su sesión, que desde el 2026-11-12 vuelve a desplegar tras cada *merge* a
`main` que cambia el sitio. La CI no despliega, y en GitHub no hay ningún token
de Cloudflare:

```sh
cd apps/docs
pnpm install --frozen-lockfile && pnpm run deploy
```

`pnpm run deploy` corre antes `astro check`, `pnpm build` y la comprobación
de la CSP (el script `predeploy`) y después `wrangler deploy`. La primera vez, `wrangler` abre el
navegador para iniciar sesión en Cloudflare y guarda la sesión en la Mac, fuera
del repo. Al terminar imprime la dirección `*.workers.dev` del Worker. Esa
dirección no se enlaza desde ningún sitio mientras dure la revisión.

**Cabeceras de seguridad.** Todas las respuestas llevan, desde la regla `/*`
de `public/_headers`, las de `apps/web` (§2) que sirven a un sitio estático:
`nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
`Cross-Origin-Opener-Policy`, una `Permissions-Policy` que apaga lo que el
sitio no usa, HSTS sin `includeSubDomains` ni `preload` (desde este host solo
cubrirían sus propios subdominios; `klav.dev` ya envía `includeSubDomains`
para todo el dominio) y una CSP sin `'unsafe-inline'` para scripts: los dos
scripts en línea (el tema y la barra lateral) van por su hash, y la búsqueda
(Pagefind) necesita `'wasm-unsafe-eval'` y su *worker*. Un segundo `/*` en
`_headers` sustituye al primero en lugar de sumarse, así que todo va en uno.
`pnpm run check:csp`, en la CI y antes de desplegar, falla si `_headers` no
tiene exactamente una regla `/*` con la CSP, si falta `X-Robots-Tag: noindex`
mientras `robots.txt` cierra el paso a todos, si un script en línea no tiene
su hash en la CSP o sobra uno, o si una página lleva un manejador en línea
(`onclick=`) o una URL `javascript:`. Tras actualizar Nimbus o tocar esos
layouts, copia los hashes que imprime.

**Después de cada despliegue**, en esa dirección:

- `/robots.txt` dice `Disallow: /`;
- las páginas llevan la cabecera `X-Robots-Tag: noindex`
  (`curl -sI <dirección>/`), y también `Content-Security-Policy`,
  `Strict-Transport-Security` y `X-Frame-Options`;
- la búsqueda devuelve resultados y el cambio de tema funciona (si la CSP
  bloqueara algo, la consola del navegador lo dice);
- `/index.md`, una página cualquiera con `/index.md` al final y `/llms.txt`
  responden, con `text/markdown` y `text/plain`;
- las páginas que cambiaron se ven bien.

**«On the way» y «Coming soon».** La sección «On the way» de los docs y lo
que `public/index.html` marca «Coming soon» nombran las mismas cosas. Un PR
que cambia una cambia la otra (ADR 0039 §3).

**Lo que espera al día en que el repo sea público** (ADR 0039 §5, Q6). Hasta
entonces, el sitio solo vive en su dirección `*.workers.dev`, sin enlazar y
cerrado a los buscadores:

- abrir `robots.txt` a los rastreadores (`OPEN_TO_CRAWLERS` en
  `src/pages/robots.txt.ts`) y quitar la línea `X-Robots-Tag: noindex` de
  `public/_headers`;
- el enlace a GitHub (`github` en `astro.config.ts`);
- los enlaces a archivos del repo que hoy faltan: `SECURITY.md`, la
  especificación criptográfica y el modelo de amenazas;
- el dominio `docs.klav.dev` (abajo);
- los enlaces desde `klav.dev`, que se encienden con `docs` en `KLAV_WEB_OPEN` (§1),
  solo cuando el dominio ya responde;
- y, ya desplegado todo eso, la casilla del roadmap.

**Poner `docs.klav.dev` (Omar).** Omar lo decidió el 2026-11-13: los docs
van en `docs.klav.dev`, y el interruptor `docs` sigue apagado hasta que ese
dominio responde. Lo hace solo Omar, en el panel de Cloudflare, con la cuenta
donde vive el Worker. Ni el ID de la cuenta ni la dirección `workers.dev` van
en el repo, en un PR ni en un *commit*. Lo que dice la página de Cloudflare
([Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/),
leída el 2026-11-13): *Cloudflare will create DNS records and issue necessary
certificates on your behalf*; y *You cannot create a Custom Domain on a
hostname with an existing CNAME DNS record*.

1. En la zona `klav.dev`, *DNS* › *Records*: comprueba que no hay ningún
   registro para `docs`. Si hay un CNAME, bórralo antes.
2. *Workers & Pages* › `klav-docs` › *Settings* › *Domains & Routes* ›
   *Add* › *Custom Domain*. Escribe `docs.klav.dev` y elige *Add Custom
   Domain*. Cloudflare crea el registro DNS y el certificado.
3. Comprueba que responde, desde una terminal cualquiera:
   `curl -sI https://docs.klav.dev/` da `200` con las cabeceras de seguridad
   de arriba, y `https://docs.klav.dev/robots.txt` es el de este repo. Haz
   también la lista «Después de cada despliegue» sobre `docs.klav.dev`.
4. Solo entonces añade `docs` a `KLAV_WEB_OPEN` en Railway y despliega los
   cambios en espera (§2).

Se hace desde el panel, no con `routes` en `wrangler.jsonc` (la otra vía que
da la página: `custom_domain = true` en cada patrón y `wrangler deploy`), para
que el dominio no dependa de un cambio en el repo. **[CHECK]** La página no
dice si la dirección `workers.dev` sigue sirviendo después; si Omar quiere
apagarla, se mira en *Domains & Routes* el día que se ponga el dominio.
