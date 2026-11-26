# Publicar la extensión en las tiendas

Lo que Omar tiene que hacer para publicar la extensión. Todo lo demás está
listo en el repositorio:

| Qué | Dónde |
|---|---|
| Los paquetes | `scripts/extension/package.sh` → `target/extension/` (§2) |
| Textos de la ficha, justificación de permisos, uso de datos y notas para la revisión, en inglés y español | [`apps/extension/store/ficha.md`](../apps/extension/store/ficha.md) |
| Capturas de 1280×800 (`en` y `es`) | `apps/extension/store/screenshots/` (§4) |
| Mosaico, marquesina y logo de Edge | `apps/extension/store/images/` (§4) |
| Política de privacidad | [`privacidad.md`](privacidad.md) y `apps/web/public/privacy/index.html`, servida en `https://klav.dev/privacy` (§5) |
| Dónde va el ID de la tienda | `STORE_CHROMIUM_IDS` en `crates/klav-daemon/src/native.rs` (§6) |

Las tiendas:

- **Chrome Web Store.** Cubre Chrome, Brave, Arc, Dia y Edge (Edge instala
  extensiones de la Chrome Web Store si se lo permites). La cuenta cuesta 5 USD,
  una sola vez.
- **addons.mozilla.org (AMO).** Firefox. Gratis.
- **Edge Add-ons.** Opcional: la de Chrome ya sirve en Edge. Gratis.

Lo que hay que saber de las tiendas (precios, pasos, plazos) es de noviembre de
2026 y cambia. Lo que no se pudo comprobar está marcado **[REVISAR]**.

## En resumen

**No se envía a ninguna tienda hasta que el repositorio sea público y haya
una descarga de Klav** (el DMG de la app de Mac o una *release*). Son las dos
condiciones de §1; los pasos de abajo las cumplen en orden.

1. Hacer público el repositorio (§1). Va antes de publicar la política,
   porque la política dice que el código es abierto y enlaza a él.
2. Publicar la política de privacidad en `klav.dev/privacy` (§5): resolver sus
   **[REVISAR]** y devolver al sitio la ruta y el enlace del pie. Hoy no se
   sirve. Las tiendas la abren al enviar, así que va antes del paso 5.
3. Crear la cuenta de Chrome Web Store y subir el paquete **como borrador**,
   sin enviarlo a revisión (§3). La tienda le da su ID en ese momento.
4. Poner ese ID en `STORE_CHROMIUM_IDS` (§6), publicar una versión de `klav`
   y el DMG de la app de Mac con él, y volver a correr
   `klav extension install-host`. Esa es la descarga de §1: una anterior no
   conecta Chrome con la extensión de la tienda.
5. Crear la cuenta para quien revisa (§1), rellenar la ficha de Chrome con
   `ficha.md`, con la descarga y la cuenta en las notas para la revisión, y
   enviarla a revisión.
6. Crear la cuenta de AMO, subir el paquete de Firefox y el código fuente, y
   rellenar su ficha (§7).
7. Opcional: Edge Add-ons (§8), que da otro ID para `STORE_CHROMIUM_IDS`.
8. Cuando aprueben las tiendas, borrar la cuenta de quien revisa (§1). Al
   publicarse, marcar la casilla del roadmap (§11).

## 1. Antes de enviar

Las tiendas instalan la extensión y la prueban; si no funciona, la rechazan
(«no hace lo que dice» o «falta funcionalidad»). Por eso hay dos condiciones
previas, y sin ellas no se envía:

1. **El repositorio, público.** La ficha, la política y las notas dicen que el
   código es abierto y enlazan a `github.com/OmarAlex24/klav`. AMO recibe el
   código fuente con el paquete, pero un enlace roto en la ficha o en la
   política es motivo de rechazo en cualquier tienda.
2. **Una descarga de Klav**: el DMG de la app de Mac (ADR
   [0027](decisiones/0027-app-de-mac.md)) o una *release* con `klav` y
   `klavd`. La extensión no hace nada sin ellos ([extension.md](extension.md)
   §1), y hoy solo se compilan desde el código. La descarga tiene que llevar
   ya el ID de Chrome Web Store (paso 4 del resumen): la app de Mac solo
   conecta en Chrome la extensión cuyo ID está en `STORE_CHROMIUM_IDS`
   ([macos.md](macos.md) §3). Su enlace va en las notas para la revisión
   (`ficha.md` §7).

**La cuenta para quien revisa.** El registro en `api.klav.dev` está cerrado
(ADR [0028](decisiones/0028-servidor-por-defecto-klav-dev.md) §3), así que
quien revisa entra con una cuenta de prueba:

- Es desechable: la creas tú al enviar, en `api.klav.dev`, vacía y sin nada
  tuyo. Abre el registro solo para crearla y vuelve a cerrarlo
  (`KLAV_ALLOW_REGISTRATION`, [self-hosting.md](self-hosting.md) §8.1,
  paso 6).
- El correo, la contraseña maestra y el Secret Key van **solo** en las notas
  para la revisión del formulario de cada tienda, en los marcadores
  `<filled in at submission: …>` de `ficha.md` §7. Nunca en el repositorio,
  en un *commit* ni en un PR, y tampoco su kit de emergencia.
- Se borra cuando aprueben las tiendas que la usan. Cada versión nueva que se
  envíe a revisión necesita otra.

**Borrar una cuenta** no existe ni en las apps ni en la API: se hace a mano.
Quien quiera borrar la suya escribe a `support@klav.dev` desde el correo de la
cuenta, y tú la borras. Lo que se borra y lo que no está en la política
([privacidad.md](privacidad.md), «Borrar tu cuenta»).

- Borrar la fila de `accounts` borra en cascada todo lo demás de la cuenta
  (`ON DELETE CASCADE` en `crates/klav-server/migrations/`).
- Con la imagen de Railway la base es SQLite, en `/data/klav.db`
  (`deploy/railway/Dockerfile`), salvo que el servicio cambie
  `KLAV_DATABASE_URL`. SQLite solo borra en cascada con
  `PRAGMA foreign_keys = ON`, que el servidor pone en sus propias conexiones
  (`crates/klav-server/src/db.rs`). En una sesión de `sqlite3` a mano hay que
  ponerlo antes de borrar; si no, quedan dispositivos, bóvedas y bitácora sin
  cuenta. La imagen no trae `sqlite3` ([self-hosting.md](self-hosting.md)
  §8.2).
- Los archivos adjuntos están en el disco (`/data/attachments/<bóveda>/`).
  Los borra la limpieza del servidor, que corre cada hora, cuando su bóveda ya
  no existe (`remove_orphan_files` en `crates/klav-server/src/purge.rs`).
- Para la App Store, Apple pide que la cuenta se pueda borrar desde la app
  (guideline 5.1.1(v)): hay que construirlo antes de publicar la app de iOS.

**El correo de contacto** es `support@klav.dev`, para el soporte, la
privacidad y el borrado de cuentas: va en la ficha (`ficha.md` §2) y en la
política. `security@klav.dev` es solo para los reportes de seguridad
(`SECURITY.md`).

## 2. Los paquetes

```sh
pnpm install
scripts/extension/package.sh
```

Desde un *checkout* limpio (el script se niega si hay cambios sin
*commit*, para que el código fuente coincida con lo compilado). Deja en
`target/extension/`:

| Archivo | Para qué |
|---|---|
| `klav-<versión>-chromium.zip` | Chrome Web Store y Edge Add-ons. Sin la llave de desarrollo (`key`), así que la tienda asigna su propio ID |
| `klav-<versión>-chromium-dev.zip` | El mismo código con la llave de desarrollo, para la descarga que se carga sin empaquetar mientras Klav no esté en la tienda ([releasing.md](releasing.md) §3). **No es para las tiendas** |
| `klav-<versión>-firefox.zip` | AMO. Con `browser_specific_settings.gecko.id = "klav@klav.dev"`. Mientras no haya ficha, AMO lo firma como complemento sin listar y ese `.xpi` firmado es la descarga de Firefox ([releasing.md](releasing.md) §3); este `.zip` sin firmar no se publica |
| `klav-<versión>-source.zip` | El código fuente que pide AMO: `git archive` del *commit* compilado, con `apps/extension/BUILDING.md` y `BUILD-INFO.txt` también en su raíz, porque la subida sin listar no tiene campo de notas |
| `BUILD-INFO.txt` | Las versiones de Rust, `wasm-bindgen`, Node y pnpm que compilaron, para pegarlas en las notas de AMO |
| `SHA256SUMS` | Los *hashes* de los cuatro `.zip` |
| `build/` | Los paquetes sin comprimir, por si quieres cargarlos a mano antes de subirlos |

Qué hace, en orden:

1. Compila `klav-wasm` con `--remap-path-prefix`: sin eso, el `.wasm` lleva
   rutas de la máquina que compila, con el nombre de usuario (`/Users/…/.cargo/registry/…`).
   Así salen los mismos bytes desde cualquier carpeta: compilar desde
   `klav-<versión>-source.zip` descomprimido en otro sitio da archivos idénticos
   a los del paquete (comprobado con `diff -r` el 2026-11-05). Los `.zip` solo
   cambian en las fechas de los archivos.
2. Compila las dos versiones con `KLAV_STORE=1` y `KLAV_DIST=target/extension/build`
   (`apps/extension/scripts/build.mjs`). `apps/extension/dist/` sigue siendo la
   versión de desarrollo, con su ID fijo, que usan las pruebas.
3. Comprueba que el paquete de Chromium no lleva `key`, que el de la llave
   lleva exactamente la de `static/dev-key.txt`, que las versiones coinciden y
   que el ID de Firefox es `klav@klav.dev`.
4. Pasa `addons-linter` (lo mismo que AMO al subir) sobre el paquete de
   Firefox.

**La versión.** Sale de `apps/extension/package.json`, hoy `0.9.0`: la misma
que el resto de Klav, y la sube el PR de versión ([releasing.md](releasing.md)
§2). Cada subida a una tienda necesita una versión mayor que la anterior: si
hay que volver a subir la extensión sin una versión nueva de Klav, súbela en
`package.json` (`0.9.1`…) en un *commit* antes de la subida.

`pnpm build` sigue dejando en `apps/extension/dist/` los `.zip` de desarrollo:
**no son para las tiendas** (el de Chromium lleva la llave de desarrollo).

## 3. Chrome Web Store

### Cuenta

1. Una cuenta de Google con **verificación en dos pasos** activada. La tienda
   no deja publicar sin ella. [REVISAR: conviene una cuenta solo para Klav,
   no la personal, porque su correo puede aparecer en la ficha.]
2. Entra en el [Developer Dashboard](https://chrome.google.com/webstore/devconsole),
   acepta el acuerdo de desarrollador y paga los **5 USD** (una vez).
3. En *Account*:
   - **Correo de contacto**: `support@klav.dev`, que la ficha muestra. Hay que
     verificarlo (el correo de verificación llega por Cloudflare Email
     Routing); sin eso no se puede publicar.
   - **Declaración de comerciante** (*trader / non-trader*, por la ley de
     servicios digitales de la Unión Europea). Si Klav va a tener un plan de
     pago, lo más probable es que seas «comerciante», y entonces la tienda
     muestra en la ficha un nombre, una dirección, un teléfono y un correo.
     [REVISAR: decide qué dirección y teléfono públicos usar.]
   - *Publisher name*: `Klav`.

### Subir el borrador y apuntar el ID

1. *Items* → *New item* → sube `target/extension/klav-<versión>-chromium.zip`.
2. La tienda crea el elemento **como borrador** y ya tiene su ID: las 32 letras
   de la dirección del borrador
   (`…/devconsole/<publicador>/<ID>/edit`). No lo envíes todavía.
3. Con ese ID, haz lo de §6 antes de enviar. Si no, la extensión de la tienda
   no podría hablar con `klavd` y la revisión vería «Klav isn’t responding».

### La ficha, campo por campo

Todo el texto está en [`ficha.md`](../apps/extension/store/ficha.md).

| Pestaña y campo | Qué va | `ficha.md` |
|---|---|---|
| *Package* | El `.zip` de Chromium | — |
| *Store listing* → *Description* | Descripción larga en inglés. Con *Add language* → *Spanish*, la española | §1 |
| *Store listing* → *Category* | *Productivity* → *Tools* [REVISAR] | §2 |
| *Store listing* → *Language* | *English* | — |
| *Store listing* → *Store icon* | `apps/extension/static/icons/128.png` | §8 |
| *Store listing* → *Screenshots* | Las cinco de `screenshots/en/` (y las de `es/` en la ficha en español) | §8 |
| *Store listing* → *Small promo tile* | `images/promo-440x280-en.png` [REVISAR: si sigue siendo obligatorio; súbelo igual] | §8 |
| *Store listing* → *Marquee promo tile* | `images/promo-1400x560-en.png` (opcional) | §8 |
| *Store listing* → *Official URL* | `klav.dev`, si verificas el dominio en Google Search Console; si no, vacío | — |
| *Store listing* → *Homepage URL* | `https://klav.dev` | §2 |
| *Store listing* → *Support URL* | `https://github.com/OmarAlex24/klav/issues` | §2 |
| *Store listing* → *Mature content* | No | §2 |
| *Privacy* → *Single purpose* | El texto en inglés | §3 |
| *Privacy* → *Permission justification* | Uno por permiso: `nativeMessaging`, `alarms`, `clipboardWrite`, `storage`, `offscreen`, `favicon` | §4 |
| *Privacy* → *Host permission justification* | El del acceso a los sitios | §4 |
| *Privacy* → *Are you using remote code?* | *No* | §4 |
| *Privacy* → *Data usage* | Las casillas y las tres certificaciones | §5 |
| *Privacy* → *Privacy policy URL* | `https://klav.dev/privacy` | §5 |
| *Distribution* → *Payments* | *Free of charge* | — |
| *Distribution* → *Visibility* | *Public*. *Unlisted* si prefieres probarla antes sin que se encuentre en búsquedas; la revisión es la misma | — |
| *Distribution* → *Regions* | Todas | — |
| *Test instructions* | Las notas para la revisión, con la cuenta de prueba (§1) | §7 |

Después, *Submit for review*. Ofrece «publicar automáticamente al aprobarse»:
déjalo marcado si ya hiciste lo de §6, o desmárcalo para publicar a mano.

## 4. Capturas e imágenes

Las capturas salen de la extensión compilada, con datos de ejemplo y un sitio
inventado (Northwind, en `app.northwind.example`, que Chromium resuelve a un
servidor local con HTTPS y un certificado de un solo uso). Ninguna lleva datos
reales.

Para rehacerlas, por ejemplo tras cambiar el *popup*:

```sh
cargo build -p klav-cli -p klav-server -p klav-daemon --bins   # los binarios de las pruebas
pnpm --filter @klav/extension build
cd apps/extension
STORE_SHOTS=1 pnpm e2e tiendas
```

Escribe `store/screenshots/{en,es}/{1-rellenar,2-boveda,3-generar,4-guardar,5-agentes}.png`.
La prueba (`e2e/tiendas.spec.ts`) se salta sin `STORE_SHOTS=1`, así que la CI
no las rehace. Con la pantalla del Mac bloqueada, `klavd` se bloquea solo:
compila con `KLAV_NO_SWIFT=1`. El *popup* de las capturas 2 y 5 es su imagen
real, dibujada sobre la página arriba a la derecha, donde cae desde la barra
del navegador.

El mosaico, la marquesina y el logo de Edge:

```sh
cd apps/extension/store
HEADLESS=$(ls -d "${PLAYWRIGHT_BROWSERS_PATH:-$HOME/Library/Caches/ms-playwright}"/chromium_headless_shell-*/*/chrome-headless-shell | head -1)
for lang in en es; do
  for size in 440x280 1400x560; do
    w=${size%x*}; h=${size#*x}
    "$HEADLESS" --hide-scrollbars --window-size=$w,$h --virtual-time-budget=3000 \
      --screenshot="$PWD/images/promo-$size-$lang.png" "file://$PWD/tools/promo.html?w=$w&h=$h&lang=$lang"
  done
done
node ../scripts/icons.mjs   # también los íconos del paquete; images/logo-300.png
```

Siguen [diseno-visual](diseno-visual/README.md): papel y tinta, la cerradura
en *dither* con sus esquinas en cruz, el azul solo en el campo.

## 5. Política de privacidad

La política está en [`privacidad.md`](privacidad.md) y la página, con el mismo texto en inglés y en español y sin JavaScript, en `apps/web/public/privacy/index.html`. `apps/web/server.mjs` la sirve en `https://klav.dev/privacy` (y `/privacy/`) con su propia CSP sin `script-src`, y el pie de `klav.dev` enlaza a ella.

**Las tiendas la necesitan en línea.** Chrome y Edge piden la URL
(`https://klav.dev/privacy`); AMO pide el texto. Comprueba que `https://klav.dev/privacy` abre tras el despliegue en Railway antes de enviar a las tiendas.

## 6. El ID de la tienda

`klav-native-host` solo atiende a las extensiones cuyo ID conoce, y el
navegador solo le deja hablar con las del manifiesto que escribe
`klav extension install-host` ([extension.md](extension.md) §2, «IDs
permitidos»). Una extensión de la tienda tiene otro ID que la de desarrollo,
así que hay que darlo de alta.

**Cómo se fija hoy:**

| Versión | ID | Cómo |
|---|---|---|
| Chromium, desarrollo (`dist/chromium`) | `niiplppgdljgimbnmokojdkofdcjkgao` | La llave pública `key` del manifiesto (`apps/extension/static/dev-key.txt`); la privada se descartó. Como la llave es pública, el *host* solo lo deja pasar con `install-host --dev` |
| Chromium, tiendas (`KLAV_STORE=1`) | el que asigne cada tienda | El paquete va sin `key`: la tienda firma con su propia llave |
| Firefox, desarrollo y AMO | `klav@klav.dev` | `browser_specific_settings.gecko.id` en `scripts/build.mjs`. Es el mismo en AMO, así que no cambia nada al publicar |

**Al tener el ID de Chrome Web Store (o de Edge Add-ons):**

1. Ponlo en `crates/klav-daemon/src/native.rs`:

   ```rust
   pub const STORE_CHROMIUM_IDS: &[&str] = &["<las 32 letras de la tienda>"];
   ```

   Con Edge, son dos: `&["<chrome>", "<edge>"]`. Es el único cambio. Desde ahí:
   - `klav-native-host` lo acepta sin `--allow` (`default_allowed()`);
   - `klav extension install-host` lo escribe en el `allowed_origins` de cada
     manifiesto de Chromium;
   - la prueba `store_ids_are_chromium_ids` falla si te equivocas al copiarlo
     (32 letras de la `a` a la `p`).
2. Actualiza la tabla «IDs permitidos» de [extension.md](extension.md) §2.
3. Publica una versión de `klav` con el cambio, y la app de Mac, que lleva su
   propio `klav` y su *host*. Después corre `klav extension install-host` otra
   vez en cada equipo, también en el tuyo. Si sigues usando en Dia la versión
   de desarrollo, añade `--dev`: sin él, el *wrapper* nuevo ya no la deja
   pasar.

**Mientras tanto**, sin publicar `klav`, sirve la opción que ya existe:

```sh
klav extension install-host --extension-id <ID de la tienda>
```

Escribe el ID en el manifiesto y pasa `--allow <ID>` al *host* desde su
*wrapper*. Vale para probar la extensión de la tienda antes de la versión
nueva de `klav`; se pierde si alguien vuelve a correr `install-host` sin la
opción.

**Opcional: el mismo ID en desarrollo.** Chrome Web Store muestra la llave
pública del elemento (*Package* → *View public key*). Si pusieras esa llave en
`static/dev-key.txt`, la versión de desarrollo tendría el ID de la tienda. No
lo recomiendo: cambiaría el ID de desarrollo, y con él cada instalación local
(la tuya en Dia también) y las pruebas de punta a punta, que comprueban
`niiplppgdljgimbnmokojdkofdcjkgao`. Las dos versiones conviven bien con IDs
distintos.

## 7. addons.mozilla.org

### Cuenta

1. Una cuenta de Mozilla (antes *Firefox Account*) con el correo que quieras
   mostrar a quien revisa. AMO exige **autenticación en dos pasos** para subir
   complementos. [REVISAR: que siga siendo así al crearla.]
2. En el [Developer Hub](https://addons.mozilla.org/developers/), acepta el
   acuerdo de distribución y las políticas. Rellena el perfil: nombre `Klav` y
   la página `https://klav.dev`.

### Subir

1. *Submit a New Add-on* → *On this site* (aparece en AMO). La otra opción,
   *On your own*, firma el `.xpi` sin ficha pública; sirve para dar una versión
   firmada a alguien antes de la ficha.
2. Sube `target/extension/klav-<versión>-firefox.zip`. AMO corre el mismo
   `addons-linter` que `package.sh`, así que no debería avisar de nada más que de
   Firefox para Android (no tiene *native messaging*, y por eso la extensión no
   se ofrece ahí).
3. *Do you need to submit source code?* → **Yes**. Sube
   `klav-<versión>-source.zip` y pega en las notas el bloque «How to build»
   de `ficha.md` §7 con el contenido de `BUILD-INFO.txt`.
4. La ficha:

| Campo | Qué va | `ficha.md` |
|---|---|---|
| *Name* | `Klav` (del manifiesto) | §1 |
| *Add-on URL* | `klav` | §2 |
| *Summary* | La descripción corta, en inglés; con *Add a localization* → español, la española | §1 |
| *Description* | La larga, en inglés y en español | §1 |
| *Categories* | *Privacy & Security* | §2 |
| *Support email* y *Support website* | `support@klav.dev` y `https://github.com/OmarAlex24/klav/issues` | §2 |
| *License* | *Apache License 2.0* | §2 |
| *Privacy policy* | Marcar que tiene y pegar el texto en inglés | §6 |
| *Notes to Reviewer* | Las notas para la revisión y el «How to build» | §7 |
| *Images* → *Screenshots* | Las cinco de `screenshots/en/`, con una leyenda corta cada una | §8 |
| *Icon* | El del paquete (128 px) | — |

5. Uso de datos: AMO lo toma de `data_collection_permissions` del manifiesto
   (`none`, `ficha.md` §6).

## 8. Edge Add-ons (opcional)

Quien use Edge puede instalar la de Chrome Web Store. Publicar en Edge
Add-ons sirve para aparecer en su tienda.

1. Una cuenta de Microsoft. En [Partner Center](https://partner.microsoft.com/dashboard/microsoftedge/overview)
   → registrarse en el programa de Microsoft Edge (gratis, cuenta individual).
   [REVISAR: que el registro siga siendo gratis.]
2. *Create new extension* → sube el mismo `klav-<versión>-chromium.zip`.
3. *Availability*: *Public*, todos los mercados.
4. *Properties*: categoría *Productivity*, `https://klav.dev/privacy` como
   política de privacidad, `https://klav.dev` como sitio web y
   `support@klav.dev` como contacto de soporte.
5. *Store listings* (inglés y español): la descripción larga (Edge pide al
   menos 250 caracteres), el logo `images/logo-300.png` (obligatorio), las
   capturas, el mosaico de 440×280 y la marquesina de 1400×560 (opcionales), y
   los términos de búsqueda de `ficha.md` §2.
6. *Notes for certification*: las notas para la revisión de `ficha.md` §7.
7. El ID de Edge es distinto del de Chrome: añádelo también a
   `STORE_CHROMIUM_IDS` (§6). [REVISAR: Partner Center lo muestra en la
   página de la extensión; confirma si ya aparece antes de publicar.]

## 9. Si piden cambios

**Chrome Web Store** manda un correo con el motivo y su nombre en clave (por
ejemplo *Purple Potassium*: permisos que no se usan; *Yellow Zinc*: falta
información en la ficha; *Purple Lithium*: la política de privacidad; *Blue
Argon*: código remoto). La lista está en la página de
[problemas de revisión](https://developer.chrome.com/docs/webstore/troubleshooting)
de Google.

1. Busca el nombre en esa página y mira qué parte de la ficha o del paquete
   señala.
2. Si es la ficha, corrígela en el *dashboard* y vuelve a enviar.
3. Si es el paquete, arréglalo en el repositorio con un PR, sube la versión en
   `package.json`, vuelve a correr `package.sh` y sube el `.zip` nuevo.
4. Si crees que se equivocan, responde desde el enlace de *One Stop Support*
   del correo, con una explicación corta y en inglés. Por ejemplo, para el
   acceso a los sitios: es un gestor de contraseñas y el *content script* no
   recibe nada hasta que la persona elige (`ficha.md` §4).

**AMO** escribe en el historial de la versión, dentro del Developer Hub, y avisa
por correo. Se contesta ahí mismo. Si piden un cambio en el código, se sube una
versión nueva con su código fuente. Si solo es la ficha, se edita sin subir
nada.

**Edge** muestra el informe de certificación en Partner Center. Se corrige y se
vuelve a publicar la misma entrega.

Si un rechazo cambia algo de la extensión (un permiso, un texto), actualiza
también `ficha.md` y [extension.md](extension.md) §9.

## 10. Cuánto tarda la revisión

Son rangos, no promesas. [REVISAR: cambian a menudo.]

- **Chrome Web Store.** La mayoría de los envíos salen en pocos días. Con un
  *content script* en todos los sitios, el *dashboard* avisa de que la
  extensión puede necesitar una revisión a fondo, y entonces puede tardar de
  una a varias semanas. Es lo normal en un gestor de contraseñas. Pedir menos
  no es posible sin dejar de rellenar en cualquier sitio.
- **AMO.** Lo que pasa la validación automática suele firmarse en minutos u
  horas; la revisión humana puede llegar antes o después de publicar. Con
  código fuente compilado y `nativeMessaging`, cuenta con revisión humana
  antes de publicar: de días a algunas semanas.
- **Edge Add-ons.** Microsoft hablaba de hasta 7 días hábiles.

## 11. Después de publicar

- Borra la cuenta de quien revisa en cuanto aprueben las tiendas que la usan
  (§1).
- Marca en [roadmap.md](roadmap.md) la casilla «Firefox + Chrome publicados» y
  quita el pendiente de Omar de **Estado actual**.
- En [extension.md](extension.md) §2, la fila «Tiendas» de «IDs permitidos»
  pasa a tener el ID de cada tienda, y §11 enlaza a las fichas publicadas.
- En [`probar-fase-5.md`](probar-fase-5.md), instalar desde la tienda en
  lugar de «Cargar descomprimida».
