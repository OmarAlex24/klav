# Ficha de la extensión en las tiendas

Los textos para pegar en Chrome Web Store, addons.mozilla.org (AMO) y Edge
Add-ons, en inglés y español. El paso a paso de cada tienda (cuentas, qué
subir y en qué orden) está en
[`docs/publicar-extension.md`](../../../docs/publicar-extension.md).

- Lo que va entre bloques de código se pega tal cual.
- Las tiendas muestran la descripción en el idioma del navegador. El inglés
  es el idioma por defecto, como en el manifiesto (`default_locale: "en"`).
- Las justificaciones de permisos y las notas para la revisión van **solo en
  inglés**: las leen las personas que revisan, no las que instalan. La
  traducción al español queda debajo, para que Omar sepa qué está firmando.
- Lo marcado **[REVISAR]** es una decisión de Omar.
- Lo que va entre `<filled in at submission: …>` se escribe en el formulario
  de la tienda al enviar, y **nunca** en este archivo ni en el repositorio:
  la cuenta de prueba, el enlace de la descarga y `BUILD-INFO.txt`.

Si cambia el manifiesto (`apps/extension/scripts/build.mjs`), hay que revisar
la §4 de esta ficha y la §9 de [`extension.md`](../../../docs/extension.md).

## 1. Nombre y descripciones

**Nombre** (sale del manifiesto, `__MSG_ext_name__`): `Klav`.

**Descripción corta.** Chrome la toma del manifiesto (`ext_description` en
`_locales/*/messages.json`, 132 caracteres como máximo) y no se escribe en
el formulario. AMO pide un resumen de hasta 250 caracteres, y Edge una
descripción corta. En los dos se pega la del manifiesto:

```text
Fill your passwords from Klav, and let your agents do it without seeing the values.
```

```text
Rellena tus contraseñas desde Klav, y deja que tus agentes lo hagan sin ver los valores.
```

(83 y 88 caracteres.)

**Descripción larga, inglés:**

```text
Klav is an open-source, end-to-end encrypted password manager built for people who work with AI agents. This extension brings your Klav vault to the browser.

FILL FROM THE FIELD
Click the Klav key in a login, card or address field and pick what to fill. Klav only offers items whose site matches the page you are on, including the frame inside it, so a look-alike address gets nothing. Sign-ins in several steps (email first, then the password, then a one-time code) are followed for you.

ONE-TIME CODES IN VIEW
Logins with two-factor codes show the live code in the popup, ready to copy. After you sign in, Klav fills the code too.

STRONG PASSWORDS AND SAVING
On a sign-up form, Klav suggests a strong password that follows the site's rules. When you send a form, it offers to save or update the login.

PASSKEYS
When a site offers you a passkey, save it in Klav, and sign in with it in any browser with Klav. Klav signs on your computer: the private key never reaches the page or the extension. Security keys and passkeys on your phone keep working: "Use another device" hands the request to the browser.

AGENTS ASK, YOU APPROVE
When an AI agent (Claude Code, Cursor, your own scripts) needs to sign in somewhere, it asks Klav. You see who is asking, for which site and why, and approve it in the popup or with Touch ID. Klav fills the page for the agent, and the agent never receives the password. Within a task you approved, an agent can also sign in with your passkey, and it never gets the key either. Everything is kept in a tamper-evident audit log, including each sign-in with a passkey.

PRIVATE BY DESIGN
- Your vault is encrypted on your devices. The server never sees your passwords, your master password or the sites you save.
- The extension talks only to the Klav app on your computer, never to a server of its own.
- No analytics, no tracking, no third-party icon services.
- What you copy is cleared from the clipboard after 30 seconds.

REQUIREMENTS
The extension works with the Klav app for your computer (the klav command and the klavd background service), which keeps your account and unlocks with Touch ID or your master password. Install it first. On a Mac, the Klav app sets everything up: open it and click "Connect the browsers". From the command line (macOS or Linux), run "klav extension install-host".

Klav is open source: https://github.com/OmarAlex24/klav
Privacy policy: https://klav.dev/privacy
```

**Descripción larga, español:**

```text
Klav es un gestor de contraseñas de código abierto, con cifrado de extremo a extremo y pensado para quien trabaja con agentes de IA. Esta extensión lleva tu bóveda de Klav al navegador.

RELLENA DESDE EL CAMPO
Pulsa la llave de Klav en un campo de inicio de sesión, de tarjeta o de dirección y elige qué rellenar. Klav solo ofrece los elementos cuyo sitio coincide con la página en la que estás, también dentro de sus marcos, así que una dirección parecida no recibe nada. Los inicios de sesión en varios pasos (primero el correo, luego la contraseña y luego un código) los sigue por ti.

CÓDIGOS DE UN SOLO USO A LA VISTA
Los logins con verificación en dos pasos muestran el código vivo en el popup, listo para copiar. Al iniciar sesión, Klav también rellena el código.

CONTRASEÑAS FUERTES Y GUARDAR
En un formulario de registro, Klav propone una contraseña fuerte que cumple las reglas del sitio. Al enviar un formulario, ofrece guardar o actualizar el login.

PASSKEYS
Cuando un sitio te ofrezca una passkey, guárdala en Klav e inicia sesión con ella en cualquier navegador con Klav. Klav firma en tu equipo: la llave privada nunca llega a la página ni a la extensión. Las llaves de seguridad y las passkeys de tu teléfono siguen funcionando: «Usar otro dispositivo» le pasa la petición al navegador.

LOS AGENTES PIDEN PERMISO
Cuando un agente de IA (Claude Code, Cursor, tus propios scripts) necesita iniciar sesión en algún sitio, se lo pide a Klav. Ves quién lo pide, para qué sitio y por qué, y lo apruebas en el popup o con Touch ID. Klav rellena la página para el agente, y el agente nunca recibe la contraseña. Dentro de una tarea que aprobaste, un agente también puede iniciar sesión con tu passkey, y tampoco recibe la llave. Todo queda en una bitácora a prueba de manipulación, también cada inicio de sesión con una passkey.

PRIVADO DESDE EL DISEÑO
- Tu bóveda se cifra en tus dispositivos. El servidor nunca ve tus contraseñas, tu contraseña maestra ni los sitios que guardas.
- La extensión solo habla con la app de Klav de tu equipo, nunca con un servidor propio.
- Sin analítica, sin rastreo y sin servicios de íconos de terceros.
- Lo que copias se borra del portapapeles a los 30 segundos.

REQUISITOS
La extensión funciona con la app de Klav para tu equipo (el comando klav y el servicio klavd), que guarda tu cuenta y desbloquea con Touch ID o con tu contraseña maestra. Instálala primero. En un Mac, la app de Klav lo prepara todo: ábrela y pulsa «Conectar los navegadores». Desde la terminal (macOS o Linux), corre «klav extension install-host».

Klav es de código abierto: https://github.com/OmarAlex24/klav
Política de privacidad: https://klav.dev/privacy
```

Las dos descripciones dicen «código abierto», enlazan al repositorio y dan por
hecho que hay una descarga de Klav. Por eso la extensión se envía cuando el
repositorio sea público y haya un DMG o una *release* que descargar
([publicar-extension.md](../../../docs/publicar-extension.md) §1).

## 2. Categoría, sitios y contacto

| Campo | Chrome Web Store | AMO | Edge Add-ons |
|---|---|---|---|
| Categoría | *Productivity* → *Tools* [REVISAR: la lista de categorías cambia; si hay una de privacidad y seguridad, mejor esa] | *Privacy & Security* | *Productivity* |
| Sitio web | `https://klav.dev` | *Homepage* `https://klav.dev` | *Website* `https://klav.dev` |
| Soporte | *Support URL* `https://github.com/OmarAlex24/klav/issues`. El correo de la cuenta de desarrollador, que la ficha muestra: `support@klav.dev` | *Support site* `https://github.com/OmarAlex24/klav/issues` y *Support email* `support@klav.dev` | *Support contact* `support@klav.dev` |
| Política de privacidad | `https://klav.dev/privacy` | casilla «This add-on has a privacy policy» y el texto de [`docs/privacidad.md`](../../../docs/privacidad.md), en inglés | `https://klav.dev/privacy` |
| Licencia | — | *Apache License 2.0* | — |
| Contenido para adultos | No | — | — |
| Precio | Gratis | Gratis | Gratis |
| Etiquetas o términos de búsqueda | — | `password manager`, `passwords`, `2fa`, `totp`, `ai agents` | hasta 7: `password manager`, `passwords`, `autofill`, `2FA`, `TOTP`, `AI agents`, `MCP` |

`support@klav.dev` es para el soporte, la privacidad y el borrado de cuentas, y
llega por Cloudflare Email Routing. Los reportes de seguridad van por
`SECURITY.md`, no por este correo.

AMO pide también un *slug* para la dirección: `klav`
(`addons.mozilla.org/firefox/addon/klav`). [REVISAR: si está ocupado,
`klav-passwords`.]

## 3. Propósito único (Chrome, *Single purpose*)

```text
Klav fills and saves the person's logins, payment cards and addresses on web pages from their Klav password manager, signs in with and saves the person's passkeys in Klav, and lets the person's AI agents fill a login or use a passkey on the open tab after the person approves it. Everything the extension does serves that one purpose: autofill and sign-in from the person's own encrypted vault.
```

> Klav rellena y guarda en las páginas los logins, tarjetas y direcciones de la
> persona desde su gestor de contraseñas Klav, inicia sesión con sus passkeys y
> las guarda en Klav, y deja que sus agentes de IA rellenen un login o usen una
> passkey en la pestaña abierta cuando la persona lo aprueba. Todo lo que hace
> la extensión sirve a ese único propósito: rellenar e iniciar sesión desde la
> bóveda cifrada de la propia persona.

## 4. Justificación de cada permiso

El manifiesto real (`dist/chromium/manifest.json` tras `pnpm build`, generado
por `scripts/build.mjs`) pide exactamente esto. No sobra ningún permiso: se
revisó cada uno contra el código (`src/`) el 2026-11-06.

| Permiso | Chromium | Firefox | Dónde se usa |
|---|---|---|---|
| `nativeMessaging` | sí | sí | `src/background/native.ts` (`runtime.connectNative`) |
| `alarms` | sí | sí | `src/background/clipboard.ts` |
| `clipboardWrite` | sí | sí | `src/ui/popup.ts`, `src/background/clipboard.ts` |
| `storage` | sí | sí | `src/background/index.ts`, `src/ui/popup.ts`, `src/ui/siteicon.ts`, `src/ui/generator.ts`, `src/background/clipboard.ts` |
| `offscreen` | sí | — | `src/background/clipboard.ts` |
| `favicon` | sí | — | `src/ui/siteicon.ts` (`_favicon/`) |
| *Content script* `content.js` en `http://*/*` y `https://*/*`, todos los marcos, `document_idle` | sí | sí | `src/content/` |
| *Content scripts* de las passkeys en `http://*/*` y `https://*/*`, todos los marcos, `document_start`: `webauthn.js` (el puente, mundo aislado) y `webauthn-page.js` (`world: "MAIN"`, el mundo de la página) | sí | sí | `src/content/webauthn.ts`, `src/page/webauthn.ts` |

No pide `tabs`, `activeTab`, `scripting`, `webRequest`, `cookies`,
`history`, `clipboardRead` ni `host_permissions`, y ningún *content script*
usa `<all_urls>`.

**Las passkeys** ([extension.md](../../../docs/extension.md) §13) no piden
ningún permiso nuevo, pero añaden los dos *content scripts* de la última fila
y `passkey.html`, el marco de Klav para elegir una passkey, a los
`web_accessible_resources` (con `use_dynamic_url` en Chromium, como las demás
superficies). Chrome revisa con cuidado un *script* en el mundo de la página,
así que la justificación del acceso a los sitios y las notas de la §7 explican:

- **Por qué hace falta.** La página llama a `navigator.credentials.create` y
  `get` en su propio mundo, y un *content script* aislado no puede contestar
  esas llamadas.
- **Qué lee y qué no.** `webauthn-page.js` sustituye solo esas dos funciones,
  y solo en un contexto seguro (`window.isSecureContext`). Lee solo las
  opciones que la página pasa a esas llamadas: el reto, el rpId, el usuario y
  las credenciales permitidas o excluidas. No toca el DOM, los formularios ni
  nada más de la página, y no guarda nada.
- **Por dónde lo manda.** Las pasa con `window.postMessage` al puente de su
  misma ventana, que solo acepta mensajes de esa ventana
  (`event.source === window`), vuelve a validar la forma de la petición y
  descarta los campos de más. El puente del marco de arriba dibuja además el
  marco de Klav (`passkey.html`).
- **Quién decide.** El *background*, con la dirección del marco que da el
  navegador (`sender.url`), nunca una que escriba la página. La llave privada
  no sale de `klavd`: la página recibe la respuesta ya firmada.
- **Qué no toma.** Un alta para una llave de seguridad o sin ES256,
  `mediation: "silent"`, un marco de otro origen que la página de arriba o un
  inicio de sesión sin passkeys de Klav para el sitio van al autenticador del
  navegador, con las opciones originales.
- **La bitácora.** Cada inicio de sesión con una passkey de Klav queda en ella
  (`passkey.used`).

Chrome pide una justificación por permiso en *Privacy practices*. En AMO no
hay campos por permiso: las notas de la §7 («Notes to reviewer») las resumen.

**`nativeMessaging`**

```text
The extension has no vault, keys or server connection of its own. It talks only to the Klav app installed on the same computer (the "dev.klav.host" native messaging host, which starts the klavd service). That app holds the person's encrypted account, decides whether a login matches the page, and returns only the values of the item the person picked. The host also checks the caller's extension ID and refuses any other.
```

> La extensión no tiene bóveda, llaves ni conexión propia a un servidor. Solo
> habla con la app de Klav instalada en el mismo equipo (el *host* nativo
> `dev.klav.host`, que arranca `klavd`). Esa app tiene la cuenta cifrada,
> decide si un login coincide con la página y devuelve solo los valores del
> elemento que la persona eligió. El *host* además comprueba el ID de la
> extensión que lo llama y rechaza cualquier otra.

**`alarms`**

```text
After the person copies a username, password or one-time code, the extension clears the clipboard 30 seconds later. An alarm is the only timer that survives the background service worker going to sleep, so the copied secret does not stay on the clipboard.
```

> Después de copiar un usuario, una contraseña o un código, la extensión vacía
> el portapapeles a los 30 segundos. Una alarma es el único temporizador que
> sobrevive a que el *service worker* se duerma, así el secreto no se queda en
> el portapapeles.

**`clipboardWrite`**

```text
The popup's copy buttons put a username, password or one-time code on the clipboard when the person clicks them, and the extension writes an empty value 30 seconds later to clear it. The extension never reads the clipboard (no clipboardRead).
```

> Los botones de copiar del *popup* ponen un usuario, una contraseña o un
> código en el portapapeles cuando la persona los pulsa, y la extensión escribe
> un valor vacío 30 segundos después para borrarlo. Nunca lee el portapapeles
> (no pide `clipboardRead`).

**`storage`**

```text
storage.local keeps four small settings and nothing from the vault: "Only fill, don't click" (onlyFill), "Ask each site for its icon" (askSites), the password generator's preferred kind (generatorDefaultKind), and the time the extension could not clear the clipboard (clipboardNotCleared), so it can tell the person. No passwords, sites, history or account data are stored.
```

> `storage.local` guarda cuatro ajustes pequeños y nada de la bóveda: «Solo
> rellenar, no pulsar» (`onlyFill`), «Pedir el ícono directamente al sitio»
> (`askSites`), el tipo preferido del generador (`generatorDefaultKind`) y la
> hora en que no pudo vaciar el portapapeles (`clipboardNotCleared`), para
> avisarlo. Ni contraseñas, ni sitios, ni historial, ni datos de la cuenta.

**`offscreen`** (solo Chrome)

```text
A Manifest V3 service worker has no clipboard. To clear the clipboard 30 seconds after a copy, the extension opens an offscreen document with the CLIPBOARD reason, writes an empty value and closes it. It is used for nothing else.
```

> Un *service worker* de MV3 no tiene portapapeles. Para vaciarlo 30 segundos
> después de copiar, la extensión abre un documento *offscreen* con el motivo
> `CLIPBOARD`, escribe un valor vacío y lo cierra. No se usa para nada más.

**`favicon`** (solo Chrome)

```text
Next to each saved login, the extension shows the site's icon. It reads it from the browser's own favicon cache (chrome-extension://<id>/_favicon/), a local lookup that sends no request to the network, so no third-party icon service learns which sites the person keeps in Klav.
```

> Junto a cada login guardado, la extensión muestra el ícono del sitio. Lo lee
> del caché de favicons del propio navegador (`_favicon/`), una consulta local
> que no hace ninguna petición a la red, para que ningún servicio de íconos sepa
> qué sitios guarda la persona en Klav.

**Acceso a los sitios** (Chrome, *Host permission justification*: los tres
*content scripts* en `http://*/*` y `https://*/*`, en todos los marcos)

Es corta a propósito, porque el campo es pequeño: el detalle de las passkeys
va en las notas de la §7.

```text
A password manager has to recognise login, card and address forms on any site, including sign-in forms inside frames. content.js only finds those fields and draws the Klav key. It gets an item's values only after the person picks it, only in a frame whose address matches the item's site, and sends nothing about pages anywhere. For passkeys, webauthn-page.js runs in the page's world ("world": "MAIN") from document_start, because pages call navigator.credentials.create and get there and an isolated script cannot answer them. It wraps only those two functions, in secure contexts, reads only the options passed to them and nothing else on the page, and hands them to webauthn.js, the isolated bridge in the same window. The background decides with the address the browser reports (sender.url); the private key stays in the local Klav app. No host_permissions, tabs, scripting or webRequest.
```

> Un gestor de contraseñas tiene que reconocer los formularios de login,
> tarjeta y dirección en cualquier sitio, también dentro de marcos.
> `content.js` solo encuentra esos campos y dibuja la llave de Klav. Recibe los
> valores de un elemento solo después de que la persona lo elige, solo en un
> marco cuya dirección coincide con el sitio del elemento, y no envía nada de
> las páginas a ningún lado. Para las passkeys, `webauthn-page.js` corre en el
> mundo de la página (`world: "MAIN"`) desde `document_start`, porque las
> páginas llaman ahí a `navigator.credentials.create` y `get` y un *script*
> aislado no puede contestarlas. Envuelve solo esas dos funciones, en
> contextos seguros, lee solo las opciones que reciben y nada más de la
> página, y se las pasa a `webauthn.js`, el puente aislado de la misma
> ventana. El *background* decide con la dirección que da el navegador
> (`sender.url`); la llave privada se queda en la app de Klav del equipo. Sin
> `host_permissions`, `tabs`, `scripting` ni `webRequest`.

**Código remoto** (Chrome, *Are you using remote code?*): **No, I am not
using remote code.**

```text
All JavaScript is bundled in the package. The only WebAssembly is klav_wasm_bg.wasm, built from the open-source crates/klav-wasm and shipped in the package; the extension pages' CSP is "script-src 'self' 'wasm-unsafe-eval'", which only lets them compile that packaged file. No eval, no remote scripts.
```

> Todo el JavaScript va en el paquete. El único WebAssembly es
> `klav_wasm_bg.wasm`, compilado desde `crates/klav-wasm` y empaquetado; la CSP
> de las páginas, `script-src 'self' 'wasm-unsafe-eval'`, solo permite compilar
> ese archivo. Sin `eval` y sin código remoto.

## 5. Uso de datos en Chrome (*Privacy practices* → *Data usage*)

Chrome pregunta qué datos de la persona **maneja** la extensión, aunque no
salgan hacia el desarrollador. La extensión lee formularios y rellena
contraseñas, tarjetas y direcciones, así que lo honesto es marcar lo que
maneja y certificar cómo se usa. Recomendación [REVISAR: decisión de Omar]:

| Casilla | ¿Marcar? | Por qué |
|---|---|---|
| *Personally identifiable information* | **Sí** | Rellena y guarda nombres, correos y direcciones |
| *Health information* | No | |
| *Financial and payment information* | **Sí** | Rellena y guarda tarjetas |
| *Authentication information* | **Sí** | Rellena y guarda contraseñas y códigos de un solo uso, y pasa a la app de Klav las peticiones de passkey de las páginas |
| *Personal communications* | No | |
| *Location* | No | |
| *Web history* | No | No guarda ni envía las páginas visitadas. Lee la dirección de la pestaña solo para compararla, en memoria, con el sitio del elemento |
| *User activity* | No | No registra clics, teclas ni desplazamientos. Detecta el envío de un formulario solo para ofrecer guardar |
| *Website content* | No [REVISAR] | Lee los campos de los formularios, no el texto de las páginas, y no lo guarda ni lo envía. Para las passkeys lee las opciones que la página pasa a WebAuthn (reto, rpId, usuario) y solo se las pasa a la app de Klav del equipo |

Las tres certificaciones se marcan, y las tres son ciertas:

- *I do not sell or transfer user data to third parties, outside of the approved use cases.*
- *I do not use or transfer user data for purposes that are unrelated to my item's single purpose.*
- *I do not use or transfer user data to determine creditworthiness or for lending purposes.*

*Privacy policy URL:* `https://klav.dev/privacy`.

La alternativa es no marcar nada, porque la extensión no transmite datos al
desarrollador: solo a la app local, que los cifra antes de sincronizar. Es
defendible, pero Chrome cuenta como «manejar» también lo que se procesa en el
equipo, y declarar de menos puede costar un rechazo. Declarar lo que se maneja
no. [REVISAR]

## 6. Uso de datos en AMO

El manifiesto de Firefox ya declara
`browser_specific_settings.gecko.data_collection_permissions: { required: ["none"] }`
(`scripts/build.mjs`), y AMO lo muestra como «no recoge datos». Para Mozilla,
«recoger» es transmitir datos fuera del equipo hacia el desarrollador o hacia
terceros. La extensión solo los pasa a la app local de la persona, que los
cifra de extremo a extremo hacia el servidor que la persona eligió. Por eso se
mantiene `none`. [REVISAR: si Mozilla lo pone en duda, la alternativa es
`required: ["authenticationInfo", "financialAndPaymentInfo", "personallyIdentifyingInfo"]`,
que muestra un aviso de consentimiento al instalar.]

En el formulario de AMO:

- *Does this add-on collect or transmit user data?*: lo que dice el
  manifiesto (`none`).
- *Privacy policy*: marcar que tiene una y pegar la versión en inglés de
  [`docs/privacidad.md`](../../../docs/privacidad.md), una vez resueltas sus
  notas [REVISAR] y sin ellas.

## 7. Notas para la revisión

**Chrome** (*Test instructions*, opcional pero recomendado), **AMO**
(*Notes to Reviewer*, en cada versión que se sube) y **Edge** (*Notes for
certification*). Los marcadores `<filled in at submission: …>` se sustituyen
en el formulario de la tienda, no aquí:

- la descarga: el enlace al DMG de la app de Mac o a la *release*, la que ya
  lleva el ID de la tienda ([publicar-extension.md](../../../docs/publicar-extension.md)
  §1);
- la cuenta de prueba: una cuenta desechable en `api.klav.dev` que Omar crea
  al enviar, vacía y sin nada suyo, y que se borra cuando la tienda apruebe.
  Su correo, su contraseña maestra y su Secret Key van solo en el formulario.

```text
Klav is an end-to-end encrypted password manager. This extension needs the Klav app on the same computer (the "klav" command and the "klavd" service; the Klav app for Mac includes both): it reaches the vault only through native messaging (host "dev.klav.host"). Without the app installed, the popup says "Klav isn’t responding" and shows the command to run; that is expected.

Test account, on Klav's server (api.klav.dev, the default). It was created for this review, holds nothing but what you add, and is deleted after the review:
- Email: <filled in at submission: reviewer account email>
- Master password: <filled in at submission: reviewer account master password>
- Secret Key: <filled in at submission: reviewer account Secret Key>

To try it:
1. Install Klav: <filled in at submission: download link (Mac app DMG or release)>.
2. Sign in and connect the browser, in one of two ways:
   - Mac app: open Klav from Applications and follow the steps in the "Set up this Mac" window. Under "Browsers", click "Connect the browsers"; under "Account", click "Sign in" and use the email, master password and Secret Key above.
   - Command line (macOS or Linux): klav login --email <filled in at submission: reviewer account email> (it asks for the Secret Key and the master password), then klav extension install-host.
3. Restart the browser and open the Klav popup: it shows the vault (unlock it with the master password if it asks).
4. Add a login for a site with a sign-in form, for example GitHub: "New item" in the popup, or klav item add login --title GitHub --username demo --url https://github.com -s password (it asks for the password).
5. Open https://github.com/login, click the Klav key in the username field and pick the login.

Passkeys: two more content scripts run from document_start in http and https frames. webauthn-page.js runs in the page's world ("world": "MAIN") because a page calls navigator.credentials.create and get in its own world, where an isolated content script cannot answer. It replaces only those two functions, only in secure contexts; it reads only the options the page passes to them (challenge, rpId, user, allowed or excluded credentials), touches nothing else on the page and stores nothing. It posts the call to webauthn.js, the isolated bridge in the same window, which accepts messages from that window only, checks the request's shape again and drops extra fields. The background decides with the frame address the browser reports (sender.url), never one the page writes, and asks klavd, which holds the private key and signs; the page only gets the signed response. A creation for a security key or without ES256, mediation "silent", a frame from another origin than the top page, or a sign-in with no Klav passkey for the site goes to the browser's own authenticator with the page's original options. Each sign-in with a Klav passkey is recorded in the person's audit log. No new permissions; passkey.html, Klav's passkey frame, is one more web-accessible resource (with use_dynamic_url in Chrome).

Permissions, in short: nativeMessaging is the only way to the vault; alarms, clipboardWrite (and offscreen in Chrome) clear the clipboard 30 seconds after a copy; storage keeps four settings, nothing from the vault; favicon (Chrome) reads the browser's local favicon cache. The main content script (content.js) runs on http and https pages in all frames to find login, card and address fields; it receives an item's values only after the person picks it, and only in a frame whose address matches the item's site. No remote code; the WebAssembly is built from crates/klav-wasm in the source.

Source: https://github.com/OmarAlex24/klav (Apache-2.0). Privacy policy: https://klav.dev/privacy
```

**AMO, código fuente** (*Do you need to submit source code?*: **Yes**,
porque el paquete lleva JavaScript empaquetado con esbuild y un WebAssembly
compilado). Se sube `klav-<versión>-source.zip` de `target/extension/` y en
las notas se añade:

```text
How to build the submitted package from the attached source (macOS or Linux):

Requirements: Node 22, pnpm 12 (corepack enable), Rust stable with the wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown), wasm-bindgen-cli 0.2.130 (cargo install wasm-bindgen-cli --version 0.2.130 --locked), zip. The exact versions used for this upload are in BUILD-INFO.txt below.

  unzip klav-<version>-source.zip && cd klav-<version>-source
  pnpm install --frozen-lockfile
  scripts/extension/package.sh

The Firefox package is target/extension/klav-<version>-firefox.zip (unpacked in target/extension/build/firefox). The script builds crates/klav-wasm with --remap-path-prefix so the WebAssembly does not depend on where the source is unpacked, bundles src/ with esbuild (scripts/build.mjs, not minified) and runs addons-linter. The files in target/extension/build/firefox match the uploaded package byte for byte (diff -r against the unzipped upload); the .zip itself differs only in file timestamps.

BUILD-INFO.txt:
<filled in at submission: contents of target/extension/BUILD-INFO.txt>
```

## 8. Capturas e imágenes

Todas salen del código del repositorio: el *popup* y las superficies reales,
compiladas, sobre un sitio de ejemplo inventado (Northwind, en un dominio
`.example`) y con datos de ejemplo. Cómo se rehacen: §4 de
[`publicar-extension.md`](../../../docs/publicar-extension.md).

| Archivo | Tamaño | Qué muestra | Chrome | AMO | Edge |
|---|---|---|---|---|---|
| `screenshots/{en,es}/1-rellenar.png` | 1280×800 | El menú en el campo, con dos cuentas del sitio, y la tarjeta «Iniciar sesión como» | sí | sí | sí |
| `screenshots/{en,es}/2-boveda.png` | 1280×800 | El *popup*: la bóveda con logos y códigos de un solo uso | sí | sí | sí |
| `screenshots/{en,es}/3-generar.png` | 1280×800 | El generador en un registro | sí | sí | sí |
| `screenshots/{en,es}/4-guardar.png` | 1280×800 | La barra para guardar el login nuevo | sí | sí | sí |
| `screenshots/{en,es}/5-agentes.png` | 1280×800 | Un agente pide rellenar y espera la aprobación | sí | sí | sí |
| `images/promo-440x280-{en,es}.png` | 440×280 | Mosaico pequeño | sí [REVISAR: si sigue siendo obligatorio] | — | opcional |
| `images/promo-1400x560-{en,es}.png` | 1400×560 | Marquesina | opcional | — | opcional |
| `images/logo-300.png` | 300×300 | Logo de la tienda | — | — | obligatorio |
| `../static/icons/128.png` | 128×128 | Ícono de la tienda (el del paquete) | obligatorio | (del paquete) | — |

Chrome acepta hasta 5 capturas y AMO las que quieras. [REVISAR: el límite de Edge; eran 6.] Las cinco
van en ese orden. Chrome y Edge permiten capturas por idioma: las de `en`
para el inglés y las de `es` para el español.

Los logos de GitHub, Linear, Figma, Notion, Stripe y Vercel de la captura 2
son los que Klav dibuja con Simple Icons (CC0) para que la persona reconozca
sus elementos ([extension.md](../../../docs/extension.md) §7). [REVISAR: si
prefieres que no aparezcan marcas en la ficha, cambia esos elementos en
`e2e/tiendas.spec.ts` por sitios inventados y vuelve a hacer las capturas.]
