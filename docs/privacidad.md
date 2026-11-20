# Política de privacidad

**Estado:** publicada en `https://klav.dev/privacy`. La página, con el mismo
texto en inglés y en español y sin JavaScript, es
[`apps/web/public/privacy/index.html`](../apps/web/public/privacy/index.html).
Las dos tienen que decir lo mismo: si cambias una, cambia la otra.

De dónde sale cada afirmación (para revisarla contra el código):

| Afirmación | Fuente |
|---|---|
| El servidor no ve la contraseña maestra | OPAQUE, ADR [0009](decisiones/0009-opaque.md), T2 |
| Títulos, URL, usuarios y valores van cifrados | [especificacion-cripto.md](especificacion-cripto.md) §7, T13 |
| Lo que queda en claro | Esquema de `crates/klav-server/migrations/`, T13, T20 |
| Los registros del servidor no llevan IP, cuerpos ni cabeceras | `crates/klav-server/src/telemetry.rs` |
| La IP solo vive en memoria, para el límite de intentos | `crates/klav-server/src/ratelimit.rs` |
| HIBP: apagado, prefijo de 5 caracteres, `Add-Padding` | `crates/klav-client/src/health.rs`, T101 |
| La extensión no hace peticiones a Klav | [extension.md](extension.md) §7 y §9 |
| El *script* de las passkeys solo envuelve `navigator.credentials.create` y `get`, y solo en páginas seguras | `apps/extension/src/page/webauthn.ts` (`install`), [extension.md](extension.md) §13 |
| La llave privada de una passkey no sale de `klavd` | [extension.md](extension.md) §13, `crates/klav-client/src/passkeys.rs` |
| La bitácora apunta cada uso de una passkey, sin el sitio | `PersonEvent` en `crates/klav-proto/src/audit.rs`, ADR [0020](decisiones/0020-passkeys.md) §10, [api.md](api.md) §9 |
| La papelera y las bóvedas borradas se purgan a los 30 días y dejan solo el identificador del elemento | `trash_days` en `crates/klav-server/src/config.rs`: 30 por defecto, y solo cambia con un archivo TOML en `KLAV_CONFIG`, que ni la imagen de Railway (`deploy/railway/Dockerfile`) ni [self-hosting.md](self-hosting.md) §8.1 ponen. `purge_item` en `crates/klav-server/src/purge.rs` |
| Qué borra el borrado de una cuenta | `ON DELETE CASCADE` desde `accounts` en `crates/klav-server/migrations/`: todas las tablas salvo `server_state`. Los adjuntos del disco, `remove_orphan_files` en `crates/klav-server/src/purge.rs` |
| La lista de espera guarda correo, idioma y fecha | [sitio-web.md](sitio-web.md) §2 |
| Avisos de iOS sin contenido | T75 |

---

**Última actualización:** 20 de noviembre de 2026

## Resumen

Klav es un gestor de contraseñas con cifrado de extremo a extremo. Tus bóvedas
se cifran en tus dispositivos antes de salir hacia el servidor, y la llave para
abrirlas nunca sale de ellos. Ni el servidor de Klav ni quien lo opere puede
leer tus contraseñas, tus notas, tus tarjetas ni los sitios que guardas. Klav no
lleva analítica, no rastrea y no vende ni comparte datos con nadie.

El código de Klav es abierto, así que cada afirmación de esta página se puede
comprobar en él.

## Quién es el responsable

Klav lo desarrolla y opera Omar Espinosa (México).

Para cualquier duda, solicitud de privacidad o ayuda con tu cuenta, escribe a
`support@klav.dev`. Los reportes de seguridad no van ahí: cómo enviarlos está
en [`SECURITY.md`](https://github.com/OmarAlex24/klav/blob/main/SECURITY.md).

## Qué ve el servidor y qué no

Por defecto, las apps de Klav sincronizan con el servidor de Klav en
`api.klav.dev`. También puedes alojar tu propio servidor; en ese caso, quien lo
opera eres tú y esta sección describe lo que vería tu servidor.

**El servidor no ve:**

- tu contraseña maestra (el inicio de sesión usa OPAQUE: el servidor nunca la
  recibe, ni un valor del que pueda deducirla);
- tu Secret Key;
- el contenido de tus elementos: contraseñas, códigos de un solo uso, notas,
  tarjetas, direcciones, llaves y archivos adjuntos;
- los títulos, los usuarios, las direcciones de los sitios y las etiquetas de
  tus elementos, que también van cifrados, salvo los sitios y las etiquetas que
  el servidor ve por tus agentes (abajo);
- los nombres de tus bóvedas y proyectos.

**El servidor sí ve, porque lo necesita para sincronizar:**

- tu correo electrónico, que es tu cuenta;
- el nombre y el tipo de cada dispositivo que conectas (por ejemplo «MacBook»,
  `macos`), cuándo se conectó y cuándo se usó por última vez;
- cuántos elementos, bóvedas y versiones tienes, cuánto ocupan y cuándo se
  crearon o cambiaron;
- los identificadores internos (aleatorios) de bóvedas, proyectos y elementos,
  y qué cuentas pueden abrir cada bóveda (hoy, solo la tuya);
- la hora de cada sincronización y de cada inicio de sesión;
- si usas agentes: el nombre y la nota de cada agente, su estado, los permisos
  que pide, y **en claro** el motivo que el agente escribe y el sitio que
  declara en cada petición, para poder mostrártelos y guardarlos en la
  bitácora;
- los permisos que das a cada agente, con los sitios y las etiquetas que
  nombren; las etiquetas de cada elemento que un agente usa, escribe o pide;
  los sitios de los elementos de cada tarea que apruebas, y el sitio de cada
  cambio de contraseña que hace un agente;
- la bitácora de lo que hicieron tus agentes (qué acción, sobre qué elemento,
  cuándo). Es una cadena cuya cabeza firman tus dispositivos al verificarla:
  así detectan que alguien cambie lo que ya verificaron, pero el servidor puede
  omitir lo posterior, y partes de cada evento, como el resultado, solo las
  escribe él;
- cada vez que inicias sesión con una passkey guardada en Klav: tu dispositivo
  lo apunta en la bitácora, con el elemento, el dispositivo y la hora y, si
  fue un agente dentro de una tarea, qué agente y qué tarea. No apunta el
  sitio. Crear o reemplazar una passkey queda como cualquier otro cambio de un
  elemento;
- si usas la app de iPhone con avisos, el *token* de avisos de Apple de ese
  dispositivo. Los avisos solo llevan un tipo y un identificador aleatorio, sin
  texto ni nombres.

**Tu dirección IP:** el servidor la usa para limitar los intentos (por ejemplo,
contra quien prueba contraseñas). Esa cuenta vive en memoria y se borra sola;
no se escribe en la base de datos. Los registros del servidor de Klav guardan el método,
la ruta (sin identificadores ni parámetros), el código de respuesta y el tiempo
de cada petición, sin IP, sin cabeceras y sin el contenido. Como `api.klav.dev`
corre detrás del *proxy* de borde de Railway, los registros HTTP propios de
Railway pueden registrar direcciones IP y metadatos de la petición bajo la
política de retención de Railway.

## La extensión del navegador

La extensión no habla con ningún servidor de Klav. Solo habla con la app de
Klav de tu equipo (`klavd`), a través del mecanismo del navegador para apps
nativas (*native messaging*). Es esa app la que sincroniza, cifrado, con tu
servidor.

- Lee los formularios de las páginas para ofrecerte rellenarlos. No recibe nada
  de tu bóveda hasta que eliges qué rellenar, y entonces solo los valores de ese
  elemento.
- Para las passkeys, pone en cada página un *script* que envuelve las dos
  funciones con las que un sitio crea o pide una passkey
  (`navigator.credentials.create` y `get`), y solo se activa en las páginas
  seguras. No lee nada más de la página: solo lo que el sitio pasa a esas
  funciones, como el reto y el nombre de la cuenta, lo mismo que recibiría
  cualquier autenticador. Lo que Klav no atiende (una llave de seguridad, tu
  teléfono) pasa al navegador tal cual. La llave privada de tus passkeys nunca
  sale de la app de Klav de tu equipo: la página recibe la respuesta ya
  firmada.
- Guarda en el navegador solo cuatro ajustes: «Solo rellenar, no pulsar», «Pedir
  el ícono directamente al sitio», el tipo de contraseña preferido del generador
  y la hora en que no pudo vaciar el portapapeles. Nada de tu bóveda, ni
  historial, ni direcciones.
- Los logos de sitios comunes vienen dentro de la extensión. En Chromium también
  usa los íconos que el navegador ya tiene en su caché. Ningún servicio de
  íconos se entera de qué sitios guardas. Si activas «Pedir el ícono
  directamente al sitio» (apagado de fábrica), pide `/favicon.ico` al propio
  sitio del elemento, sin `Referer`.
- Lo que copias se borra del portapapeles a los 30 segundos.

## Contraseñas filtradas (opcional)

La comprobación de contraseñas filtradas está **apagada de fábrica**. Si la
activas, tu dispositivo envía a Have I Been Pwned (`api.pwnedpasswords.com`)
solo los 5 primeros caracteres del hash SHA-1 de cada contraseña, con relleno
para que el tamaño de la respuesta no revele nada. La comparación se hace en tu
dispositivo. Have I Been Pwned ve tu IP y la hora, pero no tus contraseñas ni
sus hashes completos. Su política de privacidad es la de ese servicio.

## Analítica, rastreo y publicidad

No hay. Ni en las apps, ni en la extensión, ni en el sitio web: sin cookies de
rastreo, sin píxeles, sin SDK de terceros, sin informes de fallos automáticos.
Klav no vende, no alquila ni comparte tus datos, y no los usa para publicidad
ni para decidir sobre créditos o seguros.

## La lista de espera de klav.dev

Si te apuntas a la lista de espera del plan alojado, el sitio guarda tu correo,
el idioma de la página y la fecha. Nada más: ni IP, ni navegador, ni cookies.
Solo se usa para avisarte cuando el plan abra. Para darte de baja en cualquier
momento, escribe a `support@klav.dev` desde ese mismo correo.

## Cuánto tiempo se guardan los datos

- Lo que tu cuenta tiene en el servidor se guarda mientras exista la cuenta.
- Los elementos que mueves a la papelera se borran al vaciarla o a los 30
  días. Del elemento queda solo su identificador, sin contenido, para que tus
  otros dispositivos se enteren de que ya no existe. Una bóveda que borras se
  borra entera a los 30 días, con sus archivos.
- Al revocar un dispositivo o un agente, sus sesiones dejan de valer. El
  registro del dispositivo y la bitácora se conservan para que puedas ver qué
  pasó.
- Las copias de seguridad de la base de datos de `api.klav.dev` las gestionan
  los respaldos de volumen de Railway (hasta 6 días para copias diarias, 27 días
  para semanales y 89 días para mensuales) y se borran solas al caducar.

## Borrar tu cuenta

Puedes borrar tu cuenta directamente desde Klav: en la app de iPhone (Ajustes ›
Cuenta › «Borrar mi cuenta»), en la app de Mac (Ajustes › Cuenta › «Borrar mi
cuenta») o desde la CLI (`klav account delete`). Después de confirmar con tu
contraseña maestra (y Face ID o Touch ID donde esté disponible), Klav espera 7
días antes de borrar todo en el servidor; durante esa espera todos los agentes
se detienen y puedes cancelar desde cualquier dispositivo con sesión iniciada.
También puedes escribir a `support@klav.dev` desde el correo de tu cuenta si
necesitas ayuda.

De la base de datos del servidor se borra todo lo de tu cuenta:

- tu correo y los datos con los que inicias sesión;
- tus dispositivos, sus sesiones y sus *tokens* de avisos;
- tus bóvedas, con sus proyectos, sus elementos, sus versiones anteriores y
  sus archivos adjuntos (los archivos se borran del disco en la limpieza
  siguiente del servidor, que corre cada hora);
- tus agentes, con sus permisos, sus aprobaciones, sus tareas y sus cambios
  asistidos;
- la bitácora entera.

No se borra:

- lo que sigue en tus dispositivos: la copia local de tus bóvedas, el kit de
  emergencia y lo que hayas exportado. Eso lo borras tú, por ejemplo con
  «Borrar la copia de este iPhone» o «Cerrar sesión» en la app de iPhone,
  «Borrar la copia de este Mac» o «Desinstalar Klav de este Mac» en la app de
  Mac, o `klav logout` en la CLI;
- tu correo en la lista de espera de `klav.dev`, si te apuntaste: es otra base
  de datos (arriba, «La lista de espera de klav.dev»);
- lo que haya en las copias de seguridad de la base de datos, hasta que
  caduquen («Cuánto tiempo se guardan los datos»).

## Dónde están los datos

`api.klav.dev` y `klav.dev` corren en Railway en la región **US West** (Estados
Unidos). Si te conectas desde fuera de Estados Unidos, tus datos cifrados y los
metadatos de tu cuenta se transfieren y almacenan en Estados Unidos. Puedes
alojar tu propio servidor de Klav en la región que prefieras.

## Tus derechos

Puedes pedir una copia de los datos de tu cuenta que el servidor puede leer
(la lista de «sí ve» de arriba), que se corrijan o que se borren, escribiendo a
`support@klav.dev`. Respondemos en un plazo máximo de 30 días. Tratamos los
datos de tu cuenta para prestarte el servicio de sincronización (ejecución del
contrato) y los correos de la lista de espera con tu consentimiento. Lo cifrado
no lo podemos leer, así que tampoco lo podemos entregar en claro: lo exportas tú
desde tus dispositivos.

## Menores

Klav no está dirigido a menores de 13 años (o menores de 16 en el Espacio
Económico Europeo y el Reino Unido, o la edad mínima de consentimiento digital
en tu país). Si detectamos una cuenta creada por debajo de esa edad, la
borraremos.

## Cambios

Si esta política cambia, la fecha de arriba cambia también. Los cambios
importantes se anunciarán en `klav.dev` antes de que apliquen. El historial
completo está en el repositorio.

---

# Privacy policy

**Last updated:** November 20, 2026

## Summary

Klav is an end-to-end encrypted password manager. Your vaults are encrypted on
your devices before they leave for the server, and the key that opens them never
leaves your devices. Neither Klav's server nor whoever runs it can read your
passwords, notes, cards or the sites you save. Klav has no analytics, no
tracking, and does not sell or share data with anyone.

Klav is open source, so every statement on this page can be checked in its
code.

## Who is responsible

Klav is developed and operated by Omar Espinosa (Mexico).

For questions, privacy requests or account help, write to
`support@klav.dev`. Security reports go elsewhere: see
[`SECURITY.md`](https://github.com/OmarAlex24/klav/blob/main/SECURITY.md).

## What the server sees, and what it does not

By default, Klav's apps sync with Klav's server at `api.klav.dev`. You can also
host your own server; then you run it, and this section describes what your
server would see.

**The server does not see:**

- your master password (sign-in uses OPAQUE: the server never receives it, nor
  anything it could work it out from);
- your Secret Key;
- the contents of your items: passwords, one-time codes, notes, cards,
  addresses, keys and attachments;
- the titles, usernames, site addresses and tags of your items, which are
  encrypted too, except the sites and tags your agents' use shows it (below);
- the names of your vaults and projects.

**The server does see, because it needs it to sync:**

- your email address, which is your account;
- the name and kind of each device you connect (for example "MacBook",
  `macos`), when it was added and when it was last used;
- how many items, vaults and versions you have, how large they are, and when
  they were created or changed;
- the internal (random) identifiers of vaults, projects and items, and which
  accounts can open each vault (today, only yours);
- the time of each sync and each sign-in;
- if you use agents: each agent's name and note, its status, the permissions it
  asks for, and **in plain text** the reason the agent writes and the site it
  declares in each request, so that they can be shown to you and kept in the
  audit log;
- the permissions you give each agent, including any sites and tags they
  name; the tags of each item an agent uses, writes or asks about; the sites
  of the items in each task you approve; and the site of each password change
  an agent makes;
- the audit log of what your agents did (which action, on which item, when).
  It is a chain whose head your devices sign when they verify it: they catch a
  change to what they already verified, but the server can leave out later
  events, and it alone writes parts of each event, such as the outcome;
- each time you sign in with a passkey saved in Klav: your device adds it to
  the audit log, with the item, the device and the time and, if an agent did
  it within a task, which agent and which task. The site is not recorded.
  Creating or replacing a passkey is recorded like any other change to an
  item;
- if you use the iPhone app with notifications, that device's Apple push token.
  Notifications carry only a type and a random identifier, no text or names.

**Your IP address:** the server uses it to limit attempts (for example, against
someone guessing passwords). That count lives in memory and expires by itself;
it is never written to the database. Klav's server logs keep the method, the
route (without identifiers or parameters), the status code and the duration of
each request: no IP address, no headers, no contents. Because `api.klav.dev`
runs behind Railway's edge proxy, Railway's own HTTP access logs may record IP
addresses and request metadata under Railway's log retention policy.

## The browser extension

The extension does not talk to any Klav server. It only talks to the Klav app on
your computer (`klavd`), through the browser's mechanism for native apps
(native messaging). That app is what syncs, encrypted, with your server.

- It reads the forms on web pages to offer to fill them. It receives nothing
  from your vault until you choose what to fill, and then only that item's
  values.
- For passkeys, it adds a script to each page that wraps the two functions a
  site calls to create or ask for a passkey (`navigator.credentials.create`
  and `get`), and it only turns on in secure pages. It reads nothing else
  from the page: only what the site passes to those functions, such as the
  challenge and the account name, which is what any authenticator would get.
  Whatever Klav doesn't handle (a security key, your phone) goes to the
  browser unchanged. Your passkeys' private keys never leave the Klav app on
  your computer: the page gets the response already signed.
- It stores only four settings in the browser: "Only fill, don't click", "Ask
  each site for its icon", the generator's preferred password kind, and the time
  it could not clear the clipboard. Nothing from your vault, no history, no
  addresses.
- Logos for common sites ship inside the extension. In Chromium it also uses the
  icons the browser already has in its cache. No icon service learns which sites
  you keep. If you turn on "Ask each site for its icon" (off by default), it asks
  the item's own site for `/favicon.ico`, without a `Referer`.
- What you copy is cleared from the clipboard after 30 seconds.

## Breached passwords (optional)

The breached-password check is **off by default**. If you turn it on, your device
sends Have I Been Pwned (`api.pwnedpasswords.com`) only the first 5 characters of
each password's SHA-1 hash, with padding so the size of the answer reveals
nothing. The comparison happens on your device. Have I Been Pwned sees your IP
address and the time, but not your passwords or their full hashes. Its own
privacy policy applies.

## Analytics, tracking and ads

None. Not in the apps, the extension or the website: no tracking cookies, no
pixels, no third-party SDKs, no automatic crash reports. Klav does not sell,
rent or share your data, and does not use it for advertising or for credit or
insurance decisions.

## The klav.dev waitlist

If you join the waitlist for the hosted plan, the site stores your email address,
the language of the page and the date. Nothing else: no IP address, no browser,
no cookies. It is only used to tell you when the plan opens. To remove your
address from the waitlist at any time, write to `support@klav.dev` from that
address.

## How long data is kept

- What your account has on the server is kept while the account exists.
- Items you move to the trash are deleted when you empty it or after 30 days.
  Only the item's identifier stays, with no contents, so your other devices
  learn that it is gone. A vault you delete is deleted in full after 30 days,
  with its files.
- When you revoke a device or an agent, its sessions stop working. The device's
  record and the audit log are kept so you can see what happened.
- Database backups of `api.klav.dev` are managed by Railway's volume backups
  (retained for up to 6 days for daily snapshots, 27 days for weekly snapshots,
  and 89 days for monthly snapshots) and are automatically deleted as they
  expire.

## Deleting your account

You can delete your account directly from Klav: in the iPhone app (Settings ›
Account › "Delete my account"), in the Mac app (Settings › Account › "Delete my
account"), or from the CLI (`klav account delete`). After you confirm with your
master password (and Face ID or Touch ID where available), Klav waits 7 days
before deleting everything on the server; while it waits, every agent stops,
and you can cancel from any signed-in device. You can also write to
`support@klav.dev` from your account's email address for help.

Everything your account has in the server's database is deleted:

- your email address and the data you sign in with;
- your devices, their sessions and their notification tokens;
- your vaults, with their projects, items, earlier versions and attachments
  (the files are removed from disk by the server's next cleanup, which runs
  every hour);
- your agents, with their permissions, approvals, tasks and assisted changes;
- the whole audit log.

What is not deleted:

- what is still on your devices: the local copy of your vaults, your
  emergency kit and anything you exported. You remove those yourself, for
  example with "Delete this iPhone’s copy" or "Sign out" in the iPhone app,
  "Delete this Mac’s copy" or "Uninstall Klav from this Mac" in the Mac app, or
  `klav logout` in the CLI;
- your email address on the `klav.dev` waitlist, if you joined it: that is a
  separate database (see "The klav.dev waitlist" above);
- whatever is in the database backups, until they expire (see "How long data
  is kept").

## Where the data is

`api.klav.dev` and `klav.dev` run on Railway in the **US West** region (United
States). If you connect from outside the United States, your encrypted vault
data and account metadata are transferred to and stored in the United States.
You can host your own Klav server in any region you choose.

## Your rights

You can ask for a copy of the account data the server can read (the "does see"
list above), or for it to be corrected or deleted, by writing to
`support@klav.dev`. We respond within 30 days. We process account data to
provide the sync service you signed up for (performance of a contract) and
waitlist emails based on your consent. We cannot read what is encrypted, so we
cannot hand it over in plain text either: you export it yourself from your
devices.

## Children

Klav is not directed at children under 13 (or under 16 in the European Economic
Area and the UK, or the minimum age of digital consent in your country). If we
learn an account was created in violation of this age limit, we will delete it.

## Changes

If this policy changes, the date at the top changes too. Significant changes will
be announced on `klav.dev` before they apply. The full history is in the
repository.
