# CLI `klav`

`klav` es el cliente de terminal de Klav. Habla con un `klav-server`, por
defecto el de `https://api.klav.dev` o uno propio
([`self-hosting.md`](self-hosting.md)), y cifra y descifra todo en tu máquina con
`klav-core`: el servidor solo ve ciphertext.

```sh
cargo build --release -p klav-cli     # binario en target/release/klav
```

## 1. Reglas que siguen todos los comandos

> La lista de comandos, las opciones globales, las variables de entorno y los códigos de salida están en la página pública [`cli-commands.mdx`](../apps/docs/src/content/docs/reference/cli-commands.mdx) (en `apps/docs/src/content/docs/reference/`); un cambio en esa lista va primero allí.

- **Los secretos nunca van en argv.** La lista de procesos (`ps`) y el historial
  de la shell los verían. Entran:
  - por un prompt sin eco (`-s NOMBRE`);
  - por stdin (`--secret-stdin NOMBRE`, `--password-stdin`);
  - o generados (`-g NOMBRE`).

  `--field password=…` se rechaza en cualquier campo secreto.
- **Los secretos no se muestran salvo que lo pidas.** `item get` los enmascara
  (`••••••••`). Solo se imprimen:
  - con `--reveal` (`klav item get --reveal`, `klav item history --reveal N`);
  - con `klav totp`, `klav generate` y `klav generated show N`;
  - con `klav inject` sin `-o`, que existe para emitirlos.

  Con `klavd` desbloqueado, los que piden el valor a `klavd` (todos menos
  `klav generate`, que lo crea) necesitan tu presencia: Touch ID o la
  contraseña maestra en la terminal, una vez por ventana y por sesión de
  terminal (5 minutos por defecto), nunca la de stdin. Es la puerta del
  [ADR 0041](decisiones/0041-presence-for-values-and-the-inject-card.md),
  encendida desde la capa 6 (§8, «Presencia antes de los valores»;
  [`modelo-de-amenazas.md`](modelo-de-amenazas.md) T195 y riesgo 49).
- **`--password-stdin`** lee la contraseña maestra de la **primera** línea de
  stdin. Los valores de `--secret-stdin` van en las líneas siguientes, en el
  orden de los argumentos. Sirve para scripts. En una terminal, lo normal es el
  prompt.
- **`--json`** en los comandos de consulta da una salida estable para scripts.
  También enmascara los secretos sin `--reveal`.
- **Códigos de salida:**

  | Código | Significado |
  |---|---|
  | 0 | éxito |
  | 1 | error (red, contraseña incorrecta, elemento inexistente…) |
  | 2 | uso incorrecto |
  | 3 | **posible rollback del servidor** |
  | 9 | `klavd` pide tu presencia antes de dar un valor y `klav` no tiene terminal donde pedir la contraseña maestra (§8, «Presencia antes de los valores») |

  El código 3 significa que el servidor mostró un estado más viejo que uno que
  este dispositivo ya vio (amenaza T7). No se aplica nada; revisa el servidor.
  Solo `klav sync` sale con él: los demás comandos, que sincronizan de paso,
  lo avisan en stderr y siguen con la copia local sin cambios, para que un
  servidor hostil no te deje fuera de tu bóveda. Si el servidor se restauró
  de una copia en la que confías, `klav sync --reset-cache` empieza de nuevo
  (§3). Para la bitácora, que tiene su propia copia, el equivalente es
  `klav log reset` (Bitácora): `klav log` y `klav log verify` salen con 3,
  con un mensaje que lo nombra, mientras la cadena del servidor no cuadre
  con la de este dispositivo.
  Revocar, rotar y ver lo que no sale de la bitácora siguen funcionando.
  `klav run` sale con el código de su proceso hijo.

## 2. Estado local

Todo vive en `$KLAV_HOME`. Por defecto es
`~/Library/Application Support/klav` en macOS y `~/.config/klav` en Linux.

- El directorio tiene modo 0700 y los archivos 0600.
- `account.json` guarda la identidad cifrada.
- La sesión y la caché van cifradas con la llave local del dispositivo
  (especificación §12.2).
- `deletion.bin` guarda lo que este dispositivo sabe del borrado de la
  cuenta (§3): la fecha pedida y si el servidor ya la borró. Va sellado
  con la llave local (propósito `deletion`), aparte de `cache.bin`, para
  que una versión anterior de Klav siga abriendo la caché.
- `revocations.bin` guarda los cambios de llave que este dispositivo debe
  (revocaciones con algo pendiente, y proyectos quitados a un agente activo
  con `--rotate-removed`) y, por agente, los proyectos, los elementos
  compartidos uno por uno y la versión de cada grant que firmó: una
  revocación posterior cambia esas llaves aunque el servidor sirva un grant
  viejo, ninguno, o corte la bitácora. Va sellado con la llave local
  (propósito `revocations`, especificación §12.2), aparte de `cache.bin`
  por la misma razón. Si no abre, `klav agent show` lo dice y Klav no lo
  sobrescribe; firmar un grant se detiene hasta apartarlo. Si lo escribió
  una versión más nueva de Klav, el error pide actualizar Klav y no
  apartarlo, y el archivo queda intacto.
- `protection.bin` guarda el conjunto protegido de los entornos (ADR 0032
  §3.1): lo que aporta cada entorno protegido, los elementos que alguna vez
  estuvieron protegidos, lo que protegen las reglas `origin: "protected"`
  de los grants vigentes, las bóvedas cuya versión de la persona no se pudo
  saber y la última versión de la persona de cada entorno. Va sellado con la
  llave local (propósito `protection`, especificación §12.2), aparte de
  `cache.bin` por la misma razón. Se recalcula tras cada sincronización. El
  conjunto solo se achica con prueba: un entorno purgado o en una bóveda que
  no abre sigue protegiendo lo que protegía, y si el archivo existe y no
  abre, todo valor pide presencia y no se firma un grant que conserve
  permisos hasta la siguiente sincronización.
- En disco no hay contraseñas, tokens ni títulos en claro.
- `health.json` guarda los ajustes de la salud de la bóveda (la consulta de
  contraseñas filtradas, apagada por defecto); no es secreto.
- `server-moved` aparece cuando la cuenta se mudó de una URL vieja a la nueva
  (§3) y desaparece cuando `klav status` lo cuenta. No es secreto.
- `clients.json` (0600) dice qué escribió Klav en cada cliente de agentes y
  qué copias de la skill son suyas (§9, ADR 0033 §3.4). No sale del Mac.
- `client-backups/<cliente>/` (0700, archivos 0600) guarda la copia de la
  configuración de un cliente de antes de cada cambio de Klav, las 5 más
  recientes por archivo. **Lleva los secretos de otros programas** tal como
  los tiene el original: no se imprime, no se sincroniza y no entra en la
  bitácora.

Varias cuentas o varios servidores en la misma máquina: usa un `KLAV_HOME`
distinto para cada uno.

La copia de este dispositivo solo se borra con `klav logout` (§3). Ninguna
respuesta del servidor la borra, tampoco la de una cuenta borrada (T165).

## 3. Cuenta y dispositivos

> Los pasos para quien usa Klav están en las páginas públicas [`create-an-account.mdx`](../apps/docs/src/content/docs/get-started/create-an-account.mdx) y [`add-a-device.mdx`](../apps/docs/src/content/docs/get-started/add-a-device.mdx) (en `apps/docs/src/content/docs/get-started/`); un cambio en esos pasos va primero allí.

```sh
klav signup --email ana@example.com --emergency-kit ~/Desktop/klav-kit.txt
klav login  --email ana@example.com \
  --emergency-kit ~/Desktop/klav-kit.txt      # en otro dispositivo
klav signup --server https://klav.example.com --email ana@example.com …  # servidor propio
klav signup --email ana@example.com --invite KLAV-XXXXX-…   # servidor por invitación (mejor sin --invite: lo pregunta)
klav status            # sin contraseña: cuenta, servidor, dispositivo, daemon
klav sync              # trae los cambios del servidor
klav sync --reset-cache [--yes]   # olvida la copia local y las marcas y descarga todo
klav account kit [--emergency-kit RUTA]   # vuelve a generar el kit de emergencia
klav lock | unlock     # con klavd (§8); sin daemon, cada comando desbloquea
klav account kit [--emergency-kit ARCHIVO]   # el kit otra vez, con la contraseña
klav account set-server URL                  # mover la cuenta a otra URL
klav account delete                          # borrar la cuenta en 7 días (solo en una terminal)
klav account delete --cancel                 # cancelarlo, desde cualquier dispositivo (Touch ID o contraseña)
klav logout [--yes] [--discard-unsent]       # cerrar sesión y borrar la copia de este dispositivo
```

- **`signup`** crea la cuenta y la bóveda "Personal" con su proyecto
  "General".
  - El **kit de emergencia** contiene la Secret Key, que necesitas para entrar
    desde otro dispositivo.
  - Con `--emergency-kit`, el kit se escribe en un archivo nuevo con modo 0600.
    Si no, se muestra en la terminal, por stderr.
  - El kit se entrega **antes** de registrar la cuenta: si no se puede
    escribir, no se crea nada. Si el registro falla después, `klav` avisa
    que borres el archivo del kit, que no sirve.
  - Imprímelo o guárdalo fuera de línea y borra el archivo.
- **`account kit`** pide la contraseña maestra y vuelve a generar el kit
  desde la Secret Key de este dispositivo (en la terminal o en un archivo
  nuevo con `--emergency-kit`).
- **`sync --reset-cache`** olvida la copia local de las bóvedas y las marcas
  que detectan un *rollback* (T7) y vuelve a descargar todo. Conserva los
  agentes revocados y las llaves de bóveda ya firmadas. Pide confirmación;
  sin terminal hace falta `--yes`. Úsalo solo si el servidor se restauró de
  una copia en la que confías.
- Una bóveda que el servidor deja de listar no se borra de la copia local:
  queda **solo lectura**, con un aviso (T14). `sync --reset-cache` la quita.
- **`login`** lee la Secret Key del kit (`--emergency-kit`) o te la pide sin
  eco.
- **El servidor** ([ADR 0028](decisiones/0028-servidor-por-defecto-klav-dev.md)):
  - Sin `--server` ni `KLAV_SERVER`, `signup` y `login` usan
    `https://api.klav.dev` (klav.dev). Está fijado en el binario: ninguna
    respuesta de red lo cambia.
  - Antes de pedir la contraseña, dicen por stderr qué servidor usan:
    `Server: https://api.klav.dev (klav.dev). Use --server URL for your own.`
  - `--server` también se puede dar con `KLAV_SERVER`. Solo se acepta
    `https://`, salvo `http://` a `localhost`/`127.0.0.1` para pruebas.
  - Una URL vieja de la tabla de mudanzas (hoy solo la que Railway generó
    para el servidor de producción) se cambia por la nueva, así
    que los kits de emergencia viejos siguen valiendo.
  - Con `KLAV_NO_DEFAULT_SERVER=1` no hay servidor por defecto: sin `--server`,
    el comando falla. Lo fijan los arneses de prueba, para que ninguna prueba
    llegue a producción.
- **Cómo acepta cuentas el servidor** ([ADR 0048](decisiones/0048-invite-beta-and-distribution.md) §2):
  antes de pedir la contraseña, `signup` lee `GET /v1/health`
  (`klav_client::server::registration_mode`). Primero `registration_mode`
  (`open`, `invite` o `closed`); si no viene (un servidor anterior), usa
  `registration_open`, como antes. Un modo que esta versión no conoce cuenta
  como `closed`. Si `/v1/health` no responde, `signup` se detiene ahí: no
  escribe un kit para una cuenta que quizá no exista.
  - **`closed`** (o `registration_open: false`): dice «Registration on
    klav.dev is not open yet. You can host your own server:
    https://docs.klav.dev/self-hosting/» (con el nombre del servidor:
    `klav.dev` para el de por defecto, el *host* de la URL para otro;
    `klav_client::server::registration_closed_message`) y no crea nada.
  - **`invite`**: hace falta un código de invitación. Se da con
    `--invite CODE` o `KLAV_INVITE`; sin ninguno de los dos, `signup` lo pide
    después del correo y antes de la contraseña: «Invite code:», **visible**
    al escribirlo (es de un solo uso y va ligado a un correo, no es un secreto
    de larga vida; así se puede pegar y revisar). Sin terminal no lo lee de
    stdin, donde va la contraseña (`--password-stdin`): falla con un error de
    uso que dice que se dé con `--invite` o `KLAV_INVITE`.
    - El código se comprueba con `POST /v1/auth/invite/check` **antes** de la
      contraseña, del kit y de Argon2id. Si no sirve, dice «This invite code
      isn't valid for <correo>. Check the code, or request one at
      https://klav.dev.» y sale con error, sin kit, sin `account.json` y sin
      derivar nada. La respuesta es la misma por cualquier motivo (no existe,
      revocado, vencido, agotado o de otro correo).
    - `signup` lo vuelve a comprobar justo antes del kit y lo manda en
      `register/start` y `register/finish`. Si el último uso de un código de
      grupo se gasta entre medias, el registro falla con el mismo mensaje
      (y el aviso de borrar el kit, que ya se escribió).
    - `--invite` queda en el historial de la *shell* y en `ps` hasta que se
      usa; `KLAV_INVITE` o la pregunta lo evitan. Un código usado o vencido ya
      no sirve de nada. `--help` nombra `KLAV_INVITE` pero nunca muestra su
      valor, y `klav` nunca imprime el código.
  - **`open`** o un servidor que no dice nada: no hace falta código, y si se
    da uno no se manda (un servidor anterior rechaza campos que no conoce).
  - Hoy klav.dev está cerrado; `login` funciona en cualquier modo.
- **Cuotas** (ADR 0048 §3): si el servidor limita lo que guarda cada cuenta y
  una escritura lo pasaría (`403 quota_exceeded`), `klav` muestra el mensaje
  del servidor tal cual, que dice qué límite, cuánto se usa y el máximo
  (`ClientError::QuotaExceeded`), por ejemplo «This account is limited to 20
  vaults (20 used; …)». Borrar, mover a la papelera y leer nunca se niegan.
- **Mudanza automática:** al desbloquear (CLI y `klavd`), si `account.json`
  tiene una URL de la tabla, el cliente pide `GET /v1/account` a la nueva con
  el token de acceso. Solo si responde con la misma cuenta y la misma
  identidad reescribe `account.json`. Si no (sin red, `401`, otra cuenta), no
  cambia nada y lo intenta la próxima vez. `klav status` lo dice una vez:
  `server: https://api.klav.dev (moved from <host viejo>)`.
  Los agentes hacen lo mismo con una petición firmada a `GET /v1/agent/me`,
  y solo si ya fijaron la identidad de la cuenta.
- **`klav account set-server URL`** mueve la cuenta a mano, también cuando un
  dominio cae. Hace un inicio de sesión OPAQUE completo en la URL nueva con la
  contraseña maestra, para este mismo dispositivo, y solo guarda la URL si la
  cuenta, la identidad, los parámetros de Argon2id y el dispositivo coinciden.
  El token de la sesión actual nunca va a un host sin verificar. La URL se
  toma tal cual (sin la tabla), así que sirve para volver a una vieja. Si
  `klavd` está corriendo, lo bloquea para que el próximo desbloqueo use la URL
  nueva.
- **`klav account kit`** pide la contraseña maestra y vuelve a mostrar el kit
  de emergencia con el servidor que usa hoy este dispositivo (la Secret Key
  sale de `$KLAV_HOME`). Mismas reglas que en `signup`: por stderr en una
  terminal, o en un archivo nuevo con modo 0600 con `--emergency-kit`.
- **Borrar la cuenta** ([ADR 0037](decisiones/0037-borrar-la-cuenta.md)):
  - **`klav account delete`** pide al servidor que borre la cuenta **7 días
    después**: bóvedas, elementos, versiones, archivos, dispositivos, agentes
    y bitácora. Antes de pedir nada pregunta a `GET /v1/health` si el
    servidor sabe hacerlo; con uno anterior dice «This server can't delete
    accounts from the app. Ask whoever runs it.».
  - **Solo una persona en una terminal** (T164). No acepta
    `--password-stdin` (código 2) ni `--yes`, y sin terminal en stdin y
    stderr falla sin pedir nada. Primero hay que escribir el correo de la
    cuenta. Después viene Touch ID si `klavd` lo usa: si no está corriendo y
    hay alta, lo arranca, para que pararlo no sea un atajo. Decide el alta
    (`touchid.json`), no que Touch ID responda en ese momento: bloqueado
    tras varios intentos o con la tapa cerrada, el comando falla sin pedir
    la contraseña y dice cómo seguir, como la hoja del Mac: abrir la tapa
    (o, si Touch ID se bloqueó, desbloquear el Mac con su contraseña) y
    volver a intentarlo, o borrarla desde otro dispositivo. Si cambiaron
    las huellas, `klavd` olvida Touch ID y el comando pide correrlo otra
    vez, ya con la contraseña sola. Un `klavd` anterior que no conoce el
    paso de Touch ID (ni el de cancelar) lo rechaza como petición mal
    formada; la CLI lo traduce a «actualiza `klavd` y reinícialo» (`klav
    lock --stop`, después `klav unlock`). Por último, la contraseña
    maestra, que se comprueba aquí
    (un error de dedo no gasta un intento del servidor) y luego con OPAQUE
    en el servidor. Sin alta de Touch ID basta la contraseña.
  - **Con alta de Touch ID, `--no-daemon` no sirve** (enmienda A1): saltarse
    `klavd` sería saltarse Touch ID, así que `klav --no-daemon account
    delete` se niega antes de pedir nada y dice cómo borrarla: sin
    `--no-daemon`, con la tapa abierta y Touch ID disponible; desde la app
    de Klav en el Mac; o desde el iPhone.
  - Desde ese momento **todos los agentes se detienen** (código 8, §9) y
    `klavd` deja de mediar lo suyo. Si ya hay un borrado pedido y `klavd`
    lo sabe, lo dice con la fecha y no pide nada; si no, el servidor
    responde `409` después de la contraseña («already scheduled»), y `429`
    tras demasiados intentos. Si el servidor lo programó pero este
    dispositivo no pudo anotarlo, lo dice con la fecha: pedirlo otra vez
    responde que ya está programado, `--cancel` lo cancela y la siguiente
    sincronización lo anota.
  - **`klav account delete --cancel`** lo cancela desde cualquier
    dispositivo con sesión, con presencia, igual que `klav agent resume`
    (enmienda A2): cancelar devuelve a los agentes, y un agente que alcanza
    la sesión de la persona no debe poder cancelar para volver. Con
    `klavd`, Touch ID, o la contraseña maestra si no hay Touch ID o falla;
    sin `klavd`, la contraseña del desbloqueo. Si no había nada que
    cancelar, lo dice.
  - **`klav status`** muestra la fecha mientras está pendiente
    (`deletion:`, y `deletion` en `--json`). La saca de `klavd`: sin daemon,
    `klav status` no abre la copia sellada y no la ve. `klavd` la recuerda
    al reiniciar ([klavd.md](klavd.md) §3), también bloqueado.
  - **Pasada la fecha** el servidor ya no tiene la cuenta. Un dispositivo
    que conocía la fecha dice «Klav deleted your account on … UTC» en vez
    de la sesión caducada, y las lecturas siguen con la copia local, de
    solo lectura. Uno que no sincronizó en los 7 días ve una sesión
    caducada, y entrar de nuevo falla como una contraseña equivocada.
    Destruye también el kit de emergencia: con él y la contraseña, una
    copia que quede se abre.
- **`klav logout`** cierra la sesión de este dispositivo en el servidor y
  borra de `$KLAV_HOME` su copia de la cuenta: `account.json`, la Secret
  Key, la sesión, la caché, la bitácora descargada y los archivos de
  `klavd` (Touch ID, pausas, borrado). La cuenta sigue en el servidor, o
  ya no está si se borró. Detiene `klavd` antes y pide la contraseña
  maestra, que abre los tokens. Sube antes, si puede, las contraseñas
  generadas y las passkeys en cola. **Si algo queda sin subir** (sin red, o
  una cuenta que el servidor ya borró, donde toda subida falla), se niega
  sin borrar nada y dice cuántas son y cómo guardarlas (`klav sync`, o
  `klav generated show N` para copiarlas a otro sitio); `--discard-unsent`
  cierra sesión igual y las pierde. Las apps hacen lo mismo con «Borrar la
  copia» ([ios.md](ios.md) §11, [macos.md](macos.md)), y con una cuenta
  borrada `klavd` ya no acepta contraseñas generadas nuevas. Pide confirmación; sin terminal hace
  falta `--yes`. Si el servidor no cierra la sesión (sin red), avisa y
  borra la copia igual: quita el dispositivo desde otro.
- Sin red, los comandos de lectura usan la copia local y lo avisan. Escribir
  requiere conexión.

## 4. Elementos

> Los pasos para quien usa Klav están en la página pública [`cli.mdx`](../apps/docs/src/content/docs/apps/cli.mdx) (en `apps/docs/src/content/docs/apps/`); un cambio en esos pasos va primero allí.

Un elemento se nombra:

- con su referencia `klav://Bóveda/Proyecto/Título`;
- con su ID;
- o con su título, si es único.

`klav://…/Título/campo` apunta a un campo.

Los nombres van en la referencia tal como se escribieron, con espacios y
acentos: `klav://Mi bóveda/Café con leche/Banco Azul/password`. En la
terminal, entre comillas. Solo se codifica con `%` lo que rompería la
referencia o la haría engañosa: `%` (`%25`), `/` (`%2F`), `?` (`%3F`),
`#` (`%23`), los caracteres de control e invisibles (de ancho cero,
*bidi*), cualquier espacio que no sea el normal (el duro sale `%C2%A0`) y
los espacios al principio o al final de un nombre (`%20`). Así dos
referencias distintas nunca se ven iguales. La forma codificada de antes (`Mi%20b%C3%B3veda`) sigue valiendo:
las dos llevan al mismo elemento, en la CLI, `klav.toml`, las plantillas,
MCP y el SDK.

```sh
klav item add login --title GitHub --username ana --url https://github.com -s password -s totp
klav item add api-key --title Stripe --project Backend --secret-stdin api_key < key.txt
klav item add login --title Gmail -g password          # contraseña generada
klav item get GitHub                                   # secretos enmascarados
klav item get klav://Personal/General/GitHub/password --reveal
klav item edit GitHub --title "GitHub trabajo" -g password --rm-field totp
klav item attach APNs key ./AuthKey_ABC123.p8          # adjunto cifrado (campo file)
klav item ls [--vault V] [--project P] [--kind login,card] [--codes] [--tag dev] [--trash] [--json]
klav item search git
klav item rm GitHub                                    # a la papelera (30 días)
klav item sites GitHub [--confirm | --remove URL…]     # sitios confirmados y los que añadió un agente
klav totp GitHub                                       # código actual y segundos restantes
klav generate [--type smart|random|memorable|pin] [--site HOST] # no necesita cuenta
klav generated ls | show N | rm N… | rm --all  # historial del generador
klav item history GitHub [--reveal N] [--json] # contraseñas anteriores
klav health [--json]                           # salud de la bóveda, sin valores
klav health breach-check [on|off]              # consulta de filtradas (apagada)
klav health --fix-with <agente> [--only REF]… [--skip REF]… [--for 2h] [--yes]
klav vault ls | create <nombre>
klav project ls [--vault V] | create --vault V <nombre>
```

Tipos de elemento: `login`, `card`, `identity`, `ssh-key`, `totp`, `note` y
`api-key`.

**Filtrar la lista.** `item ls --kind` acepta varios tipos, con comas o
repitiendo la opción (`--kind login,card` o `--kind ssh --kind note`).
Además de los tipos de arriba, acepta `file`, y también los plurales
(`logins`, `cards`, `notes`, `identities`, `files`, `api-keys`, `ssh-keys`)
y `ssh`.

`item ls --codes` deja solo los elementos con un código de un solo uso, sean
del tipo que sean: un login con su `totp`, un `totp` suelto o una nota con
un campo de código. Es la vista «Códigos» del *popup* y de iOS. Va con
`--kind` y con las demás opciones; `--kind login --codes`, por ejemplo,
lista los logins con código. La lista sigue mostrando solo metadatos. El
código se ve con `klav totp <elemento>`.

```sh
$ klav item ls --codes
ITEM                               TYPE   USERNAME
klav://Personal/General/GitHub     login  ana
klav://Personal/General/Google     totp
```

Para saber si un elemento tiene código, `klavd` abre sus detalles la primera
vez que alguien lo pregunta y guarda la respuesta hasta la siguiente versión
del elemento. Una lista sin `--codes` sigue sin abrir ningún detalle.

- Cada tipo trae sus campos (`username`/`password`/`totp`, `number`/`cvv`…).
- `--field NOMBRE=VALOR` añade campos de texto.
- `-s`, `--secret-stdin` y `-g` añaden campos secretos.
- **El título nombra al elemento** en las referencias
  (`klav://Bóveda/Proyecto/Título`), así que `item add` se niega a crear un
  segundo elemento con el mismo título (sin distinguir mayúsculas) en el
  mismo proyecto. El error dice cuál existe y su ID: cámbialo con
  `item edit`, usa otro título o pasa `--allow-duplicate`. En otro proyecto
  el mismo título no choca.
- **Renombrar sigue la misma regla:** `item edit --title` se niega a poner un
  título que ya tiene otro elemento vivo del proyecto, con el mismo error.
  Cambiar solo las mayúsculas del propio título sí se puede, y
  `--allow-duplicate` lo fuerza. Los agentes (`update_item` de MCP y
  `Session::update_item` del SDK) nunca pueden forzarlo, y la negativa llega
  antes de pedir ninguna aprobación.
- Si dos elementos comparten título, buscarlos por título falla y el error
  lista la referencia y el ID de cada uno. Usa el ID, que también vale dentro
  de una referencia (`klav://Personal/General/<ID>/password`).
- **`item attach`** sube un archivo cifrado (hasta 64 MiB). Su contenido solo
  sale con `klav inject -r` o con los `[files]` de `klav run`.
- **Sitios que añadió un agente** (ADR 0030 §7). Si un agente con `update`
  añade una URL a un elemento, ese sitio queda **pendiente**: ni el
  autollenado, ni las sugerencias, ni el Credential Provider, ni los
  rellenos de agentes lo usan hasta que lo confirmes. `item get` lo muestra
  como «sites added by *agente* (not confirmed, never filled)». La única
  excepción es un login que creó un agente y que nadie más ha tocado (un
  alta, ADR 0022 §7): ese mismo agente sí lo rellena en sus sitios; para ti
  y para los demás agentes siguen pendientes.
  - `item sites REF` lista los sitios confirmados y los pendientes.
  - `--confirm` los confirma todos: es una edición tuya del elemento, sin
    cambios, y la versión nueva es tuya.
  - `--remove URL` quita una URL tal como está guardada (repetible).

**Marca de protección (ADR 0032 §3).** `klav item get` añade la línea
`protected: by production (presence every time; agents ask once)` a un elemento que un entorno protegido alcanza
(una variable suya o el destino de una de sus referencias), y `klav item ls`
añade una columna, `protected by …`, cuando alguno lo está. En `--json`,
`protected_by` lista los entornos, y falta cuando no hay ninguno. Revelar un
valor de ese elemento pide presencia cada vez (§8).

### Entornos (`klav env`)

> ADR 0032 §2, §6 y §8. Un entorno es un elemento de tipo `environment` de un
> proyecto: variables con un valor propio o una referencia a un campo de otro
> elemento. Nunca se imprime un valor sin `--reveal`, tampoco en los errores.

```sh
klav env ls                                         # los entornos del proyecto de klav.toml
klav env show production                            # nombres y origen; valores enmascarados
klav env create staging                             # production y prod nacen protegidos
klav env set staging -s STRIPE_KEY                  # valor por pregunta oculta
klav env set staging --ref DATABASE_URL=Postgres/url
klav env set production --protected false           # bajar la protección pide presencia
klav env rm staging OLD_VAR                         # sin variables: el entorno a la papelera
klav env import .env --env development              # revisa, nunca imprime un valor
klav env import klav.toml --env development         # migra el [env] plano por referencia
klav env link Trabajo/acme-api                      # enlaza este repositorio al proyecto
klav env scan                                       # busca .env y dice qué hace git con ellos
```

- **`--project`** elige el proyecto; por defecto, el `project` del
  `klav.toml` (`klav env ls` sin él lista todos).
- **`show`** dice de dónde sale cada variable: `value` o `reference` con su
  destino, y si ese destino está protegido. Si un agente cambió el entorno
  desde la última versión de la persona, lo dice (qué variables añadió,
  cambió o quitó) antes de nada. `--reveal` pasa por la presencia de §8:
  cada vez si el entorno está protegido.
- **`create`**: el nombre es `[a-z0-9][a-z0-9_-]{0,63}`. `production` y
  `prod` nacen protegidos salvo `--no-protected`; cualquier otro, con
  `--protected`.
- Un entorno solo se cambia con `klav env`: `klav item add` y `klav item
  edit` (y las operaciones `create` y `edit` de `klavd`) lo rechazan, porque
  no vuelven a firmar los grants. `klav item rm` sí lo manda a la papelera,
  pero lo que protegía sigue protegido (sale de la versión de la persona).
- **`set`**: `-s VAR` pregunta el valor sin eco, `--secret-stdin VAR` lo
  lee de la siguiente línea de stdin y `--ref VAR=REF` guarda una
  referencia (corta si hay `project`). Una referencia se guarda por los
  IDs de su destino, así que renombrar el elemento no la rompe; no puede
  apuntar a otro entorno.
- **Proteger y desproteger (§3.1).** Un cambio que hace crecer la
  protección (proteger un entorno, o añadir a uno protegido una variable o
  una referencia nueva) sincroniza, vuelve a firmar los grants de los
  agentes que alcanzan esos elementos con reglas `origin: "protected"`
  (escribiendo antes como reglas explícitas los permisos por defecto, ADR
  0006 §2) y solo después sube la versión. Si algo de eso falla, no guarda
  nada: «could not protect …: the environment was not saved». Uno que la
  baja pide presencia primero (Touch ID o la contraseña maestra, en
  `/dev/tty`), sube la versión y después vuelve a firmar los grants con
  `released`; si esa segunda parte falla, avisa y los grants siguen
  protegiendo de más hasta el siguiente cambio.
- **`rm`** sin variables manda el entorno a la papelera, tras confirmar (o
  `--yes`). Uno protegido pide presencia y primero se guarda sin
  protección, como prueba para liberar los grants; si se restaura de la
  papelera, vuelve sin protección.
- **`import`** lee un `.env` (o `-` para stdin) en memoria que se borra al
  terminar. Muestra por variable si es nueva, igual, distinta o igual a un
  campo de la bóveda que podría referenciar, sin el valor, y pregunta
  antes de guardar (`--dry-run` solo muestra, `--yes` acepta todo). La
  revisión compara valores, así que pasa por la presencia de §8. Al
  terminar ofrece borrar el archivo, y avisa si git lo sigue: borrarlo
  solo lo desenlaza, no lo borra de forma segura ni de la historia. Un
  error de sintaxis nombra la línea y el motivo, nunca el valor. Si el
  archivo se llama `klav.toml`, migra su `[env]` plano a un entorno por
  referencia y ofrece reescribir el archivo con `default_env`.
- **`link`/`unlink`** guardan `host/owner/repo` en los metadatos cifrados
  del proyecto. Sin `--remote`, usan `origin` o el remoto que elegiste
  antes para ese repositorio (`repo-remotes.json`). `link` ofrece escribir
  `project = …` en el `klav.toml`. El enlace solo sugiere: nunca da acceso
  ni se salta una confirmación.
- **`scan`** busca `.env` y `.env.*` (no `.env.example`)
  sin seguir enlaces simbólicos ni entrar en `.git`, `target` o
  `node_modules`, dice si git ignora, sigue o no ve cada uno, y ofrece
  importarlos si hay terminal. Nunca abre un archivo para listarlo.
  `--json` da la lista.

### Generar contraseñas

```sh
klav generate                                   # inteligente: 20 caracteres si no hay reglas
klav generate --site https://all.accor.com      # con las reglas de ese sitio
klav generate --rules "minlength: 8; maxlength: 12; required: digit;"
klav generate -t random --length 32 --no-symbols
klav generate -t memorable [--words 5] [--separator -] [--no-capitalize] [--no-number]
klav generate -t pin [--pin-length 6]
```

- **Tipos** (ADR [0022](decisiones/0022-generador-historial-y-cambio-asistido.md) §1):
  - `smart` (por defecto) sigue las reglas del sitio: las de `--rules` (la
    gramática de `passwordrules`) o, con `--site`, las que Klav trae
    empaquetadas de `apple/password-manager-resources` para ese dominio,
    sin consultar la red. Si no hay reglas, es `random` con 20 caracteres;
  - `random`: letras, dígitos y símbolos (`--no-*` quita clases);
  - `memorable`: cinco palabras de la lista EFF con mayúscula inicial y un
    dígito en una de ellas (`--words` sin `--type` también da esta). El
    separador (`--separator`, `-` por defecto) tiene de 1 a 8 bytes, sin
    letras ni dígitos ASCII y sin caracteres de control o invisibles: así
    la salud de la bóveda sabe leer de nuevo las palabras y no da por
    fuerte una frase débil. Un espacio, `.`, `·` o `_` sirven, y uno que
    empieza con guion se escribe con `=`, como `--separator=--`; uno vacío,
    `x` o `1` dan error de uso (código 2), con cualquier tipo;
  - `pin`: solo dígitos, de 4 a 12.
- La contraseña va a la salida estándar; la fuerza va a la de errores:
  bits de entropía (exactos, porque el generador es uniforme) y la
  etiqueta (débil < 40, regular < 64, fuerte < 100, muy fuerte). Si el
  sitio no permite una más fuerte, o sus reglas no se entienden o no
  tienen solución, lo dice; en esos dos últimos casos sale una `random`.
- `item add … -g password` usa el tipo inteligente con el sitio de la
  primera `--url`.
- **Historial del generador** (ADR 0022 §2): con `klavd` en marcha y
  desbloqueado, `klav generate` guarda cada contraseña antes de mostrarla.
  Sin `klavd` no la guarda y lo dice en la salida de errores; `--no-history`
  la deja fuera a propósito. El historial vive en un proyecto del sistema
  («Klav») que no aparece en las listas ni se puede dar a un agente.
  Guarda 200 entradas como mucho, un año, o 30 días desde que la contraseña
  se guardó en un login.
  - `klav generated ls` lista las entradas sin valores: cuándo, para qué
    sitio, si aún no se ha sincronizado y en qué login se guardó;
  - `klav generated show N` imprime una;
  - `klav generated rm N…` o `rm --all` las borra, también de las versiones
    guardadas en el servidor.
- **Contraseñas anteriores** (ADR 0022 §3): al cambiar una contraseña o un
  campo oculto, Klav guarda la vieja en el registro del elemento, cifrado
  con la llave de la bóveda, que los agentes no tienen. La primera vez lo
  rellena con las versiones guardadas del elemento. `klav item history`
  las lista sin valores (hasta 100 por campo) y `--reveal N` imprime una.

### Salud de la bóveda

```sh
klav health                     # reutilizadas, débiles y viejas
klav health --json              # lo mismo, para un programa
klav health breach-check        # el ajuste y qué envía
klav health breach-check on     # o off
```

Lo calcula el cliente, porque el servidor no ve nada (ADR
[0022](decisiones/0022-generador-historial-y-cambio-asistido.md) §4). Mira los
campos `password` de todos los elementos vivos; los campos ocultos (el PIN o
el CVV de una tarjeta) no, porque son cortos a propósito.

- **Reutilizadas:** la misma contraseña en dos o más elementos. Se comparan
  en memoria con el SHA-256 de una sal aleatoria de esa corrida y el valor;
  nada de eso se guarda.
- **Débiles:** puntaje de `zxcvbn` de 2 o menos (de 0 a 4), o menos de 40
  bits si salió del generador (está en su historial). Esos bits se deducen
  del valor: un PIN, una frase de la lista EFF o, si no, la longitud por el
  alfabeto de las clases que usa.
- **Viejas:** sin cambiar en más de un año, según el registro de contraseñas
  del elemento o, si no tiene cambios, su fecha de alta.
- **Filtradas** (apagado por defecto): consulta a Have I Been Pwned con
  k-anonimato. Solo sale el prefijo de 5 caracteres del SHA-1 de cada
  contraseña distinta, a `api.pwnedpasswords.com/range/`, con
  `Add-Padding: true` para que el tamaño de la respuesta no delate nada; el
  servicio ve la IP y la hora. El ajuste vive en `health.json`, en
  `KLAV_HOME`, vale solo para este equipo y lo comparten la CLI y `klavd`.
  `klav health breach-check` explica todo esto antes de encenderlo. Si la
  consulta falla, el resto del informe sale igual.

La salida nombra el elemento, sus hosts y el motivo; nunca un valor, un hash
ni las pistas de `zxcvbn`. Con `klavd` en marcha, el informe lo calcula el
daemon (`vault_health`).

#### Arreglar las repetidas con un agente

```sh
klav health --fix-with claude-code                       # en una terminal: revisar, desmarcar y confirmar
klav health --fix-with claude-code --skip Banco --yes    # sin terminal: elegir con --only o --skip
klav health --fix-with claude-code --only GitHub --only Figma --for 1h --yes --json
```

La persona ofrece al agente una tarea para cambiar las contraseñas que
repite, sitio por sitio (ADR
[0022](decisiones/0022-generador-historial-y-cambio-asistido.md) §6):

- **La lista:** los logins que comparten contraseña con otro elemento,
  ordenados por sitio, con su grupo (solo lo ves tú) y su página de cambio
  (`change_password_url`). Los que no pueden ir salen marcados con `-` y el
  motivo: sin sitio web, fuera de los proyectos del agente, o con la
  contraseña repetida en un campo que no es el principal.
- **Elegir:** en una terminal, escribe los números que quieres quitar (o
  volver a poner) y Enter para seguir. Sin terminal, `--only REF` o
  `--skip REF` (repetibles; referencia `klav://`, título o ID) y `--yes`.
- **Confirmar:** pregunta antes de ofrecer (salvo `--yes`) y después pide
  Touch ID o la contraseña maestra una vez, como `klav task approve`.
- **La tarea:** `rotate` en cada login, y `totp` («added by Klav») en los
  que tienen código y la política no lo niega. Dura 2 h (`--for`, de 5 min
  a 24 h). El título por defecto, «Change passwords», y el motivo son
  neutros: `--task` y `--reason` los cambian, y el agente los lee.
- **El agente** la encuentra con `list_tasks` y solo recibe los sitios,
  nunca cuáles comparten contraseña. Sigue el avance con
  `klav log --task <id>`.

### Importar

> Los pasos para quien usa Klav están en la página pública [`import.mdx`](../apps/docs/src/content/docs/get-started/import.mdx) (en `apps/docs/src/content/docs/get-started/`); un cambio en esos pasos va primero allí.

```sh
klav import ARCHIVO… [--from ORIGEN] [--vault V] [--project P] [--dry-run] [--json]
```

Importa desde otro gestor o un navegador (ADR 0024). Por omisión el destino es
Personal / General. Primero enseña qué va a pasar (sin valores) y después lo
hace; `--dry-run` solo enseña.

| Origen | Cómo exportar | Archivo |
|---|---|---|
| Bitwarden | En la web, Herramientas → Exportar bóveda, formato `.json` (no el «cifrado») | `bitwarden_export_….json` (o `.csv`) |
| 1Password | En la app de escritorio, Archivo → Exportar → la cuenta → formato 1PUX | `….1pux` (o `.csv`) |
| Google Authenticator | En el teléfono, menú → Transferir cuentas → Exportar cuentas: uno o varios QR | foto o captura de cada QR en `.png`, o los enlaces `otpauth-migration://` en stdin con `-` |
| Chrome, Edge, Brave, Arc, Dia | Gestor de contraseñas → Configuración → Exportar contraseñas | `….csv` |
| Firefox | `about:logins` → ⋯ → Exportar contraseñas | `logins.csv` |
| Safari | App Contraseñas → Archivo → Exportar todas las contraseñas (o Safari → Archivo → Exportar → Contraseñas) | `Passwords.csv` |
| Authy | no tiene exportación | ver abajo |

- **El formato se detecta por el contenido.** `--from` (`bitwarden`,
  `1password`, `google`, `chrome`, `edge`, `brave`, `firefox`, `safari`,
  `csv`) es una pista: si el archivo no lo parece, falla y dice qué parece.
- **Varios archivos a la vez** se importan juntos, por ejemplo los dos QR de
  una exportación de Google Authenticator, o Bitwarden y luego Chrome.
  Si falta un QR, el aviso dice cuál; importarlo después también vale.
- **Enlaces de Google Authenticator:** nunca como argumento (llevan los
  secretos). Con `-` se pegan en stdin, uno por línea, y se termina con
  Ctrl-D: `klav import -`. Los códigos HOTP y MD5 se saltan con su motivo.
- **Fusión, sin perder contraseñas:**
  - el mismo sitio y usuario son un solo elemento: lo que el archivo añade
    (sitios, código de un solo uso, notas, campos, etiquetas) se suma;
  - si la contraseña es distinta, gana la más nueva y la otra va a su
    historial (`klav item history`);
  - un código de Google Authenticator se une al login de su sitio y cuenta
    cuando hay uno solo; si no, queda como su propio elemento TOTP;
  - un título ocupado se importa con el usuario entre paréntesis,
    `Mail (bob)`, o con un número;
  - importar dos veces lo mismo no añade nada.
- **Sitios:** solo se importan enlaces `http` y `https`; uno sin esquema
  (`example.com/login`) se guarda como `https://example.com/login`. Los
  demás (`javascript:`, `data:`, los de apps como `android://`) se dejan
  fuera con un aviso en esa fila.
- **Topes:** como mucho 100 000 elementos por archivo; un archivo más grande
  se rechaza y hay que partirlo.
- **Passkeys:** las de Bitwarden se importan al login con el que vienen,
  selladas con la llave de bóveda; una por login. El resumen cuenta las que
  no (de 1Password, que no trae la llave, o no válidas) y cada fila dice por
  qué. Si una venía con contador mayor que 0, su fila lo avisa: un sitio que
  vigile el contador puede rechazarla, y entonces hay que entrar de otra
  forma y registrar en Klav una passkey nueva para ese sitio.
- **Authy:** no tiene exportación. Vuelve a dar de alta el 2FA de cada sitio
  y guarda el secreto nuevo en Klav.
- Al terminar, **borra el archivo exportado y vacía la papelera**: tiene tus
  contraseñas en texto plano.

## 5. `klav.toml`

> Los pasos para quien usa Klav están en la página pública [`use-secrets-without-seeing-them.mdx`](../apps/docs/src/content/docs/agents/use-secrets-without-seeing-them.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

Es el archivo de proyecto de un repositorio. Solo contiene referencias, nunca
secretos, así que se puede commitear.

```toml
project = "Trabajo/acme-api"          # opcional: habilita referencias cortas

[env]
STRIPE_KEY   = "klav://Trabajo/acme-api/Stripe/api_key"
DATABASE_URL = "Postgres/url"         # corta: klav://Trabajo/acme-api/Postgres/url

[files]
"secrets/AuthKey.p8" = "klav://Trabajo/app-ios/APNs/key"
```

Con entornos (ADR 0032 §5), las variables van por entorno:

```toml
project = "Trabajo/acme-api"
default_env = "development"

[env.development]
DATABASE_URL = "Postgres-dev/url"

[env.production]
DATABASE_URL = "Postgres/url"
```

- `[env.NOMBRE]` se suma al entorno `NOMBRE` del proyecto en la bóveda, y
  gana en un nombre repetido.
- `default_env` dice cuál usar sin `--env`. No puede convivir con un
  `[env]` plano: el error pide moverlas a `[env.X]`.
- `klav env import klav.toml --env NOMBRE` mueve un `[env]` plano al
  entorno `NOMBRE` por referencia.

- `klav run` e `inject` buscan el `klav.toml` más cercano, desde el
  directorio actual hacia arriba, hasta la raíz del repositorio git o tu
  directorio personal, lo que llegue antes: un `klav.toml` en `/tmp` o en
  el directorio de otro usuario no se aplica. `--config` elige otro.
- **Confirmación en `klav run`:** la primera vez que `klav run` usa un
  `klav.toml`, y cada vez que cambia, muestra las variables, los archivos y
  las referencias que pide y pregunta. Un repositorio recién clonado no
  puede meter así cualquiera de tus secretos en el entorno de un comando que
  también controla. Lo aprobado queda fijado (el texto exacto, por ruta) en
  `$KLAV_HOME/trusted-projects.json`. Sin terminal, `--trust` lo aprueba sin
  preguntar. Con entornos, se confirma además cada entorno: la pregunta
  dice de dónde sale cada variable (entorno del proceso, bóveda, `klav.toml`
  o `-e`) y los avisos de enlace, y el fijado guarda también los entornos
  aprobados. Un fijado sin entornos se sigue escribiendo como antes.
- **`project`**:
  - es `Bóveda/Proyecto`;
  - permite referencias cortas `elemento/campo` dentro de ese proyecto;
  - las referencias completas pueden apuntar a cualquier proyecto.

  El acotamiento de agentes por proyecto llega en la fase 4.
- **`[files]`**:
  - las rutas son relativas al directorio del `klav.toml` y no pueden salir de
    él (`..`, las rutas absolutas y los directorios que son enlaces
    simbólicos hacia fuera se rechazan);
  - el valor puede ser un campo de texto o un adjunto.
- Campos desconocidos en el archivo = error, para no aceptar en silencio una
  errata.

## 6. `klav run`

> Los pasos para quien usa Klav están en la página pública [`use-secrets-without-seeing-them.mdx`](../apps/docs/src/content/docs/agents/use-secrets-without-seeing-them.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav run -- npm run dev
klav run -e EXTRA=klav://Personal/General/Token/value -- ./script.sh
klav run --env production -- ./deploy.sh
STRIPE_KEY=klav://Trabajo/acme-api/Stripe/api_key klav run -- env
```

1. Junta las variables. Si un nombre se repite, gana la fuente posterior:
   - primero, las variables del entorno cuyo valor es `klav://…`;
   - después, el entorno elegido de la bóveda, si hay uno;
   - después, el `[env.NOMBRE]` del entorno elegido o el `[env]` plano del
     `klav.toml`;
   - al final, `-e NOMBRE=REF` (o `--var`).

   **Qué entorno** (ADR 0032 §5): `--env NOMBRE`; si no, `default_env`; si
   no, ninguno cuando hay `[env]` plano; si no, el único que hay entre la
   bóveda y `[env.*]`. Con más de uno, falla y los nombra. Un `--env` que
   lleva `=` se lee como `-e`, como antes de los entornos. Si el
   repositorio está enlazado a un solo proyecto y el `klav.toml` no dice
   `project`, pregunta si usarlo; sin terminal, avisa de qué escribir y sigue sin los
   entornos de ese proyecto en la bóveda.
   Avisa si el `klav.toml` pide secretos de un proyecto que no está
   enlazado a este repositorio. Antes de pedir un valor, dice si un agente
   cambió el entorno desde tu última versión y si está protegido: uno
   protegido pide presencia **cada vez** (§8), también con `--trust` o con
   una ventana abierta.
2. Resuelve todas las referencias. Si falta una, falla **antes** de ejecutar
   nada.
3. Escribe los `[files]`:
   - modo 0600, y nunca sobre un archivo existente;
   - cada uno aparece completo de una vez: se escribe en un archivo temporal
     0600 del mismo directorio (`O_EXCL`, que no sigue enlaces simbólicos) y
     toma su nombre con un enlace duro, que falla si el nombre ya existe (sin
     enlaces duros, como en `klav inject -o`, §7);
   - avisa si `git check-ignore` dice que el archivo no está ignorado, y
     recomienda ignorar también `*.klav-tmp` (el temporal; ver los límites);
   - después de escribirlos (o de que falle uno), avisa de los temporales
     de otra escritura de esos archivos, interrumpida o todavía en curso,
     como `klav inject -o` (§7), con una sola lectura de cada directorio
     aunque tenga varios `[files]`;
   - `--no-files` los omite.
4. Olvida el estado desbloqueado (llaves y elementos descifrados) y ejecuta el
   comando.
   - Los secretos solo van en el **entorno del hijo**, nunca en argv ni en la
     salida.
   - El resto del entorno se hereda.
5. Espera al hijo y le reenvía `SIGTERM` y `SIGHUP`. `Ctrl-C` ya le llega por el
   grupo de procesos de la terminal.
6. Al terminar, **borra los `[files]`** y sale con el código del hijo (128 +
   señal si lo mató una señal).

**Límites honestos:**

- **Copias en memoria:** `std::process::Command` guarda su propia copia del
  entorno. `klav` la libera justo después del `spawn`, igual que sus propias
  copias, pero esas copias no se pueden poner a cero (`zeroize`). El proceso
  hijo, por supuesto, tiene los valores en su entorno, y en Linux su propio
  usuario puede leerlo en `/proc/<pid>/environ`.
- **`SIGKILL` o un corte de luz:** impiden el borrado. Un `[files]` que quede
  hace fallar el siguiente `run` con un mensaje claro: bórralo a mano. Si
  llegan mientras se escribe un `[files]`, puede quedar además su temporal,
  `.<nombre>.<16 hex>.klav-tmp` (0600, quizá con el secreto completo), junto
  al destino; la regla de `.gitignore` del destino no lo cubre, así que
  conviene ignorar `*.klav-tmp`. El siguiente `run` que escriba ese mismo
  archivo avisa de él, y no lo borra.

## 7. `klav inject`

> Los pasos para quien usa Klav están en la página pública [`use-secrets-without-seeing-them.mdx`](../apps/docs/src/content/docs/agents/use-secrets-without-seeing-them.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav inject -i .env.tpl -o .env                    # plantilla → archivo 0600
klav inject -r klav://Trabajo/app-ios/APNs/key -o ./AuthKey.p8 --ttl 10m
klav inject -r APNs/key -o ./AuthKey.p8 --fifo     # tubería con nombre, se lee una vez
klav inject -i config.tpl > config.json            # sin -o: a stdout
klav inject --env staging --dotenv -o .env         # un entorno como .env, 0600
klav inject --env staging --dotenv -o .env --fifo  # el mismo, por una tubería
```

- **Plantilla** (`-i`, o stdin sin `-i` ni `-r`):
  - cada `{{ klav://… }}` se reemplaza por el valor del campo;
  - otros `{{ … }}` (de otros lenguajes de plantillas) se dejan intactos;
  - una referencia a un adjunto en una plantilla es un error: usa `-r`.
- **`-r REF`** escribe el valor tal cual, también adjuntos binarios. Acepta
  referencias cortas si hay `klav.toml` con `project`.
- **`-o RUTA`**:
  - crea el archivo con modo 0600;
  - no reemplaza uno existente sin `--force`;
  - el archivo aparece completo de una vez: quien lo espera nunca lo lee
    vacío ni a medias. Se escribe en un archivo temporal 0600 del mismo
    directorio y toma el nombre con un enlace duro, que falla si el nombre ya
    existe y no sigue enlaces simbólicos; con `--force`, se renombra encima
    del que había. En un sistema de archivos sin enlaces duros (FAT, exFAT,
    algunos compartidos de red), se renombra justo después de comprobar que
    el nombre sigue libre (un archivo que otro proceso cree justo entonces se
    reemplaza);
  - el temporal se llama `.<nombre>.<16 hex>.klav-tmp` y se borra siempre,
    también si la escritura falla. Solo un `SIGKILL` o un corte de luz
    durante la escritura (antes del enlace, o entre el enlace y el borrado
    del temporal) lo dejan junto al destino: 0600, quizá con el secreto
    completo, y la regla de `.gitignore` del destino no lo cubre, así que
    conviene ignorar `*.klav-tmp`;
  - después de intentar la escritura, haya salido bien o no, avisa por
    stderr de los temporales de ese mismo nombre de otra escritura,
    interrumpida o todavía en curso: en el mismo directorio, un archivo
    normal (por `symlink_metadata`: nunca sigue un enlace simbólico) que se
    llama exactamente `.<nombre>.<16 hex>.klav-tmp`. El aviso nombra los
    tres primeros y cuántos más, dice que son de una escritura
    interrumpida o todavía en curso, que pueden tener un secreto y que
    Klav no los borró: la persona puede borrarlos después de comprobar que
    nada los sigue escribiendo. Klav nunca borra, abre ni
    lee uno, no falla por eso ni cambia el código de salida. No menciona
    el temporal de esta misma escritura (si no pudo borrarlo, ya lo nombra
    el error), ni los de otros nombres, y si no puede leer el directorio
    no dice nada;
  - el temporal añade 27 bytes al nombre: un nombre de más de unos 228 bytes
    falla con «File name too long»;
  - avisa si git no lo ignora, y recomienda ignorar también `*.klav-tmp`.
- **`--ttl 30s|10m|1h|1d`**: `klav` se queda en primer plano y borra el archivo
  al vencer, o antes con `Ctrl-C`, `SIGTERM` o `SIGHUP`.
- **`--fifo`** (Unix):
  - crea una tubería con nombre 0600 en `-o` (con `--force`, bajo un nombre
    temporal que luego reemplaza al archivo, sin dejar el nombre libre);
  - la abre sin seguir enlaces simbólicos (`O_NOFOLLOW`) y solo si sigue
    siendo la que creó;
  - entrega el valor **una vez** a quien la lea y la borra;
  - el secreto nunca toca el disco;
  - espera al lector hasta `--ttl` (10 minutos por defecto).

- **`--env NOMBRE --dotenv`** escribe el entorno (con las mismas reglas
  de elección, mezcla, confirmación y presencia que `klav run --env`) como
  un `.env`: `NOMBRE='valor'` entre comillas simples, o entre dobles con
  `\\`, `\"`, `\n`, `\r` y `\$` escapados si el valor lleva una comilla
  simple o un salto de línea. Usa `-o`, `--force`, `--ttl` y `--fifo` como
  arriba; `--trust` aprueba el `klav.toml` sin preguntar.

Un archivo inyectado es texto plano en disco mientras existe (amenaza T35).
Prefiere `klav run` o `--fifo` cuando la herramienta lo permita.

## 8. Daemon `klavd`

> Los pasos para quien usa Klav están en la página pública [`cli.mdx`](../apps/docs/src/content/docs/apps/cli.mdx) (en `apps/docs/src/content/docs/apps/`); un cambio en esos pasos va primero allí.

Con `klavd` corriendo, `klav` no pide la contraseña en cada comando.

```sh
klav unlock [--idle-lock 15m] [--password]   # arranca klavd si hace falta
klav lock [--stop]
klav --no-daemon …                           # o KLAV_NO_DAEMON=1
```

En macOS, tras el primer desbloqueo con contraseña, `klavd` desbloquea con
**Touch ID**. La contraseña vuelve a pedirse cada 14 días y tras reiniciar
([`klavd.md`](klavd.md) §6).

Uso, seguridad y protocolo: [`klavd.md`](klavd.md).

### Presencia antes de los valores (ADR 0041)

Desde la capa 6, `klavd` tiene siempre encendida la puerta de presencia del
[ADR 0041](decisiones/0041-presence-for-values-and-the-inject-card.md):
antes de dar un valor, pide Touch ID o la contraseña maestra, una vez
por ventana y por clave (la sesión de tu terminal, el proceso padre o la
conexión; [`klavd.md`](klavd.md) §3, «The presence gate»). Las capas 2 a 5
la construyeron apagada, tras una opción oculta, `klavd --presence-gate`,
que ya no existe. Con un `klavd` anterior, o uno de esas capas con la puerta
apagada, la CLI hace lo mismo que antes. El modo directo (`--no-daemon`) no
pasa por `klavd` y no pide presencia, salvo para los valores de un elemento
protegido por un entorno (abajo).

- **Qué comandos.** Los que piden un valor a `klavd`: `klav item get
  --reveal` (`view`), `klav item history --reveal N` (`previous_password`),
  `klav totp` (`totp`), `klav generated show N` (`generated_value`), `klav run`
  y `klav inject` (`resolve`). Un valor de un elemento protegido por un
  entorno (ADR 0032 §3) pide presencia **cada vez**: no usa ni abre
  ventana, y la pregunta dice «It lets klav …, this once: used by …». En
  modo directo (`--no-daemon`), esos valores también la piden: la
  contraseña maestra en `/dev/tty` (sin terminal, sale con 9). Ningún comando de agente pasa por aquí: `klav
  agent …` y `klav mcp` no piden valores a `klavd` (`klav agent list`, por
  ejemplo, no pide nada). Los que ya piden
  presencia por su cuenta, como `klav agent resume`, `klav agent approve` y
  los cambios de permisos que los amplían, sí piden Touch ID y, si falla o
  no hay, la contraseña maestra, también con `--password-stdin`: confirma esa
  acción y no abre ventana. La pregunta en la terminal nombra la terminal y dice «It confirms this one action, and opens
  no window.».
- **Con Touch ID** (un Mac con Touch ID y sin `--no-touch-id`), `klavd`
  muestra el diálogo y el comando espera. Justo antes, `klavd` avisa a la CLI
  (lo pide con `notify`, [`klavd.md`](klavd.md) §3) y la CLI escribe el
  nombre de su terminal, para compararlo con el del diálogo: `klav: Touch ID
  for the terminal ttys003` (decisión 2 de Omar, 2026-11-19). Sin terminal
  de control dice `this program`. Con el ajuste en `always`, el diálogo de
  cada valor también dice para quién es, para que haya con qué comparar:
  «show the code of “GitHub” (for the terminal ttys003)» («mostrar el
  código de «GitHub» (para la terminal ttys003)» en español; decisión C de
  Omar, 2026-11-19, con un texto que todavía espera su visto bueno).
- **Sin Touch ID** (Linux, un Mac sin Touch ID o con él apagado), `klavd`
  responde `presence_required` y la CLI pide la contraseña maestra **en su
  terminal de control** (`/dev/tty`), nunca en stdin: una contraseña en stdin
  nunca cuenta como presencia para un valor, aunque haya terminal (decisión
  3 de Omar, 2026-11-19). Solo pregunta si `klav` es el trabajo en primer
  plano de esa terminal; uno en segundo plano cuenta como sin terminal.
  Antes de la pregunta escribe en esa terminal cuál es, con el nombre que le
  da `klavd` (la misma lectura y la misma conversión del número de
  dispositivo), y lo que la contraseña concede según lo que `klavd` dijo que
  concede (`lasts` y `value`, nunca el ajuste solo):

  ```text
  klav: master password for the terminal ttys003
  It lets the terminal ttys003 use your vault for 5 minutes.
  Master password for ana@example.com:
  ```

  Si no puede nombrar la terminal, dice «a terminal», como `klavd`. Con el
  ajuste en `always`, sin ventana posible (Linux antes del 6.5) o con un
  valor que pide cada vez, dice el valor con el tipo y el título que manda
  `klavd`, en inglés y limpio de caracteres de control: «It lets klav show
  the code of “GitHub”, this once.». El título es el que tiene el elemento
  cuando `klavd` pregunta: una pista, no una prueba, porque renombrar no
  pide presencia (decisión D de Omar, 2026-11-19). La pregunta que abre una
  ventana dice para quién y cuánto dura, y no nombra ningún elemento.
  `item get --reveal`, `item history --reveal` y `totp` van atados a un
  elemento: una consulta que no nombra uno solo falla antes de preguntar
  (`not_found` o `invalid`), y si el elemento cambia mientras confirmas
  (se renombra, se edita o llega una versión nueva al sincronizar), no se
  entrega nada (`conflict`, código 1; decisión F de Omar, 2026-11-19).
  Tras un `conflict` no queda ninguna ventana abierta: al volver a correr
  el comando, pregunta otra vez (decisión G). Desde la capa 6, `run` e
  `inject` van atados igual a cada elemento que nombran sus referencias, y
  `generated show` a su entrada del historial (decisión K de Omar, que
  revocó la elección propia 51 del ADR): una referencia que no nombra nada,
  o un campo que el elemento no tiene, falla antes de preguntar, y si un
  elemento o la entrada cambia mientras confirmas, no se entrega nada
  (`conflict`). `klavd` solo comprueba la contraseña si
  todavía preguntaría exactamente eso; si algo cambió (el ajuste, el
  elemento al que apunta la consulta), no la usa y vuelve a preguntar, y la
  CLI lo dice y pregunta una vez más con las palabras nuevas. Una tercera
  pregunta termina el comando.
  Un solo intento por pregunta: una contraseña equivocada termina el comando
  (`wrong_credentials`, código 1) sin valor. Ctrl-C o Ctrl-D en la pregunta
  la cancelan (código 1) y dejan la terminal como estaba, con eco (una señal de fuera durante la pregunta, como `SIGTERM`, no pasa por ahí).
  Lo que se tecleó antes de la pregunta se descarta. Tab y los caracteres
  imprimibles entran en la contraseña; Retroceso borra un carácter, Ctrl-W
  una palabra y Ctrl-U la línea; las teclas que mandan secuencias de
  escape (flechas, también con modificador, y teclas de función) no hacen
  nada y nunca entran en la contraseña. Un ESC suelto, en cambio, se lleva
  el carácter imprimible que lo sigue, como Alt con esa tecla: una
  contraseña escrita con ESC pierde un carácter y falla, nunca gana uno. No
  se puede mover el cursor. Una línea de más de 1024 bytes se rechaza
  entera («the master password is longer than 1024 bytes: nothing was
  sent», código 1), pero solo al terminar: la CLI sigue leyendo, sin eco y
  sin decir nada, hasta Enter o Ctrl-C, y descarta lo que quede en cola
  antes de devolver la terminal, así que esa línea no llega a la shell.
  Desde la capa 6 (decisión M de Omar, que cierra lo que dejaba la
  elección propia 53), después de cualquier respuesta, buena o rechazada,
  la CLI sigue leyendo sin eco hasta que la terminal calla 0,2 s (2 s como
  mucho) y lo descarta: en un pegado de varias líneas, la contraseña es la
  primera línea, y las demás nunca llegan a la shell.
- **Sin terminal** (un script, un servicio): sale con el **código 9** y dice
  qué hacer: correr el comando desde una terminal. Como el resto de los
  errores, va en stderr también con `--json`.
- **`presence_busy`** se dice según lo que mandó la CLI: sin contraseña,
  otro programa tiene abierto un diálogo de Touch ID de Klav; con ella,
  `klavd` está comprobando otra contraseña. Sale con 1; vuelve a intentarlo
  cuando termine.
- **`klav unlock`.** La CLI sabe si la puerta está encendida por el `status`
  de `klavd` (`presence`); un `klavd` anterior, o uno de las capas 2 a 5 con
  la puerta apagada, no lo manda, y la CLI hace lo de antes. Con la puerta:
  - antes de Touch ID escribe `klav: Touch ID for the terminal ttys003`, el
    nombre que verás en el diálogo;
  - la pregunta por la contraseña maestra nombra la terminal y dice qué abre
    («It unlocks Klav, and lets the terminal ttys003 use your vault for 5
    minutes.», o «It unlocks Klav, and opens no window: the next value asks
    for your presence.»), y `klavd` no abre más que eso (`shown`). El primer
    desbloqueo desde que arrancó `klavd` no abre ninguna ventana, con
    contraseña igual que con Touch ID: el ajuste está sellado hasta entonces
    y la pregunta lo dice (decisión A de Omar, 2026-11-19);
  - con `--password-stdin` desbloquea, pero no abre ninguna ventana ni
    cuenta como verificación para las passkeys: lo dice («…Each value asks
    for your presence on the terminal, and so does the next passkey use»), y
    el siguiente valor pide presencia en la terminal (decisiones 4 y B de
    Omar, 2026-11-19; la CLI manda `untyped`, [`klavd.md`](klavd.md) §3).
    Igual en cualquier comando que desbloquee con la contraseña de stdin;
  - si `klavd` ya estaba desbloqueado, no manda nada ni pide contraseña. Si lo
    desbloqueó otra clave (otra terminal, la app), avisa: «Klav was already
    unlocked elsewhere; this unlock gave this terminal nothing. If you didn't
    unlock it, lock Klav (`klav lock`)» («this program» sin terminal), y no
    te abre ventana: el siguiente valor la pide (decisión 5 de Omar,
    2026-11-19);
  - un segundo `unlock` mientras otro muestra su diálogo recibe
    `presence_busy`.

  Los avisos de la respuesta de `unlock` (el del `passkeys.json` viejo) salen
  en stderr.

```sh
klav presence window [--json]                 # el ajuste, con klavd desbloqueado
klav presence window always|5m|unlocked       # cambiarlo
```

- Muestra cada cuánto pide presencia `klavd`: `always` (cada valor), `5m`
  (una vez cada 5 minutos por clave, el valor por defecto) o `unlocked` (una
  vez hasta que Klav se bloquee). Con `--json`: `{"window": "5m"}`.
- **Solo con `klavd` desbloqueado:** el ajuste va sellado con las llaves de tu
  bóveda. Bloqueado, lo dice y pide `klav unlock`; no arranca ni desbloquea
  `klavd` por su cuenta.
- **Endurecerlo** no pide nada y acorta en el acto las ventanas abiertas.
  **Aflojarlo** pide Touch ID, o la contraseña maestra en la terminal (como
  arriba, también con el código 9 sin terminal), con el cambio en el diálogo
  («ask for your presence every 5 minutes instead of for every value»), y no
  abre ninguna ventana: el siguiente valor vuelve a pedir presencia.
- Un `klavd` de las capas 2 a 5 con la puerta apagada responde
  `not_supported` («the presence gate is off»); uno anterior no conoce la
  operación y la CLI pide actualizar Klav. Los dos salen con 1.

### Extensión de navegador

La extensión habla con `klavd` a través de `klav-native-host`, un puente que
el navegador arranca por native messaging ([`extension.md`](extension.md)).
Hay que registrarlo una vez por `KLAV_HOME`:

```sh
klav extension install-host --dev                 # todos los navegadores instalados, con la extensión de desarrollo
klav extension install-host --browser dia --browser chrome --dev
klav extension install-host --user-data-dir /tmp/perfil --dev   # un perfil concreto de Chromium
klav extension install-host --extension-id <ID>   # otra extensión (la de la tienda), sin --dev
klav extension uninstall-host [--browser B]
klav extension host-status [--json]               # qué manifiesto hay en cada navegador
```

- `--dev` permite la extensión de desarrollo en los navegadores Chromium
  (la que se carga sin empaquetar desde `apps/extension/dist/chromium`). Su
  ID sale de una llave pública que está en el repositorio, así que no se
  permite si no se pide. Sin `--dev` ni un `--extension-id` de Chromium,
  los navegadores Chromium encontrados se saltan con un aviso y los
  nombrados son un error. Firefox (`klav@klav.dev`) no lo necesita.

- Escribe `$KLAV_HOME/native-host/klav-native-host`, un *wrapper* que fija
  este `KLAV_HOME`, y el manifiesto `dev.klav.host.json` en el directorio de
  cada navegador (Chrome, Chromium, Brave, Arc, Edge, Dia, Ardia y Firefox).
- Busca `klav-native-host` junto a `klav` o en el `PATH` (`--host RUTA`
  para otro).
- Sin `--browser`, solo los navegadores cuyo directorio de datos existe.
- Hay que reiniciar el navegador si la extensión ya estaba abierta.
- `host-status` no cambia nada: por navegador, si hay manifiesto, a qué
  apunta (`points_to`) y qué `klav-native-host` ejecuta al final (`runs`,
  leído del *wrapper*). También dice si el manifiesto es de este
  `KLAV_HOME` y este `klav`, y si su *host* deja pasar todas las extensiones
  que el manifiesto permite (`current`). Para saberlo, compara la lista del
  manifiesto (`allowed_origins` o `allowed_extensions`) con los `--allow`
  del *wrapper* y lo que el *host* permite por defecto. Las que rechazaría
  van en `refused`, y `reason` da el comando que las añade, por ejemplo
  `klav extension install-host --dev` para un *wrapper* escrito antes de
  que la de desarrollo necesitara `--dev`. Si `points_to` no ejecuta
  `klav-native-host`, o el *wrapper* no se puede leer, no lo comprueba. La
  app de Mac lo usa para mostrar otra instalación antes de reemplazarla
  ([macos.md](macos.md) §3).

## 9. Agentes

> Los pasos para quien usa Klav están en la página pública [`how-agents-work.mdx`](../apps/docs/src/content/docs/agents/how-agents-work.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

Un agente de IA usa la bóveda con su propia identidad, sin conocer la
contraseña ni el Secret Key (diseño §5, ADR
[0014](decisiones/0014-agentes-fase-4.md)).

### En la máquina del agente

> Los pasos para quien usa Klav están en la página pública [`connect-an-agent.mdx`](../apps/docs/src/content/docs/agents/connect-an-agent.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav agent register --name claude-code [--server URL] [--email ana@example.com] \
    [--note "para qué"] [--key-store auto|keychain|file] [--key-file PATH] [--json]
klav agent status [--agent NOMBRE] [--wait] [--json]
klav agent totp klav://Bóveda/Proyecto/Elemento --reason "por qué" [--wait 2m] [--approval ID]
klav approval wait <id> [--timeout 10m] [--json]
```

- `register` genera el par de llaves, envía la solicitud e imprime las **6
  palabras de emparejamiento**.
  - `--server` y `--email` toman por defecto la cuenta de este `KLAV_HOME`,
    si la hay. Sin cuenta ni `--server`, el servidor es `https://api.klav.dev`
    (§3).
  - La solicitud caduca en una hora.
  - Con `--json` imprime en stdout `agent_id`, `name`, `public_identity`
    (base64url, como la lista el servidor), `pairing_code`, `expires_at` y
    `key_store`. La app de Mac compara `public_identity`, byte a byte, con la
    solicitud pendiente que aprueba (ADR 0033 §3.1).
- **La llave privada** queda, según `--key-store`:
  - **`keychain`**: en el llavero de inicio de sesión de macOS (servicio
    `dev.klav.agent`). Es lo que elige `auto` en un Mac.
  - **`file`**: en un archivo 0600, por defecto
    `$KLAV_HOME/agents/<nombre>.key`. Klav rechaza el archivo si otros
    usuarios pueden leerlo.
  - **`KLAV_AGENT_KEY`**: si la variable está definida, tiene prioridad sobre
    lo guardado. Sirve para contenedores y servidores:
    `KLAV_AGENT_KEY="$(cat bot.key)"`.
- La configuración pública del agente queda en
  `$KLAV_HOME/agents/<nombre>.json`. **Fija la identidad de la cuenta la
  primera vez que la ve.** Si cambia, el agente se niega a seguir (código de
  salida 3).
- `status` muestra el estado, las palabras del agente y las de la cuenta
  (`account:`), que deben coincidir con las que muestra `klav status` en el
  dispositivo de la persona. Con `--wait` espera la aprobación. Una
  solicitud que caducó sin que nadie decidiera sale como `denied` con
  `lapsed: true` en `--json` («the request lapsed without a decision»):
  `klav client connect` pide otra.
  - Si la persona lo pausó, `paused:` dice si es a él o a todos, desde
    cuándo y hasta cuándo (`paused` en `--json`). Con `--wait`, un agente
    aprobado pero en pausa sale con 7.
  - Si la persona pidió borrar la cuenta, `deleting:` dice cuándo
    (`account_delete_at` en `--json`, en milisegundos Unix). Con `--wait`
    sale con 8.
- Con varios agentes en el mismo `KLAV_HOME`, elige uno con `--agent` o
  `KLAV_AGENT`.
- **`totp`** genera el código como el agente. Por defecto `totp` está en
  `ask`, así que:
  - sin `--wait`, sale con el código 4, el ID de la solicitud y los comandos
    para aprobarla (`klav approval approve`) y esperarla
    (`klav approval wait`);
  - con `--wait`, espera a que la persona decida y repite la petición con esa
    aprobación;
  - con `--approval ID`, usa esa aprobación (después de
    `klav approval wait`). Vale también en `run`, `inject` y `fill`. Si es
    para otra acción, otro elemento u otro sitio, falla sin hacer nada.

  Repetir el comando sin `--approval` también sirve: si la persona ya aprobó
  la misma acción sobre el mismo elemento, se usa esa aprobación, y si sigue
  pendiente se recibe la misma solicitud, no una nueva (ADR
  [0015](decisiones/0015-aprobaciones-reutilizables-y-espera.md)).

  `--reason` es obligatorio. Con `project` en `klav.toml` acepta la forma
  corta `Elemento`, y el agente solo ve ese proyecto.

#### Solicitudes de tarea

> Los pasos para quien usa Klav están en la página pública [`approvals-and-tasks.mdx`](../apps/docs/src/content/docs/agents/approvals-and-tasks.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

Para un trabajo que toca varios elementos, el agente pide **una** tarea en
lugar de una aprobación por elemento (ADR
[0021](decisiones/0021-solicitudes-de-tarea.md)):

```sh
klav agent task request tarea.toml [--wait [10m]] [--json]   # o tarea.json; `-` lee JSON de stdin
klav agent task wait <id> [--timeout 10m] [--json]
klav agent task show <id> [--json]
klav agent task end <id> --reason "terminé"
```

```toml
task = "Descargar las facturas de octubre"
reason = "Conciliar los gastos del mes"
duration = "2h"

[[access]]
ref = "klav://Facturas/General/AWS"
permissions = ["fill", "totp"]

[[access]]
ref = "Telmex"                  # forma corta, con `project` en klav.toml
permissions = ["fill"]
domain = "telmex.com"           # opcional; si falta, valen las URLs del elemento
```

- **El archivo** es TOML o JSON, con las claves del ejemplo. YAML no se
  acepta.
  - `duration` va de `5m` a `24h` y cuenta desde la aprobación.
  - Caben de 1 a 50 accesos, cada elemento una vez.
  - Los permisos posibles son `fill`, `totp`, `inject`, `update`, `passkey` y
    `rotate`. `reveal` y `delete` nunca van en una tarea, y `list` y `create`
    no se piden.
- **Al servidor solo llegan IDs:** el runtime traduce cada `ref` con su copia
  descifrada antes de enviar. `task` y `reason` viajan en claro, como el
  motivo de cualquier petición, así que no pongas secretos ahí.
- **`request`** imprime la tarea y sale con el código de su estado:
  - sin `--wait`, sale con 4 (pendiente) y dice cómo aprobarla
    (`klav task approve <id>`) y cómo esperarla;
  - con `--wait`, espera a la persona, 10 minutos por defecto.
- **`wait`** sigue la tarea con *long-poll*, igual que `approval wait`. Sale
  con:
  - 0 si está aprobada;
  - 4 si sigue pendiente;
  - 5 si se denegó, o si la terminó la persona o una revocación;
  - 6 si venció sin decisión, o si terminó por tiempo o la cerró el agente.
- **Lo aprobado:** antes de mostrarlo, el runtime verifica la firma de la
  decisión con la identidad fijada de la cuenta. Muestra:
  - `access`: cada elemento con sus permisos y hosts, y lo que añadió Klav
    (`added_by_klav`, por ejemplo `totp`);
  - `removed`: lo que la persona dejó fuera.
- **Dentro de la tarea**, `fill`, `totp`, `inject` y `update` sobre lo
  aprobado no piden otra aprobación, aunque la política diga `ask`. Lo que
  la tarea no cubre sigue el camino normal (código 4 y `klav approval
  wait`). Una regla `deny` gana siempre.
- **`end`** cierra la tarea cuando el trabajo termina. `--reason` es
  obligatorio.

#### Usar secretos sin verlos

> Los pasos para quien usa Klav están en la página pública [`use-secrets-without-seeing-them.mdx`](../apps/docs/src/content/docs/agents/use-secrets-without-seeing-them.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav agent run --reason "por qué" [--env NOMBRE] [-e NOMBRE=REF] [--timeout 10m] -- comando …
klav agent inject --reason "por qué" (-r REF | -i plantilla) -o archivo [--ttl 10m] [--force]
klav agent fill klav://Bóveda/Proyecto/Elemento[/campo] --reason "por qué" \
    (--cdp http://127.0.0.1:9222 [--target ID] | --session NOMBRE | --extension) [--selector campo=css …] \
    [--submit] [--json]
klav agent browser register NOMBRE --cdp http://127.0.0.1:9222 [--target ID]
klav agent browser forget NOMBRE
```

Todas aceptan `--wait`, `--approval` y `--agent`, usan `klav.toml` como
`klav run` y quedan en la bitácora con su motivo.

- **`run`** pone los valores en el entorno del comando (`[env]`, `[files]`,
  `-e` y variables `NOMBRE=klav://…` heredadas) con el permiso `inject`.
  - **Entornos** ([ADR 0032](decisiones/0032-entornos-por-repositorio.md)
    §4.5): `--env NOMBRE` inyecta el entorno de ese nombre del `project` de
    `klav.toml`, más `[env.NOMBRE]`, con la misma mezcla que `klav run`
    (§6). Sin `--env`, el mismo orden que `klav run`: `default_env`, el
    `[env]` plano, el único entorno o un error que los nombra; nunca elige
    `development` por su nombre. `-e` se llama ahora `--var` en su forma
    larga, y `--env NOMBRE=REF` se sigue leyendo como `-e`. En `klav mcp`
    es el campo `environment` de `run_with_secrets`, y en `@klav/sdk`, la
    opción `environment` de `run`.
  - **Un entorno protegido** (producción) pide **una** aprobación por
    `run`: la solicitud nombra el entorno y, en `items`, los elementos
    protegidos a los que pueden apuntar sus referencias (los que las
    reglas heredadas del grant firmado protegen; el runtime no ve las
    referencias antes de abrir el entorno). Cada elemento se pide después
    con su propio acceso, que nombra esa aprobación, una vez cada uno. El
    reintento con `--approval <id>` cubre la llamada entera. Las
    referencias a elementos no protegidos se juzgan con sus propias
    reglas.
  - **Doble barrera** (§4.4): el runtime aplica el grant firmado y, cuando
    puede leer el entorno, calcula su marca efectiva (la de la última
    versión de la persona; sin versión suya, protegido si se llama
    `production` o `prod`). Un entorno protegido, y las referencias de la
    versión protegida de la persona, necesitan una aprobación firmada por
    la cuenta aunque el servidor diga `allow`; si no, sale con 3 y no usa
    ningún valor. Una tarea nunca la cubre.
  - La salida vuelve **después** de que el comando termina, con cada valor
    sustituido por `[redacted by klav]`. También se tapan las formas en que
    un comando suele imprimir un valor sin querer:
    - en base64 (estándar y URL, con relleno o sin él), también dentro de
      un bloque mayor como `Authorization: Basic …`;
    - en hexadecimal (minúsculas y mayúsculas);
    - con codificación de URL (`%2F`, `%2f` o `+` para el espacio);
    - escapado dentro de una cadena JSON (`\"`, `\\`, `\/`, `\n`,
      `\uXXXX`);
    - en trozos de 12 caracteres o más, por ejemplo partido en dos líneas.

    Coincidencias que se solapan o se tocan quedan en una sola marca, y el
    aviso de stderr cuenta esas marcas. Es una red de seguridad contra
    descuidos, no contra un comando que quiera sacar el valor:
    - un valor cifrado o transformado a su manera, o codificado dos veces,
      pasa;
    - los trozos de menos de 12 caracteres también;
    - un valor de menos de 12 caracteres solo se tapa entero, y de sus
      codificaciones, solo las de 8 caracteres o más.

    Al revés, un adjunto con texto corriente (un encabezado PEM, los
    nombres de variables de un `.env`) tapa también ese texto cuando el
    comando lo imprime por otro lado.
  - Sale con el código del comando. `--timeout` lo mata (10 min por
    defecto).
- **`inject`** escribe solo en un archivo nuevo 0600 (`-o` es obligatorio):
  un agente nunca recibe el valor por stdout. Lo escribe como `klav inject
  -o` (§7): un temporal `.<nombre>.<16 hex>.klav-tmp` en el mismo directorio
  que toma el nombre de una vez, así que nunca se lee a medias; si git no
  lo ignora, avisa y recomienda ignorar también `*.klav-tmp`. Después,
  salga bien o no, avisa por stderr de los temporales de ese nombre de
  otra escritura, interrumpida o todavía en curso, como `klav inject -o`.
  `klav agent run`
  hace lo mismo con sus `[files]`, junto al aviso de lo que tapó, sin
  cambiar su código de salida.
- **`fill`** escribe en una pestaña de Chrome o Chromium por CDP, o con
  `--extension` en la pestaña activa del navegador de la persona a través de
  la extensión de Klav ([`extension.md`](extension.md) §8) (permiso
  `fill`):
  - con una referencia a un elemento, el usuario y la contraseña de un login
    o los campos de una tarjeta; con `…/campo`, solo ese campo. Un campo
    TOTP se rellena con el código actual;
  - antes de escribir comprueba que la página sea `https` (o `http` en
    `127.0.0.1`) y que su host sea el de una URL del elemento o un
    subdominio. Si no, se niega (protección contra phishing);
  - solo se conecta a navegadores en la propia máquina;
  - justo antes de cada campo comprueba su tipo (la contraseña solo en un
    `input[type=password]`, el TOTP en uno de contraseña o de código), que
    tenga el foco y que la pestaña siga en el sitio; si no, no escribe;
  - el TOTP pide el permiso `totp` y solo sale de un campo de tipo TOTP;
  - imprime los nombres de los campos rellenados, nunca los valores;
  - **`--submit`** además envía el formulario: el del último campo escrito
    (`form.requestSubmit()`), solo si su acción es del mismo origen que la
    página, o, si no hay formulario, el botón de envío de la página.
    Antes vuelve a comprobar el host de la pestaña. Espera hasta 10 s a que
    cargue una página nueva y dice si cargó y en qué dirección quedó. Por
    defecto no envía nada. Si no encuentra qué enviar, falla diciendo que
    los campos quedaron rellenados;
  - `--json` imprime el reporte (`url`, `filled`, `submitted`, `navigated`,
    `url_after`): nombres y orígenes (esquema y host, sin ruta ni
    consulta), nunca valores.
- **`browser register`** guarda un navegador como sesión `sdk:NOMBRE`, que
  `klav mcp` puede usar como destino de `fill_login` y `fill_card`.

#### Conectar un cliente de agentes (`klav client`)

> Los pasos para quien usa Klav están en la página pública [`connect-an-agent.mdx`](../apps/docs/src/content/docs/agents/connect-an-agent.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav client list [--json]
klav client connect <cliente> [--agent NOMBRE] [--no-skill] [--dry-run] [--yes] \
    [--replace | --adopt] [--expect-sha256 HEX] [--key-store auto|keychain|file] [--json]
klav client disconnect <cliente> [--keep-skill] [--dry-run] [--yes] [--force] [--json]
klav client restore <cliente> [--force] [--json]
klav client connect <cliente> --mcp PERFIL,… [--proxy-port 8790] [--dry-run] [--yes] \
    [--replace] [--json]
klav client disconnect <cliente> --mcp [PERFIL,…] [--dry-run] [--yes] [--force] [--json]
```

Pone (o quita) la entrada `klav` del servidor MCP y la skill en un cliente
de agentes, y registra su agente (ADR
[0033](decisiones/0033-agentes-desde-la-app-de-mac.md) §1–§5). La app de Mac
hace lo mismo llamando a estos comandos.

| `<cliente>` | Configuración | Cómo la escribe Klav | Skills |
|---|---|---|---|
| `claude-code` | `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json` si está definida), `mcpServers.klav` | solo con `claude mcp add\|remove --scope user`; sin `claude` no escribe y da el comando | `~/.claude/skills/{klav,klav-migrate}/` |
| `claude-desktop` (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json`, `mcpServers.klav` | edición del archivo; hay que reiniciar la app | no tiene carpeta: le llega por las descripciones de las herramientas |
| `codex` | `$CODEX_HOME/config.toml` (`~/.codex/`), `mcp_servers.klav` | `codex mcp add\|remove` si está `codex`; si no, edición del TOML | `~/.agents/skills/{klav,klav-migrate}/` |
| `cursor` | `~/.cursor/mcp.json`, `mcpServers.klav` con `type: stdio` | edición del archivo | `~/.agents/skills/{klav,klav-migrate}/` |
| `vscode` | `~/.copilot/mcp-config.json`, `mcpServers.klav` con `type: stdio` | edición del archivo | `~/.agents/skills/{klav,klav-migrate}/` |
| `antigravity` | `~/.gemini/config/mcp_config.json` (o `~/.gemini/antigravity/mcp_config.json`), `mcpServers.klav` | edición del archivo | `~/.gemini/config/skills/{klav,klav-migrate}/` (también enlazada por T3 Code para sus hilos de Antigravity) |

- **`list`** no cambia nada. Por cliente dice si está instalado, dónde está
  su configuración (y a dónde apunta si es un enlace), cómo se escribe, la
  entrada `klav`, su agente, si una configuración administrada lo impide y
  su estado:
  - `connected`: la entrada es la que escribió Klav;
  - `changed`: Klav la escribió y alguien la cambió después;
  - `person`: hay una entrada `klav` que Klav no escribió;
  - `malformed`: el archivo no se puede leer, o repite una clave en la raíz
    o en `mcpServers` (el cliente leería solo la última, y Klav no sabría
    cuál corre);
  - `not_connected`, `not_installed`, `managed` o `unavailable`.

  De la entrada solo muestra lo que no puede ser un secreto: `type`,
  `command`, los argumentos de `klav mcp` (`mcp`, `--agent` y `--wait`, con
  su valor solo si parece un nombre de agente o una duración), los nombres
  de `env` y `headers` (con los valores de `KLAV_HOME`, `KLAV_AGENT` y
  `KLAV_BROWSER_HOME`), el esquema y el host de una `url`, y números y
  booleanos. Lo demás sale como `••••••••`. El host de una `url` solo se
  muestra si se distingue sin dudas: lo que sigue al último `@`, antes del
  primer `/`, `?` o `#`, y con los caracteres de un nombre o una dirección.
  Si una contraseña lleva `?`, `#` o `/` (`https://ana:x?y@host`), o hay un
  `@` en la ruta, sale solo el esquema. Avisa (`unknown_command`) si la
  entrada corre un programa que no es este `klav`, el enlace de la app en
  `/usr/local/bin/klav` ni el `klav` de `/Applications/Klav.app` (una
  `Klav.app` en otra carpeta no cuenta). `/usr/local/bin/klav` cuenta solo
  si es el enlace de la app: de `root` y apuntando a este `klav` o al de la
  app, nunca por su ruta. Nunca muestra los demás servidores del archivo:
  suelen llevar llaves en su `env`.
- **`connect`** muestra primero qué va a cambiar y pide confirmación. Sin
  terminal hace falta `--yes`; sin él imprime el resumen y no escribe nada.
  - **El agente**: si ya hay uno con ese nombre (por defecto, el del
    cliente) en este `KLAV_HOME`, lo usa. Si está pendiente, repite sus
    palabras y no registra otro. Si su solicitud caducó sin que nadie
    decidiera, lo olvida en este `KLAV_HOME` (configuración y llave) y
    registra otro, que pide una aprobación nueva. Si la persona lo denegó
    o lo revocó, no escribe nada, sale con el código 5 y dice el camino
    para volver: la persona registra en su terminal un agente con otro
    nombre (`klav agent register --name <otro>`) y conecta con
    `--agent <otro>`, porque el nombre sigue ocupado aquí. Si no hay
    ninguno, lo registra con el servidor y el correo de la cuenta de este
    `KLAV_HOME` (sin cuenta, falla y dice cómo registrarlo a mano).
  - **La entrada** lleva una ruta absoluta: el enlace `/usr/local/bin/klav`
    de la app si este `klav` es el de `Klav.app`, si no este mismo `klav`
    (con un aviso si su carpeta la puede escribir tu usuario). Los
    argumentos son `mcp --agent <nombre>`. Nunca lleva una llave. Solo
    lleva `env.KLAV_HOME` cuando `KLAV_HOME` está definida y no es la de
    por defecto, siempre como ruta absoluta: el cliente arranca `klav mcp`
    sin tu entorno y desde otra carpeta.
  - **Claude Code** se escribe con
    `claude mcp add --scope user --transport stdio klav [--env KLAV_HOME=…] -- <klav> mcp --agent <nombre>`:
    el nombre va antes de `--env`, porque `--env` de `claude` toma todos
    los valores hasta la opción siguiente, y `--` cierra la lista.
  - **Si la CLI del cliente falla** (`claude` o `codex`), Klav da solo su
    código de salida y el comando para correrlo a mano: nunca lo que
    imprimió, que puede citar una línea de su configuración con la llave de
    otro servidor. Una CLI puede escribir y luego fallar, o morir por el
    tiempo límite (60 s) justo después de escribir: por eso, cuando falla,
    Klav vuelve a leer el miembro `klav`, y si es la entrada que pidió, la
    registra como de Klav y termina bien, con un aviso. Si para reemplazar
    la entrada `claude mcp remove` la quita y luego `claude mcp add` falla,
    Klav primero mira qué quedó: si es la entrada nueva, es como lo de
    antes; si no hay ninguna, vuelve a poner la anterior, pero solo si
    tiene la forma de una de Klav y no oculta nada (solo `type`, `command`,
    los argumentos de `klav mcp` y `env.KLAV_HOME`); si hay otra, no
    reintenta. Una entrada que no tiene esa forma, como
    `sh -c "TOKEN=… klav mcp"`, nunca se imprime ni se pasa a `claude`:
    Klav dice dónde está la copia y que la persona la vuelva a poner a
    mano.
  - **Antes de escribir** copia el archivo a `client-backups/`, lo vuelve a
    leer y no escribe si cambió desde el resumen. `--expect-sha256` toma el
    `expect_sha256` de `--dry-run --json`: el SHA-256 del archivo entero
    cuando Klav lo edita, y el del miembro `klav` solo cuando lo escribe la
    CLI del cliente, porque Claude Code reescribe el resto de
    `~/.claude.json` todo el tiempo. Si el archivo no existe todavía, solo
    lo crea cuando la carpeta del cliente ya existe (no crea `~/.cursor` ni
    `~/.copilot`).
  - **La edición** cambia solo el miembro `klav`: conserva comentarios,
    espacios, orden y las demás claves, sigue los enlaces sin
    reemplazarlos y mantiene el modo del archivo. En el TOML de Codex
    conserva también los finales de línea CRLF y el BOM; un archivo que
    mezcla CRLF y LF no se toca. Un JSON con BOM tampoco. Después relee el
    archivo, y si algo más cambió, devuelve el original, pero solo si el
    archivo sigue siendo exactamente lo que Klav escribió: si otro programa
    lo cambió entre medias, no pone la copia encima y dice dónde está. Con
    la CLI del cliente, comprueba que la entrada que quedó sea la pedida.
    El `rename` atómico rompe un enlace duro y no conserva los atributos
    extendidos ni las ACL del archivo.
  - **Una entrada que Klav no escribió** no se toca sin preguntar, y solo se
    pregunta en una terminal: `--replace` la cambia por la de Klav y
    `--adopt` la deja como está y la registra como de Klav. Los dos piden
    confirmar en la terminal aunque haya `--yes`, y sin terminal no
    escriben nada: un agente pasa `--yes`. `--adopt` solo acepta una
    entrada que corre un programa llamado `klav` y que no lleva más que
    `type`, `command`, `args` y `env.KLAV_HOME`. Una entrada de Klav que
    alguien cambió necesita `--replace` (sin terminal, basta con
    `--replace`).
  - **La skill** se instala en la carpeta del cliente si no hay copia o la
    de Klav es más vieja. Una copia editada o ajena se deja como está, y
    una que la persona quitó no vuelve: `klav skill install` la devuelve.
    `--no-skill` no la toca. La entrada queda registrada en `clients.json`
    en cuanto se escribe, así que si la skill falla, `connect` termina
    bien, con un aviso.
  - **La salida** (`--json`) trae `agent` (`name`, `id`, `status`,
    `words`), `mcp` (acción, método, archivo, entrada antes y después,
    comandos, `file_sha256`, copia), `skill`, `warnings`, `notes` y `next`:
    lo que el agente le dice a la persona (las 6 palabras y dónde aprobar:
    Solicitudes de la app de Mac, el iPhone o `klav agent approve`) y el
    comando con el que espera la aprobación en segundo plano.
- **`disconnect`** quita solo la entrada de Klav (una cambiada, con
  `--force` o confirmando), y la skill si ningún otro cliente conectado usa
  esa carpeta y la copia no cambió. `clients.json` olvida la entrada en
  cuanto sale del archivo: si después falla quitar la skill, es un aviso
  (`action: "failed"`). **El agente conserva su acceso:** para cortarlo,
  páusalo (`klav agent pause`) o revócalo (`klav agent revoke`).
- **`restore`** devuelve la configuración a la copia más reciente de
  `client-backups/`. Si el archivo cambió desde la última escritura de
  Klav, solo con `--force` o confirmando. Lo que tenía queda aparte, como
  `<fecha>-<archivo>.before-restore` (las 5 más recientes), y nunca pasa a
  ser la copia que devuelve el siguiente `restore`. Si el archivo ya es esa
  copia, no hace nada (`already` en `--json`): un segundo `restore` no
  deshace el primero. En Claude Code no escribe `~/.claude.json`, que
  Claude Code reescribe para sí: dice dónde está la copia y qué comandos
  `claude mcp` vuelven a ella. Si la entrada de la copia no tiene la forma
  de una de Klav, no la imprime: dice que la persona la vuelva a poner a
  mano desde la copia.
- **Un candado** (`$KLAV_HOME/clients.lock`) evita que dos `klav client` o
  `klav skill` cambien clientes a la vez. Se toma solo para escribir:
  `connect`, `disconnect` y `restore` hacen el resumen, preguntan a la
  persona y leen el servidor sin él, y al tomarlo vuelven a comprobar lo
  que vieron (el registro, el agente, el archivo y la última copia). Si
  algo cambió, no escriben nada. La única petición al servidor con el
  candado tomado es el registro de un agente nuevo, para que dos `connect`
  no registren el mismo nombre; sus peticiones tienen tiempo límite (10 s
  para conectar y 60 s en total). Quien lo encuentra tomado espera como
  mucho 5 s y sale con un error que lo dice (`another klav client or klav
  skill is running`): así, el `klav skill update --json` que corre la app al arrancar nunca se
  queda colgado.
- **Casos que Klav no escribe** (ADR 0033 §4): un archivo mal formado (dice
  la línea y la columna, nunca el contenido, y da la entrada para pegarla a
  mano); un enlace a un archivo que no existe; un archivo de otro usuario,
  en un directorio del sistema o en uno que tu usuario no puede escribir
  (Klav nunca pide la contraseña de administrador); y una configuración
  administrada que lo impide: `managed-mcp.json` o `managed-settings.json`
  de Claude Code, el perfil MDM de Claude Desktop con
  `isLocalDevMcpEnabled: false`, el `[mcp_servers]` de
  `/etc/codex/requirements.toml` o las políticas `ChatMCP` y
  `ChatAllowManagedMcpServersOnly` de VS Code. Si el archivo está en un
  repositorio git o hay chezmoi, lo escribe y avisa.
- **`KLAV_SYSTEM_ROOT`** cambia la raíz desde la que Klav busca las rutas
  del sistema (`/Applications`, `/Library`, `/etc`, `/usr/local/bin`), y
  también los directorios del sistema del `PATH` (`/usr/bin`, `/bin`)
  cuando busca `claude`, `codex`, `cursor` o `code`. Es solo para las
  pruebas, que simulan un Mac en un directorio temporal y no deben ver los
  programas de la máquina donde corren, y solo funciona en una compilación
  de depuración: un `klav` de *release* usa siempre `/`.

##### El gateway MCP en un cliente (`--mcp`)

Con `--mcp`, `connect` no toca la entrada `klav`: conecta el cliente a los
perfiles MCP del proxy de credenciales en este Mac (ADR
[0049](decisiones/0049-mcp-gateway.md) §3), una entrada por perfil con el
nombre del perfil, que apunta a `http://127.0.0.1:<puerto>/<perfil><endpoint>`
con `Authorization: Bearer klc1_…`.

- **El token de cliente local** (`klc1_…`, especificación §13.16) lo crea
  `klav` con `klav-core` y solo va al archivo del cliente. `klavd` y el
  servidor reciben su resumen, que se firma en el grant del proxy
  (`local_clients`, con el nombre del cliente: `claude-code`, `codex`,
  `cursor` o `vscode`, y sus perfiles). Nunca se imprime: el plan lo muestra
  como `Bearer klc1_••••••••`. Cada `connect` firma un token nuevo y
  reescribe las entradas; el anterior deja de servir en el siguiente
  refresco del proxy (30 s).
- Primero muestra el plan (archivo, cliente local, perfiles y cada entrada:
  `add`, `replace` o `replace yours`), luego pregunta `[y/N]` (`--yes` sin
  terminal), pide Touch ID para firmar el grant y al final escribe, con una
  copia del archivo en `$KLAV_HOME/client-backups/<cliente>` y sin cambiar
  nada más del archivo (comentarios, orden, los demás servidores).
- Se niega con un perfil que no es MCP en el grant del proxy, y con una
  entrada del mismo nombre que Klav no escribió (`--replace` la sustituye).
  Una entrada es de Klav si apunta a `http://127.0.0.1:<puerto>/<perfil>/…`
  y su única credencial es un `Bearer klc1_…`.

| `<cliente>` | Entrada | Cómo la escribe Klav |
|---|---|---|
| `claude-code` | `{"type":"http","url":…,"headers":{"Authorization":…}}` | `claude mcp add-json --scope user PERFIL -`, con la entrada en la entrada estándar (nunca en la línea de órdenes); Claude Code no la acepta desde una de sus propias sesiones: hay que correrlo en tu terminal |
| `codex` | `[mcp_servers.PERFIL]` con `url` y `http_headers` | edición del TOML (su CLI solo toma un *bearer* de una variable de entorno); hay que reiniciarlo |
| `cursor` | `mcpServers.PERFIL` con `url` y `headers` | edición del archivo |
| `vscode` | `mcpServers.PERFIL` con `type: http`, `url` y `headers` | edición del archivo |

Claude Desktop y Antigravity no toman estas entradas todavía. Las formas
salen de la documentación y la ayuda de cada cliente (Claude Code 2.1.331,
Codex 0.166.0); las pruebas a mano de la capa 7 las comprueban con los
clientes en marcha (ADR 0049 §14).

- **`disconnect --mcp`** sin perfiles quita al cliente del grant del proxy
  y borra todas sus entradas del gateway; con perfiles, solo esos (el
  cliente se queda con los demás y con su token). Firma primero el grant
  (es lo que corta el token) y después borra las entradas, con copia.
  Una entrada que Klav no escribió se queda, con un aviso (`--force` la
  borra).
- **Lo que no es:** el token es una capacidad sobre el *loopback* de este
  Mac para los perfiles firmados. Cualquier programa que corra con tu
  usuario puede leerlo del archivo del cliente (riesgo residual 104): da
  nombre al que llama y limita perfiles, no separa procesos.

#### La skill (`klav skill`)

> Los pasos para quien usa Klav están en la página pública [`connect-an-agent.mdx`](../apps/docs/src/content/docs/agents/connect-an-agent.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav skill status [--json]
klav skill install [--client CLIENTE… | --dir DIR…] [--skill NOMBRE…] [--dry-run] [--replace | --adopt] [--json]
klav skill update [--keep-mine] [--dir DIR…] [--skill NOMBRE…] [--json]
klav skill uninstall [--client CLIENTE… | --dir DIR…] [--skill NOMBRE…] [--force] [--json]
klav skill show [NOMBRE]
```

Las skills [`skill/SKILL.md`](../skill/SKILL.md) (`klav`) y [`skill/klav-migrate/SKILL.md`](../skill/klav-migrate/SKILL.md) (`klav-migrate`) van dentro del binario (ADR
0033 §6 y E3). `klav` tiene las reglas, no los detalles de cada herramienta: esos
vienen con `tools/list` y con el `warning` y el `next` de cada respuesta. Su
versión es `metadata.klav-skill-version` en el *frontmatter*, propia de cada
skill. Van en `<carpeta>/<nombre>/SKILL.md`, con modo 0644.

- Una copia es de Klav **solo mientras es lo que Klav escribió** (el SHA-256
  en `clients.json`). `status` dice de cada copia que encuentra (en
  `~/.claude/skills`, `~/.agents/skills`, `~/.gemini/config/skills`, `$CODEX_HOME/skills`,
  `~/.cursor/skills`, `~/.copilot/skills` y donde Klav escribió) si está al
  día (`current`), es más vieja (`older`) o más nueva (`newer`), la
  editaron (`edited`), la borraron (`removed`) o no es de Klav
  (`unmanaged`). Una ajena que es idéntica a una skill que Klav publicó sale
  como `adoptable`.
- `install` va por defecto a las carpetas de los clientes instalados (todas las
  skills del binario salvo que se pase `--skill`).
  - Nunca pisa una copia editada o ajena: `--replace` pone la de Klav y deja
    la otra al lado como `SKILL.md.mine-<fecha>`.
  - `--adopt` registra como de Klav una copia ajena idéntica a una publicada.
  - Claude Desktop no tiene carpeta de skills.
- `update` reemplaza las copias de Klav sin cambios que son más viejas e
  instala automáticamente las nuevas skills acompañantes (como `klav-migrate`)
  en carpetas donde Klav ya administra una skill activa, siempre que no existan
  ni hayan sido borradas antes.
  - Una editada no se toca. `--keep-mine` deja de señalarla hasta que haya
    una skill más nueva.
  - Una borrada no vuelve sola: solo con `install`.
- `uninstall` quita las copias de Klav sin cambios (una editada, con
  `--force`) y su carpeta si queda vacía.
- `klav agent status` avisa con una línea cuando una copia de Klav es más
  vieja que la de este `klav` o hay una nueva skill acompañante disponible.

#### `klav mcp`

> Los pasos para quien usa Klav están en la página pública [`connect-an-agent.mdx`](../apps/docs/src/content/docs/agents/connect-an-agent.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav mcp [--agent NOMBRE] [--wait 60s]
```

Servidor MCP por stdio con la identidad del agente (ADR 0014 §8). Para
ponerlo en un cliente, usa `klav client connect` (arriba): escribe la
entrada con la ruta absoluta de `klav` y `--agent`, con una copia y sin
tocar lo demás.

- **Herramientas** (todas con `reason` obligatorio, y `wait_seconds`,
  `approval_id` y `task_id` opcionales): `search_items`, `get_item`, `fill_login`, `fill_card`,
  `run_with_secrets`, `inject_file`, `get_totp`, `reveal`, `create_item`,
  `update_item`, `delete_item` y `request_access`, y las del cambio
  asistido (abajo).
- **`create_item` con `generate`** (ADR 0022 §7): `generate: true`, o
  `{type?, site?, field?}`. `type` es el del generador (`smart` por
  defecto, `random`, `memorable` o `pin`), porque el `type` de
  `create_item` ya es el del elemento. `site` es el host cuyas reglas se
  usan (por defecto, el de la primera URL) y `field`, el campo (por
  defecto `password` en un login, si no el primer campo de contraseña u
  oculto de su plantilla).
  - El runtime genera la contraseña con las reglas del sitio y la sella en
    el elemento. Al LLM le devuelve `item` y `generated` (`field`, `type`,
    `bits`, `strength`, `site`, `rules`, `limited`, `fallback`), nunca el
    valor. No hay ninguna herramienta que devuelva una contraseña generada.
  - Se rige por `create`, como cualquier alta. Falla si `fields` ya trae
    ese campo.
  - No entra en el historial del generador de la persona (ADR 0022 §2): el
    agente no tiene la llave de ese proyecto de sistema, y el valor ya está
    en el elemento desde su primera versión.
- **Cambio asistido de contraseña** (ADR 0022 §5 y §7). Ninguna respuesta
  lleva la contraseña actual ni la nueva.
  - `change_password_url(ref)`, con `list`: `{url, host, source}`. `source`
    es `bundled` (con `domain`), de la lista empaquetada de Apple
    (`change-password-urls.json`, sin red), o `well_known`
    (`https://<host>/.well-known/change-password`, con el puerto del
    elemento si su URL lleva otro).
  - `rotate_password(ref, target, reason, task_id?, submit?)`, con `rotate`
    dentro de una tarea. Solo acepta `target: "extension"`; con `sdk:…`
    falla antes de hacer nada, porque la contraseña nueva pasaría por el
    runtime del agente.
    - Pasos: pide la pestaña activa a `klavd` y la compara con las URLs del
      elemento; elige la tarea (la de `task_id`, o la única vigente que
      cubre `rotate` en ese elemento y host); hace
      `POST /v1/agent/rotations` (API §8.6) y le pasa a `klavd` la petición
      firmada con `agent_rotate_begin` ([`klavd.md`](klavd.md) §3).
    - Devuelve solo `{filled, pending_id}`.
    - Si `klavd` no rellena (otra página, bloqueado, una prueba rechazada) y
      no se pidió `submit`, cancela el cambio en el servidor y en `klavd` en
      el acto, para que el elemento quede libre para otro intento. Con
      `submit` hace lo mismo si `klavd` no guardó la pendiente (no se
      escribió nada en la página); si la guardó, el cambio queda abierto y
      el error dice que se confirme o se cancele.
    - El error dice hasta dónde llegó esa cancelación: hecha; registrada
      en el servidor pero sin respuesta de `klavd` (el error de `klavd`
      dice si queda una pendiente); innecesaria, porque el servidor ya
      tenía el cambio cerrado (la persona decidió en la ficha mientras se
      rellenaba, o la tarea terminó); quizá no llegó, porque el servidor no
      respondió; o no registrada, con el `pending_id`. En esos dos últimos
      casos, si `rotate_cancel` responde que `klavd` no tiene pendiente, el
      elemento rechaza cambios nuevos hasta que la tarea termine:
      `end_task` lo libera, pero termina también los otros sitios de la
      tarea, y seguir con ellos pide una tarea nueva a la persona. Por eso
      el error pide terminar antes los otros sitios, o preguntarle.
    - Si el elemento ya tiene la pendiente de otro cambio de la misma
      tarea (el servidor pudo registrarlo como confirmado sin que `klavd`
      lo aplicara), `klavd` rechaza el nuevo y el cambio nuevo se cancela en
      el acto: el error pide terminar antes el otro. La bitácora muestra un
      par `rotate.started` y `rotate.cancelled` de ese cambio rechazado,
      que nunca tocó el elemento.
    - Una pendiente de otra tarea se reemplaza, y eso ya no es lo de antes:
      con el SDK anterior, `klavd` nunca podía quedarse con la pendiente de
      un cambio que el servidor ya registró como confirmado, y con este sí.
      Si entonces empieza un cambio bajo otra tarea vigente, la reemplaza:
      la contraseña actual del elemento es la vieja mientras la bitácora
      dice confirmado, y la nueva queda en el historial, no confirmada. No
      se pierde ninguna, pero el elemento está mal hasta que la persona lo
      corrige.
  - `rotate_confirm(ref, pending_id, reason)` y
    `rotate_cancel(ref, pending_id, reason)`: primero le preguntan a
    `klavd` si la pendiente del elemento es la de este cambio; luego el
    servidor registra el paso, y solo entonces `klavd` lo aplica con la
    misma petición firmada. Devuelven `{ok: true}`.
    - Si `klavd` está bloqueado, fallan y el servidor no registra nada.
    - Si el servidor rechaza el paso (pausa, revocación, borrado pedido),
      la pendiente sigue en el elemento: un reintento o la ficha lo cierran.
    - Si el servidor lo registró y `klavd` no dijo que lo aplicara (lo
      rechazó, o su respuesta se perdió), el error dice que el elemento y la
      bitácora pueden no coincidir: repetir el mismo paso lo termina (el
      servidor responde que ya está registrado y `klavd` lo aplica), o
      responde que `klavd` no tiene pendiente si ya lo había aplicado. El
      paso contrario se detiene sin tocar el elemento.
    - Si `klavd` no tiene la pendiente de este cambio (un paso anterior ya
      se aplicó, la persona ya decidió desde la ficha, o un cliente anterior
      ya lo aplicó), fallan, lo dicen y no registran nada. Si el servidor
      sigue con el cambio abierto, terminar la tarea libera el elemento.
    - Si `klavd` no llegó a rellenar, el propio `rotate_password` cancela el
      cambio en el servidor en el acto.
  - Un `deny` en estas herramientas apunta a las tareas, no a
    `request_access`: `rotate` no existe fuera de una tarea.
- **Iniciar sesión con una passkey de la persona** (ADR 0020 §9):
  `passkey_sign_in(ref, target, reason, task_id?)`, con `passkey` dentro de
  una tarea. Solo acepta `target: "extension"`; con `sdk:…` falla antes de
  hacer nada, porque el origen de la página saldría del runtime del agente.
  - Pasos: pide la pestaña activa a `klavd` y comprueba que su host pueda
    usar la passkey del elemento (su rpId); elige la tarea (la de
    `task_id`, o la única vigente que cubre `passkey` en ese elemento y
    host); hace `POST /v1/agent/access` con `passkey` (API §8.3), que el
    servidor registra, y le pasa a `klavd` la petición firmada con
    `agent_passkey_arm` ([`klavd.md`](klavd.md) §3).
  - Devuelve `{used: true, rp_id}` si la página ya pedía una passkey del
    sitio y la recibió, o `{used: false, armed: true, rp_id,
    expires_in_s: 60, next}`: el agente pulsa el botón de passkey del sitio
    y la siguiente petición del sitio en esa pestaña la recibe, una vez.
    Nunca devuelve la llave ni la aserción.
  - Con Klav bloqueado falla y lo dice: Klav no se desbloquea para un
    agente.
- **Tareas** (ADR 0021):
  - `request_task({task, reason, duration, access, wait_seconds?})`
    espera a la persona como las demás (60 s por defecto, 10 min como
    máximo).
  - Si nadie decide, devuelve `status: "pending"` con `pending_task_id`,
    `expires_at`, `approve_command` (`klav task approve <id>`), `wait_command`
    (`KLAV_HOME=… /ruta/klav agent task wait <id> --agent … --timeout 10m
    --json`, nunca con `KLAV_AGENT_KEY`) y `next`.
  - Aprobada, devuelve `task_id`, `status`, `expires_at`, `access` (`ref`,
    `permissions`, `domains`, `added_by_klav`) y `removed`.
  - `get_task(task_id, wait_seconds?)`, `list_tasks()` y
    `end_task(task_id, reason)` completan el ciclo. `get_task` y
    `list_tasks` no piden `reason`.
  - Una tarea que ofreció la persona (ADR 0022 §6) sale en `list_tasks` y
    `get_task` con `offered: true` y el `reason` de la persona: el título y
    el motivo son suyos, no del agente. En las tareas que pidió el agente,
    `offered` no aparece.
  - Con una sola tarea vigente que cubre la acción, el runtime pone el
    `task_id` solo. Con `task_id` explícito, solo cuenta esa tarea, y si no
    está vigente la herramienta falla antes de hacer nada.
- Devuelve acciones y metadatos. Los valores solo vuelven con `reveal`
  (denegado por defecto) y con `get_totp` sin `target` (un código de un solo
  uso, `ask` por defecto).
- Usa el `klav.toml` del directorio donde arranca: referencias cortas y
  solo ese proyecto.
- `search_items` acepta `limit` (50 por defecto, 200 como máximo) y añade
  `truncated` si hay más.
- `reason`, `domain` y el título de una tarea no admiten caracteres de
  control, de formato (*bidi*, de ancho cero) ni separadores de línea. Los
  errores que vienen del servidor llegan recortados y con el prefijo «the
  server says (unverified)». Una línea JSON-RPC de más de 4 MiB o que no es
  UTF-8 recibe `-32700`, y JSON que no es un objeto `-32600`; el servidor
  sigue vivo.
- `inject_file` no admite la semilla TOTP (como `run_with_secrets` y las
  plantillas: el código va por `get_totp`) ni una plantilla sin
  referencias; devuelve la ruta (nunca el tamaño) y, a veces, un `warning`
  (un texto). Puede decir que git confirmaría el archivo, y recomienda
  ignorar también `*.klav-tmp`; o nombrar temporales de ese archivo de
  una escritura interrumpida o todavía en curso (§7), y entonces la
  descripción de la herramienta le pide al agente que se lo diga a la
  persona y que no los borre él: pueden ser de una escritura que sigue en
  curso, y decidir es de la persona. Con los dos, van en ese orden: el de
  git termina con un punto, y un espacio lo separa del otro. Solo tras
  una escritura que salió bien: si falla, la respuesta es el error, sin
  cambios.
- `run_with_secrets` no avisa de los temporales que quedaron: su
  resultado es el de `klav agent run` (`code`, `stdout`, `stderr`,
  `redactions`, `timed_out`) y no tiene sitio para un aviso. `klav agent
  run` y los demás comandos sí avisan.
- `inject_file` y los `[files]` de `run_with_secrets` se escriben como los
  de `klav inject -o` (§7), con el escritor de `klav-sdk`
  (`klav_sdk::secret_file`): 0600 desde que se crean, nunca a medias con
  su nombre, y sin reemplazar un archivo que ya exista (salvo `overwrite`,
  que lo reemplaza de una vez).
- `inject_file` solo escribe dentro de ese directorio. Con `ttl_seconds`
  borra el archivo al vencer o, antes, cuando termina la sesión MCP (el
  cliente se cierra, `SIGTERM`, `SIGINT` o `SIGHUP`).
- `run_with_secrets` devuelve la salida redactada como `klav agent run`:
  cada valor, sus codificaciones habituales (base64, hex, URL, JSON) y sus
  trozos de 12 caracteres o más quedan como `[redacted by klav]`;
  `redactions` cuenta las marcas. No lo protege de un comando que cifre o
  transforme el valor a su manera (T20, riesgo residual 31).
- `fill_login`, `fill_card` y `get_totp` con `target: "extension"` escriben
  en la pestaña activa del navegador de la persona, que ve un aviso con el
  nombre del agente y su motivo. El `klavd` es el del `KLAV_HOME` del
  agente, o el de `KLAV_BROWSER_HOME` si el agente tiene su propio
  `KLAV_HOME` en la máquina de la persona.
- `fill_login` acepta `submit: true` para enviar el formulario después de
  rellenarlo (como `klav agent fill --submit`). La respuesta añade
  `submitted`, `navigated` y `url_after`; nunca los valores. Por defecto no
  envía nada, y las comprobaciones de dominio no cambian.
- **Adjuntos** (ADR 0016): con `inject`, un agente escribe un adjunto (el
  `.p8` de Apple, una llave) en un archivo con `inject_file` y `ref`, o en
  los `[files]` del `klav.toml` de `run_with_secrets`. Lo mismo con
  `klav agent inject -r` y `klav agent run`. Nunca vuelve al LLM: la
  herramienta devuelve la ruta, y si el comando imprime el archivo, la
  salida trae `[redacted by klav]`. En una plantilla no se puede, y en
  `env` solo si es texto (UTF-8 sin bytes nulos).
- Antes de pedir nada, `inject_file` y `run_with_secrets` comprueban que el
  archivo de destino no exista (salvo `overwrite`) y que su directorio sí:
  ese fallo no deja en la bitácora un acceso que no sirvió.
- Con `ask`, la herramienta espera a la persona hasta `wait_seconds` (por
  defecto 60 s, el `--wait` de `klav mcp`; 10 min como máximo). Si no
  decide, el resultado (con `isError`) es JSON con `status: "pending"`,
  `pending_approval_id`, `expires_at`, `approve_command` (lo que corre la
  persona), `wait_command` (lo que el agente deja corriendo en segundo
  plano: `KLAV_HOME=… /ruta/klav approval wait <id> --agent … --json`) y
  `next`, que dice qué hacer. Cuando `wait_command` sale con 0, el agente
  repite la herramienta con `approval_id`. Con un `approval_id` de otra
  acción, otro elemento u otro sitio, la herramienta falla sin hacer nada.
- Si la persona pausó al agente o a todos
  ([ADR 0033](decisiones/0033-agentes-desde-la-app-de-mac.md) §7.4), toda
  herramienta responde (con `isError`) JSON con `status: "paused"`, `scope`,
  `since`, `until` y `next`: que no reintente ni lo rodee, y que le diga a
  la persona que necesita Klav y le pida reanudarlo. `klav mcp` lo sabe en
  la llamada siguiente, porque cada una vuelve a preguntar al servidor.
- Si la persona pidió borrar la cuenta
  ([ADR 0037](decisiones/0037-borrar-la-cuenta.md) §3), toda herramienta
  responde (con `isError`) JSON con `status: "account_deleting"`,
  `delete_at` (milisegundos Unix; `null` cuando lo dice `klavd`, que no lo
  manda) y `next`: «The person asked Klav to delete this account. Stop and
  tell the person; do not retry.».
- Stdout lleva solo JSON-RPC; los mensajes van a stderr.
- La skill le da al agente las reglas: buscar primero, preferir acciones a
  valores, dar razones reales y pedir acceso en vez de rodear una
  denegación. Los detalles de cada herramienta van en su descripción y en
  el `next` de sus respuestas: un error de seguridad (código 3) dice que se
  detenga y avise, y una espera que sale con 4, que pregunte si espera más.
  Se instala con `klav client connect` o `klav skill install` (arriba), no
  copiándola a mano.

#### SDK

- **Rust:** `klav-sdk` (`Session::open`, `fill`, `run`, `inject_file`,
  `Session::totp`; `Session::claim_approval` para reintentar con una
  aprobación y `Agent::wait_decision` para esperarla;
  `Session::request_task`, `Agent::wait_task`, `Agent::end_task` y
  `Session::use_task` para las tareas; `Session::change_password_url`,
  `Session::rotate_password`, `Session::rotate_confirm` y
  `Session::rotate_cancel` para el cambio asistido, en `klav_sdk::rotate`;
  `Session::passkey_sign_in` para las passkeys de la persona, en
  `klav_sdk::passkeys`;
  `Session::create_item_generated` con un `GenerateSpec` para crear con una
  contraseña generada).
- El SDK de Node todavía no tiene el cambio asistido ni `generate`: hoy se
  usan por MCP o desde Rust.
- **Node:** `@klav/sdk` en `packages/sdk`, una envoltura de este binario
  (`fill(page, ref, { cdp, reason, submit? })` con una página de
  Playwright, que devuelve el reporte de `fill`; `run`,
  `inject`, `totp`, `registerSession`; la opción `approvalId` y
  `waitApproval(id)`; `requestTask(spec, { wait })`, `waitTask`, `getTask`
  y `endTask` para las tareas). Ejemplo en `examples/playwright`.

### En el dispositivo de la persona

> Los pasos para quien usa Klav están en la página pública [`pause-and-revoke.mdx`](../apps/docs/src/content/docs/agents/pause-and-revoke.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav agent list [--json]
klav agent approve <nombre|id> --project Bóveda/proyecto … [--vault Bóveda …] \
    [--allow PERMISOS] [--ask PERMISOS] [--deny PERMISOS] \
    [--fill-domain "*.example.com" …] [--env NOMBRE=allow|ask|deny …] \
    [--hours "mon-fri 09:00-18:00 -06:00" …] \
    [--expires 30d] [--policy-file politica.json] [--words "seis palabras …"] \
    [--rotate-removed] [--yes]
klav agent deny <nombre|id>
klav agent show <nombre|id> [--json]
klav agent revoke <nombre|id> [--rotate] [--yes] [--json]
klav agent pause [<nombre|id> | --all] [--for 1h] [--json]
klav agent resume [<nombre|id> | --all] [--json]
```

- **`list`** tiene la columna `PAUSED`: vacía, `yes` (hasta que la
  reanudes) o `until <fecha>` (`paused` en `--json`).

- `approve` muestra las 6 palabras y pregunta si coinciden con las del agente.
  En scripts, pásalas con `--words`; si no coinciden, `klav` sale con 3.
- **Presencia:** con `klavd`, aprobar pide Touch ID, o la contraseña si no
  hay Touch ID. Sin daemon, la contraseña del desbloqueo cuenta como
  presencia.
- **Qué recibe el agente:**
  - las llaves de los proyectos de `--project`;
  - las de todos los proyectos actuales de cada `--vault`.

  Volver a aprobar reemplaza el grant (versión + 1).
- **Un agente activo** ([ADR 0033](decisiones/0033-agentes-desde-la-app-de-mac.md),
  enmienda del 2026-11-10, F4): `approve` no pide las palabras otra vez
  (la identidad del agente va dentro de la firma de su grant) y enseña solo
  las diferencias con el grant vigente, una por línea (`+ Personal/Release`,
  `reveal: deny (default) -> ask`), marcando las que amplían (`[widens]`).
  Después pregunta «Sign it? [y/N]» (salvo `--yes` o sin terminal).
  - **Presencia:** solo si el cambio amplía (más proyectos, un permiso más
    abierto, más sitios u horas, caducidad más tarde); reducir no la pide.
    Con `klavd`, lo decide `klavd` con el grant que verificó, y el diálogo
    de Touch ID nombra lo que amplía.
  - **Si el grant cambió entre la hoja y la firma** (otro dispositivo, la
    app), no firma nada y sale con 3: vuelve a correrlo.
  - **`--rotate-removed`** cambia además la llave de cada proyecto que le
    quitas y da un grant nuevo a los demás agentes que lo tienen. Sin ella,
    el agente conserva la llave de esos proyectos: con un servidor honrado
    ya no puede usarla.
    El cambio queda apuntado en `revocations.bin` antes de firmar: si se
    corta, `klav agent show` dice lo que falta y `klavd` lo termina al
    desbloquear.
  - Un cambio que no cambia nada sale con error: el grant vigente ya es ese.
  - El grant del proxy no se cambia aquí: `klav proxy …`.
- **Política** (diseño §5.2). Sin opciones se aplican los valores por defecto:
  - `list`, `fill`, `inject` y `create`: `allow`;
  - `totp` y `update`: `ask`;
  - `reveal` y `delete`: `deny`.

  Las opciones añaden reglas:
  - `--allow`, `--ask` y `--deny` reciben listas separadas por comas, por
    ejemplo `--allow reveal --deny delete`;
  - `--fill-domain` limita `fill` a esos dominios;
  - `--env NOMBRE=allow|ask|deny` ([ADR 0032](decisiones/0032-entornos-por-repositorio.md)
    §4.3) da una regla de `inject` por entorno de los proyectos que
    compartes, por el ID del entorno (`BÓVEDA/PROYECTO/NOMBRE=…` si dos
    proyectos lo tienen). `klav agent grant` es el mismo comando:
    - si `inject` no tenía reglas, su valor por defecto entra antes como
      regla explícita sin alcance, para que lo demás no pase a `deny`
      (ADR 0006 §2);
    - un entorno protegido nunca va en `allow`: `klav` lo rechaza, y
      `=ask` es «preguntar cada vez» (`ask once`). Klav añade por su cuenta
      `ask once` para él y los elementos a los que apunta;
    - un entorno no puede quedar más abierto que una regla general que
      también lo cubre (gana la más restrictiva, ADR 0006 §3): con `--ask
      inject` y `--env development=allow`, `klav` sale con 2, nombra esa
      regla y propone acotarla por entorno;
    - `--env NOMBRE=allow` avisa si el entorno apunta a elementos que el
      grant deja en `deny`, fuera de sus proyectos, o protegidos: esa
      ejecución fallaría o pediría aprobación.
  - `--hours` limita todo a una ventana semanal con desplazamiento UTC
    explícito (actualízalo con el horario de verano);
  - `--expires` pone caducidad al grant entero;
  - `--policy-file` parte de una política JSON con la forma de §5.2 del
    diseño. Ahí las bóvedas y los proyectos pueden ir por nombre: `klav` los
    cambia por IDs antes de firmar.
- `klav status` muestra las palabras de la cuenta (`words:`).
- **`show`** muestra el agente, su grant y el reporte **"qué vio"**:
  - los proyectos cuyas llaves recibió (pudo leer títulos, usuarios y URLs
    de sus elementos);
  - según la bitácora, cada elemento que usó, con qué permisos, cuántas
    veces y cuándo, y si obtuvo un secreto (`fill`, `inject`, `totp`,
    `reveal`);
  - `SECRET` es `yes` si recibió *details* con algún valor (un campo
    secreto o notas) o un adjunto (`yes (file)`; `attachments` en
    `--json`). Un elemento cuyo único secreto es un adjunto que nunca se
    entregó sale `no`. Si este dispositivo no puede abrir el elemento, sale
    `yes`;
  - la columna `ID` (los primeros 8 caracteres; el completo en `--json`,
    `item_id`) distingue dos elementos con el mismo título. Un elemento en
    la papelera sale con `(in trash)` y uno que ya no existe en este
    dispositivo con `(deleted)` (`trashed` y `deleted` en `--json`);
  - los intentos denegados;
  - si la bitácora no cuadra con la copia de este dispositivo (un servidor
    restaurado de una copia de seguridad o que la reescribió), salen los
    proyectos del grant, ningún elemento y un aviso que dice por qué
    (`log_warning` en `--json`), y sale con 0;
  - de un agente revocado cuyo cambio de llaves no terminó, lo que falta:
    cuántos proyectos van rotados de cuántos, cuáles faltan, qué agentes
    esperan su grant nuevo y el último error (solo en texto, no en
    `--json`). `klavd` lo termina solo al desbloquear. La pista para
    terminarlo a mano lleva `--rotate` solo si la persona pidió cambiar las
    llaves de los proyectos. Si no lo pidió, solo faltan los elementos
    compartidos uno por uno, y la pista es `klav agent revoke <agente>` sin
    `--rotate`, que nunca cambia una llave que la persona quiso conservar
    (P7 de la enmienda del 2026-11-10 al ADR 0033). Con un `klavd` que no
    dice qué eligió la persona, un registro sin proyectos cuenta como «no lo
    pidió». La pista dice «you chose not to change its projects' keys» solo
    cuando la persona lo rechazó. Un proxy de credenciales revocado con
    `--rotate` no tiene proyectos: si solo le faltan elementos, su pista es
    `klav agent revoke <agente>` sin esa frase; si aún falta leer la
    bitácora, cuenta como pedido y la pista lleva `--rotate`. Si con los
    elementos ya no queda nada (ningún proyecto por rotar ni que pueda
    volver, como uno de una bóveda que dejó de aparecer; ningún grant por
    emitir otra vez; los proyectos conocidos y la bitácora leída), esa
    corrida cierra el cambio de llaves y el registro desaparece; si la
    persona lo había pedido, el reporte dice una vez qué proyectos no
    cambiaron de llave porque se borraron. Si queda algo, el registro sigue
    ahí, y esa corrida nunca rota un proyecto.
- **`revoke`** pregunta antes de seguir (salvo `--yes` o sin terminal),
  revoca al agente y muestra el mismo reporte. El servidor rechaza su
  siguiente petición. Para volver tendría que registrarse de nuevo. No pide
  Touch ID: quitar acceso no debe costar. **No depende de la bitácora:**
  primero revoca y guarda la revocación en la caché, y después arma el
  reporte. Si la bitácora no se puede leer, el reporte sale sin elementos
  y con el aviso, y la revocación (y la rotación de `--rotate`, cuyos
  proyectos salen del grant) sigue adelante. Sobre un agente ya revocado
  con llaves de elementos pendientes en `revocations.bin`, no vuelve a
  revocarlo (el servidor contestaría `409`): cambia esas llaves, aunque solo
  este registro las nombre (el grant lo firmó otro dispositivo, o salieron
  de la bitácora). Sin `--rotate`, ninguna llave de proyecto cambia.
- **`--rotate`** además rota la llave de cada proyecto del agente y vuelve a
  emitir, con las llaves nuevas, el grant de los demás agentes activos que
  compartían esos proyectos (misma política, versión + 1). Sirve también
  después de una revocación sin `--rotate`.
  - **A quién re-otorga:** el reporte lo nombra («New grants with the new
    keys for: …»; `regranted` en `--json`). Nunca al agente revocado ni a
    otro que se haya revocado desde este dispositivo, aunque el servidor lo
    reporte activo: la lista va en la caché cifrada.
  - **Si falta una llave:** si el servidor no lista la llave de algún
    elemento del proyecto que este dispositivo tiene (o la cambia), ese
    proyecto no se rota.
  - **Un proyecto cada vez:** rota uno, da a los demás agentes su grant
    nuevo para ese proyecto, lo apunta en `revocations.bin` y sigue con el
    siguiente. Con `klavd`, suelta la cuenta entre proyecto y proyecto, y
    `klav status --json` da el avance (`klavd.revocations`).
  - **Si se corta a mitad:** el reporte dice qué se rotó, qué falló
    (`failed`) y qué falta (`pending`), y el comando sale con error. Volver a
    correr `klav agent revoke <agente> --rotate` termina el trabajo sin rotar
    otra vez lo ya rotado (`already_rotated`). Con `klavd`, lo cortado por
    un bloqueo se termina solo al desbloquear.
  - **Costo:** se vuelven a envolver la llave de cada elemento y la de cada
    versión guardada (hasta 51 por elemento) en una sola transacción; es
    trabajo de cliente y de base de datos proporcional a eso.
  - **Límite:** las llaves de los elementos no cambian. La rotación protege
    lo que se cree después. Lo que el agente ya descifró, y lo que podría
    abrir si además el servidor le pasa copias, sigue expuesto: cambia en
    origen (el sitio, la API) los secretos que el reporte marca.
- **`pause`** ([ADR 0033](decisiones/0033-agentes-desde-la-app-de-mac.md)
  §7) detiene a todos los agentes (`--all`) o a uno: el servidor rechaza
  todo lo que piden, estén en la máquina que estén, hasta que los reanudes
  o hasta que pase `--for`. El grant, las llaves, las solicitudes y las
  tareas no cambian (el reloj de una tarea sigue corriendo).
  - **No pide Touch ID:** pausar no debe costar nada. La decisión va
    firmada por la cuenta y queda en la bitácora (`agents.paused`).
  - **Con `klavd`, `--all` funciona bloqueado:** se aplica al momento en
    `klavd` (rellenos por la extensión, cambio asistido, passkeys de
    agentes) y el desbloqueo siguiente la firma y la manda al servidor.
    Hasta entonces, `klav agent pause` y `klav status` dicen «on this
    computer only» y un agente que no pasa por `klavd` sigue funcionando. Sin red, o con un error del
    servidor que se arregla con tiempo, pasa lo mismo, y `klavd` reintenta
    ([`klavd.md`](klavd.md) §3). La pausa local sobrevive a un reinicio de
    `klavd`, y el desbloqueo que la firma avisa de que se decidió
    bloqueada y desde dónde. Pausar a un agente necesita la cuenta
    desbloqueada.
  - **Si otro dispositivo decidió después** (con el reloj adelantado), la
    pausa se vuelve a firmar justo después de esa decisión, si cae dentro
    de los ±5 minutos del servidor. Si no cae, el error dice desde cuándo
    volver a decidir. Un servidor anterior a las pausas da «this server
    does not support pausing agents: update it»; con `klavd`, la pausa de
    todos se queda en este Mac en vez de soltarse, y `klav agent pause` lo
    dice («on this computer only… Update the server»).
  - **Sin daemon** hay que desbloquear con la contraseña maestra: es lo que
    firma la pausa.
  - Lo que ya está corriendo no se detiene: un `run` lanzado, un archivo
    inyectado hasta su TTL o lo que el agente ya leyó. Para una llave
    robada, revoca y rota.
- **`resume`** pide Touch ID con `klavd`, o la contraseña maestra donde no
  lo hay (sin daemon, la del desbloqueo). Reanudar a todos no levanta las
  pausas de un agente: `resume` avisa de las que siguen («still paused»).
- `klav status` lista las pausas en vigor que conoce `klavd` (`agents:`).

### Aprobaciones (`ask`)

> Los pasos para quien usa Klav están en la página pública [`approvals-and-tasks.mdx`](../apps/docs/src/content/docs/agents/approvals-and-tasks.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav approval list [--all] [--json]
klav approval show <id> [--json]
klav approval approve <id> [--for 15m | --add-to-task] [-y]
klav approval deny <id>
klav approval wait <id> [--timeout 10m] [--agent NOMBRE] [--json]   # el agente
```

- `list` muestra, para cada solicitud: el agente, qué quiere hacer, sobre qué
  elemento, el sitio que dice el agente (`SITE (AGENT SAYS)`) y el
  **motivo** que dio.
- El ID admite sus primeros caracteres (6 o más).
- **`show`** imprime la tarjeta de una solicitud pendiente sin decidir
  nada.
- **Una llamada a una herramienta MCP** (ADR 0049 §5.4): `list` dice
  `proxy maple · delete_dashboard` en `WANTS` y el llamador en `AGENT`
  (`klav-proxy (for claude-code)`, o `for sandbox <id>`). La tarjeta añade
  el llamador («according to the proxy»), el perfil, la herramienta
  («according to the MCP server») y que los argumentos no se muestran:
  **aprobar una vez ata estos argumentos exactos** (su resumen), y `--for`
  deja correr esta herramienta con cualquier argumento hasta que venza; la
  pregunta `[y/N]` lo repite. El perfil sale del grant del proxy (`MCP` si
  este dispositivo no lo sabe).
- **Tarjeta de seguridad:** si la herramienta o el llamador rompen su
  gramática (algo que el servidor debió rechazar, T260), `list` dice
  `security` en `STATUS` y la tarjeta solo muestra un texto fijo, nunca el
  campo: `approve` y `deny` no firman nada y salen con 3.
- **`approve` y `deny` imprimen la solicitud entera antes de firmar:** el
  agente (nombre y comienzo de su ID), el permiso, el elemento, el sitio y el
  motivo (estos dos marcados «according to the agent», porque los escribe
  él), la tarea vigente si queda fuera de ella y hasta cuándo se puede
  decidir. En una terminal, `approve` pregunta `[y/N]` antes de firmar; `-y`
  (o no tener terminal) se lo salta.
- **Se firma lo que se mostró** (ADR 0030 §5): el cliente calcula el SHA-256
  de los bytes de la solicitud que imprimió y, si al decidir el servidor
  devuelve otros, no firma nada («the request changed while you were looking
  at it»). Vale también para `--add-to-task`, `deny` y las tareas.
- `approve` sin `--for` aprueba **una vez**. Con `--for` (24 h como máximo),
  el agente puede repetir la misma acción sobre el mismo elemento sin
  preguntar hasta que venza.
- **Lo que siempre pregunta** ([ADR 0032](decisiones/0032-entornos-por-repositorio.md)
  §3.1 y §4.2): un entorno protegido, un elemento que hereda su protección,
  o una solicitud con varios elementos. La tarjeta dice «Always asks for
  approval», y `--for` y `--add-to-task` salen con 2, aunque el servidor no
  lo diga. `klav task show` lo marca igual en cada permiso: `[-] …: Always
  asks for approval`, sin marcar y sin poder marcarse.
- **La aprobación de un entorno** nombra el entorno en `on:` y cada
  elemento protegido que cubre en una línea `and:` (`items` en `--json`):
  vale un uso de cada uno, dentro de esa llamada. La tarjeta comprueba que
  esos elementos sean referencias de tu última versión de ese entorno
  (la que guarda este dispositivo) y avisa (`WARNING:`, `items_warning`)
  de los que no lo son, y de qué otro entorno los protege, o de que este
  dispositivo no lo puede comprobar. `klav log verify` comprueba que cada
  acceso bajo esa aprobación sea del mismo agente, con el mismo permiso,
  sobre el entorno o un elemento de su lista.
- Una aprobación de un solo uso se gasta en la primera petición del agente
  que coincida (mismo permiso, elemento y sitio) y vale 10 minutos desde que
  la apruebas.
- Si el agente repite una petición pendiente, ves una sola solicitud.
- Si el agente tiene una tarea vigente (ADR 0021) y la petición queda fuera,
  `list` lo dice en la columna `TASK` («outside «…»»). **`--add-to-task`**
  la añade a la tarea: firma una revisión nueva con ese elemento, permiso y
  sitio y el **mismo** vencimiento, y aprueba la petición una vez, ligada a
  la tarea: al terminar la tarea deja de servir aunque el agente no la haya
  usado. Solo para
  `fill`, `totp`, `inject` y `update` sobre un elemento (`fill`, si el sitio
  coincide); `reveal` y `delete` solo se aprueban una vez o se deniegan.
- Con `klavd`, aprobar pide Touch ID o la contraseña. Denegar no pide nada.
- La decisión va firmada por la cuenta: el servidor no puede aprobar por ti.
- **`wait`** es del lado del agente: se autentica con su llave (`--agent` o
  `KLAV_AGENT`, como `klav mcp`) y no abre tu bóveda. Espera hasta que
  decidas, la solicitud venza o pase `--timeout`, preguntando al servidor
  con *long-poll* (una petición cada 30 s como mucho). Con `--json` imprime
  una línea:
  `{"approval_id":"…","status":"approved","lease_until":0,"used":false,"expires_at":…}`.
  Sale con 0 (aprobada), 4 (sigue pendiente), 5 (denegada) o 6 (vencida).
  Un agente lo deja corriendo en segundo plano para despertar cuando
  decidas, sin que tengas que avisarle.
- El `wait_command` que dan `klav mcp` y `klav agent …` nunca incluye la
  llave del agente. Si la llave solo está en `KLAV_AGENT_KEY` (sin llavero
  ni archivo), la terminal donde el agente corre `klav approval wait`
  también necesita esa variable (ADR 0015).

### Tareas

> Los pasos para quien usa Klav están en la página pública [`approvals-and-tasks.mdx`](../apps/docs/src/content/docs/agents/approvals-and-tasks.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav task list [--all] [--json]                 # o `klav task ls`
klav task show <id> [--json]
klav task approve <id> [--without REF[:permiso]]… [--for 1h] [-y] [--json]
klav task deny <id>
klav task end <id>
```

- `list` muestra las tareas pendientes y las vigentes. Con `--all` muestra
  también las denegadas, vencidas y terminadas.
- El ID admite sus primeros caracteres (6 o más).
- **`show` muestra la tarjeta que completa tu dispositivo**, no lo que dice
  el agente:
  - la tarea y el motivo, marcados «according to the agent» (o «yours: you
    offered it» en una tarea que ofreciste tú, ADR 0022 §6);
  - la duración y cuándo vencería;
  - por elemento, el título, el usuario y los hosts, sacados de tu bóveda.
- **Las reglas de la tarjeta:**
  - si el agente dio un `domain` que no coincide con ninguna URL del
    elemento, la fila sale «the site does not match the item», desmarcada
    y sin poder aprobarse;
  - `fill`, `passkey` y `rotate` sobre un elemento sin URL salen «no site»
    y no se aprueban. En una tarjeta o una identidad, `fill` va atado al
    `domain` que pidió el agente, marcado «according to the agent»;
  - a un `fill` sobre un login con TOTP, Klav le añade `totp` marcado
    «added by Klav», con el aviso de que el 2FA deja de ser un segundo
    factor para ese agente;
  - lo que tu política niega con una regla `deny` sale como
    «your policy denies it» y no se aprueba;
  - un elemento que ya no está en tu bóveda, o que quedó fuera del grant del
    agente, no se puede aprobar.
- **`approve`** imprime la tarjeta (sin `--json`), pregunta `[y/N]` en una
  terminal (`-y` se lo salta) y firma lo que queda marcado. Si la solicitud
  que devuelve el servidor al firmar no es la de la tarjeta (SHA-256), no
  firma nada (ADR 0030 §5):
  - `--without` quita un elemento (`REF`) o uno de sus permisos
    (`REF:totp`). `REF` es la referencia `klav://`, el título o el ID del
    elemento. Se puede repetir.
  - `--for` acorta la tarea (5 min como mínimo). Nunca la alarga más allá de
    lo pedido.
  - Con `klavd`, aprobar pide Touch ID o la contraseña. Denegar y terminar no
    piden nada.
- **La decisión va firmada por tu cuenta** (especificación §13.8): el
  servidor no puede ampliarla, y el agente la verifica antes de usarla.
- **`end`** termina una tarea vigente al momento. Va firmado
  (`klav/v1/sig/task-end`).
- **Vigencia:** una tarea vale hasta su vencimiento, hasta que la termines o
  hasta que revoques al agente. Un grant nuevo no la termina, pero cada uso
  vuelve a evaluar el grant actual.
- **Límites:** cada agente tiene como mucho 5 tareas pendientes y 10
  vigentes, y una solicitud vence si nadie la decide en 10 minutos.

### Bitácora

> Los pasos para quien usa Klav están en la página pública [`activity-log.mdx`](../apps/docs/src/content/docs/agents/activity-log.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

```sh
klav log [--item ELEMENTO] [--agent NOMBRE] [--vault BÓVEDA] \
    [--since 24h|2026-11-01|2026-11-01T09:00] [--until …] [--alerts] \
    [--permission PERMISO]… [--outcome allow|ask|deny|approve]… \
    [--text TEXTO] [-n 50] [--json | --csv]
klav log --task <id> [--json]
klav log verify [--json]
klav log reset [--yes]
```

- **`--task`** resume una tarea (el ID admite sus primeros caracteres):
  - la tarea, el motivo y su estado;
  - quién la pidió y quién la aprobó, y cuándo;
  - cada uso: hora, elemento, permiso, host, motivo y resultado; los pasos
    de un cambio asistido salen como «password change started»,
    «… confirmed» o «… cancelled» (ADR 0022 §5);
  - lo que el agente pidió aparte mientras corría («Outside the task»), con
    su `approval_id`;
  - en una tarea con `rotate`, cada sitio (`Passwords: N changed, N
    pending, N failed`): **changed** si el agente confirmó la nueva,
    **failed** si la canceló o Klav rechazó el intento, y **pending** si no
    empezó o sigue abierto («in progress»). Con `--json`, en `sites`;
  - cómo terminó: la persona, el agente, el vencimiento o una revocación;
  - si la bitácora no cuadra con la copia de este dispositivo, solo la
    tarjeta que lista el servidor, sin eventos ni sitios, con un aviso
    (`log_warning` en `--json`).

- `log` muestra, del más nuevo al más viejo: cuándo (UTC), quién (`you` o el
  nombre del agente), qué hizo y con qué resultado (`allow`, `ask`, `deny`,
  `approve`), sobre qué elemento, el motivo y las alertas. Con `--json`,
  `by_agent` dice si lo escribió un agente: es lo que distingue a la
  persona de un agente que se llame `you`, que la tabla muestra como
  `you (agent 1a2b3c4d)`. El servidor ya no deja registrar un agente con
  ese nombre; los que ya lo tenían lo conservan.
- **Llamadas MCP** (ADR 0049 §6): un acceso del proxy a un perfil MCP se
  lee `claude-code → maple:query_logs (via proxy, according to the proxy)
  → allow`: el cliente local o el sandbox (`sandbox 1a2b3c4d`) que firmó el
  proxy, el perfil y la herramienta. Los mensajes de la sesión (conectarse,
  listar herramientas) salen como `maple (MCP session: connect, list
  tools)` y los seguidos del mismo llamador se pliegan en una fila (`×N`):
  la bitácora no distingue `initialize` de `tools/list`. El perfil sale del
  grant del proxy; sin él, `mcp:herramienta`. Con `--json`, `mcp_tool`,
  `local_client` y `sandbox`.
- **Para quién fue un grant:** un `agent.granted` de la persona dice a qué
  agente: `agent.granted for "release-bot" (1a2b3c4d)`, con el nombre que
  lista el servidor, escapado, y el comienzo del ID; si el servidor ya no
  lo lista, `agent.granted for agent 1a2b3c4d`. Con `--json`, cada evento
  de un agente que el servidor lista lleva su nombre en `agent_name` (un
  `klavd` anterior no lo da).
- **Alertas:**
  - `first_use`: el primer uso de los secretos de ese elemento por ese
    agente;
  - `burst`: 20 o más accesos de un agente en un minuto;
  - `denied`: la política lo denegó.
- **Filtros:**
  - `--item` acepta una referencia, un ID o un título;
  - `--since` y `--until` aceptan una duración hacia atrás (`24h`, `7d`), una
    fecha o una fecha y hora en UTC. En `--until`, una fecha sola llega al
    final de ese día;
  - `--permission` (`list`, `fill`, `inject`, `totp`, `reveal`, `create`,
    `update`, `delete`, `passkey`, `rotate`) y `--outcome` (`allow`, `ask`
    y `deny` de la política, `approve` de la persona) se pueden repetir: un
    evento pasa si tiene uno de los que se dieron. Un permiso desconocido
    es un error de uso (ADR 0033 §8.1);
  - `--text` busca, sin distinguir mayúsculas, en el elemento (su
    referencia, con el título que solo conoce este dispositivo), el nombre
    del agente, el motivo y el sitio. No busca en el `you` de la persona:
    `--text you` no encuentra sus eventos.

  Contra un `klavd` anterior, que no conoce los filtros nuevos, `klav` los
  vuelve a aplicar a lo que responde.
- **Sin verificar todavía:** la tabla termina con «This device has not
  verified the log yet» o «Verified up to event N: run `klav log verify`
  for the M after it» cuando hay eventos descargados después del último
  que verificó este dispositivo. Con `--json`, cada evento lleva
  `verified`.
- **Solo lo nuevo:** `klav log` descarga solo los eventos que este
  dispositivo no tiene todavía; la copia vive sellada en
  `$KLAV_HOME/audit-chain.bin` y se borra con `klav logout` y con `klav log
  reset`. Si el servidor la acorta o cambia un evento que ya mandó, `klav
  log` sale con 3 y dice cuál ([`klavd.md`](klavd.md), «La bitácora en
  caché»).
- **`reset`** olvida la copia de la bitácora de este dispositivo
  (`audit-chain.bin`, también la que `klavd` tiene en memoria) y la última
  cabeza que verificó (`audit-head.json`). Es para un servidor restaurado
  de una copia de seguridad **en la que confías**, y es una decisión de
  confianza: desde ahí este dispositivo acepta como buena la cadena que el
  servidor tiene ahora, aunque sea más corta o distinta de la que ya había
  visto. La copia y la cabeza eran justo lo que lo delataba. Si no sabes
  por qué no cuadra, revisa el servidor antes.
  - Pregunta antes de seguir. Sin terminal, pide `--yes`.
  - No usa la red ni la contraseña: solo borra dos archivos de este
    `KLAV_HOME`. Con `klavd` corriendo, se lo pide a él (operación
    `audit_reset`, también bloqueado), que olvida además su copia en
    memoria. Un `klavd` anterior a este comando y desbloqueado la seguiría
    usando: `klav` pide bloquearlo (`klav lock`) primero.
  - La extensión no puede pedirlo, y no hay herramienta de `klav mcp` ni
    función del SDK que lo hagan. Un programa que corre como tu usuario en
    tu `KLAV_HOME` podría borrar esos archivos igual; eso queda fuera del
    modelo, como en `klav sync --reset-cache`.
  - Después, `klav log` descarga la cadena entera otra vez y `klav log
    verify` empieza de cero, con el aviso de la primera verificación. Sale
    con 0 aunque no hubiera nada que olvidar.
- `--json` y `--csv` exportan todos los eventos que pasan los filtros. En el
  CSV, una celda que empieza con `=`, `+`, `-` o `@` va precedida de `'`, para
  que una hoja de cálculo no ejecute un motivo escrito por un agente.
- **`verify`** (especificación §13.7, ADR 0030 §4):
  - recalcula la cadena de hashes, y exige que el servidor la entregue en
    páginas seguidas, sin huecos;
  - decide qué prueba necesita cada evento por su acción, no por quién dice
    el servidor que actuó. Una acción desconocida es un error;
  - comprueba la firma de cada petición de agente, que el método y la ruta
    firmados sean los de la acción, y que el elemento, el permiso, el motivo
    y el host del evento sean los que firmó. Un acceso o una solicitud de
    tarea sin el cuerpo firmado es un error;
  - rechaza una petición firmada que respalde dos eventos, o que se firmó a
    más de 5 minutos de cuando se registró;
  - usa la llave de un agente solo si un grant de la cadena, firmado por la
    cuenta, la avala;
  - comprueba las firmas de la cuenta en grants y decisiones (y que lo que
    dice el evento salga de lo firmado), y las cabezas firmadas por tus
    dispositivos;
  - compara con la última cabeza que firmó este dispositivo para esta cuenta
    (`$KLAV_HOME/audit-head.json`);
  - exige que la cadena conserve la copia de este dispositivo: ni más corta
    ni con un evento distinto de los que ya había mandado.

  Si todo cuadra, firma la cabeza nueva y la sube; si la bitácora no creció
  desde la última verificación, no vuelve a firmar la misma cabeza. Si algo se alteró, se
  borró o se reordenó, sale con 3 y dice desde dónde.

  Algunos casos no son una manipulación, pero quedan sin comprobar. En esos
  casos sale con 0 y muestra un aviso:
  - un agente que el servidor ya no lista (su firma no se puede comprobar);
  - un uso permitido de un agente (`agent.access`, una escritura o un paso
    suyo de un cambio de contraseña, `rotate.*`) entre una
    pausa firmada de su alcance y su reanudación o su fin
    ([ADR 0033](decisiones/0033-agentes-desde-la-app-de-mac.md) §7.6): o
    una petición en vuelo, o un servidor que ignoró la pausa;
  - un evento que firmó un agente después del `agent.revoked` que la cuenta
    firmó para ese agente, con cualquier resultado («acted after its
    revocation»). «Después» es el lugar en la cadena, no la hora que
    escribió el servidor. El servidor actual mira el estado del agente con
    el cerrojo que toma la revocación al registrar el evento, así que no
    registra ninguno, pero uno anterior (o una instancia anterior durante un
    despliegue) podía registrar una petición que ya estaba en vuelo. Por eso
    es un aviso, no un fallo: nunca cambia el código de salida;
  - la primera verificación en este dispositivo, sin cabeza fijada (lo
    anterior solo se contrasta con las cabezas de tus otros dispositivos);
  - una cabeza fijada que es de otra cuenta, o que no se puede leer.

  Con `--json`, los avisos van en `warnings`. Los de los dos últimos casos
  van además como código en `unpinned` (`missing`, `other_account` o
  `unreadable`), para que las apps los digan en su idioma.

### Códigos de salida de los comandos de agente

> Los pasos para quien usa Klav están en la página pública [`how-agents-work.mdx`](../apps/docs/src/content/docs/agents/how-agents-work.mdx) (en `apps/docs/src/content/docs/agents/`); un cambio en esos pasos va primero allí.

| Código | Significado |
|---|---|
| 3 | Comprobación de seguridad fallida (palabras distintas, identidad de la cuenta cambiada, grant o bitácora alterados) |
| 4 | Espera la aprobación de la persona |
| 5 | La política o la persona lo denegó |
| 6 | La solicitud venció sin decisión (`approval wait`, `agent task wait`), o la tarea terminó por tiempo o la cerró el agente |
| 7 | La persona pausó al agente o a todos (`agents_paused`): detente y avísale. También en `approval wait` y `agent task wait`, en la consulta siguiente a la pausa |
| 8 | La persona pidió borrar la cuenta (`account_deleting`): detente y avísale; no reintentes. Pasada la fecha, el servidor ya no conoce al agente |


## 10. `klav-proxy`, el proxy de credenciales

Binario aparte que pone en peticiones HTTP las credenciales que la persona
le concede, sin devolverlas a quien llama (ADR
[0036](decisiones/0036-sandboxes-de-agentes.md)). Despliegue, la llave, la
red y lo que todavía no hace: [self-hosting.md](self-hosting.md) §9.

```sh
klav-proxy [--home DIR] [--name klav-proxy] init --email ana@example.com \
    [--server URL] [--key-store file|keychain] [--key-file PATH] [--json]
klav-proxy [--home DIR] [--name klav-proxy] serve [--port 8790] \
    [--max-body BYTES] [--timeout SEGUNDOS] [--channel HOST:PUERTO] \
    [--no-local-calls] [--control-socket RUTA | --no-control-socket] \
    [--if-registered]
klav-proxy [--home DIR] [--name klav-proxy] status [--json]
```

El binario `klav` también es `klav-proxy` cuando arranca con ese nombre
(su `argv[0]`): así lo corre el *LaunchAgent* de la app de Mac, sin un
ayudante propio (ADR 0036, capa 11; [macos.md](macos.md) §11). Los mismos
comandos y opciones.

- `init` registra el proxy como agente e imprime las **6 palabras**. La
  persona lo nombra proxy de la cuenta con `klav proxy use own` y lo
  aprueba al concederle su primera credencial con `klav proxy grant`
  (§10.1), nunca con `klav agent approve` ni desde la lista de solicitudes
  de la app, que le darían proyectos enteros. La llave
  va en un archivo 0600 (`<home>/agents/<nombre>.key`) o en el llavero del
  Mac.
- `serve` sirve el modo (a) en `127.0.0.1:PUERTO`:
  `http://127.0.0.1:8790/<perfil>/<ruta>`. La dirección es siempre
  *loopback*. `--channel` escucha además a los sandboxes, y
  `--no-local-calls` rechaza toda llamada a un perfil en `127.0.0.1` y deja
  la API firmada del emisor ([self-hosting.md](self-hosting.md) §9.2).
  Con el puerto ocupado, el error dice quién lo tiene: otro `klav-proxy`,
  un `klav-forward` (su puerto por defecto también es 8790), otro programa
  o no se sabe, y que `--port` mueve este (o `klav-forward up --port`, el
  reenviador). El puerto por defecto no cambia: un `serve` que ya escucha
  en 8790 sigue igual.
- **El *socket* local** (ADR 0036 E3.5, capa 11): `serve` escucha además
  en `<home>/agents/<nombre>.sock`, modo 0600, solo para un proceso del
  mismo uid, con dos operaciones en líneas JSON (`sandboxes` y `revoke`,
  [api.md](api.md) §8.14): la lista en vivo y revocar sin firma. Si no
  puede abrir esa ruta (más de 103 bytes en macOS, otro `klav-proxy` que
  ya contesta en ella), sirve sin él y lo dice en el log. `--control-socket
  RUTA` lo pone en otra ruta (y entonces no poder abrirla para `serve`), y
  `--no-control-socket` lo quita.
- `--if-registered` sale con `0` sin servir si no hay un proxy registrado
  con ese nombre en `--home`, o si otro `klav-proxy` ya contesta en su
  *socket* local. Es lo que usa el *LaunchAgent* de la app de Mac, para que
  `launchd` no lo vuelva a arrancar en bucle.
- `status` muestra el estado del proxy, sus 6 palabras y sus perfiles
  (nombre, upstream, cabecera y ritmo). Nunca un valor.
- Los tres se niegan a seguir con `KLAV_AGENT_KEY`, `SSL_CERT_FILE` o
  `SSL_CERT_DIR` puestas (el mensaje nombra la variable, nunca su valor), y
  `serve` y `status` con un archivo de llave más abierto que 0600, de otro
  usuario o en un directorio en el que otros pueden escribir.
- `--home` vale por defecto lo que `KLAV_HOME` (en la imagen, `/data`).
- Logs de `serve`: `KLAV_LOG` (filtro, `info` por defecto) y
  `KLAV_LOG_FORMAT=json`.


### 10.1 `klav proxy`: lo que hace la persona

Comandos de la persona (ADR 0036 §14). `use`, `grant` y `revoke` piden Touch
ID o la contraseña maestra en `klavd` (sin `klavd`, la contraseña al
desbloquear). Esa presencia es lo que impide que un agente los corra con
provecho: el diálogo dice qué se firma y solo la persona lo confirma. La
extensión del navegador no llega a ninguno, ni a `status`. Con un `klavd`
anterior a estos comandos, `klav proxy` pide actualizarlo y reiniciarlo. Lo que imprimen
son nombres, hosts, las 6 palabras del proxy y la receta de cada perfil:
nunca un valor, una llave ni un trozo de una.

```sh
klav proxy status [--json]
klav proxy use own AGENTE | none [--json]
klav proxy grant ELEMENTO --profile NOMBRE --upstream https://HOST[:PUERTO] \
    --header CABECERA [--prefix "Bearer "] [--field CAMPO] \
    --method MÉTODO… --path-prefix PREFIJO… [--ask] [--ask-method MÉTODO]… \
    [--rate POR_MINUTO] [--words "…"] [--every-device-is-updated] [--json]
klav proxy grant ELEMENTO --preset northflank|maple [cualquier opción de arriba] \
    [--words "…"] [--every-device-is-updated] [--json]
klav proxy grant ELEMENTO --profile NOMBRE --mcp-url https://HOST[:PUERTO]/RUTA \
    [--header CABECERA] [--prefix "Bearer "] [--field CAMPO] [--mcp-header NOMBRE:VALOR]… \
    [--tools-allow PATRÓN,…] [--tools-ask PATRÓN,…] [--tools-deny PATRÓN,…] \
    [--rate POR_MINUTO] [--words "…"] [--every-device-is-updated] [--json]
klav proxy revoke ELEMENTO [--json]
klav proxy issuer add AGENTE --profile PERFIL… --url tls://HOST:PUERTO \
    [--max-ttl 8h] [--max-live 3] [--inject-ask] [--words "…"] \
    [--every-device-is-updated] [--json]
klav proxy issuer remove AGENTE [--json]
klav proxy sandboxes [--ended] [--json]
klav proxy sandboxes revoke ID | --all [--wait] [--json]
klav proxy local status [--json]
klav proxy local revoke ID | --all [--json]
klav proxy local init --email CORREO [--server URL] [--json]
```

- **`status`** muestra el ajuste de la cuenta (el elemento `preferences`,
  [especificacion-cripto.md](especificacion-cripto.md) §7.3), el agente del
  proxy con su estado y sus 6 palabras, cada credencial con su perfil y sus
  reglas, y, sin un proxy que funcione, lo que se pierde (ADR 0036 §13).
  - **Los emisores** (ADR 0036 §4): con un proxy propio, después de las
    credenciales, `Sandbox issuers:` y una línea por cada agente que el
    grant del proxy, verificado con la identidad de la cuenta, deja crear
    sandboxes: su nombre (el del servidor, escapado) y su ID, su estado si
    no está activo (`pending` si su propio grant no lo aprobó todavía),
    los perfiles y los límites (`up to 3 at once, each for at most 8h`).
    Uno que el servidor ya no lista sale por su ID. Sin ninguno, «No
    sandbox issuers» y el comando que añade uno. Con `--json`, `issuers`
    (`agent_id`, `name?`, `status?`, `profiles`, `max_ttl_secs`,
    `max_live`), `[]` sin ninguno; no está cuando no se sabe: sin proxy
    propio, con un grant del proxy que este dispositivo no puede leer o
    desde un `klavd` anterior. Si un agente escribió el ajuste de la
    cuenta, `status` sale con 3 y no lista nada del proxy, tampoco sus
    emisores: no se fía de ningún proxy, como la lista de `sandboxes`.
  - **Los sandboxes:** con un proxy propio suma una línea con sus
    sandboxes activos, los que esperan su reclamo y los de un estado que
    esta versión no conoce (abajo, `sandboxes`). Antes de esa línea va,
    por cada señal de robo, la misma línea de aviso de seguridad que da
    `sandboxes`, que tampoco se va, y sale con 0. Si el servidor mandó
    un latido del proxy más viejo que el que ya vio este dispositivo,
    antes va también la misma línea que da `sandboxes`, con
    `security warning`, y sale con 0: es un aviso, no un fallo (ADR 0036
    E9, 2026-11-16). Los demás avisos de la lista (un evento de un agente
    tras su revocación, por ejemplo) los dan `sandboxes` y
    `klav log verify`. Si no se pueden listar es un aviso, salvo una falla
    de seguridad (una bitácora alterada, un *rollback* de lo sincronizado
    o un latido que el proxy no firmó): entonces `status` lo muestra todo
    y sale con 3. `--json` no la lleva.
- **`use own AGENTE`** guarda qué agente es el proxy. Desde entonces
  `klav agent approve`, `klavd` y las apps se niegan a darle proyectos
  enteros a ese agente. Se niega con un agente que ya tiene proyectos, uno
  revocado o denegado, y mientras el proxy anterior tenga credenciales:
  revócalo antes con `klav agent revoke`, que también cambia la llave de lo
  que tenía. **`use none`** deja la cuenta sin proxy, con la misma regla.
  La primera vez avisa de las versiones viejas (abajo). `klavd` vuelve a
  comprobarlo tras Touch ID, por si cambió mientras tanto.
  - Si el ajuste no se puede leer (falla la sincronización, un elemento
    del sistema no se abre o dos copias no coinciden), `klav agent approve`
    aprueba como antes de que existiera, con un aviso; solo un ajuste
    legible que nombra a ese agente lo impide.
  - **Si un agente escribió el ajuste** (el servidor dice que la versión
    actual del elemento `preferences` es de un agente, y ningún agente
    puede escribirlo), no se usa nada de él: `status`, `grant`, `revoke` e
    `issuer` fallan con 3 y nombran al agente, y `klav agent approve` lo
    trata como un ajuste que no se puede leer (aprueba con un aviso, como
    arriba). `use own
    AGENTE` o `use none` es lo único que lo arregla: lo dice antes de Touch
    ID y, tras la presencia, reemplaza ese elemento entero con un cuerpo
    nuevo que solo lleva el ajuste elegido: no usa ni conserva nada del
    contenido del agente (el interruptor «Desarrollo» vuelve a su valor por
    defecto). Como no se fía
    del proxy que nombraba, no puede comprobar si un proxy anterior sigue
    con credenciales, y lo avisa: `klav agent list` y `klav agent revoke`.
    El diálogo de Touch ID dice que reemplaza las preferencias de la cuenta
    que escribió un agente. Si entre la vista y la firma aparece otro elemento escrito por
    un agente, no escribe nada y pide repetirlo.
- **`grant ELEMENTO`** le concede una credencial al proxy de la cuenta, con
  un perfil y sus reglas. Primero lo muestra todo; luego pide Touch ID.
  - **El diálogo de Touch ID lo arma `klavd`** con lo que va a firmar: el
    agente; el elemento con su bóveda y proyecto y, si tiene, el host de
    su primer sitio; el host del upstream, con el puerto si no es el 443;
    la cabecera si no es `authorization` y el campo si no es el secreto
    principal; cada método (los que pasan y los que preguntan antes), cada
    prefijo de ruta, y que el agente nunca ve el valor. No muestra el
    nombre del perfil, el texto antes del valor (`--prefix`) ni el ritmo
    (`--rate`), aunque también se firman. Las reglas no se recortan: una
    credencial lleva como mucho 4 métodos, 3 prefijos de 32 caracteres, un
    host de 64 y una cabecera y un campo de 32; más se rechaza antes de
    Touch ID, con un mensaje que pide partirla. Los nombres (agente,
    título, bóveda/proyecto) se recortan a 40 caracteres con «…», como en
    todos los diálogos, y el sitio por el principio, para que quede el
    final que lo nombra. En el peor caso (un método admite hasta 16
    letras) el texto llega a 793 caracteres en inglés y 832 en español.
  - El título lo puede cambiar sin presencia cualquier proceso que hable
    con `klavd`: por eso el diálogo añade la bóveda y el proyecto, que
    `klavd` no deja mover ni renombrar. Además, `klavd` vuelve a buscar el
    elemento al firmar y se niega si ya no es el que mostró la vista
    previa (`shown_item`).
  - Con la **primera** credencial el proxy está pendiente: el diálogo dice
    que lo aprueba y muestra sus 6 palabras, que `klavd` saca de la llave
    pública que firma. Esa comparación es la que cuenta. La terminal las
    enseña antes (sí/no, o `--words`) solo por comodidad. Con las
    siguientes no hace falta, porque su llave es la que la persona ya
    aprobó.
  - El **primer grant por elemento de la cuenta** necesita
    `--every-device-is-updated`: `klavd` lo rechaza sin esa confirmación, y
    el diálogo dice lo que se rompe en un dispositivo sin actualizar
    (abajo). Los siguientes no la necesitan.
  - Sin `--preset`, todo va explícito: `--profile`, `--upstream`,
    `--header`, `--method` y `--path-prefix` son obligatorios
    (`--path-prefix /` para cualquier ruta). El único host es el del
    upstream, nunca `*` ni una IP: los hosts extra llegan con el modo (b).
  - **`--preset northflank`** (capa 10, ADR 0036 §7) es la forma corta:
    rellena el perfil `northflank` con el token de API en
    `Authorization: Bearer`, `https://api.northflank.com`, todas las rutas
    (`/`), `GET`, `POST` y `PATCH` sin preguntar y `DELETE` pidiendo
    aprobación, con el ritmo por defecto. **`PUT` se rechaza**: una
    credencial lleva como mucho 4 métodos, y son los que fija el ADR 0036
    §7 (nota del 2026-11-17). **Nada en el *preset* protege los cambios de
    roles o de tokens por ruta**: un `POST` o un `PATCH` que los cambia
    pasa como cualquier otra llamada. Antes del perfil, la terminal muestra
    una nota que dice las dos cosas. Si las opciones cambian lo que se
    firma, la nota se cambia por una línea que dice que las opciones
    cambiaron el *preset* y que el perfil de abajo es el que se firma; la
    frase de los roles y los tokens se queda mientras el perfil deje pasar
    un `POST` o un `PATCH`, o pida aprobación para ellos. Lo que se imprime
    sale del perfil final, no de las opciones escritas: repetir las del
    *preset* deja la nota completa.
    - Es un punto de partida: cada opción que la persona añade **reemplaza
      esa parte** del *preset*, y solo esa. Así `--method GET` deja pasar
      solo `GET` y conserva `DELETE` pidiendo aprobación; `--ask-method`
      reemplaza los que preguntan. La vista previa y el diálogo de Touch
      ID muestran el perfil final, con el *preset* y las opciones, y se
      firma ese.
    - Si el *preset* más las opciones pasan de 4 métodos (por ejemplo
      `--method GET,POST,PATCH,PUT`, que con el `DELETE` del *preset* son
      cinco), se rechaza antes de la vista previa con un mensaje que nombra
      el límite, cada método y de dónde vino. Nunca se quita uno en
      silencio. `--method GET,POST,PUT` (cuatro con `DELETE`) sí vale.
    - El perfil sale con los mismos bytes que las opciones explícitas
      `--profile northflank --upstream https://api.northflank.com --header
      authorization --prefix "Bearer " --method GET,POST,PATCH --ask-method
      DELETE --path-prefix /`, así que un `klav`, un `klavd`, un proxy o un
      servidor más viejos ven lo mismo. Deja pasar sin aprobación el
      `GET /v1/login` de la línea `northflank login` de `klav sandbox
      start`.
  - **`--preset maple`** (la puerta MCP, ADR 0036 §7, nota del
    2026-11-19, paso M4) rellena el perfil `maple` con la llave de API de
    Maple en `Authorization: Bearer`, `https://api.maple.dev` y solo las
    rutas bajo `/mcp`; `POST`, `GET` y `DELETE` pasan y ninguno pide
    aprobación, con el ritmo por defecto. Cualquier otra ruta se rechaza,
    también la de descubrir OAuth (`/.well-known/…`). `--upstream
    https://api.eu.maple.dev` cambia al host europeo y deja la nota
    completa. Toda llamada MCP es el mismo `POST` a `/mcp`, así que el
    proxy no puede preguntar por herramienta: **el límite son los permisos
    de la llave**, y la nota pide una llave restringida de solo lectura que
    venza en 90 días como mucho. Con opciones que cambian lo que se firma,
    la nota es la misma línea que en `northflank`, más la frase de las
    herramientas mientras el perfil deje pasar un `POST` o pida aprobación
    para él. El perfil sale con los mismos bytes que `--profile maple
    --upstream https://api.maple.dev --header authorization --prefix
    "Bearer " --method POST,GET,DELETE --path-prefix /mcp`. El cliente MCP
    del sandbox apunta a `http://127.0.0.1:<puerto>/maple/mcp` (las líneas
    de `klav sandbox start`, abajo), y el proxy trata sus respuestas
    `text/event-stream` como *streams* ([api.md](api.md) §8.7).
  - `--preset railway` se rechaza sin conceder nada: necesita el modo (b),
    que el proxy todavía no tiene. Un nombre desconocido se rechaza con la
    lista de los que hay.
  - Sin `--field`, el valor es el secreto principal: la contraseña de un
    login o la clave de una API key. Cualquier otro tipo necesita
    `--field`, y se rechaza antes de Touch ID.
  - `--ask` hace que cada llamada pida aprobación; `--ask-method` añade
    métodos que piden aprobación en cada llamada. Si un método está en las
    dos listas, pide aprobación (gana la regla más restrictiva).
  - Concederle de nuevo un elemento que ya tiene **reemplaza** su perfil y
    sus reglas.
  - El grant siempre lleva `reveal`, `inject` y `fill` en `deny`.
  - **Avisa** cuando el host es de un proveedor que también aloja
    aplicaciones (Railway, Northflank, Fly.io, Render, Heroku, Vercel,
    DigitalOcean, Koyeb): si el proxy corre ahí, ese token podría alcanzar
    el propio servicio del proxy (T151). Klav no sabe dónde corre el proxy,
    así que avisa siempre con esos hosts.
  - Se arma sobre la versión del grant que mostró: si otro dispositivo lo
    cambió entre medias, no firma y pide repetirlo.
- **`grant ELEMENTO --mcp-url URL`** concede un **perfil MCP** (ADR
  [0049](decisiones/0049-mcp-gateway.md) §2 y §5.3): el proxy reenvía solo
  esa ruta (`POST`, `GET` y `DELETE`), lee el JSON-RPC, quita de
  `tools/list` las herramientas que ninguna regla permite ni pregunta, y
  juzga cada `tools/call` por su nombre.
  - `--mcp-url` se parte en el upstream (`https://HOST[:PUERTO]`) y el
    *endpoint* (la ruta, de letras, dígitos y `/ . _ - ~`, 64 bytes como
    mucho): sin consulta. Sin `--header`, la credencial va en
    `authorization`, y sin `--prefix`, con `Bearer `. No acepta
    `--upstream`, `--path-prefix`, `--ask` ni `--ask-method`: un perfil MCP
    pregunta por herramienta, no por método.
  - `--tools-allow`, `--tools-ask` y `--tools-deny` toman patrones
    separados por comas o repetidos: un nombre exacto (`query_logs`), un
    prefijo con un `*` final (`get_*`) o `*` solo (todas, también las que
    el servidor añada después; la hoja lo marca). Distinguen mayúsculas y no
    hay sufijos (`*_api_key` no es un patrón). Gana la regla más
    restrictiva: `--tools-allow 'get_*' --tools-deny get_api_key` niega
    `get_api_key`. **Una herramienta que ningún patrón nombra se niega y no
    aparece en la lista del agente** (Q3). Sin `--tools-allow` ni
    `--tools-ask`, avisa de que toda llamada a una herramienta se negará.
  - `--mcp-header NOMBRE:VALOR` (hasta 4) añade una cabecera fija y no
    secreta, como un interruptor de solo lectura del proveedor; nunca una
    reservada (`authorization`, `cookie`, `mcp-session-id`…).
  - **La hoja** muestra, antes de Touch ID, el *endpoint*, las cabeceras
    fijas, la regla de la sesión (conectarse y listar, nunca una llamada a
    una herramienta) y **cada patrón**, agrupado en `tools allow`, `tools
    ask` y `tools deny`, más la línea `tools other denied and hidden`. Lleva
    como mucho 24 patrones por regla, 48 por perfil y 64 bytes por patrón
    (los topes del ADR §5.3); más se rechaza con un mensaje que pide
    prefijos más amplios. El diálogo de Touch ID nombra hasta 12 patrones
    de cada tipo y cuenta el resto.
  - **El primer perfil MCP** (con el interruptor `mcp_gateway` de la cuenta
    apagado, o un grant del proxy anterior a `v: 4`) pide
    `--every-device-is-updated`: los dispositivos y el `klav-proxy` sin el
    gateway fallan al cargar sus aprobaciones, `klav log verify` informa de
    una alteración y el proxy viejo rechaza el grant (ADR 0049 §9). Con la
    confirmación y tras Touch ID, `klav` enciende el interruptor
    (`POST /v1/account/mcp-gateway`) y después firma el grant. Un servidor
    anterior al gateway lo rechaza antes de pedir nada.
  - Volver a conceder el mismo perfil conserva sus clientes locales; si un
    cambio les quita un perfil, la hoja dice cuáles.
  - **Los *presets* del gateway** (`maple` con reglas de herramientas,
    `github`, `cloudflare`, `linear`, `stripe`) se rechazan hasta que cada
    uno pase su prueba a mano (ADR 0049 §2.3, elección 14); el mensaje dice
    cómo pasar `--mcp-url` y `--tools-…` a mano. `--preset maple` sin
    `--mcp-url` sigue siendo la compuerta MCP del ADR 0036, sin cambios.
  - `status` muestra, en un perfil MCP, la línea `mcp` y las reglas de
    herramientas; con `--json`, `profile.mcp` y `rules[].mcp_tools`, y
    `local_clients` (`name`, `profiles`; nunca el token ni su resumen).
- **`revoke ELEMENTO`** le quita una credencial al proxy y cambia la llave
  del elemento (ADR 0036 §18). Después recuerda rotar el token en su
  proveedor: el proxy lo tuvo en memoria. La última no se quita así: eso es
  revocar el proxy, con `klav agent revoke`. Un elemento del grant que
  espera en la papelera no impide quitar otro. Un elemento que este
  dispositivo ya no ve (purgado) se quita igual, por su ID: no queda llave
  que cambiar, y lo dice, con el mismo recordatorio de rotar el token.
- **`grant` y `revoke` salen con error si no terminan**, también con
  `--json`, y dicen en qué estado quedó: «sigue concedido, la llave no
  cambió»; «la llave cambió en el servidor, pero este dispositivo no lo
  confirmó (falló la sincronización de después), y los agentes X e Y
  necesitan un grant con la llave nueva»; o «quitado y con llave nueva,
  pero los agentes X e Y no recibieron su grant nuevo y no pueden
  abrirlo». Repetir el mismo comando termina lo que falte. Con
  `klav proxy revoke ELEMENTO`, también cuando el proxy ya no tiene el
  elemento y solo faltaba volver a emitir el grant de los otros agentes
  que lo tienen: entonces el diálogo dice «terminar de darle ELEMENTO con
  su clave nueva a los agentes X e Y», no que se lo quita al proxy.

- **`issuer add AGENTE`** deja que ese agente (el **emisor**: T3 Code, un
  orquestador) cree sandboxes con el proxy de la cuenta (ADR 0036 §4).
  Firma dos grants `v: 3`
  ([especificacion-cripto.md](especificacion-cripto.md) §13.4): el del
  emisor, que nombra al proxy con su llave y `--url` (donde un sandbox lo
  alcanza), y el del proxy, que lista al emisor con sus perfiles
  (`--profile`, de 1 a 6, de los que el proxy ya tiene), cuánto puede durar
  cada sandbox (`--max-ttl`, de 5 min a 24 h, 8 h si falta) y cuántos puede
  tener vivos (`--max-live`, de 1 a 50, 3 si falta). Pide Touch ID; el
  diálogo dice todo eso, nada recortado salvo los nombres de los agentes.
  - Un emisor **pendiente** se aprueba aquí, sin proyectos: un emisor no
    necesita llaves. El diálogo muestra sus 6 palabras, como con el proxy;
    la terminal las enseña antes (sí/no, o `--words`). Un emisor con
    proyectos los conserva.
  - Si la política del emisor deja `inject` sin preguntar, avisa: podría
    pasarle el token de un proveedor al comando que crea un sandbox, que es
    lo que los sandboxes evitan (T171). `--inject-ask` añade en el mismo
    grant una regla `inject: ask`. La tarjeta de esa aprobación muestra el
    agente, el elemento y el motivo, no el comando: mostrarlo es el
    [ADR 0041](decisiones/0041-presence-for-values-and-the-inject-card.md),
    aceptado y sin construir.
  - El **primer emisor de la cuenta** pide `--every-device-is-updated`:
    los `klav-proxy` y los dispositivos anteriores no leen `v: 3` (abajo).
  - `klavd` vuelve a buscar al emisor y al proxy al firmar y se niega si
    no son los que mostró la vista previa (`shown_issuer`, `shown_proxy`):
    los agentes eligen su nombre al registrarse.
  - Firma primero el grant del emisor y luego el del proxy. Si el segundo
    falla, lo dice («el grant de X nombra al proxy, pero el proxy aún no lo
    lista, así que rechaza sus sandboxes») y repetir el comando lo termina.
- **`issuer remove AGENTE`** firma primero el grant del proxy, sin el
  emisor, y luego el del emisor, que deja de nombrar al proxy: con
  proyectos pierde `sandbox`; sin ellos queda con `sandbox` sin proxy. El
  grant del proxy vuelve a `v: 2` al quitar el último emisor. Pide Touch ID.
- **`use`** con otro proxy (o `none`) vuelve a firmar a cada emisor con
  `sandbox` sin proxy: el proxy nuevo no los lista, así que hay que
  repetir `issuer add`. Repetir `use` termina los que fallaran.
- **`sandboxes`** muestra los sandboxes del proxy de la cuenta, de todos
  sus emisores (ADR 0036 E2.1, E6.2), sacados de la bitácora verificada
  (verifica la cadena entera, como `klav log verify`) y del último latido
  firmado del proxy: el comienzo del ID, la etiqueta (palabras del emisor),
  los perfiles, el emisor, cuándo vence, cuándo lo vio el proxy por última
  vez y el estado (`waiting for claim`, `active`, `revoking`, `expired` y,
  con `--ended`, cómo terminó o `proxy revoked`, abajo; uno que esta
  versión no conoce, de un `klavd` más nuevo, sale como `unknown state`,
  nunca como terminado).
  - **Un sandbox cuyo proxy revocaste** (`klav agent revoke`) sale como
    `proxy revoked: its end can no longer be logged (proxy revoked HH:MM
    UTC)`, con `--json` `"status": "proxy_revoked"` y `proxy_revoked_at`:
    un proxy revocado nunca puede registrar el fin, así que sin esto la
    fila se quedaría en `revoking` (si lo revocaste) o en `waiting for
    claim`, `active` o `expired` para siempre. Sale así cualquier fila sin
    fin de ese proxy emitida antes de su revocación en la bitácora, la
    hayas revocado o no. Lo decide solo la bitácora verificada: el
    `agent.revoked` de ese proxy que firmó la cuenta. Nada que diga el
    servidor o un agente sin ese evento firmado lo da, y un fin que el
    proxy ya registró gana. Un sandbox emitido después de la revocación
    (una petición en vuelo que registró un servidor anterior, con el aviso
    de `klav log verify`) sale como saldría sin ella. No dice que terminó: el servidor
    rechaza lo que pida ese proxy, pero nada en la bitácora prueba que el
    sandbox se detuvo, y un proxy que ignore su revocación se queda con lo
    que ya descifró (ADR 0036, riesgo 62). Como un sandbox terminado, la
    lista sin `--ended` no lo muestra y la línea de `status` no lo cuenta;
    si no queda otro, la lista lo dice sin decir que terminaron: `No
    sandboxes to show without --ended, which also shows those that ended
    and those whose proxy was revoked.` Revocar uno así por su fila de la
    lista verificada (sus primeros caracteres, o el ID con el ajuste en
    duda) dice que no puede llegar un fin; con el ID entero por el ajuste,
    o con `--all`, que no leen la lista, la línea dice qué prueba el fin y
    que un proxy revocado no da ninguno. Un `klavd` anterior lo sigue
    mostrando como antes (`revoking`, `waiting for claim`…), y una CLI
    anterior que lo lee de un `klavd` nuevo lo muestra como `unknown
    state`, vivo. Las apps, que todavía no tienen palabras para este
    estado, lo muestran con el que tenía antes, como se lo da un `klavd`
    anterior.
  **Una señal de robo nunca se oculta:** un sandbox que terminó porque
  alguien lo reclamó por segunda vez con el secreto correcto desde otra
  llave (`theft`) sale también sin `--ended`, con el estado `theft signal`,
  y arriba de la tabla va una línea por cada uno, como aviso de seguridad:
  `Sandbox 9c02e5f1: security warning: theft signal at 2026-11-17 10:42
  UTC.`, la etiqueta (palabras del emisor) y el emisor, que si no fueron ni
  la persona ni el emisor alguien copió su entorno, y que
  `klav agent pause ID` corta también los demás sandboxes de ese emisor
  (ADR 0036 E2.1). Sale con 0. **Esa línea no se va:** sale en cada
  `sandboxes` y en cada `status` mientras la bitácora tenga ese sandbox, y
  la cadena verificada nunca suelta uno. La CLI no tiene un «Entendido»
  que la apague ni un plazo que oculte los robos viejos. La primera línea
  dice cuándo latió el proxy, o por qué no da señales. Un latido más viejo
  que el que ya vio este dispositivo no se lee como un proxy callado: sale
  como aviso de seguridad (`security warning`), porque así lo haría un
  servidor que vuelve atrás, y la lista sale igual con 0. Sin proxy
  propio, muestra los de todos los proxies de la bitácora. `--json` es la
  lista de `klavd` (`sandbox_list`, [klavd.md](klavd.md)) con esas mismas
  filas, más `theft_signals`: los IDs de todas las filas que terminó una
  señal de robo, `[]` sin ninguna. Una falla con `--json` es una línea,
  como en `klav sandbox`. Sale con 3 ante una
  bitácora alterada, un latido que el proxy no firmó o un servidor que no
  lista el proxy de la cuenta.
  - **Si un agente escribió el ajuste de la cuenta**, la lista sale igual,
    con las filas de todos los proxies de la bitácora (no se fía de ningún
    proxy), y la primera línea es un aviso de seguridad que nombra al
    agente y dice cómo arreglarlo (`klav proxy use`). Sale con 3. Con
    `--json`, el mismo documento lleva `security`
    (`{"kind": "preferences_by_agent", "agent_id": …}`; un `kind` que esta
    versión no conoce, de un `klavd` más nuevo, sale como
    `{"kind": "unknown"}` y también con 3), aparte de `warnings`. Le pide a
    `klavd` `sandbox_list_flagged`; uno anterior responde `bad_request`, y
    entonces pide `sandbox_list`, que falla con 3: nunca una lista limpia.
    La línea de `status` sale con 3 mientras dure el aviso. `revoke`
    revoca por la fila verificada (abajo, «Con el ajuste en duda»), salvo
    `--all`.
- **`sandboxes revoke ID | --all`** revoca un sandbox, o todos los que el
  proxy emitió hasta ahora. Firma con la identidad de la cuenta y no pide
  Touch ID, porque solo quita acceso (ADR 0036 E2.3, riesgo 64). La
  revocación se firma y el servidor dice que la guardó; según él, les
  niega el acceso desde ese momento. Lo que prueba que terminaron es el fin
  que el proxy firma en la bitácora verificada, en su siguiente lectura
  (cada 30 s). Un agente nunca la corre.
  - **Un ID entero y `--all`** toman el proxy del ajuste de la cuenta sin
    verificar la bitácora, así que un servidor que rompa la verificación no
    impide revocar, salvo con el ajuste en duda (abajo): entonces un ID
    entero necesita su fila de la lista verificada, y una bitácora que no
    verifica lo impide. Los primeros 8 caracteres del ID, como los muestra la
    lista, necesitan la lista verificada para encontrarlo: si la bitácora
    no verifica, salen con 3 y el error pide el ID entero, que revoca sin
    la lista; con el ajuste en duda no lo pide, porque tampoco serviría, y
    pide volver a fijar el proxy con `klav proxy use own <agente>` (o, con
    un `klavd` anterior, actualizarlo). Sin proxy
    propio, un ID entero o `--all` fallan y piden los primeros 8
    caracteres o `klav proxy use own <agente>`.
  - **Con el ajuste en duda** (un agente lo escribió, arriba), un ID
    entero o sus primeros caracteres revocan el sandbox de una fila de la
    lista verificada en el proxy que esa fila nombra, nunca en el que diga
    el ajuste: unas preferencias hostiles no pueden mandar la revocación a
    otro proxy ni impedirla. Dice la revocación como siempre (la línea de
    texto o la de `--json`, y con `--wait` también espera, sobre la lista
    verificada) y después sale con 3, con el aviso de seguridad y el ID
    del agente proxy al que fue, para compararlo con el `proxy_id` de su
    fila en `klav proxy sandboxes --ended --json`. Sin ningún aviso, un ID
    entero sigue tomando el proxy del ajuste sin la lista, como arriba.
  - **Con el ajuste en duda, `revoke` siempre sale con 3**, con el aviso de
    seguridad, también cuando revocó: el código no dice si revocó, lo dice
    la línea `Revoked …` (o la línea `revoked` de `--json`). Cuando no
    revoca, el error dice por qué y que no se revocó nada: un ID o un
    comienzo de ID que la lista verificada no tiene, que nombra varios o
    uno ya terminado (sin el aviso salen con 2, 2 y 1), una espera que se
    acaba sin el fin (sin el aviso, 1) o cualquier otra falla. Un
    argumento mal escrito (un comienzo de menos de 8 caracteres o que no
    es hexadecimal, o un ID junto con `--all`) sale con 2, antes de leer
    nada. `--all` sale con 3 sin revocar nada: ninguna fila nombra el
    proxy de la cuenta, y elegir uno de la bitácora sería adivinar; el
    error pide revocar cada sandbox por su ID o volver a fijar el proxy
    con `klav proxy use own <agente>`. Con un `klavd` anterior, que
    responde `bad_request` a `sandbox_list_flagged`, sale con 3 sin
    revocar nada, como antes, y el error pide actualizar `klavd` o volver
    a fijar el proxy. Revocar no pide Touch ID, igual que sin el aviso.
  - **`--wait`** espera hasta 2 minutos a que el proxy registre el fin del
    sandbox que nombraste o, con `--all`, el de los que el servidor dice
    que cubre y el de las filas verificadas del proxy que esa revocación
    cubrió. Sale con 1 si no llega: según el servidor ya no tienen
    acceso, pero solo el fin que firma el proxy en la bitácora verificada
    lo prueba. Sale con 3 si la bitácora no verifica mientras espera.
    Deja de esperar el de un sandbox cuyo proxy fue revocado (`proxy
    revoked`, arriba), que nunca llegará: si solo quedan de esos, termina
    en seguida, sale con 1 (con 3 con el ajuste en duda) y los deja en
    `not_ended`; nunca dice `The proxy logged their end`. En texto dice,
    por cada uno, que su proxy fue revocado y que nada prueba que se
    detuvo. Con `--json` solo da `not_ended`, sin decir por qué: un script
    distingue un plazo que se acabó de un proxy revocado leyendo la lista
    (`klav proxy sandboxes --ended --json`, su fila con `"status":
    "proxy_revoked"`).
  - **Si el servidor ya tiene una revocación posterior** del mismo
    alcance, firmada por delante del reloj de este dispositivo, la nueva no
    se aplica. Para un sandbox no es un error, porque según el servidor esa
    ya lo cubre (la lista verificada lo muestra como `revoking`), y
    `--wait` no espera su fin: la línea lo dice (`Not waited`); con
    `--json`, la línea `not_applied` es la única, sin `not_ended`, y
    tampoco espera. `klav proxy sandboxes` lo muestra cuando llegue. Para `--all` sale con
    1, porque no cubre los sandboxes emitidos después.
  - Con `--json`, una línea por resultado (con el ajuste en duda, después
    de la línea o las líneas `revoked` va la línea de error del código 3,
    `{"error", "message", "next"}`, con el ID del proxy en `next`):
    `{"outcome": "revoked", "scope",
    "at", "sandbox_ids", "not_ended"}` (`not_ended` solo con `--wait`: los
    que el proxy aún no terminó) o `{"outcome": "not_applied", "scope",
    "later_at"}`. Un comienzo de ID de menos de 8 caracteres, que no es
    hexadecimal, que no nombra ninguno o que nombra varios sale con 2 antes
    de firmar nada (los dos últimos, con 3 con el ajuste en duda).
  - Con `--wait --json`, la revocación sale en una línea antes de esperar,
    sin `not_ended`, y otra igual con `not_ended` al terminar. Un comienzo
    de ID que nombra un sandbox ya terminado sale con 1, sin firmar nada
    (con 3 con el ajuste en duda).

**Antes de la primera credencial, actualiza Klav en todos tus
dispositivos** (apps, CLI y `klavd`). Con el primer grant por elemento de
la cuenta, un dispositivo anterior a esos grants:

1. con la CLI o `klavd` viejos, ya no puede listar agentes;
2. en el iPhone deja de cargar solicitudes, y en el Mac deja de cargar
   solicitudes y tareas, también detrás de un `klavd` nuevo (su FFI no
   conoce el permiso `proxy`);
3. al revocar otro agente con `--rotate`, se detiene en el grant del proxy
   después de la rotación, así que los agentes que van después en la lista
   pierden el acceso;
4. y nada puede comprobarlo por ti: los dispositivos no dicen su versión.

**Antes del primer emisor, actualiza también `klav-proxy`.** Con el primer
`issuer add`, el grant del proxy pasa a `v: 3`: un `klav-proxy` anterior deja
de servir cualquier credencial, y un dispositivo anterior a los emisores ya
no lista agentes y su `klav log verify` falla en ese grant. El grant del
emisor también pasa a `v: 3`: si ese agente corre un Klav anterior, deja de
poder leer su propio grant y su `run`, su `inject` y su MCP dejan de
funcionar; actualízalo antes. `issuer remove`
no lo deshace: el grant del emisor sigue en `v: 3`, y la bitácora guarda
cada grant.

Es **para siempre**, no hasta revocar el proxy: el servidor guarda el grant
de un agente revocado, y esas versiones abren el grant de cada agente,
también de los revocados. Solo actualizar el dispositivo lo arregla.

Las versiones anteriores al elemento `preferences` lo saltan con un aviso
de que no se descifra, en cada comando, y no saben qué agente es el
proxy.

#### `klav proxy local`: el proxy de este equipo (ADR 0036 E3.5, capa 11)

Hablan con el `klav-proxy` que corre en este equipo, como el mismo
usuario, por su *socket* local (`<KLAV_HOME>/agents/klav-proxy.sock`). No
pasan por `klavd` ni necesitan la bóveda abierta: funcionan con Klav
bloqueado (E2.3).

- **`status`**: el ID del proxy, su puerto en `127.0.0.1`, si sirve también
  un canal para sandboxes, sus perfiles MCP con su URL local, y sus
  sandboxes vivos con la conexión real de cada uno («connected», «waiting
  for its claim» o hace cuánto se vio). La etiqueta va entre comillas y
  «as its issuer says», sin caracteres ocultos (T136, T157). `--json` da la
  respuesta del *socket* tal cual. Nunca un valor, un resumen de un secreto
  ni una llave.
- **`revoke ID | --all`**: termina al momento uno de sus sandboxes vivos
  (el ID entero o sus primeros 8 caracteres) o todos, sin Touch ID ni
  desbloquear. El proxy deja de servirlo, corta sus llamadas en curso y
  registra `sandbox.revoked` con el motivo `person_local`; espera como mucho
  5 s a que el servidor lo tome y dice si lo tiene (`logged`). Si no, el
  proxy lo manda en sus barridos siguientes y mientras tanto no sirve ese
  sandbox. «Todos» son los vivos en ese momento: un arranque que todavía
  espera al servidor queda fuera. Es de la persona: un agente nunca lo
  corre (el *socket* acepta a cualquier proceso del mismo usuario, riesgo
  residual 64).
- **`init`**: registra un proxy para este equipo, como `klav-proxy init`
  con el nombre `klav-proxy` y este `KLAV_HOME` (la llave en
  `<KLAV_HOME>/agents/klav-proxy.key`, 0600), corriendo este mismo binario
  como `klav-proxy`. Imprime las 6 palabras; después, `klav proxy use own
  klav-proxy` y `klav proxy grant`.
- Sin un proxy que conteste: sale con `1` y el código `klav_local_proxy_not_running`
  («No credential proxy runs on this machine.»), con qué hacer.

### 10.2 `klav sandbox`: lo que hace el emisor

Con la identidad del agente emisor, en la máquina donde corre
`klav-proxy serve` (ADR [0036](decisiones/0036-sandboxes-de-agentes.md) §4,
E6.1). Habla solo con el proxy en `127.0.0.1`, con peticiones firmadas con
su llave ([api.md](api.md) §8.9); nunca con un `HTTP_PROXY` ni siguiendo una
redirección.

```
klav sandbox start --label ETIQUETA --profile PERFIL… [--ttl 8h] \
  [--proxy-port 8790] [--agent NOMBRE] [--json] -- COMANDO…
klav sandbox start --label ETIQUETA --profile PERFIL… --package-file RUTA [--json]
klav sandbox ls [--json]
klav sandbox stop ID | --all [--json]
```

- **`start`** pide al proxy un sandbox con esos perfiles. El proxy registra
  `sandbox.issued` en la bitácora antes de dar el secreto. El **paquete**
  (`ksb1_…`, especificación §13.10) lo arma la CLI con la dirección y el pin
  del proxy que dice el grant del propio emisor, firmado por la persona.
  - **Nunca se imprime**, tampoco con `--json`. Sale por uno de dos caminos:
    - **`-- COMANDO…`**: el comando corre con el paquete en `KLAV_SANDBOX`.
      Su salida, por stdout y stderr, pasa por la misma redacción que
      `klav agent run`, y lo que la CLI dice va a stderr, antes del comando.
      No recibe entrada (stdin vacío): la redacción retiene el final de
      cada salida hasta que llega más, así que una pregunta no se vería.
      Si el comando deja un proceso que mantiene abierta su salida, una
      señal (Ctrl-C, `SIGTERM`) deja de leerla y la CLI sale con el código
      del comando. La señal que llega mientras el comando corre también
      cuenta: la CLI se la pasa (Ctrl-C ya le llega por el grupo de la
      terminal) y, cuando el comando termina, espera su salida solo medio
      segundo más, sin pedir una segunda señal.
      Si el comando falla, el sandbox sigue vivo y la CLI lo dice: páralo
      si el comando no llegó a crearlo.
    - **`--package-file RUTA`**: un archivo nuevo con modo 0600, para un
      programa que lo pasa al proveedor y lo borra. Una ruta que ya existe,
      también un enlace simbólico, se rechaza antes de pedir el sandbox, y
      también un archivo que no se puede crear: antes de pedirlo se crea
      su temporal 0600 `.<nombre>.<16 hex>.klav-tmp` en el mismo directorio.
      El archivo toma su nombre solo cuando llega el paquete, completo y de
      una vez, como `klav inject -o` (§7): mientras tanto la ruta no existe,
      y nunca tiene un paquete vacío o a medias. Si alguien la ocupa
      mientras tanto, no se reemplaza: la CLI para el sandbox y lo dice,
      como cuando el archivo no se puede escribir. En un sistema de
      archivos sin enlaces duros hay, como en `klav inject -o`, un momento
      corto en el que un archivo que otro cree con ese nombre sí se
      reemplaza. Dos `klav sandbox start --package-file RUTA` a la vez con
      la misma ruta reciben los dos su sandbox: el primero que escribe se
      queda la ruta, y al otro la CLI le para el suyo y lo dice. Después de
      intentar escribir el paquete, salga bien o no, avisa por stderr de
      los temporales de ese nombre de otra escritura, interrumpida o
      todavía en curso (§7),
      sin cambiar la salida de `--json` ni el código de salida; si el
      arranque falla antes, no hay escritura y no avisa.
  - Sin ninguno de los dos, sale con código 2 sin pedir nada.
  - Si el sandbox empezó pero el paquete no se puede armar (la dirección
    del proxy en el grant del emisor no vale), la CLI lo para y lo dice; si
    no puede pararlo, dice que puede que siga vivo, como abajo.
  - **Una señal mientras espera al proxy** (Ctrl-C, `SIGTERM`, `SIGHUP`)
    corta el arranque: el comando no corre, el archivo de `--package-file`
    no se escribe (su temporal se borra), y sale con 128 más el número de
    la señal (130 con Ctrl-C). Si el proxy ya había contestado, la CLI para
    ese sandbox. Si no, `klav sandbox ls` dice si llegó a empezar.
  - **Una respuesta del proxy rota o que no llega** (la red, un tiempo de
    espera de 30 s, un cuerpo cortado) sale con código 1 y lo mismo: puede
    que el sandbox haya empezado, y `klav sandbox ls` lo dice. Un error
    antes de preguntar al proxy (el servidor de Klav sin respuesta) no lo
    dice: no empezó nada.
  - `--ttl` vale 8 h por defecto, o el límite del emisor si la persona le
    dio uno menor, y nunca puede pasar ese límite.
  - **Las líneas del *setup script*** del sandbox salen después, sin
    secretos y en este orden:
    - `klav-forward down --if-other-package` para el reenviador de **otro**
      paquete que siga vivo, como en un sandbox que se reanuda con su
      memoria y recibe un paquete nuevo: si no, tendría ocupado el puerto, y
      `up` se negaría con `klav_forward_port_in_use` antes de reclamar
      nada. Suelta ese sandbox en el proxy y para su reenviador. El de
      **este** paquete lo deja como está, vivo, ocupado o muerto, porque
      correr las líneas otra vez con el mismo paquete no debe romper un
      sandbox que funciona. Tampoco para nada si este paquete ya se
      reclamó en ese directorio de estado (su marca de reclamo está ahí),
      como cuando un proveedor repite un paquete viejo sobre el reenviador
      de uno más nuevo: `up` lo rechazaría de todos modos, y el sandbox
      que corre sigue. Donde no corre ninguno, o si no puede saber cuál es
      el de este paquete (`KLAV_SANDBOX` o el `state.json` no se pueden
      leer), no para nada. En todos esos casos sale con `0`; solo sale con
      `1` si no puede parar el reenviador de otro paquete que tiene el
      puerto. Detalle en [api.md](api.md) §8.11.
    - `klav-forward up --daemon` reclama el sandbox con el paquete de
      `KLAV_SANDBOX` y sigue en segundo plano; o dice que el reenviador de
      ese paquete ya corre; o pasa el rechazo del proxy para él (revocado,
      vencido, agentes en pausa), también el que guardó un reenviador que
      salió solo porque el proxy revocó el sandbox; o rechaza un paquete que ya se usó aquí
      con `klav_forward_already_claimed`, y entonces hace falta otro
      `klav sandbox start`.
    - `eval "$(klav-forward env)"` da las URL locales de cada perfil (ver
      [api.md](api.md) §8.11).
    - Solo si el sandbox lleva el perfil `northflank`:
      `northflank login -n klav -t klav-placeholder --override --host "$KLAV_FORWARD_NORTHFLANK_URL"`.
      Apunta la CLI de Northflank al reenviador, con la URL que acaba de
      poner la línea anterior (nunca un puerto fijo) y un token de mentira
      que el proxy quita antes de poner el real: no es una credencial.
      `--override` reemplaza un contexto `klav` de un arranque anterior.
      El `login` comprueba el contexto con `GET <host>/v1/login` (3 s, 3
      intentos), así que **el perfil `northflank` que firma la persona
      tiene que dejar pasar ese `GET` sin aprobación**: si pide una, el
      `login` falla antes de que la persona responda. `next` lo recuerda.
      La línea necesita la CLI de Northflank en el `PATH` del sandbox: sin
      ella sale con `127`, y con `set -e` el *script* para ahí, cuando `up`
      ya reclamó el sandbox. Instálala antes de correr las líneas.
      Sin comprobar todavía: la CLI de Northflank (`@northflank/cli`
      0.15.0) se leyó y no se corrió, y sus comandos que van por WebSocket
      probablemente fallan a través del proxy (ADR
      [0036](decisiones/0036-sandboxes-de-agentes.md) §5, decisión del
      2026-11-16).
    - Solo si el sandbox lleva el perfil `maple` (la puerta MCP, ADR 0036
      §7, nota del 2026-11-19, decisión 6), dos líneas que escriben la
      entrada MCP con la CLI de cada cliente, solo donde está instalado
      (sin él, la línea no hace nada y sale con `0`):
      ```sh
      if command -v claude >/dev/null 2>&1; then claude mcp remove --scope user maple >/dev/null 2>&1 || true; claude mcp add --transport http --scope user maple "$KLAV_FORWARD_MAPLE_URL/mcp" --header "Authorization: Bearer klav-placeholder"; fi
      if command -v codex >/dev/null 2>&1; then codex mcp add maple --url "$KLAV_FORWARD_MAPLE_URL/mcp"; fi
      ```
      La URL es la que puso la línea `eval`, más `/mcp`:
      `http://127.0.0.1:<puerto>/maple/mcp`. Claude Code la guarda en su
      configuración de usuario, con un *bearer* de mentira que el proxy
      quita antes de poner el real (para que un `401` o un `403` del proxy
      no parezca un inicio de sesión). Como `claude mcp add` rechaza una
      entrada que ya existe, la línea quita antes la que se llame `maple`:
      correrla otra vez deja la misma. `codex mcp add` reemplaza la de su
      mismo nombre, y su CLI toma un *bearer* solo de una variable de
      entorno (`--bearer-token-env-var`), no de una cabecera fija, así que
      la entrada de Codex va **sin** el valor de mentira (ADR 0036 §7, nota
      del 2026-11-25). Comprobadas, dos veces seguidas y con `sh -e`, con
      Claude Code 2.1.331 y Codex 0.166.0. Otro cliente MCP usa la misma
      URL. El perfil tiene que dejar pasar `POST /mcp` sin aprobación;
      `next` lo recuerda. `klav-forward` no edita la configuración de
      ningún cliente.
    - **Cualquier perfil MCP** (ADR 0049, capa 5): por cada perfil del
      sandbox que el proxy lista como perfil MCP (`GET /_klav/sandboxes`
      trae `mcp: [{profile, endpoint}]`), las mismas dos líneas con su
      nombre, su variable y su *endpoint*: para `acme-ops` en `/v1/mcp`,
      `claude mcp add … acme-ops "$KLAV_FORWARD_ACME_OPS_URL/v1/mcp" …` y
      `codex mcp add acme-ops --url "$KLAV_FORWARD_ACME_OPS_URL/v1/mcp"`.
      Para `maple` en `/mcp` son las de arriba, byte a byte. Un `maple` que
      el proxy no lista como MCP (un proxy anterior, o la puerta del ADR
      0036) sigue llevando las de arriba por su nombre. Un *endpoint* con
      caracteres que una línea de órdenes leería distinto no da líneas. Si
      el proxy no contesta la lista, `start` entrega el paquete igual, sin
      líneas MCP salvo las de `maple`.

    Las líneas necesitan un `klav-forward` de esta versión de Klav o
    posterior, el primero con `down --if-other-package`. Con uno anterior,
    la primera línea sale con `2` (`unexpected argument
    '--if-other-package' found`, o `unrecognized subcommand 'down'`) y
    `set -e` para el *script* antes de `up`, sin reclamar nada: hay que
    poner un `klav-forward` actual en la imagen del sandbox y correr las
    mismas líneas con el mismo paquete, que sigue sirviendo. `klav sandbox
    start` no mira la versión de `klav-forward`. Un sandbox que nadie
    reclama termina por inactividad una hora después de empezar, o antes si
    su `--ttl` es menor.
  - `--json` da `{sandbox_id, label, profiles, expires_at, setup, next}`,
    con esas líneas en `setup`: tres, más una con el perfil `northflank` y
    dos por cada perfil MCP (o con el perfil `maple`).
- **`ls`** lista solo los sandboxes vivos de este emisor, preguntando al
  proxy: ID, etiqueta, perfiles, vencimiento y si ya se reclamó.
- **`stop`** termina enseguida uno de los suyos, o todos con `--all`
  (salta los que el barrido terminó entre la lista y la parada). Si
  `--all` falla a medias, lo que ya paró sale por stdout, también con
  `--json` (`{stopped, logged}`), y el error después. Uno
  ajeno recibe la misma respuesta que uno que no existe. Funciona también
  con los agentes en pausa: terminar solo quita acceso. Si el proxy no
  llega al servidor, el sandbox ya está terminado y la bitácora lo
  registra cuando pueda (`"logged": false`).

Códigos de salida, además de los de §9:

| Código | Cuándo |
|---|---|
| 1 | El proxy no contesta en ese puerto (`klav_proxy_unreachable`), el sandbox no existe, u otro error |
| 5 | El grant del emisor no nombra proxy (`klav_no_proxy`: la persona apagó o cambió el proxy de la cuenta, o le quitó a este agente, sin proyectos, el permiso de empezar sandboxes; el grant firmado es el mismo en los tres casos), el agente no es emisor (`klav_not_issuer`), un perfil que no tiene (`klav_profile_not_allowed`) o ya tiene todos los sandboxes que puede (`klav_too_many_sandboxes`) |
| 7 | La persona pausó los agentes o a este (`klav_agents_paused`) |
| 8 | La persona pidió borrar la cuenta (`klav_account_deleting`) |
| 128 + señal | Una señal antes de que corra el comando (130 con Ctrl-C) |

Cada rechazo del proxy, y los de `klav_no_proxy` y `klav_not_issuer`, dicen
en `Next:` qué hacer; los del estado del propio agente (pausa, cuenta en
borrado) dan el mensaje de siempre. Todo texto que llega del puerto del
proxy (mensajes de error, etiquetas y perfiles de `ls`, también en
`--json`) se muestra sin caracteres de control ni invisibles. Los de código 5
no se arreglan reintentando: el agente no puede hacerse emisor ni ampliar
sus límites, solo la persona. `klav_rate_limited` se reintenta una vez,
tras unos segundos, y `klav_proxy_unreachable` cuando la persona arranque
`klav-proxy serve`.

**Errores con `--json`.** Si `start`, `ls` o `stop` fallan con `--json`,
además del texto de siempre en stderr y con el mismo código de salida,
escriben en stdout una sola línea de JSON, como `klav-forward`:
`{"error": …, "message": …, "next": …}`. `message` y `next` son el texto
de stderr sin el `klav: ` ni el `Next: ` (y sin caracteres de control ni
invisibles); `next` es `null` cuando el texto no trae `Next:`. `error` es
un código `klav_*` solo donde Klav ya tiene uno: el del rechazo del proxy
(solo si tiene la forma `klav_` seguida de minúsculas, dígitos o `_`),
`klav_no_proxy`, `klav_proxy_unreachable`, `klav_agents_paused` y
`klav_account_deleting`. En lo demás (un error de uso, una señal, una
respuesta del proxy perdida, el servidor de Klav sin respuesta, el estado
del propio agente) vale `null`, y el código de salida los distingue: la CLI
no inventa códigos que parezcan del protocolo. Un `stop --all` que falla a
medias deja en esa misma línea lo que ya paró (`stopped`, `logged`), en un
solo documento JSON. Si stdout está cerrado, la línea se pierde y nada más
cambia: ni stderr ni el código de salida. Excepciones: con `-- COMANDO`, si el comando corre y
falla, stdout es solo del comando y la CLI no añade nada (sale con su
código); en ese modo el JSON de un arranque que funcionó va a stderr, y la
línea de un error que llega antes de que el comando corra, a stdout; y los errores de argumentos que rechaza `clap` antes de correr
nada no dan JSON. El paquete nunca aparece en esta línea.
