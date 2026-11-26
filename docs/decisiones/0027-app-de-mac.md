# 0027 · App de Mac: SwiftUI nativa sobre `klavd`, barra de menús y ventana, un DMG que instala todo y actualizaciones sin dependencias

- Estado: aceptado
- Fecha: 2026-11-05

## Contexto
Hoy, usar Klav en un Mac exige la terminal. Hay que compilar o descargar `klav` y `klavd`, correr `klav signup` o `klav login`, escribir a mano el *plist* del LaunchAgent ([`klavd.md`](../klavd.md) §2), correr `klav extension install-host` ([`extension.md`](../extension.md) §2) y cargar la extensión. Omar quiere una app **nativa en Swift, súper ligera pero bonita**: un DMG que instale todo, para que la gente no tenga que abrir la terminal.

**Lo que ya existe y se reutiliza:**
- **La app de iOS** (ADR [0018](0018-app-ios.md), [`ios.md`](../ios.md)) es SwiftUI sin dependencias de terceros. Ya tiene en `apps/ios/Shared/` el tema claro y oscuro, el dither, la llave en pixel, las fuentes y `CoreService`. Sus pantallas cubren la bóveda, la ficha, el generador, las aprobaciones, las tareas, la salud y la importación.
- **`KlavFFI`** (uniffi sobre `klav-client`) se compila hoy para `aarch64-apple-ios` y `aarch64-apple-ios-sim`.
- **`klavd`** (ADR [0012](0012-daemon-klavd.md)) ya es el motor del escritorio. Guarda la cuenta desbloqueada, hace el desbloqueo con Touch ID con el shim de `klav-touchid` (ADR [0013](0013-touch-id-secure-enclave.md)), sincroniza, firma las aprobaciones y atiende a la extensión.
- **`klav extension install-host`** ya escribe los manifiestos de Chrome, Chromium, Brave, Edge, Arc, Dia y Firefox, incluido el de Mozilla que lee Dia (PR #113).
- **`scripts/macos/build-sign.sh` y `notarize.sh`** firman `klav` y `klavd` con el Developer ID `SZ3F58F8LX` y los notarizan.

**Tamaño de hoy**, medido el 2026-11-05 en *release* para `aarch64-apple-darwin`: `klav` 15,7 MB, `klavd` 11,3 MB y `klav-native-host` 2,9 MB. Suman unos 30 MB sin comprimir.

## Decisión propuesta

### 1. Forma: una sola app con barra de menús y ventana
- **La barra de menús** (`MenuBarExtra`) se queda siempre visible:
  - el estado (bloqueada o desbloqueada) y desbloquear con Touch ID;
  - la búsqueda rápida con copiar usuario, contraseña o código;
  - las aprobaciones y tareas pendientes, con su número en el ícono;
  - «Abrir Klav» y «Bloquear».
- **La ventana** tiene lo demás:
  - la bienvenida y la instalación (§4);
  - el registro y el inicio de sesión;
  - la bóveda con la ficha;
  - los agentes, las aprobaciones y las tareas;
  - la salud, la importación y los ajustes.
- **El ícono del Dock** solo aparece con la ventana abierta: la app cambia su `activationPolicy` de `.accessory` a `.regular` y vuelve al cerrarla, como hacen muchas utilidades de barra de menús.
- **Los avisos son locales.** Mientras corre, la app le pide a `klavd` las aprobaciones y tareas pendientes, y muestra un aviso del sistema por cada una nueva. En el Mac no hay APNs: exigiría un perfil de aprovisionamiento con el *entitlement* de avisos para una app de Developer ID, y la app ya está despierta en la barra de menús. Para el Mac apagado está el iPhone.
- **Descartado, solo la barra de menús:** el registro, la bienvenida y la bóveda con 350 elementos no caben en un *popover*.
- **Descartado, solo la ventana:** las aprobaciones de agentes llegan mientras la persona trabaja en otra app. Un ícono con el número y un aviso del sistema (`UserNotifications`) son la forma de no perderlas sin tener una ventana abierta.

### 2. Target macOS nativo, no Mac Catalyst
**Se recomienda un target de macOS en SwiftUI**, en el mismo `apps/ios/project.yml` (XcodeGen), con sus fuentes en `apps/ios/Mac/` y lo común en `apps/ios/Shared/`.

| | macOS nativo | Mac Catalyst |
|---|---|---|
| Barra de menús | `MenuBarExtra` | no existe en Catalyst; haría falta un *bundle* de AppKit cargado aparte |
| LaunchAgent | `SMAppService.agent` | disponible, pero desde un proceso de UIKit |
| Aspecto | controles, menús, atajos y ventanas de Mac | una app de iPad en una ventana |
| Reutilización | las vistas de SwiftUI con `#if os(macOS)` donde cambian (`UIPasteboard` frente a `NSPasteboard`, hojas, barras) | casi todo tal cual, incluido lo que en un Mac sobra |
| Tamaño | solo AppKit y SwiftUI del sistema | arrastra la capa de UIKit para Mac |

El argumento de Catalyst es reutilizar más código. Aquí pesa menos, porque la app de Mac no es la de iOS en grande: es una app de barra de menús que instala ayudantes. El código común se lleva a `Shared/` en una capa propia (§8, capa 2), sin cambiar lo que ve la persona en iOS.

**Versión mínima: macOS 15 (Sequoia).** Es la del mismo año que iOS 18, el mínimo de la app de iOS, así que las vistas comunes usan las mismas API de SwiftUI sin `#available`. La capa 2 lo comprueba compilando `Shared/` para macOS 15. Bajar a macOS 14 queda como pregunta (M3).

**Solo Apple Silicon** (`arm64`). Una app universal casi dobla el tamaño (§5) para Macs que Apple ya no vende, y los Intel tampoco tienen simulador de iOS en este repo (ADR 0018 §1). Queda como pregunta (M4).

### 3. El motor es `klavd`, no un segundo `klav-client` dentro de la app
**La app de Mac es un cliente de `klavd`, como la CLI y la extensión.** No guarda la cuenta desbloqueada en su propio proceso.

- **Por qué:** con un `klav-client` dentro de la app habría dos estados desbloqueados en el mismo Mac. Habría también dos altas de Touch ID (`touchid.json` de `klavd` y otra de la app) y dos procesos renovando el mismo *refresh token* de un solo uso. La extensión diría «bloqueada» mientras la app dice «abierta». Con `klavd` como único motor, bloquear en la barra de menús bloquea la extensión y la CLI, y al revés.
- **`KlavFFI` gana una rebanada `aarch64-apple-darwin`** en el XCFramework (`scripts/ios/build-xcframework.sh`), con dos partes:
  - **El cliente del socket de `klavd`**, en Rust: `klav-daemon::client`, que ya usan la CLI y `klav-native-host`, expuesto con uniffi como un objeto `DaemonEngine`. Habla el protocolo de [`klavd.md`](../klavd.md) §3 por el socket de `$KLAV_HOME`, con el mismo control de UID (T32).
  - **El registro y el inicio de sesión** con `klav-client` dentro del proceso, como `klav signup` y `klav login` en modo directo. Escriben `account.json`, la sesión y la caché en `$KLAV_HOME`, sueltan la cuenta y le piden a `klavd` el `unlock` con la contraseña, que da de alta Touch ID (ADR 0013 §5). Es exactamente lo que hace hoy `klav login` seguido de `klav unlock`, con el candado de `session.lock` entre procesos (ADR 0011 §7).
- **Las vistas de SwiftUI no saben cuál de los dos motores tienen.** `Shared/` define un protocolo de Swift con lo que la interfaz necesita (listar, ver, editar, aprobar, tareas, salud…). En iOS lo implementa `KlavCore` y en macOS, `DaemonEngine`.
- **`KLAV_HOME`** es el de siempre en macOS, `~/Library/Application Support/klav` (ADR 0011 §5). La CLI, la extensión y la app ven la misma cuenta. Por eso la app no puede ir en el *sandbox* (§6).
- **Operaciones que faltan en `klavd`:** las que la app necesite y `klavd` no tenga entran como `op` nuevas de la versión 1 del protocolo. Una `op` desconocida responde `bad_request` en un `klavd` viejo, pero la app lleva su propio `klavd` (§4), así que van siempre juntos. Si la app encuentra un `klavd` de otra versión corriendo (`status` devuelve `version`), lo reinicia con el del *bundle* (§4.1).
- **`kind` del dispositivo:** la app inicia sesión como el dispositivo del Mac, que comparten la CLI y `klavd`. Se propone un valor nuevo `macos` en `DeviceKind` (`klav-proto`). El servidor rechaza un valor que no conoce, así que la capa del servidor va antes que la de la app. Mientras tanto, se usa `daemon`.
- **Kit de emergencia:** el registro lo ofrece como PDF, con PDFKit y el diálogo de imprimir y guardar del sistema. Los datos salen de `EmergencyKit` de `klav-core` (especificación §4.2). El PDF se escribe solo donde la persona elige y nunca se guarda una copia.

### 4. El DMG instala todo
El DMG trae solo `Klav.app` y un alias a `/Applications`. Todo lo demás va **dentro del *bundle***, firmado con el mismo Team ID:

```
Klav.app/Contents/
  MacOS/Klav                                  la app (SwiftUI + KlavFFI)
  Helpers/klav, klavd, klav-native-host       los binarios de siempre
  Library/LaunchAgents/dev.klav.klavd.plist   el LaunchAgent (BundleProgram → Helpers/klavd)
```

*`klavd` vive ahora en `Helpers/klavd.app`, con `Helpers/klavd` como enlace: nota del 2026-11-05, abajo.*

La bienvenida («Configurar este Mac») hace cinco pasos. Cada uno dice qué va a tocar antes de hacerlo, y se puede repetir desde Ajustes › Este Mac.

1. **`klavd` como LaunchAgent**, con `SMAppService.agent(plistName:)`. El *plist* vive dentro del *bundle*, no en `~/Library/LaunchAgents`, así que ningún proceso puede editarlo sin romper la firma. macOS lo muestra en Ajustes del Sistema › General › Ítems de inicio como «Klav», y la persona puede apagarlo ahí.
2. **La CLI en el PATH:** un enlace simbólico `/usr/local/bin/klav` → `Klav.app/Contents/Helpers/klav`, como hace VS Code con `code`.
   - Pide la contraseña de administrador una vez, porque `/usr/local/bin` es de `root` y en Apple Silicon a veces ni existe. El enlace queda de `root`.
   - Como apunta dentro del *bundle*, cada actualización de la app actualiza la CLI.
   - Si ya hay otro `klav` antes en el PATH (por ejemplo `~/.cargo/bin/klav`), la app lo dice con su ruta y no lo toca.
   - Si la persona no quiere dar la contraseña, la app muestra el comando para hacerlo a mano.
3. **Los *native messaging hosts*:** la app corre `Helpers/klav extension install-host` para los navegadores instalados (Chrome, Chromium, Brave, Edge, Arc, Dia y Firefox; para Dia también el manifiesto de Mozilla). El *wrapper* de `$KLAV_HOME/native-host/` apunta a `Helpers/klav-native-host`.
   - **Sin la extensión de desarrollo por defecto.** La app corre `install-host` sin `--dev`: Firefox (ID fijo) y, en Chromium, solo los IDs de la tienda (`STORE_CHROMIUM_IDS`, vacío hasta que Chrome Web Store asigne uno). Mientras esté vacío no conecta ningún navegador Chromium, y el paso lo dice. La opción avanzada «Extensión de desarrollo», apagada por defecto y guardada en las preferencias de la app, añade `--dev` para Chrome, Dia y los demás Chromium. Antes de encenderla, la app explica el riesgo en una frase: cualquier extensión sin empaquetar con la llave pública del repositorio podría hablar con `klavd`. Apagarla quita al momento los manifiestos de Chromium y el *wrapper* de la app (T122).
   - **Manifiestos y `klavd` de otra ruta.** Antes de escribir, la app busca un manifiesto que apunte a otro *host* y un `klavd` corriendo desde otra ruta (`ps`), por ejemplo de una instalación con `cargo`. A Omar le pasó en Dia: un manifiesto viejo en el directorio de Mozilla ganaba al nuevo. La app enseña la ruta y ofrece «Usar el de esta app». Nunca lo reemplaza sin preguntar.
4. **La extensión:** por cada navegador detectado, un botón que abre su página en la tienda.
   - Hasta que existan las fichas de Chrome Web Store y addons.mozilla.org (roadmap, fase 5, pendiente de Omar), abre una página con los pasos para cargarla a mano.
   - La app sabe si la extensión ya habló con `klavd`: un campo opcional nuevo en `status` dice qué navegadores conectaron su *host* y cuándo. Así marca «Conectada en Dia».
5. **La cuenta:** registro o inicio de sesión (§3), con el servidor por defecto del ADR [0028](0028-servidor-por-defecto-klav-dev.md), o con «Añadir este Mac desde el iPhone» cuando exista el ADR [0029](0029-anadir-dispositivo-con-qr.md).

**La app no se instala desde el DMG.** Si corre traslocada (Gatekeeper la abre desde una ruta temporal porque sigue en el DMG o en Descargas), no hace ningún paso y pide moverla a Aplicaciones: un enlace o un LaunchAgent que apunten a una ruta traslocada se rompen.

#### 4.1 Actualizar y desinstalar
- **Al actualizar,** la app reemplaza el *bundle* entero, y con él los ayudantes. Al abrir la versión nueva, si `klavd` corre con otra versión, la app le pide `shutdown` y lo vuelve a lanzar con `launchctl kickstart`. `KeepAlive` solo lo relanza tras una salida con error, y `shutdown` sale bien. El desbloqueo se pierde: la persona vuelve a poner el dedo.
- **«Desinstalar Klav de este Mac»** (en el menú de la app) quita el LaunchAgent (`unregister`), el enlace de `/usr/local/bin` y los manifiestos de los navegadores. `$KLAV_HOME` solo se borra si la persona lo marca, porque guarda el Secret Key y la caché.

### 5. Ligera: presupuesto
Sin Electron, sin `WKWebView` y sin dependencias de terceros en Swift (igual que ADR 0018 §7). Solo SwiftUI, AppKit y los *frameworks* del sistema.

| Medida | Presupuesto (arm64) | Cómo se mide |
|---|---|---|
| DMG | ≤ 26 MB (25 MB hasta el 2026-11-26) | tamaño del archivo (`hdiutil create -format ULFO`) |
| `Klav.app` instalada | ≤ 60 MB | `du -sh`; los ayudantes son ~30 MB de ese total |
| Memoria, solo la barra de menús | ≤ 40 MB | `footprint` de `Klav` tras 10 min en reposo |
| Memoria, ventana abierta con 1000 elementos | ≤ 120 MB | lo mismo, con una bóveda de prueba |
| Arranque hasta el ícono de la barra | ≤ 0,5 s | desde el inicio de sesión del Mac |
| `klavd` | lo de hoy | ya medido aparte; durante un desbloqueo con contraseña sube 256 MiB por Argon2id (especificación §4.4), solo mientras dura |

- `klav` y `klavd` enlazan cada uno su `klav-client`. Si el DMG pasa del presupuesto, la primera palanca es un solo binario que actúe como `klav` o `klavd` según su nombre. Queda fuera de este ADR.
- **2026-11-26:** Omar subió el tope del DMG de 25 MB a 26 MB para el proxy alojado de Klav Cloud ([ADR 0051](0051-hosted-nitro-enclave-proxy.md) §17): la verificación de la atestación (`nitro-attestation`) añade unos 85 KB comprimidos a cada binario que la enlaza (`klav`, `klavd` y la app), y al DMG le quedaban unos 60 KB.
- La CI comprueba el tamaño del DMG cuando exista un *runner* de macOS (ADR 0018 §7). Hasta entonces, el script del DMG falla si se pasa.

### 6. Distribución: Developer ID, notarización y DMG
- **Firma:** `Klav.app` y cada ayudante con el Developer ID `SZ3F58F8LX`, *hardened runtime* y sello de tiempo, de dentro hacia fuera. Sin *sandbox* y sin *entitlements* que relajen el *hardened runtime*: la app no carga código de otros equipos.
- **Notarización** con `notarytool` y el perfil del llavero de ADR 0013 §8, y **grapado** (`stapler staple`) de la app y del DMG. A diferencia de los binarios sueltos de hoy, una app y un DMG sí se pueden grapar, así que Gatekeeper no necesita red la primera vez.
- **Script nuevo** `scripts/macos/build-app.sh`: compila los ayudantes y la app, firma, arma el DMG, lo notariza y lo grapa. Las credenciales siguen fuera del repositorio y de `argv`.
- **Mac App Store: se recomienda que no**, y queda como pregunta (M6). El *sandbox* obligatorio impide justo lo que hace esta app:
  - escribir manifiestos en los directorios de otros navegadores;
  - crear el enlace de la CLI;
  - compartir `$KLAV_HOME` con `klav` y `klavd`, porque el contenedor del *sandbox* es otra ruta.

  Las excepciones temporales del *sandbox* que lo permitirían son justo las que App Review rechaza. Una versión de la tienda sería otra app: sin CLI, sin extensión y con su propio motor.

### 7. Actualizaciones: Sparkle 2
**Omar eligió Sparkle (M5, 2026-11-05)**: la app se actualiza sola, como la mayoría de apps de Mac. La tabla queda como registro de lo que se comparó.

- **Sparkle 2 por Swift Package Manager**, con la versión fijada exacta en `Package.resolved` (al menos dos semanas de antigüedad) y sin actualizaciones automáticas de la dependencia. Es la primera dependencia de terceros en Swift: este ADR la aprueba como excepción al ADR 0018 §7, solo para el *target* de macOS.
- **El *appcast*** vive en `https://klav.dev/releases/mac/appcast.xml`, con cada DMG firmado con la llave EdDSA de Sparkle. La llave pública va en el `Info.plist`; la privada **se guarda en la bóveda de Omar**, con copia en el kit de emergencia del proyecto, y solo la usa `scripts/macos/build-app.sh` al publicar.
- **Dos comprobaciones, no una:** la firma EdDSA de Sparkle y, además, el requisito de código del Team ID de abajo sobre la app nueva antes de reemplazar la actual (Sparkle lo permite). Así, quien se quede con `klav.dev` no puede colar una «Klav» notarizada con otra cuenta de Apple, y quien robe la llave EdDSA tampoco, sin el Developer ID.
- La criptografía de Sparkle autentica la distribución, como TLS (ADR 0011): no toca la bóveda ni pasa por `klav-core`.

| | Aviso propio | Sparkle 2 |
|---|---|---|
| Qué hace | una vez al día pide un JSON pequeño (`https://klav.dev/releases/mac.json`: versión, notas y URL del DMG), y si hay versión nueva dice «Hay una versión nueva» y abre la descarga en el navegador; la persona arrastra la app nueva | descarga, verifica e instala en su sitio, con *deltas* y relanzamiento |
| Dependencia | ninguna | **la primera dependencia de terceros en Swift** (contra ADR 0018 §7), con su propio XPC de instalación |
| Criptografía | ninguna propia: la autenticidad del DMG la dan Gatekeeper y la notarización | verifica cada actualización con su propia firma EdDSA (Ed25519), fuera de `klav-core`. Es autenticación de la distribución, como TLS (ADR 0011), pero es criptografía que no pasa por el núcleo; por eso necesita este ADR y que Omar la apruebe |
| Llaves que cuidar | ninguna más | una llave privada EdDSA de Sparkle, aparte del Developer ID |
| Comodidad | dos clics y arrastrar | un clic |

**El riesgo de las dos es el mismo dominio.** Quien se quede con `klav.dev` (ADR 0028 §6) puede servir un JSON que apunte a un DMG suyo.
- Gatekeeper rechaza lo que no esté firmado y notarizado, pero **acepta cualquier Developer ID**: un atacante con su propia cuenta de Apple puede notarizar una «Klav» falsa.
- **Por eso la app no confía en Gatekeeper solo** (con el aviso propio, o junto a Sparkle, §7 arriba). Si la descarga la hace la app (opción «Descargar» además de «Abrir en el navegador»), comprueba la firma del `Klav.app` descargado con un requisito de código `anchor apple generic and certificate leaf[subject.OU] = "SZ3F58F8LX"` antes de abrirlo, y se niega si no coincide.
- Con Sparkle, la defensa es su llave EdDSA, que no está en el dominio.
- En los dos casos, el JSON solo lleva la versión y una URL: nunca un comando ni un script.

### 8. Seguridad: la app es otro cliente
- **La criptografía sigue en `klav-core`.** La app no descifra nada: lo hace `klavd`. El registro y el inicio de sesión pasan por `klav-client`, dentro de `KlavFFI`.
- **`unsafe` solo donde ya está:** el código generado por uniffi en `klav-ffi` y el shim de Touch ID de `klav-touchid`, que usa `klavd`. Touch ID lo pide `klavd` (ADR 0013), así que la app no tiene código propio del Secure Enclave. La app de Swift no usa punteros inseguros.
- **Secretos en Swift:** la contraseña maestra al iniciar sesión y los valores que la persona revela o copia cruzan como `String`, igual que en iOS (ADR 0018 §1). La llave local y las de la bóveda nunca llegan a la app.
- **El portapapeles** se vacía a los 30 s, sin Handoff (`NSPasteboard` con `.currentHostOnly`), como en la extensión y en iOS (T36).

**Amenazas nuevas.** Entraron en la §5.11 del [modelo de amenazas](../modelo-de-amenazas.md) con estos IDs. Van después de los que ya usa `main` el 2026-11-05: T109–T112 (ADR 0028), los reservados para el QR (T113–T117, ADR 0029) y los de la ronda de seguridad (T118 y T119, ADR 0030). El riesgo residual va con el número 43, porque esa ronda usa hasta el 42:

| ID | Amenaza | Mitigación |
|---|---|---|
| T120 | Otro programa del usuario cambia un ayudante dentro de `Klav.app` o el destino del enlace de la CLI | El enlace es de `root` y apunta dentro del *bundle*. El *plist* del LaunchAgent está en el *bundle* (`SMAppService`) y no en `~/Library/LaunchAgents`. Un proceso del mismo usuario que reescribe el *bundle* ya está fuera de alcance (§6: puede leer `$KLAV_HOME` y la memoria de `klavd`). La app comprueba al arrancar la firma de sus ayudantes con el mismo requisito de §7, y si falla no lanza `klavd` |
| T121 | Persistencia: el LaunchAgent de Klav queda instalado aunque la persona borre la app | `SMAppService` lo da de baja si la app desaparece, y macOS lo enseña en «Ítems de inicio». «Desinstalar Klav de este Mac» quita también el enlace y los manifiestos (§4.1) |
| T122 | La app conecta los navegadores a `klavd` de más: pisa una instalación que la persona hizo a mano (`cargo install`, otro `KLAV_HOME`, un manifiesto propio) y la extensión acaba hablando con otro `klavd`, o deja entrar a cualquier extensión sin empaquetar que use la llave pública del repositorio (el ID de desarrollo de Chromium, T64) | La app detecta manifiestos y `klavd` de otras rutas y pregunta antes de reemplazarlos (§4, paso 3). No toca `~/.cargo/bin` ni otro `klav` del PATH, salvo lo que haya en la ruta de su propio enlace (`/usr/local/bin/klav`): eso lo reemplaza solo después de preguntar, con la ruta en la pregunta y, si es un enlace, adónde apunta. De los demás solo lee su archivo para compararlo con el suyo (T193). Sin `--dev` por defecto: en Chromium solo los IDs de la tienda; la extensión de desarrollo solo con la opción avanzada «Extensión de desarrollo», que explica el riesgo antes de encenderse y, al apagarse, quita los manifiestos de Chromium y el *wrapper* de la app. Si `klav extension install-host --dev` ya la dejó entrar, la app no enciende la opción por su cuenta ni la quita sin avisar: lo dice en el paso «Navegadores» y pregunta si la conserva antes de volver a escribir el *wrapper* |
| T123 | Una actualización falsa (dominio perdido, JSON alterado) instala otra app | Gatekeeper con notarización, y además la comprobación del Team ID de la app descargada (§7), y la llave EdDSA de Sparkle. El JSON no lleva comandos |
| T124 | Una app que imita a Klav pide la contraseña maestra en una ventana parecida | Igual que con cualquier app de escritorio, no se puede impedir. La app de Klav nunca pide la contraseña para aprobar algo si Touch ID está disponible, y el desbloqueo normal es con el dedo. Riesgo residual |

**Riesgo residual nuevo (41):** el desbloqueo con Touch ID lo pide `klavd`, un proceso sin interfaz, así que el diálogo del sistema nombra a «klavd» y no a la app. Una persona que vea un diálogo de Touch ID inesperado no sabe si lo pidió la app, la CLI o la extensión. La barra de menús muestra «Desbloqueando…» mientras dura, para que quede claro. *Desde la nota del 2026-11-05, abajo, el diálogo de la app dice «Klav».*

### 9. Plan por capas
Una pila de `gh stack`, una rama `mac/NN-…` por capa:

1. **ADR:** este ADR aceptado, el modelo de amenazas (§5.11) y el roadmap.
2. **`Shared/` para macOS:** las vistas comunes salen de `apps/ios/Klav/` a `Shared/`, con `#if os` donde cambian; el protocolo del motor (§3) con `KlavCore` detrás. iOS no cambia nada visible: `scripts/ios/test.sh` sigue en verde y las capturas de `ios.md` no cambian.
3. **`KlavFFI` para macOS:** la rebanada `aarch64-apple-darwin`, `DaemonEngine` sobre `klav-daemon::client`, `sign_up` en `KlavCore` y `DeviceKind::Macos` (servidor y `klav-proto` primero). Pruebas de `DaemonEngine` contra un `klavd` real.
4. **App, barra de menús y ventana:** el target `KlavMac`, desbloqueo, bóveda, ficha, aprobaciones, tareas, agentes y salud, con las capturas en un `docs/macos.md` nuevo.
5. **Instalación:** ayudantes en el *bundle*, `SMAppService`, el enlace de la CLI, los manifiestos con la detección de §4 paso 3, la extensión, la traslocación, y desinstalar.
6. **Distribución:** `scripts/macos/build-app.sh` (firma, DMG, notarización y grapado), el presupuesto de §5 en el script, y Sparkle: el *appcast*, la firma EdDSA de cada DMG y la comprobación del Team ID.
7. **Prueba de punta a punta y guía:** `docs/probar-mac.md` con lo que hay que probar a mano en un Mac limpio (otro usuario de macOS): abrir el DMG, instalar, registrarse, la extensión en Dia y Chrome, `klav` en una terminal nueva, actualizar y desinstalar.

## Alternativas descartadas
- **Electron, Tauri o una vista web:** cientos de MB y un motor de navegador entero junto a la bóveda. Omar pidió nativa y ligera.
- **Un instalador `.pkg`** con *scripts* de `postinstall`: puede escribir en cualquier sitio como `root`, que es justo el poder que no hace falta. El DMG con la app que se configura a sí misma pide permisos solo para el enlace de la CLI, y la persona ve cada paso.
- **Homebrew como vía principal:** sigue siendo terminal. Puede llegar después (una *cask* que instala el mismo DMG), sin cambiar nada de esto.
- **La app con su propio `klav-client` en memoria** (como iOS): dos estados desbloqueados en el mismo Mac (§3).
- **Mac Catalyst:** §2.

## Consecuencias
- **`docs/diseno.md` §8:** la app de escritorio sale de «Fuera del MVP» para macOS (Windows y Linux siguen fuera).
- **Modelo de amenazas:** §5.11 con T120–T124 y el riesgo residual 43 (§8).
- **`klavd.md`:** las `op` nuevas que necesite la app, el campo de navegadores conectados en `status`, y el LaunchAgent por `SMAppService` en lugar del *plist* a mano (que sigue documentado para quien no usa la app).
- **`extension.md` §2:** la app como forma normal de instalar el *host*.
- **`klav-proto`:** `DeviceKind::Macos`.
- **`scripts/ios/build-xcframework.sh`:** una tercera rebanada, que alarga la compilación local.
- **Dependencias:** una nueva, Sparkle 2, solo en el *target* de macOS (M5).
- **Lo que solo puede hacer Omar:** la notarización con sus credenciales, probar Touch ID con el dedo, probar en un Mac limpio y, si se quiere, la cuenta de la Mac App Store.

## Respuestas de Omar (2026-11-05)
Omar aceptó todas las respuestas por defecto salvo M5, donde eligió Sparkle.

| # | Pregunta | Respuesta |
|---|---|---|
| M1 | ¿Barra de menús, ventana o ambas? | Ambas: la barra siempre, la ventana para la bóveda y la configuración, y el Dock solo con la ventana abierta |
| M2 | ¿Mac Catalyst o target de macOS nativo? | macOS nativo en SwiftUI, compartiendo `Shared/` con iOS |
| M3 | ¿macOS mínimo? | macOS 15 (Sequoia), el mismo año que iOS 18 |
| M4 | ¿Solo Apple Silicon o universal? | Solo `arm64` |
| M5 | ¿Sparkle o un aviso propio? | **Sparkle 2**, aprobada como dependencia nueva (§7), con la firma EdDSA y la comprobación del Team ID |
| M6 | ¿También en la Mac App Store? | No: el *sandbox* impide la CLI, los *hosts* y compartir `KLAV_HOME` |
| M7 | ¿Cómo va la CLI al PATH? | Enlace `/usr/local/bin/klav` al *bundle*, con la contraseña de administrador una vez |
| M8 | ¿Qué hace la app con una instalación a mano (`cargo`, manifiestos propios)? | La detecta y pregunta; nunca la reemplaza sola |
| M9 | ¿Identificador del *bundle*? | `dev.klav.mac`, con el prefijo de `Local.xcconfig` como en iOS |

## Nota (2026-11-05): el diálogo de Touch ID dice «Klav», no «klavd»
El riesgo residual 43 venía de que el diálogo nombraba a «klavd», con el ícono genérico de un ejecutable. La decisión no cambia: Touch ID lo sigue pidiendo `klavd` (§3). Cambia dónde vive su binario dentro del *bundle* de §4.

**Qué se probó.** Un arnés desechable, fuera del repositorio, llamó a `LAContext.evaluatePolicy` desde cada variante. El diálogo real se capturó con `screencapture` y se cerró con `invalidate()`, sin poner el dedo:

| Variante | Nombre e ícono en el diálogo |
|---|---|
| Binario suelto `klavd` (lo de antes) | «klavd», ícono de ejecutable |
| (a) El mismo binario con un `Info.plist` incrustado (`__TEXT,__info_plist`, `CFBundleDisplayName` Klav) | «klavd», ícono de ejecutable: no cambia nada |
| (b) El binario dentro de `Helpers/Klav.app`, con `Info.plist` e ícono | «Klav», ícono de la app |
| (b2) Igual, con otro nombre de carpeta (`KlavAgentHelper.app`) | «Klav»: manda `CFBundleDisplayName`, no el nombre de la carpeta |
| (c) Como LaunchAgent, el binario suelto | «klavd» |
| (c2) Como LaunchAgent, el binario del *bundle* anidado | «Klav», ícono de la app |
| (d) Un enlace simbólico al binario del *bundle*, lanzado directo | «Klav», ícono de la app |
| (e) El mismo enlace, como LaunchAgent | «Klav», ícono de la app |

macOS toma el nombre y el ícono del *bundle* que guarda el ejecutable, y un enlace no lo cambia: cuenta el archivo al que lleva.

**Qué cambia:**

```
Klav.app/Contents/Helpers/
  klav, klav-native-host
  klavd.app/                 dev.klav.klavd, «Klav», LSUIElement, el ícono de la app
    Contents/MacOS/klavd
  klavd -> klavd.app/Contents/MacOS/klavd
```

- **`embed-helpers.sh`** arma `klavd.app` con `scripts/macos/klavd-Info.plist`, las versiones de la app y su `AppIcon.icns`.
- **`Helpers/klavd` queda como enlace relativo**, para lo que ejecuta `klavd` por esa ruta:
  - `klav` y `klav-native-host`, que arrancan el `klavd` de al lado (la prueba `the_cli_in_the_app_starts_klavd_through_the_link_to_its_bundle`);
  - `--version` al actualizar (§4.1);
  - el `same()` del instalador, que resuelve enlaces;
  - desinstalar;
  - un LaunchAgent cargado con el *plist* de una versión anterior.
- **El `BundleProgram`** del *plist* apunta al binario de dentro (`Contents/Helpers/klavd.app/Contents/MacOS/klavd`), no al enlace, porque una comprobación estática de la firma a través de un enlace falla (`-67030`) aunque la firma sea buena.
- **Por la misma razón, T120** (`HelperSignature`) y `build-app.sh` firman y comprueban `klavd.app`, no `Helpers/klavd`, y exigen que `Helpers/klavd` sea exactamente el enlace.
- **Sin `build.rs`:** la variante (a) muestra que un `Info.plist` incrustado no cambia el nombre. Un `klavd` de `cargo install` sigue saliendo como «klavd» (riesgo 43).

**Visto en la compilación Debug:**
- `codesign --verify --deep --strict` acepta el enlace dentro de `Helpers` y valida `klavd.app`.
- `Helpers/klavd --version` responde a través del enlace.
- Launch Services registra `klavd.app` como una app más («Klav», `dev.klav.klavd`) al registrar `Klav.app`. Con `LSUIElement` no sale en el Dock, y sin tipos de documento no aparece en «Abrir con». Spotlight no la encontró (`mdfind`).
- El Monitor de Actividad puede mostrar el proceso de `klavd` como «Klav».

**Lo que no se pudo probar aquí:** que `SMAppService` registre el *plist* con el `BundleProgram` nuevo. Habría hecho falta registrar un ítem de inicio en el Mac de Omar. Lo cubre el paso 4.1 de [`probar-mac.md`](../probar-mac.md), en un usuario limpio.
