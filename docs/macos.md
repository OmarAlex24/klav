# App de Mac

La app nativa de Klav para macOS ([ADR 0027](decisiones/0027-app-de-mac.md)): SwiftUI para macOS 15 o más nuevo, solo Apple Silicon, siempre en la barra de menús y con una ventana para la bóveda y los agentes. Es otro cliente de `klavd`: desbloquear en la app desbloquea también la extensión y la CLI, y bloquear en cualquiera de los tres bloquea a los demás.

Esta página cubre la app, la instalación desde ella, el DMG y las actualizaciones (capas 3 a 6 del ADR). La prueba a mano en un Mac limpio está en [probar-mac.md](probar-mac.md).

| Bóveda | Solicitudes de agentes | Bóveda, en oscuro |
|---|---|---|
| ![La bóveda con la ficha de GitHub](img/mac/boveda.png) | ![Un agente que pide unirse y una tarea por decidir](img/mac/solicitudes.png) | ![La bóveda en oscuro](img/mac/boveda-oscuro.png) |

| Barra de menús | Barra de menús, en oscuro | Bloqueada | Salud de la bóveda |
|---|---|---|---|
| ![El panel de la barra de menús](img/mac/menu.png) | ![El panel en oscuro](img/mac/menu-oscuro.png) | ![La cerradura de luz y el desbloqueo](img/mac/bloqueo-oscuro.png) | ![Repetidas, débiles y viejas, con «Arreglar mis contraseñas repetidas»](img/mac/salud.png) |

| Configurar este Mac | En oscuro | Crear la cuenta | Desinstalar |
|---|---|---|---|
| ![Los cinco pasos, con un manifiesto viejo de Dia](img/mac/configurar.png) | ![En oscuro, de una versión anterior de la app: Chrome y Dia esperan a Chrome Web Store, con «Extensión de desarrollo» apagada y su riesgo a la vista. Hoy el paso dice que se conectan con «Extensión de desarrollo», en «Opciones avanzadas»](img/mac/configurar-oscuro.png) | ![La hoja para crear la cuenta](img/mac/crear-cuenta.png) | ![Qué quita y qué deja](img/mac/desinstalar-oscuro.png) |

| Desarrollo › Agentes | Agentes en pausa, en oscuro | Actividad | Quién lo usó |
|---|---|---|---|
| ![«Pausar agentes» arriba y los agentes con su estado, su cliente y su último uso](img/mac/agentes.png) | ![Todos los agentes en pausa: la franja cobalto, el fin y «Reanudar»](img/mac/agentes-pausa-oscuro.png) | ![La bitácora por días, con el estado de la cadena y los filtros](img/mac/actividad.png) | ![Lo que hicieron los agentes con Cloudflare y cómo pasó](img/mac/quien-lo-uso.png) |

| Clientes, en oscuro | Conectar un cliente | El paso «Agentes» | Barra de menús en pausa |
|---|---|---|---|
| ![Cada cliente con su entrada MCP y su skill](img/mac/clientes-oscuro.png) | ![El resumen antes de escribir: solo la entrada de Klav, la copia y el agente](img/mac/conectar.png) | ![La skill en las carpetas de los clientes, con su resumen antes](img/mac/configurar-agentes.png) | ![La pausa en el panel, con «Reanudar»](img/mac/menu-pausa-oscuro.png) |

| La ficha de un agente | Revocar | Revisar un cambio | Llaves por cambiar, en oscuro |
|---|---|---|---|
| ![«deploy-bot» con sus proyectos y los ocho permisos en permitir, preguntar o denegar](img/mac/agente-permisos.png) | ![Qué vio deploy-bot, «Cambiar también las llaves de sus proyectos» marcada y qué hace revocar](img/mac/agente-revocar.png) | ![Solo las diferencias: un proyecto más amplía y pide Touch ID; inyectar pasa a denegar](img/mac/agente-revisar.png) | ![old-scraper revocado, con una de tres llaves cambiada, el error y «Terminar»](img/mac/agente-llaves-oscuro.png) |

| Nuevo elemento | El generador, en oscuro | Editar, en oscuro | Sitios de un agente | Papelera, en oscuro |
|---|---|---|---|---|
| ![«Nuevo elemento» con los cuatro tipos, el proyecto y los campos del login](img/mac/editor-nuevo.png) | ![El generador sobre el editor: los cuatro tipos, la contraseña por clases y su fuerza](img/mac/editor-generador-oscuro.png) | ![Editar GitHub: los secretos dicen «Sin cambios»](img/mac/editor-editar-oscuro.png) | ![Un sitio que añadió deploy-bot, sin confirmar, con «Confirmar» y «Quitar»](img/mac/sitios-agente.png) | ![«¿Mover “Cloudflare” a la papelera?» en una hoja](img/mac/papelera-oscuro.png) |

| Arreglar las repetidas | Una tarea en curso, en oscuro |
|---|---|
| ![La tarjeta para release-agent: los logins que puede cambiar, marcados, con su página de cambio, y los de otro proyecto apagados](img/mac/salud-arreglar.png) | ![«release-agent está cambiando tus contraseñas»: Cloudflare cambiada, AWS en curso](img/mac/salud-progreso-oscuro.png) |

| Desarrollo › Sandboxes | En oscuro | En inglés | En inglés, en oscuro |
|---|---|---|---|
| ![El proxy con su latido, una señal de robo arriba y los sandboxes activos con su estado y «Revocar»](img/mac/sandboxes.png) | ![Lo mismo en oscuro](img/mac/sandboxes-oscuro.png) | ![El panel en inglés](img/mac/sandboxes-ingles.png) | ![El panel en inglés y en oscuro](img/mac/sandboxes-ingles-oscuro.png) |

| Sin proxy | Un latido que retrocede, en oscuro | El aviso de seguridad | «Revocar todos» | En pausa | La señal de robo en la barra de menús |
|---|---|---|---|---|---|
| ![Solo el encabezado: qué se pierde sin proxy y cómo configurarlo](img/mac/sandboxes-sin-proxy.png) | ![El aviso de seguridad en rojo en el encabezado del proxy](img/mac/sandboxes-latido-oscuro.png) | ![Un agente escribió las preferencias: el problema arriba, el comando y las filas de todos los proxies](img/mac/sandboxes-seguridad.png) | ![Cuántos cubre, que no se deshace y los emisores, con «Pausar agentes…»](img/mac/sandboxes-revocar-todos.png) | ![La franja de la pausa y cada fila en pausa](img/mac/sandboxes-pausa.png) | ![«Señal de robo en «chat-118» (según el emisor)» con «Ver»](img/mac/menu-robo.png) |

| Sin sandboxes, con la hora de la lectura | La lista no pasó sus comprobaciones | Lo mismo en la barra de menús | El servidor no registró la revocación |
|---|---|---|---|
| ![El proxy con su latido, «No hay ningún sandbox vivo» y abajo de dónde sale la lista y cuándo se leyó](img/mac/sandboxes-vacio.png) | ![«Problema de seguridad» que nombra el agente del ajuste del proxy que el servidor no lista, con el comando de la terminal y «Volver a leer», sin lista vieja](img/mac/sandboxes-integridad.png) | ![«La lista de sandboxes no pasó sus comprobaciones de seguridad» con «Ver»](img/mac/menu-integridad.png) | ![«El servidor no registró tu revocación» con «Revocar otra vez», «Pausar agentes…» y «Abrir el proxy»](img/mac/sandboxes-sin-registrar.png) |

Todas las capturas usan la bóveda de ejemplo (§4), sin valores reales. Las de Clientes y del paso «Agentes» usan el `klav` de verdad sobre un home temporal con Claude Code, Codex y Cursor de mentira; el resumen de «Conectar» sale de un `--dry-run` fijo, porque ese home no tiene cuenta. Las de Sandboxes usan las filas de ejemplo de `SandboxSamples` (`-KlavSampleSandboxes`), sin proxy ni servidor. Las de la configuración usan además un home temporal con Dia, Chrome y un manifiesto de otra instalación en el directorio de Mozilla.

## 1. Arquitectura

- **El código vive con el de iOS**, en `apps/ios/`, y sale del mismo `project.yml` (ADR 0027 §2):
  - `Mac/` es solo de la app de Mac;
  - `Shared/` es de las dos apps y de la extensión de autollenado, sin `Keystore.swift` ni `CoreService.swift`;
  - `Shared/App/` es de las dos apps: el protocolo del motor, las tarjetas de las solicitudes de agentes, las palabras de las tareas y de la salud, lo que hace el editor de elementos (`ItemDraft`) y el generador (`GeneratorWords`), y la tarjeta de «Arreglar mis contraseñas repetidas» con su progreso (`FixReused`).

  Detalle en [ios.md](ios.md) §1.
- **El motor es `klavd`** (ADR 0027 §3). La rebanada `macos-arm64` de `KlavFFI` trae `DaemonEngine`, un cliente del socket de `klavd` con una conexión por petición. Así, un desbloqueo que espera a Touch ID no detiene el estado de la barra de menús. `DaemonEngine` cumple `VaultEngine`, el mismo protocolo que `KlavCore` en iOS, y además `MacEngine`, con lo que solo hace `klavd`:
  - su estado;
  - desbloquear con Touch ID o con la contraseña, y bloquear;
  - las variantes `…WithPassword` para aprobar en un Mac sin Touch ID.
- **Ningún secreto vive en la app:** los valores se piden a `klavd` cuando la persona los copia o los muestra, como en la CLI con `--reveal`. Al bloquear o al cambiar de elemento, la ficha los olvida.
- **El directorio es el de la CLI y `klavd`:** `KLAV_HOME` si está definido, si no `~/Library/Application Support/klav`. El [ADR 0041](decisiones/0041-presence-for-values-and-the-inject-card.md) §1.2 (aceptado, sin construir) hace que la versión con Developer ID no haga caso de `KLAV_HOME` y use siempre el directorio por defecto; las compilaciones Debug y la app de ejemplo lo siguen respetando. La app no tiene *sandbox*, porque se distribuye fuera de la Mac App Store.
- **`MacModel`** consulta el estado de `klavd` cada 2 s (un socket Unix, barato) y las solicitudes cada 10 s mientras está desbloqueado. Cuando cambia la revisión de `klavd`, las vistas vuelven a leer.
- **Avisos locales:** cada solicitud nueva (una aprobación, un agente que pide unirse o una tarea) avisa con una notificación del sistema. No hay APNs en el Mac (ADR 0027 §1). La primera lectura después de desbloquear solo recuerda lo que ya había. Al pulsar un aviso, la ventana se abre en Solicitudes.

## 2. Barra de menús y ventana

> Los pasos para quien usa Klav están en la página pública [`mac.mdx`](../apps/docs/src/content/docs/apps/mac.mdx) (en `apps/docs/src/content/docs/apps/`); un cambio en esos pasos va primero allí.

- **La app vive en la barra de menús** (`LSUIElement`). El ícono es la llave en pixel, tenue mientras está bloqueada, con el número de solicitudes que esperan al lado. Con todos los agentes en pausa lleva dos barras bajo los dientes (ADR 0033 §7.5). El ícono del Dock aparece solo mientras la ventana está abierta (`DockWhileOpen`), y cerrar la ventana deja la app en la barra.
- **El panel de la barra de menús** muestra:
  - el estado («Se bloquea en 14 min»);
  - una búsqueda con los seis primeros resultados, cada uno con Usuario, Contraseña y Código para copiar sin abrir la ventana. Código aparece solo si `klavd` dice que el elemento tiene uno;
  - la franja de solicitudes;
  - el último uso de un agente («deploy-bot lo rellenó en signin.aws.amazon.com · AWS console · hace 2 min», con el comienzo de su ID), que abre Actividad (ADR 0033 §8.1);
  - en rojo, lo que cambió fuera de Klav: la entrada de un cliente («La entrada de Klav en Cursor cambió», con «Ver» y «Dejarla»), una entrada que corre un programa que no es el de este Klav, o una skill editada («Hay una skill de Klav nueva; la tuya tiene cambios», con «Ver los cambios»). La app lo mira una vez al abrir, si los ayudantes están firmados. «Dejarla» lo calla hasta la próxima vez que se abre (ADR 0033 §4, §6, E1);
  - en rojo, cada señal de robo de un sandbox que la persona no ha contestado: «Señal de robo en «chat-118» (según el emisor)», con «Ver», que abre Desarrollo › Sandboxes (ADR 0036 E4, §9). Sale también con Klav bloqueado si la app ya leyó la lista desde que se abrió (bloqueada no la lee, y al abrirse no tiene ninguna). Si la última lectura falló sus comprobaciones, en su lugar dice «La lista de sandboxes no pasó sus comprobaciones de seguridad», con «Ver»;
  - «Pausar agentes» con «1 hora» o «Hasta que reanude», sin preguntar nada. En pausa, la línea dice hasta cuándo y dónde vale, y «Reanudar» abre Desarrollo › Agentes, donde se reanuda con Touch ID (sin él, con la contraseña maestra). Sale también con la bóveda bloqueada: `klavd` guarda la pausa en este Mac y se la manda al servidor en cuanto puede. Mientras no llega, dice «Todos los agentes están en pausa en este Mac», nunca «en todas partes», y con la bóveda bloqueada ofrece «Desbloquear para pausar en todas partes» en lugar de «Reanudar» (§7.2, §7.3);
  - abajo, junto a las filas de agentes y en tinta, un `klav` más viejo que el de la app: «Hay un klav más viejo en ~/.cargo/bin/klav. Tu terminal puede ejecutarlo en lugar del de esta app.», con «Mostrar» (abre Ajustes › Este Mac) y «Ahora no». Para VoiceOver, los dos botones nombran la ruta (§3, Otro `klav` en el PATH);
  - Abrir Klav, Bloquear y Salir.
- **La ventana tiene una barra lateral** con:
  - todos los elementos, los tipos y las bóvedas (si hay más de una), cada uno con cuántos elementos tiene. Un tipo sin elementos no aparece, como en las pestañas del iPhone y de la extensión, salvo el que está elegido;
  - una línea y Solicitudes, sola: lo que pide una decisión nunca se oculta (ADR 0033 E1);
  - el grupo «Desarrollo», con Agentes, Sandboxes, Actividad y Clientes;
  - el grupo «Contraseñas», con Salud de la bóveda;
  - la cuenta con Bloquear.
- **Bóveda:** la lista va a la izquierda, con búsqueda (⌘F), flechas y códigos en vivo, y la ficha a la derecha.
  - Los campos van en un bloque con cruces en las esquinas.
  - Los secretos aparecen como ruido hasta pulsar Mostrar.
  - El código va en grande.
  - Los sitios tienen Abrir, y la referencia `klav://` se puede copiar.
  - Las notas y las contraseñas anteriores se muestran a petición.
  - Los sitios que añadió un agente van aparte, bajo «Sitios añadidos por *agente*», con borde cobalto, cada uno entero y «Sin confirmar». «Confirmar» y «Quitar» actúan sobre todos, como en el iPhone, la extensión y `klav item sites` (ADR 0030 §7). Arriba, «Abrir» solo sale en los sitios confirmados.
  - **Quién lo usó** (ADR 0033 §8.1): los cinco últimos usos del elemento por un agente (con el comienzo de su ID), con qué hizo, el motivo entre comillas «según el agente», cuándo y cómo pasó («permitido por tu política», «aprobado una vez», «aprobado 15 min», «dentro de la tarea “…”» o «denegado»), y las alertas. «Abrir en la bitácora» abre Actividad filtrada por el elemento.
- **Crear y editar** (lo mismo que en el iPhone, [ios.md](ios.md)): el «+» sobre la lista o ⌘N abre «Nuevo elemento», y «Editar» en la ficha o ⌘E abre el mismo editor sobre el elemento. Lo que hace sale de `Shared/App/ItemDraft.swift`, el mismo código del iPhone: los campos de cada tipo y qué se manda a `create`/`edit` de `klavd`.
  - «Nuevo elemento» trae el tipo que muestra la lista si el editor lo crea (login, llave de API, tarjeta o nota) y si no un login, el proyecto (Personal / General por defecto), el título, los campos de la plantilla, el sitio y las notas.
  - Un título que el proyecto ya tiene se dice antes de guardar, con la regla de `klav-client` (`titleTaken`: sin espacios alrededor ni mayúsculas ASCII), y «Guardar» se apaga. `klavd` lo rechaza igual.
  - «Generar» junto a la contraseña abre el generador de `klav-core` con las reglas del sitio que se está escribiendo, o del primero confirmado: los cuatro tipos, la fuerza, las reglas del sitio y «Usar esta contraseña». Lo que se usa o se copia entra antes en el historial del generador de `klavd` (`generator_record`); si no se pudo guardar, no se usa y lo dice.
  - El código de un solo uso se escribe como llave (base32) o como enlace `otpauth://`: lo lee `klav-core`.
  - Los secretos nunca vienen rellenados: un campo secreto vacío deja el valor que hay («Sin cambios»). Lo escrito vive solo en la hoja y se olvida al cancelar, al guardar y al bloquear (la hoja se cierra); lo que se mostró con «Mostrar» se vuelve a ocultar cuando la app deja de estar al frente. La ficha oculta lo que había mostrado al abrir el editor y al volver de él.
  - Guardar un elemento con sitios que añadió un agente los confirma (ADR 0030 §7), y la hoja lo dice antes.
  - «Mover a la papelera…», al final de la ficha, pide confirmar en una hoja, no en el diálogo del sistema: Return no hace nada y Escape cancela.
  - Después del borrado de la cuenta no hay «+», «Editar» ni papelera (D-C), y una hoja abierta se cierra.
- **Solicitudes:** las tarjetas son las del iPhone (`Shared/App/RequestCards.swift`), en el mismo orden:
  - agentes que piden unirse, con «Comparar palabras» en una hoja. La tarjeta y la hoja muestran el comienzo del ID del agente. Si la cuenta ya tiene un agente con ese nombre, activo, pendiente, denegado o revocado, la tarjeta lo dice (ADR 0033 E2.2); si este Mac registró otro con ese nombre, dice que este no es ese. La nota del agente sale en una línea, «según el agente». La hoja no trae ningún proyecto marcado (P4). Si la app lanzó el registro desde Clientes con su `klav` firmado por el equipo de Klav, compara sola las palabras con las que imprimió y dice «Coinciden (este Mac lanzó el registro)»; si no coinciden, no deja aprobar (§3.1, P5). Una compilación local (Debug) nunca lo hace: ahí se comparan a ojo;
  - tareas por decidir;
  - aprobaciones;
  - tareas en marcha con «Terminar tarea».
- **Desarrollo › Agentes** (ADR 0033 E1, §7.5): arriba, «Pausar agentes» con su duración (15 min, 1 hora, hasta que reanude) y lo que la pausa no detiene (§7.7). En pausa, el bloque dice hasta cuándo, si solo vale en este Mac por ahora o porque el servidor no admite pausas, y «Reanudar» pide Touch ID o, en un Mac sin él, la contraseña maestra; el texto dice cuál de las dos. Debajo, los agentes que esperan, los que tienen acceso y los denegados o revocados, cada uno con su estado, el cliente si su nombre es el de uno (§2), el comienzo de su ID, sus proyectos y su último uso. Los que tienen acceso traen «Pausar» y «Reanudar» propios y «Actividad». Un agente revocado con llaves por cambiar lleva un cuadro rojo y lo dice en su fila.
- **La ficha de un agente** (enmienda del ADR 0033 del 2026-11-10, F1 a F3): se abre al pulsar su fila. El nombre va entre comillas y «nombre puesto por el agente» (T136). Debajo, sus proyectos y, por cada uno de los ocho permisos, «permitir», «preguntar» o «denegar»; el que sigue en su valor por defecto sale atenuado. Las palabras son las del diálogo de `klavd`. Un grant que la app no sabe editar (reglas a mano, de un emisor, de un proxy, o un `klavd` anterior) se muestra solo para leer, con el comando de la CLI que lo cambia, que nombra al agente por su ID: su nombre lo puso él. Si el grant no se puede leer o `klavd` es anterior, proyectos y reglas dicen «No se sabe», nunca «Ninguno»; si `klavd` no contesta, la ficha lo dice y «Revocar…» sigue ahí: revocar nunca depende de leer el grant ni la lista de revocaciones.
  - **«Cambiar permisos…»** abre el editor: proyectos, los ocho permisos, los sitios donde rellena, el horario y la caducidad. «Revisar cambios» le pide a `klavd` la vista previa y la hoja muestra solo sus líneas, las mismas que firmará. Si alguna amplía lo que puede hacer el agente, lo marca y avisa que pedirá Touch ID (o la contraseña maestra en un Mac sin él); reducir no pide nada (P8). Al quitar proyectos ofrece cambiar sus llaves, sin marcar (P9). Si el grant cambió mientras tanto, `klavd` rechaza la firma y la hoja vuelve a cargar.
  - **«Revocar…»** muestra qué vio: los proyectos cuyas llaves tenía, los elementos que usó según la bitácora (con «obtuvo un secreto» o «sin secreto») y cuántos intentos le negó Klav. «Cambiar también las llaves de sus proyectos» viene marcada (P7) y dice cuántos elementos vuelve a envolver y qué otros agentes reciben un grant nuevo. Si no pudo contarlos todos dice «al menos», y si no pudo leer el grant de algún otro agente lo avisa: nunca da por cero lo que no pudo leer. Los proyectos son los del grant más todos los que la bitácora verificada le dio alguna vez. Si este Mac no puede leer el grant, la casilla sigue ahí, marcada, y dice que no sabe qué proyectos tenía. «Revocar», en rojo, no pide Touch ID. Con la casilla marcada, la app pide a `klavd` revocar y cambiar las llaves en segundo plano (`background`): `klavd` apunta el cambio de llaves antes de contestar y lo sigue solo, también tras bloquear y desbloquear. La hoja dice «Revocado» en cuanto el servidor lo confirma y sigue el cambio de llaves desde `status`; se puede cerrar. Con un `klavd` anterior, la app revoca primero y cambia las llaves en una segunda llamada. Con la casilla desmarcada no cambia la llave de ningún proyecto, ni al terminar ni al volver a abrir la ficha; sí cambian las de los elementos que se le compartieron uno por uno (un proxy de credenciales), como siempre al revocar, y la hoja termina en «Revocado», nunca en «cambiaron todas las llaves». Si alguno de esos elementos queda fuera de alcance, la ficha dice cuántos y por qué (su bóveda ya no está, o este Mac ya no los ve) y que, si alguno vuelve a aparecer, Klav le cambia la llave entonces; uno borrado para siempre (purgado) ya no vuelve, así que esa línea se queda. Nunca habla de todas las llaves ni de proyectos (`without_key_change` en `status`; con un `klavd` anterior, que no lo manda, decide la casilla que se marcó en este Mac, y sin ella, una revocación sin proyectos que cambiar). Con la casilla marcada, «Hecho» sale solo cuando `klavd` ya no lista al agente en dos lecturas seguidas con Klav desbloqueado (T189): su registro guarda todo lo que falta, también los elementos sin llave nueva y la bitácora sin leer. Si algo se queda a medias, la ficha dice qué falta y trae «Terminar», y `klavd` lo retoma al desbloquear (P11). «Terminar» respeta la casilla: sin el flujo de esta sesión (la app se reinició), la deduce de lo que `klavd` dice que falta (`without_key_change`; con un `klavd` anterior, que no lo manda, los proyectos contados), y si no se puede saber no cambia la llave de ningún proyecto. Lo que Klav no alcanza (una bóveda borrada o que el servidor ya no lista, un proyecto borrado, un elemento que este Mac ya no ve) no lo bloquea: la ficha dice «Klav cambió todas las llaves a su alcance» y cuántas quedaron fuera, sin «Terminar», nunca «cambiaron todas las llaves», y vuelve a estar pendiente si la bóveda o el elemento vuelven. Un proyecto borrado no vuelve, así que su registro desaparece al terminar; `klavd` sigue diciendo lo que saltó hasta que se reinicia. Si `klavd` no puede leer su registro, la ficha lo dice y nunca da nada por terminado; si lo escribió una versión más nueva de Klav, pide actualizar Klav. El cambio de llaves de proyectos quitados a un agente activo sale en su ficha como tal, sin «Terminar» (revocaría al agente): `klavd` lo retoma en cada desbloqueo.
  - **Con Klav bloqueado**, «Revocar…» dice que hay que desbloquear, que no se revocó nada y que, tras desbloquear, la hoja vuelve a abrirse; mientras tanto ofrece «Pausar todos ahora», que sí funciona bloqueado (P12) y, si falla, dice por qué. Bloquear cierra las dos hojas.
- **Desarrollo › Sandboxes** (⌘7, ADR 0036 E2, E4): el proxy de credenciales arriba y los sandboxes que sirve debajo; los detalles, en §9.
- **Desarrollo › Actividad** (⌘5, §8.1): la bitácora por días, lo más nuevo arriba, sobre la copia en caché de `klavd` (§8.4). Arriba, el estado de la cadena («Verificada hasta el evento #209 · 5 sin verificar todavía») y «Verificar ahora», que corre `verify_audit`. Filtros: texto (títulos, agentes, motivos y sitios), agente, permiso, resultado, periodo y solo con alertas, más el elemento cuando llega desde «Abrir en la bitácora». Cada fila dice quién hizo qué con qué elemento (el agente con el comienzo de su ID, y el sitio que declara «según el agente»), el motivo «según el agente» en una línea, el resultado, las alertas y «Sin verificar todavía». Muestra los 500 más recientes; el resto, `klav log`.
- **Desarrollo › Clientes** (⌘6, §2–§6): una fila por cliente de `klav client list --json`, con su estado (conectado, sin conectar, no instalado, gestionado por la organización, o en rojo la entrada cambiada fuera de Klav o que corre otro programa), su archivo, el agente si está registrado en este Mac y su skill. Arriba, los mismos avisos rojos que en la barra de menús. La casilla «MCP de Klav» conecta o desconecta, y la fila dice que no es un interruptor de seguridad.
  - **Conectar** corre `klav client connect <cliente> --dry-run --json` y muestra el resumen: el archivo (y adónde apunta si es un enlace), la acción, solo la entrada de Klav antes y después (nunca el resto del archivo), los comandos del propio cliente si escribe con su CLI (y qué `claude` o `codex` va a correr, con que usa la configuración de ese archivo y no el `CODEX_HOME` ni el `CLAUDE_CONFIG_DIR` de la terminal), la copia previa, el agente y la skill. Del agente dice si lo registra y si las palabras se comparan solas o a ojo. «Conectar» repite el comando con `--yes --expect-sha256 <el del resumen>`, así que si el archivo cambió mientras tanto no escribe nada.
  - Una entrada de Klav cambiada fuera de Klav se puede volver a poner desde la hoja (`--replace`, con copia). Una entrada `klav` que Klav no escribió es de la persona: la hoja da los comandos para reemplazarla o adoptarla en Terminal, donde `klav` pregunta (§3.4).
  - Si `connect` registra el agente, la app abre Solicitudes. Guarda en memoria el ID y las palabras que imprimió su propio `klav` solo si su firma es la del equipo de Klav (P5).
  - Debajo, el bloque «Skill de Klav» con `klav skill status --json`: la versión que trae este `klav` y cada copia con su ruta, su versión, su estado y sus acciones (§6): «Actualizar», «Quedarme con la mía», «Usar la de Klav (con copia)», «Adoptarla» o «Instalarla otra vez». Una copia editada trae «Ver los cambios», el *diff* línea a línea con la que trae este `klav` (`klav skill show`). Una que la persona guardó con «Quedarme con la mía» dice «Guardada como la editaste», sin rojo ni acciones.
  - La app corre el `klav` del *bundle* con el home de la persona, su `KLAV_HOME` y un PATH como el de una terminal (`/etc/paths`, `/etc/paths.d`, Homebrew, `~/.cargo/bin`, `~/.local/bin`, `~/bin`): abierta desde el Finder, su PATH no tendría `claude` ni `codex`, cuyas CLI escriben sus entradas.
- **La skill al día:** al abrir, si los ayudantes están firmados y la app está en Aplicaciones, corre una vez `klav skill update --json`. Pone al día las copias de Klav que nadie editó; las editadas se quedan y salen en Clientes (§6).
- **Salud de la bóveda:** las contraseñas reutilizadas, débiles, viejas y filtradas que calcula `klavd`, y el interruptor de la comprobación con Have I Been Pwned. Un clic en una fila abre el elemento.
- **Arreglar mis contraseñas repetidas** (ADR 0022 §6), la misma tarjeta del iPhone (`Shared/App/FixReused.swift`): se elige el agente, se desmarcan los sitios que no se quieren, se elige la duración y se aprueba una vez con Touch ID en `klavd`; sin Touch ID, la contraseña maestra en una hoja, que se cierra si Klav se bloquea o se borra la cuenta, y entonces no se ofrece nada. El agente recibe los sitios, nunca cuáles comparten contraseña; los logins de un proyecto fuera de su permiso salen apagados y con el motivo. Mientras la tarea corre, una tarjeta arriba de Salud dice cada sitio como cambiado, en curso, pendiente o fallido; se actualiza cada 5 s solo con el panel abierto y Klav desbloqueado. Al bloquear se olvidan el informe, la tarjeta y el progreso.
- **Atajos:**

  | Atajo | Acción |
  |---|---|
  | ⌘L | Bloquear |
  | ⌘1 | Todos los elementos |
  | ⌘2 | Solicitudes |
  | ⌘3 | Agentes |
  | ⌘4 | Salud |
  | ⌘5 | Actividad |
  | ⌘6 | Clientes |
  | ⌘7 | Sandboxes |
  | ⌘N | Nuevo elemento |
  | ⌘E | Editar el elemento abierto |
  | ⌘F | Buscar |
  | ⌘C | Copiar la contraseña |
  | ⇧⌘C | Copiar el usuario |
  | ⌘O | Abrir Klav (desde el panel) |

- **Portapapeles:** solo en este Mac (`.currentHostOnly`, sin Universal Clipboard) y marcado como oculto y transitorio (`org.nspasteboard.ConcealedType` y `TransientType`), para que los gestores de portapapeles no lo guarden. Se vacía a los 30 s si nadie copió otra cosa.

### Diseño

El lenguaje es el de iOS ([diseno-visual](diseno-visual)):

- los colores Tinta, Papel, Niebla, Línea y Gris, con Cobalto solo para lo que hacen los agentes;
- Geist, Geist Mono para los valores y Departure Mono para los códigos;
- esquinas rectas con cruces;
- el dither de la cerradura de luz.

Lo propio del Mac:

- **La barra lateral** tiene filas cuadradas con una línea de tinta a la izquierda en la elegida, no la selección azul del sistema.
  - Cada fila lleva su ícono de trazo de 16 pt, en gris y en tinta en la elegida o bajo el cursor. Los tipos usan los mismos íconos del iPhone y de la extensión ([diseno-visual](diseno-visual) §7).
  - El número va al final en gris; el de Solicitudes, en un cuadro cobalto porque son cosa de agentes.
  - Solicitudes va sola, sin encabezado, bajo una línea que la separa de la bóveda. «Desarrollo» y «Contraseñas» llevan su nombre en gris.
  - Con todos los agentes en pausa, la fila Agentes lleva una etiqueta «En pausa» con borde cobalto en lugar del número.
- **Los atajos** aparecen al pasar el cursor por cada fila, en el lugar del número. Solicitudes deja ver cuántas esperan.
- **El papel llega hasta la barra de título,** también en oscuro (`containerBackground` sobre la ventana).
- **Las fuentes** van en el *bundle*, cargadas con `ATSApplicationFontsPath`.
- **El ícono** es la llave en pixel de iOS dentro del cuadrado redondeado de macOS, con su margen y su sombra. Cada celda del pixel mide 26 px a 832 px, así que no se remuestrea. Lo genera `scripts/macos/app-icon.swift`.

### Desbloqueo

- **Touch ID lo pide `klavd`, no la app**, pero el diálogo del sistema dice «Klav», con el ícono de la app:
  - macOS nombra al proceso por el *bundle* que guarda su ejecutable, y el `klavd` de la app vive en el suyo, `Contents/Helpers/klavd.app` (§3).
  - Un `klavd` de `cargo install`, sin *bundle*, sigue saliendo como «klavd» con el ícono de un ejecutable (riesgo residual 43 del [modelo de amenazas](modelo-de-amenazas.md)).
  - Mientras espera, la app dice «macOS lo pide en nombre del servicio de Klav en segundo plano», que vale en los dos casos.
- **El texto del diálogo** dice qué se pide, sobre qué elemento y desde dónde, en el idioma del Mac ([klavd.md](klavd.md) §6.1). Desde la app, por ejemplo:
  - Klav está intentando desbloquear tu bóveda para la app de Klav (ana@example.com).
  - Klav está intentando dejar que «claude-code» rellene «GitHub» (desde la app de Klav).

  Los nombres de los agentes y los títulos van limpios y entre comillas, sin IDs ni el motivo del agente (T140).
- **Con la contraseña maestra:** si el Mac no tiene Touch ID, si está apagado o si `klavd` pide la contraseña (tras reiniciar el Mac o cada 14 días), la pantalla de bloqueo pide la contraseña maestra.
- **Aprobaciones sin Touch ID:** se piden con la contraseña maestra en una hoja, y la acción se repite con ella.

### Idiomas

Inglés como base y español desde `Shared/Localizable.xcstrings`, el mismo catálogo de iOS. Los textos que solo usa el Mac van en ese catálogo, con «Touch ID» donde iOS dice «Face ID».

## 3. Configurar este Mac

> Los pasos para quien usa Klav están en las páginas públicas [`install.mdx`](../apps/docs/src/content/docs/get-started/install.mdx) y [`create-an-account.mdx`](../apps/docs/src/content/docs/get-started/create-an-account.mdx) (en `apps/docs/src/content/docs/get-started/`); un cambio en esos pasos va primero allí.

Sin `klavd` o sin cuenta, la ventana abre «Configurar este Mac» (ADR 0027 §4), con seis pasos. Lo mismo, con «Desinstalar Klav de este Mac…», está en Ajustes (⌘,). Cada paso dice qué va a cambiar antes de hacerlo:

1. **Servicio en segundo plano:** registra `klavd` como LaunchAgent con `SMAppService.agent(plistName: "dev.klav.klavd.plist")`.
   - El *plist* va dentro del *bundle* (`Contents/Library/LaunchAgents`), con `BundleProgram` `Contents/Helpers/klavd.app/Contents/MacOS/klavd`: el binario dentro de su *bundle*, no el enlace `Helpers/klavd`, porque una comprobación estática de la firma a través de un enlace falla.
   - Lleva `--if-not-running`: si otro `klavd` ya responde en el socket, sale bien y `KeepAlive` no lo relanza ([klavd.md](klavd.md) §1).
   - Si macOS pide permiso, la app abre Ítems de inicio.
   - Si `klavd` corre desde otra ruta (la de `proc_pidpath` del `pid` de `status`), la app la muestra y ofrece «Usar el de esta app». Eso hace `shutdown` del otro y arranca el suyo.
2. **Línea de comandos:** el enlace `/usr/local/bin/klav` → `Klav.app/Contents/Helpers/klav`, con `do shell script … with administrator privileges` (`mkdir -p` y `ln -sfn`).
   - Si en esa ruta hay otra cosa, la app pregunta antes de reemplazarla, con la ruta en la pregunta y, si es un enlace, adónde apunta (de un archivo no dice más que su ruta). Es lo único fuera de la app que el paso reemplaza.
   - Si hay otro `klav` en el PATH (`/etc/paths`, `/etc/paths.d`, Homebrew, `~/.cargo/bin`, `~/.local/bin`, `~/bin`), avisa con su ruta y lo compara con el suyo (abajo, «Otro `klav` en el PATH»). No lo toca, salvo si está en la ruta del enlace (el punto anterior).
   - «Mejor copiar el comando» copia el `sudo` para hacerlo a mano.
   - `klav unlock` desde el enlace arranca el `klavd` de `Helpers`, porque busca junto al destino del enlace. Ese `Helpers/klavd` es a su vez el enlace a `klavd.app`, y arrancado así el diálogo también dice «Klav».
3. **Navegadores:** `klav extension host-status --json` del *bundle* dice, sin cambiar nada, qué manifiesto hay en cada navegador y qué *host* ejecuta ([cli.md](cli.md) §8).
   - Dia lee el de Mozilla, así que cuenta dos.
   - Uno de otra instalación sale en rojo con la ruta de su *host*. Reemplazarlo pide confirmación, con la lista de lo que cambia. Si ese *host* deja entrar la extensión de desarrollo (otro `klav` corrió `install-host --dev`, aunque sea con este `KLAV_HOME`) y la casilla está apagada, depende de qué puede cambiar la app:
     - Si el manifiesto apunta al *wrapper* de este `KLAV_HOME` y `install-host` va a escribirlo (hay un manifiesto con formato de Firefox que escribir), «Usar el de esta app» lo reescribe sin el ID de desarrollo, y la confirmación dice que deja de conectarse en esos navegadores (`foreignDevBrowsers`): «El host que hay ahora deja entrar la extensión de desarrollo en Chrome. El de esta app no lo hará mientras «Extensión de desarrollo» esté apagada, así que ahí deja de conectarse.»
     - Si apunta al *wrapper* de otro `KLAV_HOME`, o solo hay navegadores Chromium (`install-host` se detiene antes del *wrapper*), la app no puede cambiarlo hasta que Klav esté en Chrome Web Store (`foreignDevKept`). No ofrece reemplazar esos navegadores, no los cuenta como en espera de la tienda, y el paso y la confirmación dicen que la puerta sigue abierta: «El host de otra instalación deja entrar la extensión de desarrollo en Chrome. Klav no puede reemplazarlo ahí mientras no esté en Chrome Web Store, así que la extensión de desarrollo se sigue conectando.»
   - Uno de esta app con el *wrapper* viejo no cuenta como de otra instalación. Apunta al *wrapper* de esta app y ejecuta su *host*, pero ese *host* rechazaría una extensión que el manifiesto permite (`refused`). Pasa, por ejemplo, con un *wrapper* escrito antes de que la de desarrollo necesitara `--dev`. El paso dice «hay que volver a conectarlo», y «Conectar los navegadores» lo reescribe sin preguntar. Uno de otro `KLAV_HOME` sigue siendo de otra instalación aunque ejecute el mismo *host*.
   - «Conectar los navegadores» corre `klav extension install-host --host Helpers/klav-native-host --json`, **sin `--dev`**. Conecta Firefox (su ID es fijo, `klav@klav.dev`) y, en los navegadores Chromium, solo la extensión de la tienda. Su ID va en `STORE_CHROMIUM_IDS` cuando Chrome Web Store lo asigne (PR #164); hasta entonces `klav` deja fuera a Chrome, Dia y los demás Chromium (`skipped` en la salida) y el paso dice cómo conectarlos mientras tanto: «Chrome: se conecta con “Extensión de desarrollo”, en “Opciones avanzadas”, hasta que Klav esté en Chrome Web Store». La extensión de Chromium que publica una versión es la de desarrollo (`klav-extension-chromium.zip`, [releasing.md](releasing.md) §3), con el mismo ID. La app recuerda qué quedó fuera por versión del *bundle*, así que una actualización con el ID de la tienda vuelve a ofrecer el botón.
   - **«Opciones avanzadas» › «Extensión de desarrollo»**, apagada por defecto, añade `--dev`: Chrome, Dia y los demás Chromium dejan entrar a la extensión de desarrollo que el paso 4 carga sin empaquetar. Antes de encenderla, la casilla explica el riesgo en una frase: cualquier extensión sin empaquetar con la llave pública del repositorio podría hablar con `klavd` (ADR 0030, capa 09; T122). La elección se guarda en las preferencias de la app (`devExtension` en `dev.klav.mac`).
   - **Si ya entra la de desarrollo** porque la persona corrió `klav extension install-host --dev` (lo que dice la guía de instalación para la CLI), la app lo ve en un manifiesto suyo y vigente de Chromium que lista ese ID (`cliDevBrowsers`), con la casilla apagada. No la enciende por su cuenta, y abrir la app no cambia nada. El paso lo dice, una línea por navegador: «Chrome: deja entrar la extensión de desarrollo, que se conectó desde la línea de comandos»; ese navegador no cuenta como en espera de la tienda. Los dos botones que conectan los navegadores primero vuelven a leerlos (la persona pudo correr el comando con la ventana abierta) y, antes de volver a escribir el *wrapper*, preguntan «¿Conservar la extensión de desarrollo?», con el riesgo de la casilla y diciendo que conservarla la deja entrar en todos los navegadores Chromium de este Mac. «Conservarla» enciende la casilla y conecta con `--dev`. «Quitarla», en un solo paso, vuelve a leer los navegadores, borra los manifiestos de Chromium de la app que la listan y el *wrapper* de este `KLAV_HOME` (como al apagar la casilla; un manifiesto que `host-status` no ve, de `install-host --dev --user-data-dir`, también apuntaba a él), y vuelve a conectar sin `--dev`. Si `install-host` tiene un manifiesto con formato de Firefox que escribir (Firefox, o la copia de Dia en la carpeta de Mozilla), escribe el *wrapper* otra vez sin el ID de desarrollo. Si solo hay navegadores Chromium, no tiene nada que permitir y se detiene antes, y el *wrapper* no vuelve. En los dos casos ningún *wrapper* lista ese ID y la extensión de desarrollo deja de entrar.
   - «Conectar los navegadores» y «Usar el de esta app» leen los navegadores dentro de su propio paso, no de la lista de `refresh` (que sale vacía si `host-status` falla): si esa lectura falla, el paso se detiene con su error y no escribe nada. Cada lectura lleva un número, y una que termina después de otra más nueva (un `refresh` lento tras conectar) no vuelve a poner su lista vieja.
   - **Una extensión sin llave** cargada sin empaquetar (el paquete de la tienda, `klav-<versión>-chromium.zip`) tiene un ID que sale de su carpeta y entra solo con `klav extension install-host --extension-id <ID>`. La app no lo pasa: «Conectar los navegadores» reescribe el *wrapper* sin él, y el *host* la rechaza desde entonces ([releasing.md](releasing.md) §3).
   - Al apagarla, la app quita en el momento sus manifiestos de Chromium y el *wrapper* (que lleva la lista de extensiones que deja entrar), y vuelve a conectar sin `--dev`. Firefox sigue conectado.
4. **Extensión:** por cada navegador, «Cómo instalarla» abre los pasos para cargarla a mano, en la guía pública (`https://docs.klav.dev/get-started/install/#browser-extension`), hasta que esté en las tiendas. «Conectada en Chrome» sale del campo `browsers` de `status` ([klavd.md](klavd.md) §5), con el nombre que da el navegador.
5. **Cuenta:** «Iniciar sesión» (con el kit de emergencia) o «Crear una cuenta», con el servidor por defecto o «Usar mi propio servidor» (ADR 0028). Se hace así (ADR 0027 §3):
   - la app crea o abre la cuenta en su propio proceso con `KlavCore`, sin llavero;
   - la vuelve a cerrar (`lock`);
   - pide a `klavd` que desbloquee con la misma contraseña. Así solo `klavd` deja la bóveda abierta, y desde ahí ofrece Touch ID.
   - Al crear la cuenta, el kit de emergencia (con la Secret Key) se muestra una vez. «Imprimir o guardar como PDF…» abre el diálogo de impresión del sistema, cuyo menú PDF lo guarda donde la persona elija. «Ya lo guardé» se activa después. Klav no guarda copia, y el texto se olvida al cerrar la hoja.
6. **Agentes** (ADR 0033 E2.3): la skill de Klav en las carpetas de los clientes de agentes de este Mac, para que Claude Code, Codex o Cursor sepan usar Klav y conectarse la primera vez que lo necesiten. No escribe ninguna entrada MCP ni registra ningún agente: eso se decide cuando un agente pide, con su motivo.
   - Sale con la cuenta abierta. Lee `klav client list --json` y `klav skill status --json`, y ofrece una casilla por carpeta de skills, no por cliente: Codex, Cursor y VS Code comparten `~/.agents/skills`. Solo salen las carpetas de un cliente instalado, y vienen marcadas las que no tienen ya la skill al día.
   - «Revisar e instalar» corre `klav skill install --client … --dry-run --json` y muestra cada carpeta con lo que le pasa. «Instalar» repite el comando sin `--dry-run`. Una copia que no es de Klav, o que la persona editó, se deja como está y se decide en Desarrollo › Clientes.
   - «Ahora no» lo salta. Tras iniciar sesión o crear la cuenta (también si la bóveda tarda en desbloquearse), la ventana se queda en «Configurar este Mac» con este paso a la vista hasta que la persona instala la skill o dice «Ahora no»; después no vuelve a salir (`KlavAgentsStepDone` en las preferencias). En Ajustes sigue disponible.

**Otro `klav` en el PATH.** Con los ayudantes firmados (o en *debug*), la app compara cada otro `klav` con el `klav` de su *bundle* por la identidad de la compilación: el *commit* y su fecha (`crates/klav-daemon/build.rs`): todas las compilaciones de una versión dicen el mismo número, y todas las anteriores a 0.9.0 decían `0.0.0`. Nunca ejecuta un `klav` que no instaló: lee su archivo.

- **Qué lee** (`BuildMarker`, T193): cada `klav` y `klavd` desde la identidad de la compilación lleva una línea de texto, `klav-build-identity: ` y lo mismo que imprime `--version` tras el nombre del programa (`klav-build-identity: 0.9.0 (ce4fa5099092 2026-11-13T18:17:02Z)`). La app abre el archivo como esta persona, nunca como administrador, sin bloquear (un FIFO llamado `klav` no la cuelga), y con `fstat` sobre lo abierto exige un archivo regular. Lee como mucho 128 MiB (un `klav` de hoy ocupa en arm64 16 MB como lo compila la app y 26 MB con los ajustes de *release* por defecto de `cargo`), en trozos de 1 MiB que se solapan, fuera del hilo principal, y guarda una sola línea. Ninguna, un archivo más grande, o una segunda distinta o sin fin de línea (las porciones de un binario universal deben coincidir): «no dice su compilación»; en esos dos últimos casos deja de leer ahí, así que la memoria se queda en un trozo sea cual sea el archivo.
- **Cuándo vuelve a leer:** todo lo que toca la carpeta de otro `klav` del PATH (ver si hay un ejecutable, seguir sus enlaces, su línea y el registro de `cargo`) va en una tarea por ruta, fuera del hilo principal (`BuildMarker.Reader`). Un `stat` o un `open` en un volumen que dejó de responder se cuelgan, y ningún *flag* lo evita: el refresco espera como mucho 3 s a todas las tareas juntas, y una ruta cuya tarea no terminó queda «no leída» (solo su ruta, aunque no se sepa si ahí hay un `klav`) sin detener el refresco. No hay dos tareas de la misma ruta a la vez: quien llega con una en marcha espera su resultado hasta el plazo de esa tarea, así que dos llamadas al abrir la app (`checkCLIs` y `refresh`) reciben las dos la respuesta, y pasado el plazo recibe «no leído» al momento. Un `klav` que no cambió (dispositivo, inodo, tamaño y fechas de modificación y de cambio de estado) no se vuelve a leer; el registro de `cargo` sí se lee en cada refresco (como mucho 1 MB) y, si no cambió, solo se ahorra interpretarlo; una lectura que falló o no terminó no se guarda y se repite en el refresco siguiente. La línea se lee estricta (`BuildIdentity`) y en pantalla solo sale lo que la app entendió, nunca el texto tal cual. La compilación de la app sale de su propio `Helpers/klav --version`, que sí es suyo y está firmado.
- **Qué es «más viejo»** (`BuildIdentity.age`): el mismo *commit* (uno puede ser más corto) es el mismo, diga lo que diga el número. Si el de la app o el otro no dice su *commit* y su fecha, no se compara: es neutro, nunca «más viejo». Si no, decide la fecha del *commit*: antes es más viejo y después más nuevo; la misma fecha con otro *commit* es neutro. El número de versión nunca ordena dos compilaciones.
- **Qué muestra el paso 2:**
  - uno más viejo, en rojo: «Hay un klav más viejo en <ruta>. Tu terminal puede ejecutarlo en lugar del de esta app.», con su compilación y la de la app;
  - uno más nuevo, también en rojo, porque la terminal puede ejecutarlo;
  - uno igual, en gris: «En <ruta> hay un klav igual al de esta app.»;
  - uno que no dice su compilación, en rojo y sin comando: «Hay otro klav en <ruta> que no dice su compilación. Tu terminal puede ejecutarlo en lugar del de esta app.»;
  - con los ayudantes sin la firma de Klav no lee nada, y solo dice la ruta.
- **Cómo se actualiza uno más viejo:** la app nunca lo reemplaza (salvo el que esté en la ruta de su enlace, paso 2) ni corre el comando: lo muestra con «Copiar el comando», y solo si la línea de su archivo dice que es más viejo.
  - **De `cargo install`:** junto a su carpeta `bin` está el registro de `cargo` (`../.crates2.json`, valga lo que valga `CARGO_HOME` o `--root`). La app arma el comando con él: `cargo install --locked --path …` para un código fuente local o `--git … [--branch|--tag|--rev …]` para un repositorio, también para `klavd` si `cargo` lo instaló. De una fuente `https` quita el `usuario:contraseña@`. El registro se lee como el `klav`: se abre sin bloquear, `fstat` sobre lo abierto exige un archivo regular (también al final de un enlace: uno a `/dev/zero` es un dispositivo) de como mucho 1 MB, y se leen de ese descriptor como mucho 1 MB y un byte. Sin registro, o con uno que no lee, no inventa un comando. Tampoco ofrece uno que, ya decodificado (`%0A`, `%E2%80%AE`, `%5C`), no sea todo ASCII imprimible o lleve `\` o `!`: el comando va entre comillas simples de POSIX, que fish no lee igual (`\'` cierra la comilla), y por eso tampoco sale para una ruta con apóstrofo. Si el de `klav` o el de `klavd` no se puede ofrecer, no sale ninguno (T193).
  - **De Homebrew** (su archivo, seguidos los enlaces, está dentro de un `Cellar`, también con `libexec`): `brew upgrade <fórmula>`.
  - **Cualquier otro:** solo su compilación y la de la app.
- **Dónde se ve sin abrir Ajustes:** al abrir, la app hace la misma comprobación una vez, corra `klavd` o no, y si hay uno más viejo lo dice abajo en el panel de la barra de menús, en tinta, no en rojo (el rojo es para lo que cambió fuera de Klav): «Mostrar» abre Ajustes › Este Mac y «Ahora no» lo calla hasta que cambie alguna de las dos compilaciones (`olderCLIsLeft` en las preferencias).

**No se instala desde un sitio temporal:** traslocada por Gatekeeper o abierta desde el DMG, la app no hace ningún paso y pide moverla a Aplicaciones (`Placement`). Si el *bundle* no trae los ayudantes (una compilación sin ellos), lo dice.

**Al actualizar,** cuando la app abre, si el `klavd` del LaunchAgent no es la compilación de `Helpers/klavd --version`, le pide `shutdown` y lo relanza con `launchctl kickstart -k gui/<uid>/dev.klav.klavd` (ADR 0027 §4.1). El `klavd` nuevo arranca con la bóveda bloqueada: la persona la desbloquea otra vez. Un `klavd` de otra ruta no se reinicia sin preguntar.

- **Qué es «otra compilación»** (`BuildIdentity.sameBuild`): `status` da `commit` y `commit_time`, y `--version` el *commit* y su fecha. Son otra si los *commits* difieren, si solo uno de los dos dice el suyo (un `klavd` anterior a la identidad de la compilación solo da `0.0.0`) o, si ninguno lo dice, si los números difieren.
- **Antes,** la app comparaba solo el número, y todas las compilaciones decían `0.0.0`: tras una actualización el `klavd` viejo seguía corriendo hasta reiniciar el Mac.
- Siempre converge: tras el reinicio corre el binario del *bundle*, que dice lo mismo que su `--version`.
- `build-app.sh release` se niega a publicar desde un *checkout* con cambios sin confirmar, y con ayudantes cuyo `--version` no nombre `HEAD`.

**«Abrir Klav al iniciar sesión»** está en Ajustes › Este Mac, debajo de los pasos y encima de «Desinstalar Klav de este Mac…». Viene apagada.

- **Qué hace:** registra la app misma como ítem de inicio con `SMAppService.mainApp`. Al iniciar sesión, Klav se abre solo en la barra de menús: sus ventanas no se abren al arrancar (`.defaultLaunchBehavior(.suppressed)`), ni macOS vuelve a abrir la ventana o Ajustes de la sesión anterior (`.restorationBehavior(.disabled)`).
- **Lo que hace sola al abrirse,** sin que la persona abra la app: lo mismo que cada vez que abre. Lee el archivo de cada otro `klav` del PATH (§3, Otro `klav` en el PATH, T193). Si el `klavd` del LaunchAgent no es la compilación del *bundle*, lo reinicia, y la bóveda queda bloqueada hasta que la persona la desbloquea. Pone al día las copias de la skill que la persona no editó (ADR 0033 §6) y revisa los clientes de agentes, para los avisos rojos de la barra de menús. Todo eso solo con los ayudantes firmados y desde Aplicaciones.
- **Sparkle en el segundo arranque:** el `Info.plist` no fija `SUEnableAutomaticChecks` y la app no implementa `updaterShouldPromptForPermissionToCheckForUpdates`. Así, Sparkle 2.10.0 (`SPUUpdater.startUpdateCycle`) no pregunta nada en el primer arranque y, desde el segundo, que puede ser un inicio de sesión, abre su propia ventana para preguntar una vez si busca actualizaciones solo. Hasta que la persona contesta no busca nada por su cuenta; «Buscar actualizaciones…» funciona siempre. El ADR 0027 §7 pide que la app se actualice sola, como la mayoría de apps de Mac: con esta pregunta, lo hace solo si la persona dice que sí. Esta capa lo documenta y no cambia nada.
- **No es el servicio en segundo plano:** el LaunchAgent de `klavd` (paso 1) es otro ítem de inicio y arranca `klavd` al iniciar sesión con la opción encendida o apagada. Ni encenderla ni apagarla lo toca.
- **Dice lo que dice macOS,** no lo último que se eligió: la app lee `SMAppService.mainApp.status` en cada refresco y cada vez que pasa al frente, porque la persona puede cambiarlo en Ajustes del Sistema › General › Ítems de inicio y extensiones (así se llama desde macOS 15; antes, «Ítems de inicio»).
  - Está encendida solo si macOS dice `enabled`. Si macOS pide permiso (`requiresApproval`), Klav aún no se abre al iniciar sesión: sale apagada, con «Permite Klav en Ajustes del Sistema › General › Ítems de inicio y extensiones» y «Abrir Ítems de inicio», y encenderla abre ese panel en vez de registrarla otra vez.
  - Si macOS se niega, lo dice: «macOS no añadió Klav a Ítems de inicio: …», con el motivo de macOS. Registrar algo ya registrado, o quitar algo ya quitado, no es un error.
- **Cuándo se puede encender:** no traslocada ni desde el DMG (`Placement.canInstall`), y con los ayudantes firmados por el equipo de Klav (T120). Apagarla se puede siempre que esté encendida (`enabled`), también desde una copia traslocada o con ayudantes sin esa firma. Un registro que espera permiso (`requiresApproval`) sale apagado y no se quita desde la casilla: se retira en Ajustes del Sistema › General › Ítems de inicio y extensiones, o al desinstalar.

**«Desinstalar Klav de este Mac…»** está en el menú de la app y en Ajustes. Antes de hacer nada, la hoja dice qué quita y qué deja:

- Quita:
  - el LaunchAgent (`unregister`), y detiene `klavd`;
  - la app como ítem de inicio, si «Abrir Klav al iniciar sesión» estaba encendida;
  - los manifiestos que apuntan al *wrapper* de esta app, también los que su *host* ya rechazaría, y el *wrapper*;
  - el enlace, solo si es el suyo. Si `/usr/local/bin` es de `root`, macOS pide la contraseña.
- Deja:
  - los manifiestos de otra instalación;
  - `$KLAV_HOME`, salvo que la persona marque borrarlo.

Después, la hoja ofrece mostrar `Klav.app` en el Finder para tirarla a la Papelera.

**Los ayudantes en el *bundle*:** `scripts/macos/embed-helpers.sh` es una fase de compilación del *target*. Copia `klav`, `klavd` y `klav-native-host`, y el *plist*, antes de que Xcode firme la app:

```
Klav.app/Contents/Helpers/
  klav
  klav-native-host
  klavd.app/                 dev.klav.klavd, «Klav», LSUIElement
    Contents/Info.plist      de scripts/macos/klavd-Info.plist
    Contents/MacOS/klavd
    Contents/Resources/AppIcon.icns
  klavd -> klavd.app/Contents/MacOS/klavd
```

- **`klavd` va en su propio *bundle*** para que el diálogo de Touch ID diga «Klav» con su ícono (ADR 0027, nota del 2026-11-05):
  - el *script* rellena las versiones y el macOS mínimo del `Info.plist` con los de la app (`MARKETING_VERSION`, `CURRENT_PROJECT_VERSION`, `MACOSX_DEPLOYMENT_TARGET`), y copia el `AppIcon.icns` que ya compiló `actool`;
  - el *template* vive en `scripts/macos`, no en `apps/ios/Mac`, porque XcodeGen copiaría a la app como recurso lo que hay ahí.
- **`Helpers/klavd` queda como enlace relativo** al binario, para lo que lo ejecuta por esa ruta:
  - `klav` y `klav-native-host`, que arrancan el `klavd` que tienen al lado;
  - `--version` al actualizar;
  - un LaunchAgent que cargó una `Klav.app` anterior.

  Al ser relativo, sobrevive a `ditto`, al DMG y a Sparkle.
- Por defecto los toma de `target/debug` (o de `$CARGO_TARGET_DIR/debug`).
- `KLAV_HELPERS_SOURCE` apunta a otro directorio (la versión de publicación, en la capa 5).
- En Debug los firma *ad hoc* con *hardened runtime*.
- Sin ellos, la app compila igual y lo avisa en la configuración.

**La firma de los ayudantes (T120):** antes de configurar nada, la app comprueba con `SecStaticCodeCheckValidity` que `klav`, `klavd` y `klav-native-host` cumplen `identifier "dev.klav.<nombre>" and anchor apple generic and certificate leaf[subject.OU] = "SZ3F58F8LX"` (`HelperSignature`), y que su propio sello sigue intacto.

- **El equipo que nombra la firma de la app** se lee sin validarla (`SecCodeCopySigningInformation`), y solo elige el camino. Se lee aunque el sello esté roto: se comprobó con una app de otro equipo a la que se le cambió un byte de un recurso. Nunca se cree:
  - **Si nombra a SZ3F58F8LX,** la app se comprueba entera contra el requisito de verdad: el ancla de Apple y el equipo en el certificado. Primero cada ayudante, que da el mensaje más claro. Después el enlace `Helpers/klavd`. Al final la propia app, porque solo su sello cubre el *plist* del LaunchAgent y el enlace. Un nombre falsificado solo lleva a fallar ahí.
  - **Si nombra a otro equipo o a ninguno** (*ad hoc*), no es la compilación de Klav. En una compilación de publicación no configura nada y dice «Esta copia de Klav no la firmó Klav». En una de *debug* configura igual y lo avisa: «Compilación de desarrollo: Klav no comprueba que el equipo de Klav haya firmado sus ayudantes».
  - **El permiso de desarrollo es compilar en *debug*.** No hay ajuste, variable ni argumento que apague la comprobación en una compilación de publicación. `build-app.sh adhoc` arma una de publicación, así que no configura nada; en [probar-mac.md](probar-mac.md) §7 solo sirve como actualización que se rechaza.
- **Antes de este cambio,** una app del equipo con el sello roto daba «sin comprobar» y configuraba igual. Un ayudante cambiado rompe primero el sello de la app, así que el aviso casi nunca salía.
- `klavd` se comprueba en su *bundle*, `klavd.app`. A través del enlace, la comprobación estática falla aunque la firma sea buena (`-67030`). Además, `Helpers/klavd` tiene que ser exactamente el enlace a `klavd.app/Contents/MacOS/klavd`.
- Si algo falla, no registra el LaunchAgent, no crea el enlace ni escribe manifiestos: pide bajar Klav otra vez. Desinstalar sigue funcionando.

Lo que falta aquí: «Añadir este Mac desde el iPhone» llega con el ADR 0029.

## 4. Compilar y probar

Requisitos: los de [ios.md](ios.md) §5 (Xcode, XcodeGen y Rust con `aarch64-apple-darwin`).

```sh
scripts/macos/test.sh            # XCFramework, proyecto, compilar y pruebas
scripts/macos/test.sh build      # solo compilar
KLAV_IOS_SKIP_FFI=1 scripts/macos/test.sh   # reusar target/ios/KlavFFI.xcframework
```

- **Esquema y DerivedData:** el esquema `KlavMac` compila la app (`dev.klav.mac`, arm64, *hardened runtime*), firmada para correr en este Mac. La firma con Developer ID la pone el script del DMG (capa 5). La DerivedData va en `target/xcode/mac-derived` (`KLAV_MAC_DERIVED`); la de `build-app.sh`, aparte, en `target/xcode/mac-release-derived` (`KLAV_MAC_RELEASE_DERIVED`). Los dos se pueden fijar en la configuración local de compilación ([ios.md](ios.md) §5).
- **Las pruebas** (`KlavMacTests`) corren la app sobre la bóveda de ejemplo y no tocan ningún `klavd` ni el directorio real: `test.sh` les da un home temporal, y la bóveda de ejemplo se niega a correr `klav` sobre el real (`SampleSafetyTests`, con un `klav` falso que solo deja una marca en la carpeta de la prueba). Cubren:
  - las fases (bloqueada y desbloqueada);
  - la contraseña equivocada;
  - aprobar sin Touch ID (pide la contraseña);
  - una tarea sin casillas;
  - el número de solicitudes;
  - los mensajes de error;
  - el directorio;
  - `klavd.app`: su identificador, su nombre «Klav», su ícono, el enlace `Helpers/klavd` y que el LaunchAgent ejecute el binario de dentro;
  - Desarrollo (`DevelopmentTests`): pausar no pregunta nada y reanudar pide la contraseña sin Touch ID; la pausa de un agente no es la de todos; la tarjeta avisa de un nombre denegado antes; solo un registro que lanzó la app compara las palabras sola; los filtros de Actividad, «Aprobado 15 min» y el estado de la cadena antes y después de verificar; el texto del agente en una línea, sin controles ni marcas bidi; la lectura de `klav client list`, del resumen de `connect` y de `klav skill status`; y lo que añadió la revisión del PR #230: solo se guarda un registro que hizo este `connect` con la firma de Klav, «Coinciden: aprobar» se apaga si no coinciden, el resumen promete la comparación solo cuando la hay, la tarjeta avisa de otro pendiente con el nombre o de otro registrado por este Mac, la pausa en este Mac, el paso «Agentes» tras iniciar sesión (con el desbloqueo que tarda de `SampleEngine`) y solo con clientes instalados, los avisos rojos, el *diff* de la skill y el sitio «según el agente». Lo que usa `SampleEngine` o `SampleAccounts` prueba la lógica de la app, no `klavd` ni el servidor;
  - la configuración y la desinstalación (`InstallerTests`). Usan el `klav` real de `Helpers` sobre un home temporal: Dia con un manifiesto viejo en Mozilla, un manifiesto de la app con el *wrapper* viejo, el *wrapper* de otro `KLAV_HOME` que ejecuta el mismo *host*, otro `klav` en el PATH y un enlace en un directorio de la prueba. De los navegadores: la extensión de desarrollo que dejó entrar otra instalación en sus tres casos (este `KLAV_HOME` con Firefox, solo Chrome, otro `KLAV_HOME`), con el texto exacto en inglés y en español; «Quitarla» con solo Chrome y un manifiesto de `--user-data-dir`; una lectura de los navegadores que falla al conectar, y una vieja que termina después de una nueva. Del otro `klav`: la lectura estricta de `--version` y de la línea de su archivo (secuencias de terminal, marcas *bidi*, dos líneas, demasiado larga); el lector (`BuildMarker`) con un FIFO, un directorio, un bucle de enlaces, un archivo mayor que el tope, dos líneas distintas, una línea sin fin y una línea partida entre dos trozos; una carpeta del PATH cuya tarea se cuelga (el refresco sigue y no empieza otra), dos llamadas a la vez a una lectura lenta y una lectura que falló una vez; el registro de `cargo` como FIFO, directorio, enlace a `/dev/zero` y de 1 MB y un byte (también tras un enlace); los comandos con `\` o `!`; los cuatro estados con `klav` falsos que nunca se ejecutan; que solo uno más viejo trae comando, solo de `cargo` (con el registro junto a `bin`, sin el usuario de una fuente `https`) o de Homebrew (`Cellar` y `libexec`); que «Ahora no» se guarda hasta que cambia una compilación; que la bóveda de ejemplo no lee ningún `klav` del PATH real ni de Aplicaciones; los ayudantes de la app, cuya línea coincide con su `--version` (con `TEST_RUNNER_KLAV_READER_FIXTURES`, además, un `klav` anterior a la identidad de la compilación y binarios de *release*); y el reinicio de `klavd` por compilación (el mismo *commit*, uno sin *commit*, otro *commit* más viejo o más nuevo, y el número que no decide). De «Abrir Klav al iniciar sesión»: que viene apagada, que sigue lo que dice macOS (también si la persona la cambia en Ajustes del Sistema), el permiso pendiente, el error de macOS dicho tal cual, que no se enciende traslocada ni con ayudantes sin la firma del equipo pero sí se apaga, que no toca el LaunchAgent de `klavd` y que desinstalar la quita. En vez de `SMAppService` y de la contraseña de administrador usan `SampleSystem`, así que no registran nada en el sistema. `KLAV_MAC_TEST_TMPDIR` elige dónde van esos homes.

  - crear y editar (`ItemEditorTests`): lo que manda un login nuevo (solo lo escrito, el sitio con `https://`), un código como llave o como `otpauth://`, que una edición solo manda lo que cambió y nunca rellena un secreto, el título repetido como lo ve `klav-client`, el tipo de la lista en ⌘N, que ⌘E solo edita lo que muestra la bóveda, que ni ⌘N ni ⌘E abren nada sobre una hoja abierta (el editor, la papelera, la contraseña maestra o desinstalar), que bloquear y el borrado de la cuenta cierran el editor, la papelera, los sitios de un agente y los textos en español. La prueba de `create_item`, `edit_item` y `trash_item` contra un `klavd` real está en Rust (`crates/klav-ffi/tests/daemon.rs`);
  - arreglar las repetidas (`FixReusedTests`), lo que hace la tarjeta sobre `SampleEngine`: con dos agentes nadie queda elegido, los logins se revisan contra el proyecto del agente y los que no puede cambiar van al final, la tarjeta muestra los sitios que le da el motor, aprobar con Touch ID manda solo los marcados y su progreso aparece, sin Touch ID la contraseña maestra va primero y la tarjeta no recibe la tarea hasta que el motor la acepta, bloquear con su hoja abierta la cierra y la oferta ya no sale de ella ni tras desbloquear, el borrado de la cuenta también la cierra, bloqueado no hay tarjeta ni progreso, y los textos en español. `SampleEngine` deja fuera por su cuenta el sitio que añadió un agente y rechaza él mismo una contraseña mala, así que estas pruebas no demuestran ninguna de las dos garantías: solo que la tarjeta muestra y manda lo que el motor le da. Las garantías están en Rust: `crates/klav-client/src/offer.rs` arma los sitios de una oferta solo con `confirmed_urls`, así que nunca entra un sitio que añadió un agente, y `klavd` vuelve a comprobar la oferta con `prepare_offer` antes de pedir Touch ID o la contraseña y de firmarla. Que una contraseña mala no ofrece nada lo prueba `offer_task_with_password` en `crates/klav-ffi/tests/daemon.rs`;
  - Sandboxes (`SandboxesTests`, §9), sobre las filas de ejemplo de `SandboxSamples`: sin proxy solo queda el encabezado; un proxy sin señales dice desde hace cuánto; un latido que retrocede es un aviso de seguridad en rojo, también en pausa, y no se repite entre los avisos; con el aviso de seguridad las filas son de todos los proxies, sin «Revocar todos»; una señal de robo va arriba y en la barra de menús hasta «Entendido»; las palabras de cada estado, uno desconocido incluido (vivo y revocable); los terminados en 24 h con su motivo; la pausa; revocar uno y todos, «No se aplicó» y Klav bloqueado; una lectura fallida por la red conserva la lista y una que falla sus comprobaciones (`Security`, `Rollback` o la comprobación que nombra `sandbox_list_checked`) la tira; las palabras de cada comprobación, en inglés y en español, cada una con su punto, y una desconocida con la frase genérica y las palabras de `klav-client` aparte; las edades corren desde la lectura; la lectura después de revocar no es la que ya estaba en curso (con el modelo deteniendo esa lectura); una revocación que la bitácora no muestra sale en rojo y «Revocar otra vez» la quita; un «Revocar otra vez» que falla o no se aplica la deja en rojo, y uno aceptado sigue en rojo mientras las lecturas fallen; sobre un «Revocar todos» abre su hoja sin firmar, para el proxy de la revocación, y sin lista o con la de otro proxy firma sin decir cuántos; «Revocar todos» desde la lista usa su proxy y su cuenta; un aviso se va si la lista falla sus comprobaciones o Klav se bloquea; el prefijo `SECURITY: ` de `klavd` no sale en el bloque; una lectura que no puede decirlo no quita una ya en rojo; la respuesta se queda con la misma lista, se va cuando cambia o con la siguiente acción, y cede ante su bloque rojo; una lectura vieja no dice el latido ni las conexiones; el mensaje de integridad más largo de `klav-client` cabe entero; una lectura que termina después de cerrar sesión o de borrarse la cuenta no deja nada (con la lectura detenida por una continuación, sin bloquear un hilo); los interruptores de ejemplo de las capturas; revocar bajo el aviso de seguridad usa el proxy de la fila; «Entendido» solo en memoria, con dos señales y una contestada: otra ejecución de la app las muestra las dos, y la respuesta se olvida cuando la señal sale de la lista; sin proxy ninguna fila habla «según el proxy»; el aviso de un latido que retrocede solo quita esa línea exacta; y algunas palabras en español;
  - los textos (`WordingTests`): en español, la hora de fin de una tarea dice «hasta la 1:15» y «termina a la 1:15» a la una y «las» a cualquier otra hora (`TaskWords.atOne`, con 12 y 24 horas), y la pausa sin Touch ID habla de la contraseña maestra;
  - borrar la cuenta (`DeleteAccountMacTests`, §8): la contraseña equivocada no pide nada; cancelar pide Touch ID o, sin él, la contraseña maestra (una mala no cancela), dice cuando otro dispositivo ya lo canceló y, con `klavd` bloqueado, «Desbloquea Klav para cancelar»; pedirlo dos veces (`409`) deja la fecha que ya había; un servidor que no puede lo dice primero; y tras el borrado la bóveda queda en solo lectura, sin solicitudes ni agentes, hasta «Borrar la copia de este Mac», que vuelve a arrancar `klavd` sin cuenta; los textos en español con «este Mac».

  La prueba de `DaemonEngine` contra un `klavd` real está en Rust: `cargo test -p klav-ffi --features daemon --test daemon`. Cubre también «Arreglar mis contraseñas repetidas»: `reused_offer` con dos logins que comparten contraseña, `offer_task_with_password` (sin logins, sin Touch ID, con una contraseña mala y con la buena) y `task_progress` con los dos sitios pendientes.
- **Bóveda de ejemplo** (solo en *debug*): `-KlavSample YES` usa `SampleEngine`, con datos inventados y sin servidor. Otros argumentos:

  | Argumento | Qué hace |
  |---|---|
  | `-KlavSampleLocked YES` | La bóveda empieza bloqueada |
  | `-KlavSampleNoTouchID YES` | Simula un Mac sin Touch ID (la contraseña de ejemplo es `sample`) |
  | `-KlavAppearance light` o `dark` | Fija la apariencia |
  | `-KlavOpen main,menu` | Abre la ventana y el panel de la barra en una ventana, para capturarlos |
  | `-KlavSection requests`, `agents`, `sandboxes`, `activity`, `clients` o `health` | Abre esa sección |
  | `-KlavSamplePaused YES` | Todos los agentes de ejemplo empiezan en pausa |
  | `-KlavItem <id>` | Abre ese elemento |
  | `-KlavSampleSignedOut YES` | Sin cuenta: abre «Configurar este Mac» |
  | `-KlavSampleAgent YES` | El LaunchAgent de ejemplo ya está registrado |
  | `-KlavSheet signIn`, `signUp` o `uninstall` | Abre esa hoja |
  | `-KlavSheet connect-<cliente>` | Abre el resumen de «Conectar» de ese cliente (`connect-codex`) en Clientes |
  | `-KlavSetupAgents YES` | Deja la ventana en «Configurar este Mac» con el paso «Agentes» a la vista, como tras iniciar sesión |
  | `-KlavSampleDeletion pending`, `deleted`, `deleted-unsent` o `unsupported` | El borrado de la cuenta pedido desde el iPhone, ya hecho, ya hecho con dos contraseñas generadas sin subir, o un servidor que no puede (§8) |
  | `-KlavOpen settings` con `-KlavSettingsTab account` | Abre Ajustes en la pestaña Cuenta |
  | `-KlavSettingsBottom YES` | Abre Ajustes › Este Mac al final, con «Abrir Klav al iniciar sesión» y «Desinstalar Klav de este Mac…» |
  | `-KlavSheet deleteAccount` | Abre la hoja del borrado en Ajustes › Cuenta |
  | `-KlavSheet newItem` o `editItem` | Abre el editor en un login nuevo o en `-KlavItem` |
  | `-KlavSheet trash` | Abre «Mover a la papelera» de `-KlavItem` |
  | `-KlavGenerator YES` | Con `newItem`, abre el generador sobre el editor |
  | `-KlavSheet fixReused` | Con `-KlavSection health`, abre «Arreglar mis contraseñas repetidas» para release-agent |
  | `-KlavSampleFix YES` | Esa tarea ya corre, con un sitio cambiado y otro en curso |
  | `-KlavAgent <id>` | Con `-KlavSection agents`, abre la ficha de ese agente (`ag1` se puede editar; `ag2` tiene reglas a mano) |
  | `-KlavSheet revoke` o `changeGrant` | Abre «Revocar…» o «Cambiar permisos…» de `-KlavAgent` |
  | `-KlavSheet reviewGrant` | Abre la revisión de un cambio de ejemplo de `-KlavAgent`: un proyecto más e «inyectar» en denegar |
  | `-KlavSign YES` | Con `-KlavSheet reviewGrant`, pulsa «Firmar»; con `-KlavSampleNoTouchID YES`, la contraseña maestra sale sobre la hoja |
  | `-KlavSampleKeysLeft YES` | old-scraper (`ag4`) está revocado con una de tres llaves cambiada y un error |
  | `-KlavSampleSandboxes none`, `empty`, `quiet`, `rollback`, `flagged` o `paused` | La lista de Sandboxes (§9): sin proxy, sin sandboxes, un proxy callado, un latido que retrocede, el aviso de seguridad o en pausa. Sin él, un proxy con un sandbox en cada estado y una señal de robo |
  | `-KlavSampleSandboxes integrity` | Cada lectura de la lista falla sus comprobaciones (`Security`): «Problema de seguridad» en el panel y la línea roja en la barra de menús |
  | `-KlavSampleSandboxes unregistered` | Cada estado y una revocación de «chat-123» que la bitácora no muestra: «El servidor no registró tu revocación» con sus tres acciones |
  | `-KlavSheet revokeAllSandboxes` | Con `-KlavSection sandboxes`, abre «Revocar todos» |

  Con `-KlavOpen`, la ventana no se pone al frente: una captura no le quita el foco a quien está escribiendo en otra app.

  En *debug*, `KLAV_BROWSER_HOME`, `KLAV_CLI_LINK_DIR` y `KLAV_HELPERS_DIR` llevan la configuración a un home, una carpeta del enlace y unos ayudantes de prueba. Con la bóveda de ejemplo, el LaunchAgent y la contraseña de administrador son de mentira (`SampleSystem`). Sin ella, «Configurar» registra el LaunchAgent de verdad.

  **La bóveda de ejemplo nunca corre `klav` sobre el home real** (`SampleSafety`, revisión del PR #230: una corrida de las pruebas llegó a escribir `clients.json` en el `KLAV_HOME` de verdad con `klav skill update`). Corre `klav` y `klavd`, y hace un paso de «Configurar» o de desinstalar, solo si `KLAV_HOME` y `KLAV_BROWSER_HOME` están fuera de la carpeta de inicio (también `CODEX_HOME` y `CLAUDE_CONFIG_DIR`, si están definidas) y la carpeta del enlace no es una del PATH real. Si no, se niega y lo dice: Clientes y «Configurar» muestran el error en vez de leer o escribir nada. `scripts/macos/test.sh` le da al *host* de las pruebas un `KLAV_HOME`, un `KLAV_BROWSER_HOME` y un `KLAV_CLI_LINK_DIR` nuevos en un directorio temporal (`TEST_RUNNER_*`), y los borra al terminar; desde Xcode, sin ellos, la barrera es la que protege. Para las capturas de Clientes y del paso «Agentes», define los tres.

  Por ejemplo, con la DerivedData por defecto (si la tuya está en otro sitio, `KLAV_DEV_CONFIG_PRINT=1 scripts/macos/test.sh` dice dónde):

  ```sh
  open -n target/xcode/mac-derived/Build/Products/Debug/Klav.app \
    --args -KlavSample YES -KlavOpen main,menu -KlavAppearance dark
  ```

- **Contra un `klavd` de prueba:** con `KLAV_HOME` apuntando a un directorio de prueba, un `klav-server` local y `klavd` con `KLAV_NO_TOUCH_ID=1`, la app muestra esa cuenta. Nunca uses el `KLAV_HOME` real para probar.
- **CI corre en Linux:** prueba `DaemonEngine` y genera sus *bindings*. Compilar y probar la app es una puerta local antes de cada PR del Mac, como en iOS.

## 5. Publicar: el DMG

`scripts/macos/build-app.sh` arma lo que se publica (ADR 0027 §4 y §5) en `target/macos/dist`:

```sh
nice -n 19 env CARGO_BUILD_JOBS=2 scripts/macos/build-app.sh release   # Developer ID, notarizado y grapado
scripts/macos/build-app.sh adhoc                                         # sin cuenta de Apple, para probar
```

1. **Los ayudantes** con `cargo build --release`, sin símbolos y con LTO entre *crates* (`--config profile.release.strip`, `lto` y `codegen-units`, sin tocar el perfil del *workspace*). Sin LTO pesan 41 MB y la app pasa del presupuesto (§7).
2. **`KlavFFI` en *release*** y la app en Release. `embed-helpers.sh` mete los ayudantes de `target/release` sin firmarlos.
3. **La firma, de dentro hacia fuera,** con la identidad «Developer ID Application» del equipo SZ3F58F8LX que encuentre en el llavero (`KLAV_MAC_IDENTITY` para otra), *hardened runtime* y sello de tiempo:
   - cada ayudante con su identificador `dev.klav.<nombre>`. `klavd` se firma como su *bundle*, `klavd.app`, y el script comprueba que `Helpers/klavd` sea el enlace a él;
   - después la app, que sella `Helpers` (el enlace incluido) y el *plist*.

   El script comprueba la firma completa (`codesign --verify --deep --strict`) y la misma regla de T120 en cada ayudante (`klavd.app` para `klavd`).
4. **La notarización** con `notarytool` y la llave de App Store Connect, pasada solo como ruta (`KLAV_NOTARY_KEY`, con su ID en `KLAV_NOTARY_KEY_ID` y el del emisor en `KLAV_NOTARY_ISSUER`; no tienen valor por defecto: van en el entorno o en la configuración local de compilación, [ios.md](ios.md) §5, y sin ellos `release` se detiene antes de compilar): primero la app (en un zip), que se grapa para abrir sin red; después el DMG, que también se grapa. Si Apple no la acepta, el script imprime su registro y para.
5. **El DMG** (`Klav-<versión>.dmg`, ULFO): `Klav.app` y un alias a `/Applications`, firmado. Al final, `spctl` evalúa el DMG y la app como lo haría Gatekeeper.

El script falla si la app pasa de 60 MB o el DMG de 25 MB. Sin la identidad en el llavero, explica qué crear (un certificado «Developer ID Application» en developer.apple.com) y sugiere `adhoc`.

## 6. Actualizaciones con Sparkle

Sparkle 2.10.0 (ADR 0027 §7), fijado exacto en `apps/ios/project.yml` y en `apps/ios/Package.resolved`. Esa versión salió el 2026-09-13; la 2.10.1, del 2026-10-25, no cumplía las dos semanas. Solo lo usa el *target* `KlavMac`.

- **El proyecto de Xcode no se versiona,** así que `Package.resolved` vive en `apps/ios/` y el `postGenCommand` de XcodeGen lo copia al proyecto. Los scripts compilan con `-onlyUsePackageVersionsFromResolvedFile` y guardan la caché de paquetes en `target/xcode/spm-cache` (`KLAV_SPM_CACHE`).
- **Qué hace la app:**
  - busca `https://klav.dev/releases/mac/appcast.xml` (`SUFeedURL`, de `Config/Base.xcconfig`);
  - exige el appcast firmado (`SURequireSignedFeed`);
  - comprueba la firma EdDSA del DMG antes de extraerlo (`SUVerifyUpdateBeforeExtraction`).

  «Buscar actualizaciones…» está en el menú de la app.
- **El Team ID (T123):** con una firma EdDSA válida, Sparkle acepta una app que firmó otro equipo, y no deja ver la app extraída antes de que su instalador la tome. Por eso `UpdateGuard` revisa en `didDownloadUpdate`, que Sparkle llama justo antes de extraer, que todo lo descargado esté firmado por SZ3F58F8LX. El DMG lo está (§5), y su firma sella la imagen entera. Si no lo está, borra la descarga y Sparkle no tiene qué extraer. Cuando Sparkle se detiene, la app avisa de que no instaló esa versión.
  - La ruta de las descargas sale del código de Sparkle 2.10.0 (`~/Library/Caches/dev.klav.mac/org.sparkle-project.Sparkle/PersistentDownloads`); su propio instalador rechaza cualquier otra. Al subir de versión de Sparkle hay que volver a comprobarla.
- **La llave pública** está en `Config/Base.xcconfig` (`KLAV_SPARKLE_PUBLIC_KEY`). `build-app.sh release` se niega a publicar sin llave (salvo `KLAV_ALLOW_NO_UPDATES=1`).

### La llave de producción

Omar la creó el 2026-11-05 en su Mac. Es solo de Klav: la cuenta `klav` de `generate_keys`, no la `ed25519` por defecto, que Sparkle comparte entre todas las apps de una persona. Así, una filtración de la llave de otra app no firma versiones de Klav, ni al revés.

- **Pública:** `aTHvmuTyrmDiml3MqEkppSQwtYCpFcWOf+Eo5Xrks9E=`, en `Config/Base.xcconfig`. No es secreta.
- **Privada, en dos sitios:**
  - en la bóveda, en `klav://Personal/Release/Sparkle EdDSA/api_key`;
  - en el llavero de inicio de sesión de Omar, como respaldo (servicio `https://sparkle-project.org`, cuenta `klav`).
- **«Release» es un proyecto aparte** porque un grant da las llaves del proyecto entero: un agente con acceso a «General» vería todo lo demás.
- **El agente `release-mac`** firma las versiones sin ver la llave (siguiente sección). Su grant da solo `Personal/Release`, con `list` permitido, `inject` en `ask` (Touch ID en cada versión) y lo demás denegado, `reveal` incluido.

Se creó así (`generate_keys` está en `<DerivedData>/SourcePackages/artifacts/sparkle/Sparkle/bin/`):

```sh
generate_keys --account klav               # la crea en el llavero e imprime la pública
generate_keys --account klav -x klav-sparkle.key
klav item add api-key --title "Sparkle EdDSA" --vault Personal --project Release \
  --secret-stdin api_key < klav-sparkle.key
rm -P klav-sparkle.key
```

Si se pierden las dos copias de la privada, las apps ya instaladas no aceptan más actualizaciones: la única salida es bajar el DMG nuevo a mano. Nunca uses aquí una llave de prueba.

### Publicar una versión

Los pasos de una versión, en orden, y cuáles hace solo Omar están en [releasing.md](releasing.md) §2. Aquí queda lo propio de Sparkle: compilar y firmar el appcast.

```sh
scripts/macos/build-app.sh release
```

La versión y la compilación salen de `apps/ios/project.yml` ([releasing.md](releasing.md) §2, paso 1). `KLAV_MAC_VERSION` y `KLAV_MAC_BUILD` las sustituyen solo en la prueba de actualización ([probar-mac.md](probar-mac.md)).

El appcast lo firma un agente sin ver la llave: `klav agent run` la pone en el entorno y tapa su valor en la salida. Como `inject` está en `ask`, la primera vez sale con el código 4 y el ID de la solicitud. Omar la aprueba con `klav approval approve <id>` (Touch ID), y el comando se repite con `--approval <id>`, o con `--wait` desde el principio:

```sh
klav agent run --agent release-mac --wait --reason "appcast de Klav 0.2.0" \
  -e 'SPARKLE_KEY=klav://Personal/Release/Sparkle EdDSA/api_key' \
  -- sh -c 'printf "%s\n" "$SPARKLE_KEY" | scripts/macos/appcast.sh make --key-file - target/macos/dist/Klav-0.2.0.dmg'
```

Omar también puede firmarlo sin agente:

```sh
klav item get "klav://Personal/Release/Sparkle EdDSA/api_key" --reveal \
  | scripts/macos/appcast.sh make --key-file - target/macos/dist/Klav-0.2.0.dmg
```

- `appcast.sh make` escribe `target/macos/dist/appcast.xml` con un `<item>`:
  - la versión, la compilación (`sparkle:version`, que es lo que Sparkle compara: tiene que subir siempre);
  - el macOS mínimo;
  - el `enclosure` con la firma EdDSA y la longitud del DMG.

  Después firma el appcast entero y verifica la firma.
- **La llave entra por stdin, nunca por argv.** El script la lee una vez y se la pasa a `sign_update --ed-key-file -`.
- **El script no publica nada.** El DMG y el `appcast.xml` firmado son archivos de una GitHub Release ([releasing.md](releasing.md) §1), no se suben a `klav.dev`. La app sigue buscando `https://klav.dev/releases/mac/appcast.xml` (`SUFeedURL`, que no cambia): cuando Omar lo enciende, esa dirección responde con una redirección al appcast de la última versión publicada. Que Sparkle siga esas redirecciones aún no se ha probado con una versión real ([releasing.md](releasing.md) §5).
- `appcast.sh test-key FILE` crea una llave de prueba (Ed25519 con CryptoKit, 0600, nunca en el llavero) para la prueba de abajo.

### La prueba de una actualización

En un directorio de prueba:

1. una llave de prueba;
2. la versión nueva con `build-app.sh release`, `KLAV_SPARKLE_PUBLIC_KEY` de prueba y `KLAV_MAC_VERSION`/`KLAV_MAC_BUILD` mayores;
3. su appcast con `--url-base http://127.0.0.1:<puerto>`, servido desde ese directorio con `python3 -I -m http.server <puerto> --bind 127.0.0.1`. Con `file://` Sparkle no baja nada (error 2001). ATS no aplica a una IP literal, así que HTTP sirve para la prueba;
4. una app vieja de Debug compilada con la misma llave (`xcodebuild … build KLAV_SPARKLE_PUBLIC_KEY=<pública de prueba>`), abierta con:
   - `-KlavSample YES` y un `KLAV_HOME` temporal;
   - `KLAV_SPARKLE_FEED_URL=http://127.0.0.1:<puerto>/appcast.xml`;
   - `-KlavCheckUpdatesNow YES`, `-SUAutomaticallyUpdate YES` y `-SUHasLaunchedBefore YES`.

La app baja la versión nueva en segundo plano, el registro dice `update <versión>: signed by Klav's team` y, al salir, Sparkle la instala: la app de prueba pasa a la versión nueva, firmada por SZ3F58F8LX.

Para el rechazo, firma *ad hoc* una copia del DMG (`codesign --force --sign -`) y haz su appcast con la misma llave. La firma EdDSA es válida y Sparkle la acepta, pero `UpdateGuard` registra `rejected: … code failed to satisfy specified code requirement(s)`, borra la descarga y avisa; la app vieja se queda en su versión.

| El aviso del rechazo | En oscuro |
|---|---|
| ![Klav 0.1.1 no se instaló: la actualización no está firmada por Klav](img/mac/actualizacion-rechazada.png) | ![El mismo aviso en oscuro](img/mac/actualizacion-rechazada-oscuro.png) |

Sparkle deja rastros con el identificador de la app: hay que borrar `~/Library/Caches/dev.klav.mac` y `~/Library/HTTPStorages/dev.klav.mac`, y devolver las preferencias de `dev.klav.mac` a como estaban (`defaults export` antes de empezar, `defaults import` al final).

## 7. Presupuesto

ADR 0027 §5: el DMG pesa como mucho 25 MB y la app en reposo se mantiene ligera.

| Medida | Valor | Cómo |
|---|---|---|
| Memoria en reposo, *debug*, solo en la barra de menús | 18 MB | `footprint <pid>` a los 25 s |
| Memoria en reposo, *debug*, ventana abierta y desbloqueada contra un `klavd` real | 35 MB (pico de 168 MB al dibujar la cerradura de luz y las listas) | `footprint <pid>` |
| `.app` en *debug*, con los ayudantes de *debug* | 171 MB | `du -sh` |
| **DMG publicado** (Developer ID, notarizado y grapado), con Sparkle | **24,6 MB** (presupuesto 25 MB), medido el 2026-11-12; **22,1 MB** en `adhoc` el 2026-11-20 tras compilar los ayudantes con `opt-level="s"` (manteniendo `argon2` y `blake2` en `3`) | `scripts/macos/build-app.sh release` / `adhoc` |
| **`Klav.app` publicada** | **54,8 MB** (presupuesto 60 MB) el 2026-11-12; **49,4 MB** en `adhoc` el 2026-11-20 con `opt-level="s"` y LTO en los ayudantes (sin LTO eran 65,2 MB) | igual |
| Memoria en reposo de la app publicada, solo en la barra de menús, con Sparkle | 19 MB, 0,4 % de CPU | `footprint <pid>` a los 25 s |

## 8. Borrar la cuenta

> Los pasos para quien usa Klav están en la página pública [`mac.mdx`](../apps/docs/src/content/docs/apps/mac.mdx) (en `apps/docs/src/content/docs/apps/`); un cambio en esos pasos va primero allí.

Lo mismo que en el iPhone ([ios.md](ios.md) §11), con «este Mac» donde iOS dice «este iPhone» ([ADR 0037](decisiones/0037-borrar-la-cuenta.md) §4, §7).

| La franja mientras espera | Ajustes › Cuenta | El primer paso | Después del borrado, en oscuro |
|---|---|---|---|
| ![La franja con la fecha y «Cancelar el borrado» sobre la bóveda](img/mac/borrar-franja.png) | ![El borrado pedido desde el iPhone, con la fecha y «Cancelar el borrado»](img/mac/borrar-ajustes.png) | ![Qué se borra y qué no, con la fecha a 7 días](img/mac/borrar-hoja.png) | ![La bóveda en solo lectura bajo «Klav borró tu cuenta», con «Borrar la copia de este Mac…»](img/mac/cuenta-borrada-oscuro.png) |

Las capturas usan la bóveda de ejemplo con `-KlavSampleDeletion` (§4).

- **Dónde:** Ajustes (⌘,) › Cuenta, el botón rojo «Borrar mi cuenta». Ajustes tiene ahora dos pestañas: «Este Mac» (la configuración y desinstalar) y «Cuenta». Antes de nada, la app pregunta al servidor si puede (`account_deletion` en `/v1/health`); si no, dice «Este servidor no permite borrar la cuenta desde la app. Pídeselo a quien lo opera.».
- **Los dos pasos** son los del iPhone en una hoja: qué se borra y qué no, con la fecha a 7 días, y la contraseña maestra.
- **Quién hace qué** (ADR 0037 §1, T164):
  - La petición sale del proceso de la app, con `DaemonEngine::request_account_deletion`, como el inicio de sesión (ADR 0027 §3). La contraseña se comprueba aquí y va al servidor con OPAQUE; `klavd` nunca la ve.
  - Touch ID lo pide `klavd`, porque la llave del Secure Enclave es suya: `confirm_presence` abre esa llave y no borra nada. El diálogo lo dice en nombre del servicio de Klav ([klavd.md](klavd.md) §6.1).
  - Touch ID se pide siempre que `touchid.json` exista en `KLAV_HOME`, no solo cuando `klavd` dice que está disponible. Un Touch ID bloqueado por intentos fallidos, o con la tapa cerrada, rechaza la petición en vez de dejar sola a la contraseña, y la hoja dice cómo seguir: abrir la tapa (o, si Touch ID se bloqueó, desbloquear el Mac con su contraseña) y volver a intentarlo, o borrarla desde otro dispositivo. Sin `klavd` corriendo pasa lo mismo: nadie confirma Touch ID, así que no se pide nada. La CLI hace lo mismo: `klav account delete` pide Touch ID a `klavd`, y `klav --no-daemon account delete` se niega mientras exista `touchid.json` ([cli.md](cli.md), enmienda A1 del ADR 0037).
  - Si cambiaron las huellas, `klavd` olvida Touch ID, como al desbloquear, y la hoja pide volver a escribir la contraseña: desde entonces basta ella (riesgo 57). El Mac no tiene un interruptor para apagar Touch ID en Klav. `touchid.json` solo se borra con la cuenta entera (`klav logout` y «Borrar la copia de este Mac»), o en `klavd` cuando el archivo está dañado o cuando, tras un Touch ID correcto, la llave ya no abre. Otro proceso del mismo usuario sí puede borrarlo, o copiar la cuenta a otro `KLAV_HOME` sin él, y desde entonces basta la contraseña (riesgo 57, que es el 49 aplicado a Touch ID).
  - Después, un `klavd` desbloqueado sincroniza y corta en el momento lo que media para los agentes. Uno bloqueado lo aprende al desbloquear.
- **Si ya estaba pedido** (`409`, desde otro dispositivo o con una respuesta perdida), la app pide a `klavd` que sincronice y la franja aparece con la fecha. Con el límite de pedidos (`429`), lo dice en el idioma de la persona.
- **La espera:** Cuenta dice «Tu cuenta se borrará el *día*», desde qué dispositivo y qué día se pidió, con «Cancelar el borrado». En la ventana, una franja con la fecha y el mismo botón queda encima del contenido, en cualquier sección. Pasada la fecha sin que el servidor haya respondido (sin red), dice «Tu cuenta debía borrarse el *día*» y que Klav lo confirma cuando se conecte, nunca «se borrará».
- **Cancelar pide presencia** (enmienda A2 del ADR 0037), lo mismo que reanudar agentes: `klavd` pide Touch ID y, si no puede (un Mac sin Touch ID, la tapa cerrada), la app pide la contraseña maestra y lo intenta otra vez con ella (`cancel_account_deletion_with_password`); una contraseña mala no cancela. Lo hace `klavd` con su sesión, así que tiene que estar desbloqueado: si no, «Desbloquea Klav para cancelar.». Si otro dispositivo ya lo canceló, lo dice.
- **El estado** sale de `status` (`account_deletion`, también con `klavd` bloqueado), que la app lee cada 2 s, así que un borrado pedido o cancelado en otro dispositivo aparece cuando `klavd` sincroniza. `klavd` lo guarda en `account-deletion.json`, así que sigue ahí si `klavd` se reinicia ([klavd.md](klavd.md), Borrar la cuenta). Lo que la app acaba de pedir se muestra hasta que un `klavd` desbloqueado responde después del pedido; uno bloqueado lo aprende al desbloquear. El Mac no recibe avisos de APNs.
- **Después del borrado** (D-C): con `account_deleted` en `status`, la ventana sigue mostrando la bóveda, en solo lectura, bajo una franja fija: «Klav borró tu cuenta. Solo lectura: puedes buscar y copiar, pero no editar ni sincronizar.». Klav no exporta todavía, y un servidor malicioso que finge el borrado no debe empujar a borrar la única copia (T165).
  - Desaparecen Solicitudes, Desarrollo (Agentes, Sandboxes, Actividad, Clientes) y Salud de la bóveda: en la barra lateral, en el menú Ir (⌘2–⌘7) y en la barra de menús, que tampoco muestra la pausa, el último uso de un agente ni las señales de robo. La app deja de pedir las solicitudes.
  - La pantalla de bloqueo dice que la copia se abre en solo lectura; `klavd` la abre con la contraseña o Touch ID, sin red.
  - `klavd` ya no escribe nada de la persona: crear, editar, mover a la papelera, adjuntar, guardar una passkey, el generador (también el de la extensión), borrar el historial, importar, `reset_cache` y las decisiones sobre agentes responden `account_deleted` sin red. Tampoco intenta subir lo que quedó en la cola del generador ([klavd.md](klavd.md), Borrar la cuenta).
  - «Borrar la copia de este Mac…» está en la franja y en Ajustes › Cuenta (con la fecha y el kit de emergencia), y pide confirmar en una hoja: «Klav todavía no exporta tu bóveda: lo que no copies antes a otro lado se pierde.». No es el diálogo del sistema, donde el botón destructivo es el predeterminado y un Return suelto borraría la copia: en la hoja, Return no hace nada y Escape cancela. Funciona también con `klavd` bloqueado. Corre `DaemonEngine::delete_this_copy`: detiene `klavd`, borra los archivos de la cuenta (los mismos que `klav logout`, `touchid.json` incluido) y la app vuelve a arrancar el LaunchAgent, que queda sin cuenta. No toca el servidor, donde ya no hay nada.
  - **Contraseñas generadas sin subir** (pregunta 3 de la revisión, como `klav logout`): las que nunca llegaron a la cuenta solo están en la cola del generador de este Mac (`generator-outbox.bin`), y puede que un sitio ya tenga una. Al abrirse, la hoja las cuenta (`delete_copy_check`): dice «Hay *N* contraseñas generadas que nunca llegaron a tu cuenta: solo están en este Mac. Cópialas en otro sitio antes de borrar esta copia.», las lista con el sitio, la fecha y un botón para copiar cada una, y en lugar del botón de siempre ofrece «Borrar de todos modos». Con `klavd` bloqueado no puede listarlas, así que cualquier cola cuenta: «Puede que en este Mac haya contraseñas generadas…», y desbloquear las muestra. Sin «Borrar de todos modos», `delete_this_copy` se niega (`Denied`) antes de detener `klavd`, y otra vez bajo el cerrojo del *home* después; si esa segunda se niega, la app vuelve a arrancar `klavd`, todavía con la cuenta. La app de Mac no tiene historial del generador: esta lista es lo que deja verlas y copiarlas.
- **Sin cuenta,** Ajustes › Cuenta solo dice «Este Mac aún no tiene una cuenta.».
- **Pruebas:**
  - `crates/klav-ffi/tests/daemon.rs`, con un `klavd` real y el servidor real con la limpieza cada segundo: con `touchid.json` y un `klavd` que no puede confirmar no se pide nada; una contraseña mala, tampoco; pedir con `klavd` desbloqueado lo deja en `status` al momento; cancelar sin Touch ID responde `BiometryUnavailable`, con una contraseña mala no cancela y con la buena sí, y sin nada que cancelar da `false`; con `klavd` bloqueado, `Locked`; pedir con `klavd` bloqueado; y tras el borrado, `account_deleted` con la fecha y la copia legible. Una contraseña que el generador guardó sin red antes de la fecha queda en la cola; después, `klavd` niega el generador y `reset_cache`, el historial la sigue mostrando para copiarla, y `delete_this_copy` se niega (desbloqueado y bloqueado) hasta `discard_unsent`, que borra también la cola;
  - `KlavMacTests/DeleteAccountMacTests.swift` sobre la bóveda de ejemplo (§4), también ya hecho con contraseñas sin subir.
- **A mano:** Touch ID con un dedo de verdad (Omar).

## 9. Sandboxes (ADR 0036 E2, E3.3, E4)

Desarrollo › Sandboxes (⌘7), debajo de Agentes en la barra lateral. Lo arma `SandboxesPane.swift`, y lo que lee y dice sale de `SandboxesModel.swift` (`SandboxBoard`, `SandboxWords`).

- **Lee `sandbox_list_checked(all_proxies: false)`, nunca `sandbox_list`.** Cada lectura sincroniza (`GET /v1/sync`), verifica la bitácora entera y firma una cabeza nueva, así que el panel la vuelve a leer cada minuto mientras está abierto (y al abrirse, si la última tiene más de 30 s) y la barra de menús como mucho cada 5 min; «Volver a leer» la pide al momento. Solo lee con Klav desbloqueado. Abajo dice de dónde sale y cuándo se leyó: «Según la bitácora verificada, hasta el evento n.º 412. Leída hace 3 min».
- **Si una lectura falla** por la red o porque `klavd` no responde, el panel conserva la última lista y dice por qué. Esa lista es una lectura vieja: el encabezado del proxy dice «El proxy no da señales.» en lugar de la edad del latido (un latido que retrocede sigue en rojo) y ninguna fila dice su última conexión, hasta que una lectura salga bien. **Si falla sus comprobaciones** (`Security`: la bitácora no verifica, el latido no es del proxy, el servidor no lista el proxy de la cuenta; o `Rollback`: el servidor mandó datos más viejos), la app tira la lista: no muestra nada viejo como si fuera actual, ni filas ni el encabezado del proxy ni las señales de robo. En su lugar sale «Problema de seguridad» en rojo, arriba, con el motivo y «Volver a leer», y en el panel de la barra de menús, en rojo, «La lista de sandboxes no pasó sus comprobaciones de seguridad», con «Ver». El motivo va en palabras de la app, en el idioma de la persona y con su punto: `sandbox_list_checked` nombra la comprobación que falló (`unlisted_proxy` con el agente, más el comando de la terminal para volver a elegir el proxy; `proxy_heartbeat` con el agente; `log`). Una comprobación que esta versión no conoce, un `Security` de la sesión o un `klavd` anterior a `sandbox_list_checked` (que contesta `bad_request`; la app lee entonces `sandbox_list_flagged`, que falla con `Security`) dan la frase genérica, «Klav no pudo verificar la lista de sandboxes, así que no muestra la última lista que leyó, que puede ya no ser cierta.», y aparte, bajo «Lo que dijo la comprobación (en inglés):», las palabras de `klav-client` sin el `SECURITY: ` de `klavd`.
- **Las edades corren** mientras el panel está abierto (cada 30 s, sin volver a leer): la del latido es la que dio la lista más el tiempo desde la lectura. Si el proxy está callado lo decide `klav-client` en cada lectura (10 min con sandboxes vivos, 40 sin ellos, `NO_SIGNS_LIVE_MS` y `NO_SIGNS_IDLE_MS`); esos umbrales no llegan a Swift, así que la app no lo vuelve a juzgar entre lecturas, que con el panel abierto son cada minuto.
- **El proxy arriba:** «Proxy de credenciales», su nombre entre comillas con el comienzo de su ID, «En pausa» si lo está, y su latido: hace cuánto llegó el último «según el proxy», desde hace cuánto no da señales o por qué (`no_signs`: sin latido, otro almacén, firmado por delante del reloj, un proxy más nuevo…). Un latido que retrocede (`Rollback`) sale en rojo como aviso de seguridad, nunca como un proxy callado: el servidor puede estar reteniendo el último; la lista es correcta y el estado del proxy no se conoce (decisión «Un latido que retrocede», 2026-11-16). Ese aviso no se repite entre los `warnings`.
- **Sin proxy** el encabezado dice «Sin proxy», qué se pierde sin él (credenciales propias por sandbox, *presets* que dejan el token fuera, aprobación y registro de cada llamada, la puerta de MCP y la señal de robo) y cómo configurarlo desde la terminal (`klav-proxy init`, luego `klav proxy use own`). Debajo solo sale lo que la cadena todavía tiene vivo y las señales de robo sin contestar; si no hay nada, solo el encabezado, nunca una lista vacía. Sin proxy ninguna fila dice nada «según el proxy»: no hay latido que hable por ella.
- **El aviso de seguridad** (`security`: `PreferencesByAgent { agent_id, message }` o `Unknown { message }`) va en rojo arriba de todo, aparte de los avisos: dice qué agente escribió las preferencias de la cuenta, que Klav no confía en ningún proxy hasta volver a elegir el propio y que, mientras tanto, la lista muestra los sandboxes de todos los proxies (el encabezado de la lista dice «Sandboxes activos (todos los proxies)», y el del proxy, «Ningún proxy de confianza», sin el texto de «Sin proxy»). «Revocar» en una fila de otro proxy revoca con el proxy de esa fila. La app no puede correr `klav proxy use`: muestra el comando, «Se cambia desde la terminal, con Touch ID:», como la ficha de un agente. Los `warnings` salen como avisos normales.
- **Señales de robo** en rojo, arriba de la lista y en el panel de la barra de menús. Con Klav bloqueado siguen ahí solo si la app leyó la lista desde que se abrió. La app de Mac no tiene el interruptor «Desarrollo» (ADR 0033 E1), así que nada las oculta. Cada una trae «Ver actividad» (la del proxy en Actividad), «Pausar al emisor» (`pause_agents` con su ID, sin preguntar; dice «Pausando…» mientras tanto) y «Entendido», que la pasa a los terminados. «Entendido» vive solo en memoria (decisión de Omar, 2026-11-17): si la app se reinicia, la señal sale otra vez, y nada fuera de la app (sus preferencias, un argumento de arranque) puede marcarla como vista. Las respuestas de señales que ya no están en la lista se olvidan en cada lectura.
- **Sandboxes activos:** esperando el reclamo (si pasan 15 min, dice que puede no haber arrancado), activo, revocando (si el proxy no lo confirma en 2 min, lo dice) y un estado que esta versión no conoce, que cuenta como vivo y nunca se omite. Cada fila: la etiqueta entre comillas «según el emisor», los perfiles, el emisor (abre su ficha), cuándo vence y la última conexión según el latido (nada que creer si el proxy no da señales).
- **«Revocar»** en cada fila y **«Revocar todos…»** arriba, sin Touch ID (E2.3), por `revoke_sandbox` y `revoke_all_sandboxes`. «Revocar todos» abre una hoja: cuántos cubre, que no se puede deshacer, y que sus emisores pueden lanzar otros, con cada emisor y «Pausar agentes…». La respuesta se dice tal cual: revocado en el servidor y «Revocando…» hasta que el proxy confirme, o «No se aplicó» porque el servidor ya tiene una revocación posterior firmada por delante del reloj de este Mac. Con Klav bloqueado: «Desbloquea Klav para revocar… No se revocó nada.». Con el aviso de seguridad no hay «Revocar todos» (`all` es de un proxy y las filas son de todos). La respuesta se queda mientras la lista de la que habla no cambie (una lectura que cambia el estado de una fila, su revocación o su fin, o el proxy de la cuenta, la quita) o hasta la siguiente acción del panel; se va también si una lectura falla sus comprobaciones o Klav cambia de estado (se bloquea, se desbloquea, cierra sesión), y si esa revocación sale en rojo.
- **Después de revocar** la app vuelve a leer con una lectura que empieza después de la respuesta: si había otra en curso, con la lista de antes, la espera y lee otra vez.
- **«El servidor no registró tu revocación»** (E3.3): esa lectura tiene que mostrar la revocación en la bitácora verificada, con `revoked_by_person_ms` de cada sandbox cubierto igual o posterior a la hora firmada que devolvió `revoke_sandbox`. Si no, sale en rojo arriba, con «Revocar otra vez», «Pausar agentes…» y «Abrir el proxy» (su ficha, donde se revoca), en cualquier estado del panel: también sin lista, tras una lectura fallida o mientras corre la primera. «Revocar otra vez» firma de nuevo el mismo sandbox; si era un «Revocar todos», abre su hoja para el proxy de esa revocación, porque un `all` nuevo cubre también los emitidos después. La hoja dice cuántos cubre si la lista en pantalla es de ese proxy; si no hay lista, o es de otro proxy (el ajuste cambió, o el aviso de seguridad), dice que Klav no puede saber cuántos y revoca igual: firmar `all` solo necesita el ID del proxy y la hora, y revocar solo quita acceso. Si «Revocar otra vez» falla, o el servidor contesta «No se aplicó», el bloque sigue en rojo; si el servidor la acepta, la revocación nueva reemplaza a la anterior y sigue en rojo hasta que una lectura la muestre, aunque las lecturas que siguen fallen. Klav lo vuelve a comprobar en cada lectura y lo quita cuando la bitácora lo muestra; una lectura que no puede decirlo (los sandboxes cubiertos ya no están en la lista) no quita uno que ya está en rojo. No reintenta solo: un `all` firmado otra vez cubriría también los sandboxes emitidos después, así que lo decide la persona. Lo que espera esta comprobación vive en memoria: si la app se cierra, se pierde.
- **«Terminados en las últimas 24 h»**, plegado, del más reciente al más viejo por cuándo terminó (o venció), cada uno con por qué terminó (el emisor lo detuvo, venció, una hora sin conexión, señal de robo, el sandbox lo soltó, quitaste su emisor, lo revocaste, un motivo desconocido) y hace cuánto. También los vencidos cuyo fin el proxy aún no registra.
- **En pausa,** una franja cobalto arriba dice que ningún sandbox puede usar el proxy, y un «Revocando…» dice que el proxy lo confirma al reanudar.

**Lo que falta**, porque `DaemonEngine` no lo da y esta capa no toca `crates/`:

- **El bloque «Emisores»** con «Configurar» y «Usar desde sandboxes»: `DaemonEngine` no da la lista `issuers` del grant del proxy ni los perfiles de cada emisor. `grant_editor` solo dice, agente por agente, si un grant es de emisor (`ReadOnlyKind::Issuer`), descifrándolo, y nada añade ni quita un emisor (`klav proxy issuer add/remove`, con Touch ID). Haría falta una operación de `klavd` que lea el grant del proxy, otra que firme el cambio con presencia, y sus funciones en `klav-ffi`.
- **Los avisos locales de E5** (una señal de robo con la app cerrada): `klavd` no reenvía el evento `sandbox` de `GET /v1/events` a la app; haría falta que `klavd` lo exponga (o un `status` con un contador de señales) y un programador de notificaciones en la app.
- **El último uso de cada sandbox** en la bitácora: `LogEntryInfo` no trae el sandbox.
- **El *socket* local del proxy** (E3.5), para el estado en vivo sin esperar al latido.
- **De E3.3, reintentar sola y recordar la comprobación:** «El servidor no registró tu revocación» ofrece «Revocar otra vez» en lugar de reintentar sola, porque un `all` firmado otra vez cubriría también los sandboxes emitidos después (lo decide Omar). Y lo que espera la comprobación vive en memoria: si la app se cierra antes de la siguiente lectura, se pierde. Guardarlo no necesita nada nuevo de `klavd`; queda para una capa siguiente.

Lo que ya estaba:

- **`sandbox_list` sigue fallando con `Security`** si un agente escribió el ajuste, para una app que no sepa mostrar el aviso: nunca le llega una lista limpia.
- **Con un `klavd` anterior** al aviso, `sandbox_list_flagged` pide `sandbox_list`, que falla con `Security`. Lo prueba `the_flagged_sandbox_list_shows_the_flag_or_fails_closed_on_an_older_klavd` en `crates/klav-ffi/tests/daemon.rs`; y `the_checked_sandbox_list_names_its_check_or_fails_closed_on_an_older_klavd`, que cada comprobación llega con su nombre, que una desconocida o una respuesta sin lista ni comprobación sigue siendo un rechazo, y que un `klavd` sin `sandbox_list_checked` cae en `sandbox_list_flagged`.
