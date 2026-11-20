# Diseño visual y de interacción

Fuente única para rehacer la interfaz de la extensión y de la app de iOS. Omar
aprobó la dirección el 2026-11-03 sobre la maqueta [`maqueta.png`](maqueta.png).
Lo que no esté aquí se decide siguiendo el mismo espíritu y se anota en esta
página.

## 1. Idea

Técnico y minimalista: la precisión en blanco y negro de Better Auth y Vercel,
con el dither de boat.dev. **El dither no es adorno, es la metáfora del
cifrado:** lo bloqueado u oculto se ve como ruido de píxeles, y al desbloquear
o al pulsar «Mostrar» se disuelve en algo nítido.

- Base blanca y tinta casi negra, líneas finas, esquinas en cruz (como Better
  Auth), botones cuadrados, sin radios ni sombras blandas salvo en lo que
  flota sobre una página.
- **El azul tiene significado:** marca a los agentes (peticiones, avisos, lo
  que un agente hizo) y el tiempo del código de un solo uso. El resto es blanco
  y negro.
- Prohibido (reglas de Omar): fondo crema, palabras en itálica en titulares,
  etiquetas monoespaciadas de adorno o numeración 01/02/03 sin un orden real
  detrás, botones de píldora.

## 2. Tokens

### Claro (por defecto)

| Nombre | Hex | Uso |
|---|---|---|
| Tinta | `#09090B` | Texto, botón principal, borde de lo que flota |
| Papel | `#FFFFFF` | Fondo |
| Niebla | `#F4F4F5` | Fila seleccionada, separadores suaves |
| Línea | `#E4E4E7` | Bordes y divisores |
| Cruz | `#A1A1AA` | Esquinas en cruz |
| Gris | `#71717A` | Texto secundario |
| Marino | `#0D1466` | Tono oscuro del dither |
| Cobalto | `#2337FF` | Agentes, tiempo del código, foco |
| Rojo | `#E5484D` | Denegar, errores, «no coinciden» |

### Oscuro (automático según el sistema)

| Nombre | Hex |
|---|---|
| Fondo | `#09090B` |
| Texto | `#FAFAFA` |
| Niebla | `#18181B` |
| Línea | `#27272A` |
| Cruz | `#52525B` |
| Gris | `#A1A1AA` |
| Marino | `#0A0F4D` |
| Cobalto | `#4555FF` |
| Rojo | `#F2555A` |

El botón principal se invierte (fondo `#FAFAFA`, texto `#09090B`). El dither
oscuro usa la paleta marino → cobalto → `#C9CEFF` en lugar de llegar a blanco
puro. Contraste mínimo AA en todo el texto.

### Tipografía

Las tres son OFL y van empaquetadas (nada de CDN en la extensión ni en iOS):

| Fuente | Uso | Detalle |
|---|---|---|
| **Geist** 400/500/600 | Toda la interfaz | Títulos en 600 con tracking negativo (≈ −0,045em a 22–26 px) |
| **Departure Mono** | Solo códigos de un solo uso y las 6 palabras de emparejamiento | Pixel; da la textura del dither al dato más «vivo» |
| **Geist Mono** | Referencias `klav://`, atajos de teclado, tipo de elemento | Pequeña (10,5–11,5 px), en gris |

Escala: 11 / 12 / 13 (base del popup) / 15 (base de iOS) / 17 / 22 / 26 / 30.

### Forma

- Radio 0 en todo lo de Klav. Lo que flota sobre una página lleva borde de 1 px
  en tinta y sombra `0 12px 32px -12px rgb(9 9 11 / .35)`.
- Esquinas en cruz: marcas de 9 px en «Cruz» en las cuatro esquinas de los
  bloques que agrupan datos (la ficha de un elemento, una petición de agente,
  las 6 palabras). No en cada caja.
- Íconos de acción en cuadros de 28 px con borde «Línea».

## 3. Dither

Dither ordenado con matriz de Bayer 8×8, en *canvas* (extensión) y en
`Canvas`/Metal o una imagen precalculada (iOS). Cada campo es una función
`(u, v) → brillo 0…1` que se reparte entre una paleta de 2 o 3 colores:

```js
const B = [[0,32,8,40,2,34,10,42],[48,16,56,24,50,18,58,26],[12,44,4,36,14,46,6,38],[60,28,52,20,62,30,54,22],
           [3,35,11,43,1,33,9,41],[51,19,59,27,49,17,57,25],[15,47,7,39,13,45,5,37],[63,31,55,23,61,29,53,21]];
// brillo b en [0,1], paleta pal (2 o 3 colores), umbral th = (B[y%8][x%8] + .5) / 64
function pick(b, pal, th) {
  const n = pal.length - 1, s = b * n, i = Math.min(n - 1, Math.floor(s));
  return pal[s - i > th ? i + 1 : i];
}
```

Campos de la maqueta (ruido de valor `vn` suave; ver `maqueta.png`):

- **Cerradura** (pantallas de bloqueo): un ojo de cerradura de luz (círculo +
  ranura que se ensancha hacia abajo) con resplandor exponencial, sobre un
  fondo marino que aclara hacia abajo con vetas horizontales de ruido. Paleta
  marino → cobalto → papel. Píxel de 2 px en el popup y 3 px en iOS.
- **Banda** (peticiones y avisos de agentes): degradado vertical con vetas.
  Misma paleta. Por debajo de 12 pt de ancho el dither ya no se lee como
  banda (a 2 o 3 pt por píxel le quedan tres o cuatro columnas de ruido):
  ahí la marca es una barra lisa en cobalto, el token «Cobalto» (el tono de
  en medio de la paleta, en claro y en oscuro), del mismo tamaño. Es el caso
  de las filas compactas del Mac: la de las solicitudes y la de la pausa en
  el panel de la barra de menús, la línea de la pausa en Sandboxes y el
  bloque de la pausa en Agentes. Con ancho de banda sigue siendo el dither,
  como en las tarjetas de Solicitudes, Actividad y Agentes y en la
  extensión. Decisión de Omar del 2026-11-17. La app de iOS todavía dibuja
  el dither a 10 pt en el bloque de la pausa de Agentes.
- **Máscara** (secreto oculto): ruido de dos tonos gris claro sobre papel, en
  lugar de `••••`.
- **Glifo** (sello del campo y logo): la llave en pixel de 8×8. Es el logo
  definitivo de Klav (§7, «Logo»).

Movimiento, siempre con `prefers-reduced-motion` respetado (sin animación,
cambio directo):

- **Desbloquear:** el umbral sube en ~400 ms y la luz de la cerradura inunda
  el campo antes de pasar a la bóveda.
- **Mostrar:** la máscara se disuelve en el texto en ~200 ms (el texto aparece
  por píxeles según el mismo umbral).
- **Código de un solo uso:** la barra avanza por bloques, uno por segundo; nada
  de transiciones suaves.

## 4. Comportamiento que pidió Omar

### 4.1 Códigos de un solo uso a la vista

- Al abrir el popup en un sitio con un login que tiene TOTP, la fila de ese
  login muestra **el código vivo** en Departure Mono con su botón de copiar y
  la barra de tiempo, sin entrar a la ficha. Copiar = un clic (y un atajo de
  teclado que se documenta).
- En la lista general, los elementos con TOTP también enseñan el código en su
  fila.
- El código se pide a `klavd` solo mientras se ve; el portapapeles se borra a
  los 30 s como hoy.

### 4.2 Propuestas inteligentes, en tres lugares

Referencias de Omar: el aviso de inicio de sesión arriba de la página y el
buscador central de 1Password.

1. **En el campo:** al enfocar un campo de usuario, contraseña, código o
   tarjeta, aparece el menú anclado al campo (el que ya existe, rediseñado).
2. **Arriba de la página:** si la página tiene un login y hay un elemento que
   coincide, aparece una tarjeta pequeña arriba a la derecha (o centrada en
   pantallas estrechas): «Iniciar sesión como **ana** · github.com» con
   «Iniciar sesión» y cerrar. No tapa el formulario y desaparece si el usuario
   empieza a escribir. Nunca rellena sola sin un clic.
3. **Buscador central:** con un atajo (y desde el menú del campo: «Buscar otro
   elemento»), una paleta centrada en la página con búsqueda («Busca un
   login…») y la lista filtrada, primero los del sitio. Sirve para cuando el
   usuario quiere otra cuenta o el campo no se detectó.

Las tres siguen la regla anti-phishing: solo se ofrecen elementos cuyo sitio
coincide con el origen del marco donde se va a escribir (ADR 0006 y 0017). El
buscador central puede listar otros elementos, pero rellenar uno que no
coincide pide confirmación explícita con el host a la vista.

### 4.3 Login en varios pasos

Sitios como developer.apple.com, Google o Microsoft piden primero el correo,
un botón «Continuar», y luego la contraseña (a veces en un `iframe` de otro
subdominio del mismo sitio, como `idmsa.apple.com`).

Al elegir un login, Klav:

1. rellena el usuario y pulsa «Continuar» (o el botón de envío del
   formulario);
2. espera a que aparezca el campo de contraseña, en la misma página (cambio
   del DOM) o tras una navegación del mismo sitio, durante un tiempo corto;
3. rellena la contraseña y pulsa «Iniciar sesión»;
4. si después aparece un campo de código y el elemento tiene TOTP, lo rellena
   también.

Reglas:

- El estado «a medio rellenar» vive en el *service worker*, ligado a la
  pestaña, al sitio del elemento y a un plazo corto (≈ 60 s). Se cancela si el
  usuario cambia de sitio, cierra la pestaña o escribe a mano.
- Cada paso vuelve a comprobar que el marco coincide con el elemento. Un marco
  de otro subdominio solo recibe datos si el elemento lo permite según
  ADR 0006.
- Pulsar los botones solos es el comportamiento por defecto en este flujo,
  porque el usuario ya eligió el login. Un ajuste permite desactivarlo
  («Solo rellenar, no pulsar»).
- Si algo no cuadra (no aparece la contraseña, aparece un captcha), Klav se
  detiene y lo dice con el menú abierto en el campo, sin reintentar a ciegas.

## 5. Superficies

- **Extensión:** popup (bloqueado, bóveda, ficha, peticiones de agentes,
  copiado), menú en el campo, tarjeta de arriba, buscador central, barra de
  guardar/actualizar, generador y aviso «Klav rellenó esta página para el
  agente …». Íconos de la extensión.
- **iOS:** desbloqueo, inicio de sesión, bóveda, ficha, editor, ajustes,
  peticiones, aprobación de agentes (las 6 palabras en rejilla de 3×2) y la
  interfaz del autollenado (lista y «Abre Klav primero»). Ícono de la app.

## 6. Textos

La interfaz habla inglés (el idioma base) y español, según el idioma del
navegador o del sistema; cualquier otro idioma cae en inglés. En los dos,
desde el lado de quien usa Klav y con verbos concretos: «Sign in as ana» /
«Iniciar sesión como ana», «Copy code» / «Copiar código», «They match:
approve» / «Coinciden: aprobar». Una acción conserva su nombre en todo el
flujo. Los errores dicen qué pasó y qué hacer, sin disculparse. Cómo se
organizan los catálogos: [extension.md](../extension.md) §10 y
[ios.md](../ios.md).

## 7. Decisiones de la implementación

Lo que la implementación fijó y esta página no decía. Se anota aquí para que
iOS lo siga igual.

### Logo

La llave en pixel, sola, es el logo definitivo de Klav: la misma rejilla de
8×8 del glifo, sin letra al lado ni dentro. Va en el sello del campo, en la
cabecera del *popup* junto a «klav», en los íconos de la extensión y en el
de la app. No hay otras variantes del logo.

### Base (tokens, fuentes, dither e íconos)

- **Fuentes:** Geist va como fuente variable (`Geist[wght].woff2`, un solo
  archivo para 400/500/600), Geist Mono en 400 y Departure Mono 1.500. Viven
  en `apps/extension/static/fonts` con sus licencias OFL; ninguna se carga
  de fuera.
- **Máscara:** la paleta clara es papel → `#E4E4E7` → `#C8C8CE`; la oscura,
  `#09090B` → `#27272A` → `#3F3F46`. El tercer tono es un gris propio (un
  paso más oscuro que «Línea») para que el ruido se lea sin parecer texto.
- **Glifo:** la llave ocupa 8×5 celdas de su rejilla de 8×8: un
  anillo de 4×5 con hueco, el vástago y dos dientes hacia abajo
  (`apps/extension/src/shared/glyph.ts`).
- **Íconos de la extensión:** la llave en papel sobre un cuadrado de tinta,
  con un número entero de píxeles por celda (1, 3, 4 y 11 px en 16, 32, 48
  y 128). Se ve igual en barras claras y oscuras. `scripts/icons.mjs` los
  vuelve a generar sin navegador.
- **Barra del código:** 30 bloques, uno por segundo del periodo; los que
  quedan van en cobalto desde la izquierda y los gastados en «Línea».
- **Íconos de sitios:** el cuadro de la inicial (radio 0, borde «Línea»)
  lleva el logo del sitio si Klav lo trae (Simple Icons, 16 px dentro del
  cuadro de 28, en el color de la tinta, nunca el de la marca); si no, el
  favicon que el navegador ya tiene, en escala de grises para que ningún
  color ajeno compita con el cobalto; si no, la inicial. Nunca se consulta
  a un servicio de íconos: las tres capas y el ajuste para pedirlo al
  propio sitio están en [extension.md](../extension.md) §7. iOS usa el
  mismo mapa (`assets/site-icons/site-icons.json`).

### *Popup*: nuevo elemento

- **«+»** en la cabecera, primero de los cuadros de 32 px (antes de Salud,
  Generador y Ajustes): crear es la acción más general de las cuatro.
- **Tipo:** el mismo selector de cuatro casillas que el generador (Login,
  Nota segura, Tarjeta, Código), con la casilla elegida en «Niebla» y una
  raya de tinta debajo. Nada en azul: crear a mano no es cosa de agentes.
- **Campos:** la etiqueta en gris de 11 px encima de cada entrada de 36 px,
  como en la ficha de un elemento. Los secretos (contraseña, número, código
  de seguridad y la clave del código) van tapados con puntos mientras se
  escriben, en Geist Mono; «Mostrar» y el asterisco del generador son
  cuadros de 36 px al lado del campo. El error va debajo de su campo, en
  rojo, y el borde del campo se pone rojo.
- **Guardar:** botón principal a todo el ancho, al final; no hay
  «Cancelar» porque «Tu bóveda» y «Esc» ya salen sin guardar.

### Pestañas por tipo y «Códigos»

- **Pestañas:** una línea bajo la búsqueda, texto en gris de 12 px (14 pt
  en iOS) con el ícono del tipo delante (abajo) y el número en gris más
  pequeño, sin cajas. La elegida va en
  tinta con la raya de 2 px abajo, la misma de los tipos del generador. Una
  línea «Línea» cierra la fila. Si no caben, se desplazan de lado y se
  desvanecen 36 px (32 pt) en el borde que esconde más; nunca se cortan en
  seco. Sin azul: elegir un tipo no es cosa de agentes ni de tiempo.
- **«Códigos»:** cada fila es un solo botón que copia, con el cursor
  `copy` en el *popup*. Arriba el título en tinta y el usuario en gris en
  la misma línea; debajo el código en Departure Mono de 30 px (34 pt en
  iOS) y sus 30 bloques. A la derecha va un cuadro de copiar de 28 px
  (36 pt) que pasa a ✓ con borde de tinta 1,5 s después de copiar. Al
  pasar el ratón o al pulsar, la fila toma «Niebla» y la raya de 2 px en
  cobalto a la izquierda, como la fila elegida del menú. Las filas se
  separan con «Línea».

### Íconos de los tipos

- **Familia:** los íconos de trazo de la interfaz (rejilla de 16, trazo
  de 1,5, puntas cuadradas), no el pixel. La rejilla de 8×8 es el logo y
  no tiene variantes, y a 16 pt sus celdas de 2 pt no alcanzan para nueve
  figuras que se distingan. Un punto es un trazo casi sin largo: lo dibuja
  la punta cuadrada.
- **Uno por tipo, el mismo en el iPhone, el Mac y la extensión:**

  | Tipo | Ícono |
  |---|---|
  | Todo | cuatro cuadros |
  | Logins | un campo con tres puntos |
  | Códigos (y los `totp` sueltos) | un cronómetro |
  | Tarjetas | la tarjeta con su banda |
  | Notas seguras | una hoja con renglones |
  | Llaves de API | `{ }` |
  | Llaves SSH | el *prompt* `>_` |
  | Direcciones | una casa |
  | Archivos | la hoja con la esquina doblada |

  La llave de trazo no es de ningún tipo: la usan las *passkeys* en la
  extensión.
- **Dónde:** las pestañas por tipo del iPhone (16 pt, crece con Dynamic
  Type) y del *popup* (14 px), y la barra lateral del Mac (16 pt). Los
  trazos están dos veces, iguales: `Icon` en `apps/ios/Shared/Theme.swift`
  y `ICONS` en `apps/extension/src/ui/kit.ts`. Eligen `Kind.icon`,
  `VaultFilter.icon` y `KIND_ICONS`.
- **Color:** gris; tinta en la pestaña o la fila elegida, y bajo el cursor
  en el Mac. Nunca cobalto: un tipo no es cosa de agentes ni de tiempo.
- **El resto de la barra del Mac,** en la misma familia: las bóvedas (una
  caja fuerte), Solicitudes (una bandeja), Agentes (un robot), Sandboxes
  (un cubo en perspectiva, la caja desechable donde trabaja un agente),
  Actividad (una lista con viñetas), Clientes (un enchufe) y Salud (el
  pulso que la extensión ya usa). «Pausar agentes» usa dos barras verticales, en el
  bloque de Agentes y en el panel de la barra de menús; con todos los
  agentes en pausa, la llave de la barra de menús lleva esas dos barras en
  pixel bajo los dientes (ADR 0033 §7.5).

### En la página (menú, tarjeta, buscador, guardar y aviso)

- **Cinco marcos, una hoja de estilos:** cada superficie es una página de la
  extensión en un `iframe` dentro de la raíz *shadow* cerrada
  (`apps/extension/src/ui/inpage.css`). El borde de tinta lo dibuja el propio
  marco (`.frame-edge`, el mismo elemento que vigila el control contra
  *clickjacking*); la sombra la pone el `iframe`.
- **Menú del campo:** cabecera «Klav · host» con el atajo, filas con el
  ícono del sitio (o la inicial), el título y el usuario, y `↵` solo en la fila elegida. La fila
  elegida lleva fondo «Niebla» y una raya de 2 px en cobalto (el foco del
  teclado necesita algo más visible que el gris). Al final, siempre, «Buscar
  otro elemento» con su cuadro punteado, como «Generar contraseña» en la
  maqueta.
- **Generador:** solo en campos de contraseña nueva, arriba del menú, y en el
  *popup* (asterisco). Su firma es la propia contraseña: Geist Mono de 15 px
  sobre papel, **letras en tinta, dígitos en gris y cada símbolo en su celda
  de «Niebla»** (G10), sin azul, porque el cobalto es de los agentes y del
  tiempo. Encima, los cuatro tipos en una fila de cuadros con borde
  «Línea». El elegido va sobre «Niebla» con una raya de 2 px en tinta, la
  misma que dice «esto está elegido» en el resto. Al lado del valor, «Copiar»
  y «Otra» en cuadros de 36 px. Debajo, la fuerza en cuatro segmentos de
  14 × 6 px: en tinta o, si es débil, en rojo, que aquí es marca y no texto.
  Sigue la etiqueta «Fuerte · 64 bits», y en gris qué reglas siguió. Las
  casillas son cuadradas: tinta con una marca de papel.
- **Bloqueado:** la cerradura en dither en un cuadro de 32 px junto a «Klav
  está bloqueado.»; mismo campo que el popup, en pequeño.
- **Tarjeta de arriba:** 380 px arriba a la derecha (centrada si la ventana
  mide menos de 560). «Iniciar sesión como **ana** · host», el título y su
  proyecto debajo, «Iniciar sesión» y, si hay más logins del sitio, «Otra
  cuenta», que abre el buscador. Solo sale con Klav desbloqueado, una por
  pestaña; cerrarla o escribir en el formulario la descarta para ese sitio en
  esa pestaña.
- **Buscador:** 560 px centrado a un 12 % del alto, sobre un velo de tinta al
  28 %. Secciones «En host», «Otros logins», «Tarjetas» y «Direcciones»; los
  logins de otro sitio llevan su host en Geist Mono a la derecha. Elegir uno
  lleva a «¿Rellenar X en host?»: los dos hosts lado a lado en un bloque con
  esquinas en cruz, el de la página subrayado en rojo y «No coinciden» con
  su cuadrito rojo. El rojo nunca va en texto pequeño (no llega a AA sobre
  papel): marca, no letra.
- **Atajo:** ⌘⇧L (Ctrl+Shift+L) abre el menú si hay un campo enfocado y el
  buscador si no.
- **Avisos y errores en los marcos:** texto en tinta sobre «Niebla» con una
  raya roja a la izquierda, por la misma razón.
- **Barra de guardar:** misma posición que la tarjeta; la pregunta con la
  inicial y «usuario · host», campos «Título» y «Dónde», «Guardar» o
  «Actualizar» y «Ahora no».
- **Aviso de agente:** a lo ancho, pegado abajo, con borde de tinta solo
  arriba, como en la maqueta: una banda en dither de 36 px, «Klav rellenó esta
  página para …» en cobalto y el motivo en gris. Se cierra solo a los 12 s.

### Login en varios pasos

- **Quién conduce:** Klav sigue los pasos cuando la persona eligió el login
  en el menú, la tarjeta, el buscador o el *popup*. En el primer paso solo
  pulsa si el formulario pedía únicamente la cuenta («Continuar»); un
  formulario de una sola página se rellena y se envía a mano, como siempre.
  El código de un solo uso entra solo si Klav venía conduciendo (pulsó un
  botón); si la persona envió el formulario, la página del código lo ofrece
  en el menú y espera un clic, como antes.
- **Plazos:** el flujo dura como mucho 60 s por pestaña; tras «Continuar»,
  Klav espera la contraseña 10 s. Se cancela si la persona escribe en un
  campo, si la pestaña se cierra o si una página nueva de la pestaña ya no
  es del sitio del elemento.
- **Qué botón:** el de envío del formulario, o uno cuyo texto diga
  «Continuar», «Siguiente», «Iniciar sesión», «Entrar», «Verificar»…; nunca
  «Continuar con Google», «¿Olvidaste tu contraseña?» ni «Crear cuenta».
- **Paradas:** con un captcha a la vista (reCAPTCHA, hCaptcha, Turnstile)
  Klav no pulsa nada; si la contraseña no aparece, o aparece en un marco de
  otro sitio, se detiene. En los tres casos abre el menú en el campo con una
  frase de lo que pasó (raya de tinta, no roja: no es un error de la
  persona) y no reintenta.
- **Códigos en casillas:** de 4 a 8 cajas de un carácter seguidas se tratan
  como un solo código; cada dígito va a su caja.
- **Ajuste:** «Solo rellenar, no pulsar» en una pantalla de ajustes del
  *popup* (botón de engranaje junto a «Bloquear»), con una casilla cuadrada
  en tinta. La misma pantalla lista los dos atajos.

### iOS (app y autollenado)

- **Fuentes:** los mismos `woff2` de la extensión, convertidos a `ttf` con
  `scripts/ios/fonts.sh` (fontTools; iOS no carga `woff2`). Geist sigue
  siendo variable: SwiftUI pide sus instancias por nombre PostScript
  (`Geist-Regular`, `Geist-Medium`, `Geist-SemiBold`). Todas crecen con
  Dynamic Type (`relativeTo:`).
- **Píxel del dither:** 4 pt en los campos que ocupan todo el ancho (la
  cerradura del bloqueo, del inicio de sesión, del selector de apps y del
  autollenado). La maqueta los dibuja más gruesos que los 3 pt de §3. La
  banda de las peticiones va a 3 pt y la máscara a 2 pt.
- **Bloqueo:** la cerradura empieza debajo de la barra de estado y ocupa el
  52 % del alto; con el teclado abierto baja al 22 %. Al desbloquear, el
  umbral sube en 12 pasos (~400 ms) antes de mostrar la bóveda.
- **Botón principal deshabilitado:** «Niebla» con texto gris y borde
  «Línea». En oscuro, la opacidad al 50 % se leía como un bloque gris.
- **Interruptores:** una casilla cuadrada de 22 pt con borde de tinta;
  encendida, se llena de tinta con un ✓ en papel. Va en lugar del
  interruptor redondo de iOS, como la casilla del *popup*.
- **Íconos de la interfaz:** trazos dibujados a mano en una rejilla de 16
  (copiar, cerrar, atrás, +, ✓, buscar, ajustes y los de los tipos), sin SF
  Symbols. El área
  que se toca mide 44 pt aunque el cuadro se vea de 36.
- **Ícono de la app:** la llave en pixel (celdas de 80 px) sobre la banda en
  dither de marino a cobalto, con píxel de 16 px en 1024. La variante oscura
  usa tinta → marino oscuro con la llave en `#C9CEFF`; la teñida, solo
  grises. `scripts/ios/app-icon.sh` las genera con el mismo código del
  dither.
- **Filas de la bóveda:** el código en vivo se pide a `klav-core` solo
  mientras la fila está en pantalla, y tocarlo lo copia. Con texto de
  accesibilidad la fila se apila: el código pasa bajo el título y la
  etiqueta del tipo se oculta.
- **Copiar:** el aviso cuenta hacia atrás los 30 s hasta que Klav borra el
  portapapeles. Una hoja que copia (el generador) lo muestra encima de
  ella, porque la hoja tapa el de la raíz.
- **Generador:** el mismo de la extensión, en una hoja. Con texto de
  accesibilidad los cuatro tipos pasan a una columna y la raya de tinta
  del elegido va a la izquierda, como en la fila elegida del menú.
- **Peticiones:** tres acciones de ancho natural («Aprobar una vez»,
  «Aprobar 15 min», «Denegar») que pasan a dos filas si no caben. La
  petición que abrió un aviso lleva borde cobalto de 1,5 pt.
- **Agente nuevo:** su tarjeta dice «Comparar palabras». Proyectos y
  duración son fichas cuadradas con ✓. «Coinciden: aprobar» y «No
  coinciden» quedan fijos abajo.
- **Bienvenida al autollenado:** la cerradura en la paleta de la máscara
  (cerrada, como «Abre Klav primero») sobre el camino de Ajustes. Cada
  página es una fila unida por una ruta a la izquierda, con paradas de
  5 pt en «Cruz», no casillas: la única casilla es la de la fila de Klav,
  la misma de los interruptores. Al activarlo, la casilla se llena y la
  cerradura pasa a la paleta azul con la luz abierta a 0,3 (8 pasos,
  ~320 ms). La inundación completa del desbloqueo dejaría el campo en
  blanco. Con Reducir movimiento cambia de golpe.
- **Autollenado:** «Rellenar», no «Llenar», como la extensión. «Abre Klav
  primero» usa la cerradura en la paleta de la máscara, en grises: está
  cerrada hasta que la app la abra.
- **Papelera:** solo «Mover a la papelera», con confirmación. No hay lista
  porque `klav-client` aún no sabe restaurar.
- **Arranque:** la pantalla de arranque es «Papel», con su tono oscuro.

### Sitio web (`klav.dev`)

La página de [`apps/web`](../../apps/web) ([sitio-web.md](../sitio-web.md))
cuenta que Klav es el gestor de secretos para la era de los agentes, en seis
bloques: arriba, el problema, «acciones, no valores», el proxy
(próximamente), las contraseñas en corto y el precio. Qué afirma y de dónde
sale cada cosa: [sitio-web.md](../sitio-web.md) §6.

- **Mismos tokens, mismas fuentes:** el CSS repite los de la extensión, con
  el tema oscuro según el sistema (y `?theme=dark` para capturas). Las tres
  fuentes se sirven desde el propio sitio; nada se carga de fuera y la
  página sigue sin dependencias de npm.
- **Arriba:** «The agent asks. You decide.» / «El agente pide. Tú
  decides.», en dos líneas de 44–70 px, y a la derecha la cerradura en
  dither (píxel de 4 px, esquinas en cruz) con una petición de `claude-code`
  flotando encima: quiere inyectar Stripe en `npm test`. «Aprobar» sube la
  luz de la cerradura a 0,34 en 10 pasos (~400 ms) y la tarjeta pasa a
  «claude-code corrió las pruebas»; «Denegar» la deja con el cuadrito rojo.
  Es la única petición animada de la página.
- **El problema:** tres paneles sobre «Niebla» (en un sandbox, en la CI, en
  tu computadora) con el valor expuesto subrayado en tinta. Sin rojo: no es
  un error de quien lee.
- **Acciones, no valores:** cinco escenas en un bloque con esquinas en
  cruz, el texto a la izquierda y la ilustración sobre «Niebla» a la
  derecha (debajo, en pantallas estrechas), y dos piezas cortas al final
  (MCP, skill y CLI; el informe «qué vio»).
  - **La tarjeta del agente:** las 6 palabras en Departure Mono y su
    política en una rejilla de 8 permisos × `allow`/`ask`/`deny`. La casilla
    elegida va en tinta; en `deny`, en rojo (marca, no letra). Es la misma
    política que pide la petición de arriba (`inject` en `ask`).
  - **La tarea:** la tarjeta de una tarea con la banda en dither, tres
    elementos y «Aprobar» / «Denegar» de adorno.
  - **La salida tapada** y **el `.env` que se vuelve `klav.toml`:** dos
    ilustraciones de dos estados. Las pestañas nombran los estados
    («./debug.sh printed» / «claude-code got back», con el cuadrito del
    agente en `#AAB2FF`, legible sobre la terminal; `.env` / `klav.toml`),
    para que nunca parezca que el agente vio el valor. Cada estado se
    sostiene ~3 s o ~4,5 s; para pasar al otro, lo que cambia se cubre con
    la **máscara** en dither (§3), barriendo de izquierda a derecha por
    umbrales de Bayer en 6 pasos, el contenido cambia debajo y la máscara
    se retira en otros 6. En la terminal la máscara usa la paleta oscura
    (fondo de la terminal → `#27272A` → `#3F3F46`) en los dos temas. Pulsar
    una pestaña detiene el ciclo y elige ese estado.
  - **Tu agente personal:** arriba, la terminal del agente (`my-agent`,
    con el nombre en `#AAB2FF`) con la llamada a `fill_login`; debajo, una
    ventana de navegador en «Papel» con la dirección y el sello de la llave,
    y el login de un sitio inventado. Klav escribe el usuario y después la
    contraseña, un carácter por paso, con el campo activo en tinta y el
    sello encendido mientras escribe. Al terminar aparece el aviso de la
    extensión (la banda azul en dither que entra por umbrales, el cuadrito
    y «Klav filled this page for “my-agent”» con el motivo) y en la
    terminal, la respuesta: los nombres de los campos, nunca los valores.
    El valor no pasa por la terminal en ningún momento. Sin máscara: aquí
    nada se quita. Ciclo de ~8 s, sin pestañas.
- **El proxy (próximamente):** la etiqueta cuadrada «Coming soon» con borde
  de tinta encima del titular. La escena es el sandbox (un campo azul en
  dither, porque es el sitio del agente, con `env | grep RAILWAY` y «no hay
  ningún token»), el proxy (la llave en su sello) y la API, unidos por
  cables punteados en «Cruz». Por los cables viajan cuadritos de 12 px a
  saltos: azul, la credencial del sandbox; tinta, tu token, que solo va del
  proxy a la API; papel con borde gris, la respuesta. Tras dos vueltas el
  sandbox se disuelve (umbral hacia abajo), su borde pasa a punteado y la
  terminal dice que su credencial murió; la llave sigue en el proxy y un
  sandbox nuevo vuelve a aparecer. Una leyenda nombra los tres cuadritos.
  Debajo van seis frases de lo que hace el proxy, la tabla de los tres
  modos (las dos columnas de Klav sobre «Niebla»), «te toca» y «lo que
  ningún modo resuelve», y «También en camino», con sus cuatro puntos en
  una rejilla de 2 × 2 (una columna en el móvil).
- **Tablas en móvil:** cada fila se apila; el nombre de la columna va a la
  izquierda en gris de 12 px y el valor a la derecha.
- **Movimiento:** todo avanza a ~8 cuadros por segundo, por umbrales y sin
  suavizado, y cada ilustración se detiene fuera de pantalla
  (`IntersectionObserver`). Con *Reducir movimiento* nada se mueve: la
  salida tapada y el `klav.toml` se ven en su estado final, el agente
  personal con el login relleno, el aviso y la respuesta, el proxy con tu
  token a medio camino hacia la API, las pestañas cambian de golpe y
  aprobar también.
- **Contraseñas:** tres réplicas en pequeño de lo que ya existe: el menú del
  campo, una fila de passkey en ese menú y el código de un solo uso con su
  barra de 30 bloques (inventado, cambia cada 30 s).
- **Precio y lista de espera:** dos tarjetas; la del plan alojado lleva
  borde de tinta. El formulario es un campo y «Unirme a la lista», sin
  azul: los errores van en tinta sobre «Niebla» con una raya roja y lo
  hecho, con una raya de tinta («Ya estás en la lista…»). El botón «Unirme a
  la lista» de arriba lleva al formulario con el cursor ya en el campo.
- **Idioma:** inglés o español según el navegador, con el selector EN/ES en
  la cabecera; la elección se recuerda en ese navegador. Los textos que las
  ilustraciones cambian solas no llevan `data-i18n`: los escribe el JS en
  el idioma elegido.
- **Imagen para redes:** `og.png`, 1200×630, «The agent asks. You decide.»
  a la izquierda y la cerradura a la derecha, con los mismos tokens.
