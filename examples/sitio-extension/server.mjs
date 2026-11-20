// A small site on this computer to try the browser extension by hand
// (docs/probar-fase-5.md): a login, a login with a one-time code, a
// sign-up form, a payment form, a shipping address, a page that frames
// the login and sign-ins in several steps (the account first, then the
// password on the same page, after a navigation or in a frame of another
// subdomain, then a code). It accepts anything, stores nothing and never
// prints what it receives: it only says which fields arrived and how long
// they were.
//
//   node examples/sitio-extension/server.mjs          # http://localhost:8766
//   PORT=9000 node examples/sitio-extension/server.mjs
//
// The frame of another subdomain is http://idmsa.localhost:<port>: browsers
// resolve every *.localhost name to this computer themselves (RFC 6761).

import { createServer } from "node:http";

const port = Number(process.env.PORT || 8766);

const page = (title, body) => `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>${title}</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; color: #1f2937; background: #f4f6fa; margin: 0; }
  main { max-width: 26rem; margin: 3rem auto; background: #fff; padding: 2rem; border-radius: 12px; box-shadow: 0 1px 3px #0002; }
  label { display: block; margin-top: 0.9rem; font-size: 0.9rem; color: #475569; }
  input, select { display: block; width: 100%; box-sizing: border-box; font: inherit; padding: 0.55rem 0.7rem; border: 1px solid #cbd5e1; border-radius: 6px; }
  button { margin-top: 1.4rem; width: 100%; font: inherit; font-weight: 600; padding: 0.7rem; border: 0; border-radius: 6px; background: #2b59c3; color: #fff; }
  nav a { display: block; margin: 0.4rem 0; }
  iframe { width: 100%; height: 26rem; border: 1px dashed #94a3b8; border-radius: 8px; }
  .account { margin: 0.9rem 0 0; color: #475569; font-size: 0.9rem; }
  .digits { display: flex; gap: 0.4rem; }
  .digits input { width: 2.6rem; text-align: center; }
  .robot { margin-top: 1rem; display: flex; align-items: center; gap: 0.6rem; padding: 0.8rem; border: 1px solid #cbd5e1; border-radius: 6px; width: auto; }
  .robot input { width: auto; display: inline; }
</style></head>
<body><main>${body}</main></body></html>`;

const LOGIN = (action) =>
  page(
    "Entrar",
    `<h1>Entrar</h1>
<form method="post" action="${action}">
  <label for="usuario">Correo o usuario</label><input id="usuario" name="username" autocomplete="username">
  <label for="clave">Contraseña</label><input id="clave" name="password" type="password" autocomplete="current-password">
  <button>Entrar</button>
</form>`,
  );

/**
 * The account first: «Continuar» shows the password in the same page a
 * moment later (as Apple, Google or Microsoft do), then «Iniciar sesión».
 */
const STEPS = (action) =>
  page(
    "Entrar",
    `<h1>Entrar</h1>
<form method="post" action="${action}">
  <label for="correo">Correo</label><input id="correo" name="username" type="email" autocomplete="username">
  <button type="button" id="continuar">Continuar</button>
  <div id="paso-clave" hidden>
    <label for="clave">Contraseña</label><input id="clave" name="password" type="password" autocomplete="current-password">
    <button>Iniciar sesión</button>
  </div>
</form>
<script>
  document.getElementById("continuar").addEventListener("click", () => {
    if (!document.getElementById("correo").value) return;
    document.getElementById("continuar").hidden = true;
    setTimeout(() => { document.getElementById("paso-clave").hidden = false; }, 400);
  });
</script>`,
  );

/** The second page of a sign-in that navigates: the account as text, then the password. */
const PASSWORD_PAGE = (account) =>
  page(
    "Contraseña",
    `<h1>Contraseña</h1>
<form method="post" action="/sesion">
  <p class="account">${account.replace(/[^\w@.+-]/g, "")}</p>
  <input type="hidden" name="username" value="${account.replace(/[^\w@.+-]/g, "")}">
  <label for="clave">Contraseña</label><input id="clave" name="password" type="password" autocomplete="current-password">
  <button>Iniciar sesión</button>
</form>`,
  );

/** The account here; «Continuar» opens the password in a frame of `host`. */
const FRAMED_STEP = (host) =>
  page(
    "Entrar",
    `<h1>Entrar</h1>
<form id="cuenta" onsubmit="event.preventDefault()">
  <label for="correo">Correo</label><input id="correo" name="username" type="email" autocomplete="username">
  <button type="button" id="continuar">Continuar</button>
</form>
<div id="hueco"></div>
<script>
  document.getElementById("continuar").addEventListener("click", () => {
    const correo = document.getElementById("correo");
    if (!correo.value) return;
    document.getElementById("continuar").hidden = true;
    const frame = document.createElement("iframe");
    frame.title = "Contraseña";
    frame.src = "http://${host}:" + location.port + "/clave-marco";
    document.getElementById("hueco").append(frame);
  });
</script>`,
  );

/** A code in one box per digit, as many sites ask for it. */
const CODE_DIGITS = page(
  "Código de verificación",
  `<h1>Código de verificación</h1>
<form method="post" action="/sesion">
  <label>Código de 6 dígitos</label>
  <div class="digits">${[1, 2, 3, 4, 5, 6].map((i) => `<input name="d${i}" inputmode="numeric" maxlength="1" aria-label="Dígito ${i}"${i === 1 ? ' autocomplete="one-time-code"' : ""}>`).join("")}</div>
  <button>Verificar</button>
</form>`,
);

const PAGES = {
  "/": page(
    "Sitio de prueba de Klav",
    `<h1>Sitio de prueba</h1>
<p>Acepta cualquier dato y no guarda nada.</p>
<nav>
  <a href="/entrar">Entrar</a>
  <a href="/entrar-2fa">Entrar con código de un solo uso</a>
  <a href="/registro">Crear cuenta</a>
  <a href="/pago">Pagar con tarjeta</a>
  <a href="/envio">Dirección de envío</a>
  <a href="/marco">Entrar dentro de un marco</a>
</nav>
<h2>Inicios de sesión en varios pasos</h2>
<nav>
  <a href="/pasos">Primero el correo, luego la contraseña (misma página)</a>
  <a href="/pasos-navega">Primero el correo, luego otra página</a>
  <a href="/pasos-marco">La contraseña en un marco de otro subdominio</a>
  <a href="/pasos-marco-ajeno">La contraseña en un marco de otro sitio (Klav no la escribe)</a>
  <a href="/pasos-2fa">Correo, contraseña y código en casillas</a>
  <a href="/pasos-captcha">Con una casilla «No soy un robot»</a>
  <a href="/pasos-sin-clave">La contraseña nunca aparece</a>
</nav>`,
  ),
  "/entrar": LOGIN("/sesion"),
  "/entrar-2fa": LOGIN("/sesion-2fa"),
  "/registro": page(
    "Crear cuenta",
    `<h1>Crear cuenta</h1>
<form method="post" action="/bienvenida">
  <label for="correo">Correo</label><input id="correo" name="email" type="email" autocomplete="username">
  <label for="nueva">Contraseña</label><input id="nueva" name="password" type="password" autocomplete="new-password">
  <label for="repetir">Repite la contraseña</label><input id="repetir" name="password2" type="password" autocomplete="new-password">
  <button>Crear cuenta</button>
</form>`,
  ),
  "/pago": page(
    "Pagar",
    `<h1>Pagar</h1>
<form method="post" action="/pagado">
  <label for="titular">Nombre en la tarjeta</label><input id="titular" name="cc-name" autocomplete="cc-name">
  <label for="numero">Número de tarjeta</label><input id="numero" name="cc-number" autocomplete="cc-number" inputmode="numeric">
  <label for="caducidad">Caducidad (MM/AA)</label><input id="caducidad" name="cc-exp" autocomplete="cc-exp" placeholder="MM/AA">
  <label for="cvc">Código de seguridad</label><input id="cvc" name="cc-csc" autocomplete="cc-csc" inputmode="numeric">
  <button>Pagar</button>
</form>`,
  ),
  "/envio": page(
    "Dirección de envío",
    `<h1>Dirección de envío</h1>
<form method="post" action="/enviado">
  <label for="nombre">Nombre</label><input id="nombre" name="given-name" autocomplete="given-name">
  <label for="apellidos">Apellidos</label><input id="apellidos" name="family-name" autocomplete="family-name">
  <label for="direccion">Dirección</label><input id="direccion" name="address" autocomplete="street-address">
  <label for="ciudad">Ciudad</label><input id="ciudad" name="city" autocomplete="address-level2">
  <label for="cp">Código postal</label><input id="cp" name="postal-code" autocomplete="postal-code">
  <label for="pais">País</label>
  <select id="pais" name="country" autocomplete="country">
    <option value="">Elige…</option><option value="MX">México</option><option value="ES">España</option><option value="AR">Argentina</option>
  </select>
  <label for="tel">Teléfono</label><input id="tel" name="tel" type="tel" autocomplete="tel">
  <button>Enviar aquí</button>
</form>`,
  ),
  "/marco": page("Panel con un marco", `<h1>Panel con un marco</h1><iframe src="/entrar" title="Entrar"></iframe>`),
  "/pasos": STEPS("/sesion"),
  "/pasos-2fa": STEPS("/sesion-pasos-2fa"),
  "/pasos-navega": page(
    "Entrar",
    `<h1>Entrar</h1>
<form method="post" action="/pasos-navega/clave">
  <label for="correo">Correo</label><input id="correo" name="username" type="email" autocomplete="username">
  <button>Continuar</button>
</form>`,
  ),
  "/pasos-marco": FRAMED_STEP("idmsa.localhost"),
  // The password in a frame of another site (127.0.0.1 is not localhost for Klav): Klav types nothing there.
  "/pasos-marco-ajeno": FRAMED_STEP("127.0.0.1"),
  "/clave-marco": page(
    "Contraseña",
    `<form method="post" action="/sesion">
  <label for="clave">Contraseña</label><input id="clave" name="password" type="password" autocomplete="current-password">
  <button>Iniciar sesión</button>
</form>`,
  ),
  "/pasos-captcha": page(
    "Entrar",
    `<h1>Entrar</h1>
<form method="post" action="/sesion">
  <label for="correo">Correo</label><input id="correo" name="username" type="email" autocomplete="username">
  <div class="robot g-recaptcha" data-sitekey="prueba"><input type="checkbox" id="robot"><label for="robot" style="margin:0">No soy un robot</label></div>
  <button>Continuar</button>
</form>`,
  ),
  "/pasos-sin-clave": page(
    "Entrar",
    `<h1>Entrar</h1>
<form id="cuenta" onsubmit="event.preventDefault()">
  <label for="correo">Correo</label><input id="correo" name="username" type="email" autocomplete="username">
  <button type="button">Continuar</button>
</form>`,
  ),
};

const CODE = page(
  "Código de verificación",
  `<h1>Código de verificación</h1>
<form method="post" action="/sesion">
  <label for="codigo">Código de 6 dígitos</label>
  <input id="codigo" name="code" autocomplete="one-time-code" inputmode="numeric" autofocus>
  <button>Verificar</button>
</form>`,
);

/** Which fields arrived, and how long each was: never their values. */
function received(form) {
  const rows = [...form.entries()].map(([name, value]) => `<li><code>${name.replace(/[^\w-]/g, "")}</code>: ${value.length} caracteres</li>`);
  return page("Recibido", `<h1>Recibido</h1><ul>${rows.join("")}</ul><p><a href="/">Volver</a></p>`);
}

createServer((req, res) => {
  const path = new URL(req.url ?? "/", "http://x").pathname;
  if (req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const form = new URLSearchParams(body);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      if (path === "/sesion-2fa") res.end(CODE);
      else if (path === "/sesion-pasos-2fa") res.end(CODE_DIGITS);
      else if (path === "/pasos-navega/clave") res.end(PASSWORD_PAGE(form.get("username") ?? ""));
      else res.end(received(form));
    });
    return;
  }
  const html = PAGES[path];
  res.writeHead(html ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
  res.end(html ?? page("No existe", "<h1>No existe</h1><p><a href=\"/\">Volver</a></p>"));
}).listen(port, "127.0.0.1", () => {
  console.log(`Sitio de prueba en http://localhost:${port} (parecido: http://127.0.0.1:${port})`);
});
