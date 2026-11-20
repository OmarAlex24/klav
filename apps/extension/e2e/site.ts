/**
 * A small local website to fill: a login form, a one-time code step, a
 * checkout, a same-origin frame, two change-password forms and a
 * password-only confirmation. It listens on 127.0.0.1 and is reached
 * as `localhost` (the item's site) or `127.0.0.1` (a look-alike); a site
 * started with `name: "127.0.0.1"` swaps the two. A form post the test told
 * the site to refuse (`refuse`) answers 422 with the site's error message.
 */
import { createServer, type Server } from "node:http";

const page = (title: string, body: string): string => `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>${title}</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; margin: 0; background: #f4f6fb; color: #1d2433; }
  main { max-width: 360px; margin: 56px auto; background: #fff; padding: 28px 32px 32px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.12); }
  h1 { font-size: 22px; margin: 0 0 18px; }
  label { display: block; font-size: 14px; margin: 14px 0 4px; color: #4a5368; }
  input { width: 100%; box-sizing: border-box; font: inherit; padding: 9px 11px; border: 1px solid #c5cbd8; border-radius: 6px; }
  button { margin-top: 20px; width: 100%; font: inherit; font-weight: 600; padding: 10px; border: 0; border-radius: 6px; background: #2b59c3; color: #fff; }
  iframe { width: 100%; height: 420px; border: 0; }
</style></head><body>${body}</body></html>`;

const LOGIN = page(
  "Entrar · Sitio local",
  `<main><h1>Entrar en Sitio local</h1>
  <form method="post" action="/session">
    <label for="username">Usuario</label>
    <input id="username" name="username" autocomplete="username">
    <label for="password">Contraseña</label>
    <input id="password" name="password" type="password" autocomplete="current-password">
    <button>Entrar</button>
  </form></main>`,
);

const LOGIN_2FA = LOGIN.replace('action="/session"', 'action="/session-2fa"');

const OTP = page(
  "Verificación · Sitio local",
  `<main><h1>Código de verificación</h1>
  <form method="post" action="/done">
    <label for="code">Código de 6 dígitos</label>
    <input id="code" name="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6" autofocus>
    <button>Verificar</button>
  </form></main>`,
);

const SIGNUP = page(
  "Crear cuenta · Sitio local",
  `<main><h1>Crear cuenta</h1>
  <form method="post" action="/welcome">
    <label for="email">Correo</label>
    <input id="email" name="email" type="email" autocomplete="email">
    <label for="new">Contraseña</label>
    <input id="new" name="password" type="password" autocomplete="new-password">
    <label for="again">Repite la contraseña</label>
    <input id="again" name="password_confirmation" type="password" autocomplete="new-password">
    <button>Crear cuenta</button>
  </form></main>`,
);

/** A sign-up whose password field says what it takes (`passwordrules`). */
const SIGNUP_RULES = page(
  "Crear cuenta con reglas · Sitio local",
  `<main><h1>Crear cuenta</h1>
  <form method="post" action="/welcome">
    <label for="email">Correo</label>
    <input id="email" name="email" type="email" autocomplete="email">
    <label for="new">Contraseña (8 letras minúsculas y dígitos)</label>
    <input id="new" name="password" type="password" autocomplete="new-password" maxlength="8"
      passwordrules="minlength: 8; maxlength: 8; required: digit; allowed: lower;">
    <label for="again">Repite la contraseña</label>
    <input id="again" name="password_confirmation" type="password" autocomplete="new-password" maxlength="8">
    <button>Crear cuenta</button>
  </form></main>`,
);

/** A standard change-password form: current, new and confirmation boxes. */
const CHANGE = page(
  "Cambiar contraseña · Sitio local",
  `<main><h1>Cambiar contraseña</h1>
  <form method="post" action="/changed">
    <label for="current">Contraseña actual</label>
    <input id="current" name="current_password" type="password" autocomplete="current-password">
    <label for="new">Contraseña nueva</label>
    <input id="new" name="new_password" type="password" autocomplete="new-password">
    <label for="confirm">Confirma la contraseña nueva</label>
    <input id="confirm" name="confirm_password" type="password" autocomplete="new-password">
    <button>Cambiar</button>
  </form></main>`,
);

/**
 * A change form Klav cannot read: no `autocomplete` and neutral names, so
 * every password box looks like a current password. Only the box the
 * agent focuses tells Klav where the new one goes.
 */
const SETTINGS = page(
  "Ajustes · Sitio local",
  `<main><h1>Ajustes de la cuenta</h1>
  <form method="post" action="/settings">
    <label for="alias">Alias</label>
    <input id="alias" name="alias" type="text">
    <label for="k1">Clave A</label>
    <input id="k1" name="k1" type="password">
    <label for="k2">Clave B</label>
    <input id="k2" name="k2" type="password">
    <button>Guardar</button>
  </form></main>`,
);

/**
 * A password-only confirmation («confirm access», or a username-first
 * sign-in's password step): the account is shown as text, not a box.
 */
const CONFIRM = page(
  "Confirmar acceso · Sitio local",
  `<main><h1>Confirma tu acceso</h1>
  <p>Entraste como <strong>bea</strong>.</p>
  <form method="post" action="/confirmed">
    <label for="password">Contraseña</label>
    <input id="password" name="password" type="password" autocomplete="current-password">
    <button>Confirmar</button>
  </form></main>`,
);

const FRAME = page(
  "Panel · Sitio local",
  `<main><h1>Panel con un marco</h1><iframe src="/login" title="Entrar"></iframe></main>`,
);

/** The site's favicon: a 32×32 teal disc with a white stripe. */
const FAVICON = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAkElEQVR42tXXwQ2AMAxD0U7A3AzAvuXEqaKqYztNI3F+/1SS1k6b67n77NuCWmOiOB3BwlSIGociXPhyhAL5Bg5Q4nCEA4ciXHhKAIoPAdn4ELEDpwNYnApQ4OEAFR4KUOJwgBqHAhz48luQgv8FuHA6wLYXRH+v0qUEXTBKbkRl98Jz1vISh0mZ06zEceqcF3aG0AtDGyroAAAAAElFTkSuQmCC", "base64");

export interface Site {
  port: number;
  /** The item's address. */
  url(path: string): string;
  /** The same server under another name: a look-alike for the login. */
  lookAlike(path: string): string;
  /** Form posts the site received (to check what was submitted), refused ones too. */
  posts: URLSearchParams[];
  /** From now on, posts to `path` fail with `message` (422), like a site that rejects the form. */
  refuse(path: string, message: string): void;
  /** Each request for /favicon.ico: its host (`localhost:…`, `127.0.0.1:…`) and referrer. */
  favicons: { host: string; referer?: string }[];
  close(): Promise<void>;
}

export async function startSite(options: { name?: "localhost" | "127.0.0.1" } = {}): Promise<Site> {
  const posts: URLSearchParams[] = [];
  const refused = new Map<string, string>();
  const favicons: { host: string; referer?: string }[] = [];
  const server: Server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    if (req.method === "POST") {
      let body = "";
      req.on("data", (chunk: Buffer) => (body += chunk.toString()));
      req.on("end", () => {
        posts.push(new URLSearchParams(body));
        const error = refused.get(path);
        if (error !== undefined) {
          res.writeHead(422, { "content-type": "text/html; charset=utf-8" });
          res.end(page("Error · Sitio local", `<main><h1>No se pudo</h1><p role="alert">${error}</p></main>`));
          return;
        }
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(path === "/session-2fa" ? OTP : page("Hola", "<main><h1>Hola</h1></main>"));
      });
      return;
    }
    if (path === "/favicon.ico") {
      favicons.push({ host: req.headers.host ?? "", ...(req.headers.referer ? { referer: req.headers.referer } : {}) });
      res.writeHead(200, { "content-type": "image/png" });
      res.end(FAVICON);
      return;
    }
    const pages: Record<string, string> = {
      "/login": LOGIN,
      "/login-2fa": LOGIN_2FA,
      "/signup": SIGNUP,
      "/signup-rules": SIGNUP_RULES,
      "/frame": FRAME,
      "/password": CHANGE,
      "/settings": SETTINGS,
      "/confirm": CONFIRM,
    };
    const html = pages[path];
    res.writeHead(html ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
    res.end(html ?? "not found");
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  const name = options.name ?? "localhost";
  const other = name === "localhost" ? "127.0.0.1" : "localhost";
  return {
    port,
    url: (path) => `http://${name}:${String(port)}${path}`,
    lookAlike: (path) => `http://${other}:${String(port)}${path}`,
    posts,
    refuse: (path, message) => {
      refused.set(path, message);
    },
    favicons,
    close: () =>
      new Promise((done) => {
        server.closeAllConnections();
        server.close(() => {
          done();
        });
      }),
  };
}
