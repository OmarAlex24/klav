// A tiny login page on 127.0.0.1 to try `fill` without a real account
// (docs/probar-hito-a.md). It accepts any username and password, never
// prints or stores the password, and only reports how long it was.
//
//   node examples/login-site/server.mjs            # http://127.0.0.1:8765
//   PORT=9000 node examples/login-site/server.mjs

import { createServer } from "node:http";

const port = Number(process.env.PORT || 8765);

const page = (title, body) =>
  `<!doctype html><html lang="en"><meta charset="utf-8"><title>${title}</title>` +
  `<body style="font-family: system-ui; max-width: 24rem; margin: 4rem auto">${body}</body></html>`;

const form = page(
  "Login",
  `<h1>Test site</h1>
<form method="post" action="/session">
  <p><label>Username <input id="user" name="username" autocomplete="username"></label></p>
  <p><label>Password <input id="pass" name="password" type="password" autocomplete="current-password"></label></p>
  <p><button>Sign in</button></p>
</form>`,
);

const escape = (s) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

createServer((req, res) => {
  if (req.method === "POST" && req.url === "/session") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      const fields = new URLSearchParams(body);
      const user = fields.get("username") || "";
      const length = (fields.get("password") || "").length;
      console.log(`login: user=${JSON.stringify(user)}, password of ${length} characters`);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(
        page(
          "Welcome",
          `<h1>Welcome, ${escape(user)}</h1><p>The site received a password of ${length} characters.</p><p><a href="/">Sign out</a></p>`,
        ),
      );
    });
    return;
  }
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(form);
}).listen(port, "127.0.0.1", () => {
  console.log(`test site on http://127.0.0.1:${port}`);
});
