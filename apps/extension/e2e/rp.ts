/**
 * A relying party for the passkey e2e (ADR 0020): a page that registers
 * and signs in with WebAuthn, and a server that verifies both the way a
 * real RP does, independently of Klav's code. It uses only `node:crypto`
 * and the small CBOR decoder below (no new dependency):
 *
 * - registration: `clientDataJSON` (type, challenge, origin), the `none`
 *   attestation object, the authenticator data (rpIdHash, flags, counter,
 *   AAGUID, credential ID) and the COSE key it carries;
 * - sign-in: `clientDataJSON`, the authenticator data, and the ES256
 *   signature over `authData ‖ SHA-256(clientDataJSON)` with the key saved
 *   at registration, and the user handle.
 *
 * It listens on 127.0.0.1 and is reached as `localhost` (rpId
 * `localhost`, which WebAuthn and Klav accept over http).
 */
import { createHash, createPublicKey, type KeyObject, randomBytes, verify } from "node:crypto";
import { createServer, type Server } from "node:http";

// ------------------------------------------------------------ CBOR --

type Cbor = number | bigint | Uint8Array | string | Cbor[] | Map<Cbor, Cbor> | boolean | null | undefined;

/** Decodes one CBOR item (definite lengths; what WebAuthn uses). Throws on anything odd. */
export function decodeCbor(bytes: Uint8Array): { value: Cbor; rest: Uint8Array } {
  let at = 0;
  const take = (n: number): Uint8Array => {
    if (at + n > bytes.length) throw new Error("CBOR: truncated");
    const out = bytes.subarray(at, at + n);
    at += n;
    return out;
  };
  const length = (info: number): number => {
    if (info < 24) return info;
    const size = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
    if (!size) throw new Error("CBOR: indefinite or reserved length");
    let n = 0;
    for (const b of take(size)) n = n * 256 + b;
    return n;
  };
  const item = (): Cbor => {
    const head = take(1)[0] ?? 0;
    const major = head >> 5;
    const info = head & 31;
    switch (major) {
      case 0:
        return length(info);
      case 1:
        return -1 - length(info);
      case 2:
        return Uint8Array.from(take(length(info)));
      case 3:
        return new TextDecoder("utf-8", { fatal: true }).decode(take(length(info)));
      case 4:
        return Array.from({ length: length(info) }, item);
      case 5: {
        const map = new Map<Cbor, Cbor>();
        const n = length(info);
        for (let i = 0; i < n; i++) {
          const key = item();
          map.set(key, item());
        }
        return map;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new Error("CBOR: unsupported simple value");
      default:
        throw new Error(`CBOR: unsupported major type ${String(major)}`);
    }
  };
  const value = item();
  return { value, rest: bytes.subarray(at) };
}

// ------------------------------------------------------- WebAuthn RP --

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
const unb64 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "base64url"));
const sha256 = (data: Uint8Array): Uint8Array => new Uint8Array(createHash("sha256").update(data).digest());
const equal = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/** Klav's AAGUID (spec §14.8). */
export const KLAV_AAGUID = "a36a6cd0-200d-411f-a41d-b964cce16689";

function uuid(bytes: Uint8Array): string {
  const hex = Buffer.from(bytes).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface AuthData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  aaguid?: string;
  credentialId?: Uint8Array;
  coseKey?: Map<Cbor, Cbor>;
}

function parseAuthData(data: Uint8Array): AuthData {
  if (data.length < 37) throw new Error("authData too short");
  const flags = data[32] ?? 0;
  const signCount = new DataView(data.buffer, data.byteOffset + 33, 4).getUint32(0);
  const out: AuthData = { rpIdHash: data.subarray(0, 32), flags, signCount };
  if (flags & 0x40) {
    out.aaguid = uuid(data.subarray(37, 53));
    const idLen = new DataView(data.buffer, data.byteOffset + 53, 2).getUint16(0);
    out.credentialId = data.subarray(55, 55 + idLen);
    const { value, rest } = decodeCbor(data.subarray(55 + idLen));
    if (!(value instanceof Map)) throw new Error("COSE key is not a map");
    if (rest.length !== 0) throw new Error("bytes after the COSE key (no extensions expected)");
    out.coseKey = value;
  } else if (data.length !== 37) {
    throw new Error("unexpected bytes after the counter");
  }
  return out;
}

/** An ES256 COSE key as a public key (rejects anything else). */
function es256Key(cose: Map<Cbor, Cbor>): KeyObject {
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
    throw new Error("not an ES256 P-256 COSE key");
  }
  return createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64(x), y: b64(y) }, format: "jwk" });
}

interface ClientData {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
}

function checkClientData(raw: Uint8Array, type: string, challenge: string, origin: string): void {
  const c = JSON.parse(new TextDecoder().decode(raw)) as ClientData;
  if (c.type !== type) throw new Error(`clientData type ${c.type}`);
  if (c.challenge !== challenge) throw new Error("clientData challenge does not match");
  if (c.origin !== origin) throw new Error(`clientData origin ${c.origin}`);
  if (c.crossOrigin === true) throw new Error("cross-origin");
}

export interface Registered {
  credentialId: string;
  userHandle: string;
  userName: string;
  aaguid: string;
  flags: number;
  fmt: string;
  key: KeyObject;
}

export interface SignedIn {
  credentialId: string;
  userName: string;
  flags: number;
  signCount: number;
}

// --------------------------------------------------------------- page --

const PAGE = (rpName: string): string => `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>${rpName}</title></head>
<body><main><h1>${rpName}</h1>
<button id="register">Crear passkey</button>
<button id="register-key">Crear con llave de seguridad</button>
<button id="signin">Entrar con passkey</button>
<button id="signin-allow">Entrar con la última llave</button>
<form id="login" onsubmit="return false"><label>Usuario <input id="username" name="username" autocomplete="username webauthn"></label>
<label>Contraseña <input id="password" name="password" type="password" autocomplete="current-password"></label>
<button type="submit">Entrar</button></form>
<button id="signin-conditional">Esperar passkey en el campo</button>
<p id="out" role="status"></p></main>
<script>
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const out = document.getElementById("out");
async function post(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await res.text();
  if (!res.ok) throw new Error(text);
  return JSON.parse(text);
}
async function register(attachment) {
  out.textContent = "…";
  try {
    const o = await post("/options/register", {});
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { id: o.rpId, name: o.rpName },
      user: { id: unb64(o.userId), name: o.userName, displayName: o.displayName },
      challenge: unb64(o.challenge),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      excludeCredentials: o.exclude.map((id) => ({ type: "public-key", id: unb64(id) })),
      authenticatorSelection: { residentKey: "required", userVerification: "required", ...(attachment ? { authenticatorAttachment: attachment } : {}) },
      attestation: "none",
      extensions: { credProps: true },
    } });
    const r = await post("/verify/register", {
      id: cred.id, rawId: b64(cred.rawId), type: cred.type,
      clientDataJSON: b64(cred.response.clientDataJSON), attestationObject: b64(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
      credProps: cred.getClientExtensionResults().credProps ?? null,
      isPublicKeyCredential: cred instanceof PublicKeyCredential,
    });
    out.textContent = "registrada " + r.aaguid;
  } catch (e) {
    out.textContent = "error " + (e.name || "") + " " + e.message;
  }
}
async function signIn(allowLast, mediation) {
  out.textContent = "…";
  try {
    const o = await post("/options/sign-in", { allowLast });
    const cred = await navigator.credentials.get({ ...(mediation ? { mediation } : {}), publicKey: {
      rpId: o.rpId, challenge: unb64(o.challenge), userVerification: "required",
      allowCredentials: o.allow.map((id) => ({ type: "public-key", id: unb64(id) })),
    } });
    const r = await post("/verify/sign-in", {
      id: cred.id, rawId: b64(cred.rawId),
      clientDataJSON: b64(cred.response.clientDataJSON), authenticatorData: b64(cred.response.authenticatorData),
      signature: b64(cred.response.signature), userHandle: cred.response.userHandle ? b64(cred.response.userHandle) : null,
    });
    out.textContent = "dentro como " + r.userName;
  } catch (e) {
    out.textContent = "error " + (e.name || "") + " " + e.message;
  }
}
document.getElementById("register").onclick = () => register();
document.getElementById("register-key").onclick = () => register("cross-platform");
document.getElementById("signin").onclick = () => signIn(false);
document.getElementById("signin-allow").onclick = () => signIn(true);
document.getElementById("signin-conditional").onclick = () => signIn(false, "conditional");
</script></body></html>`;

export interface RelyingParty {
  url(path: string): string;
  origin: string;
  registered: Registered[];
  signedIn: SignedIn[];
  /** Errors the server found while verifying (a test expects none unless it says so). */
  failures: string[];
  /** The next registration is for this user (name and handle). */
  user: { name: string; id: Uint8Array };
  close(): Promise<void>;
}

export async function startRelyingParty(rpName = "Sitio RP"): Promise<RelyingParty> {
  const registered: Registered[] = [];
  const signedIn: SignedIn[] = [];
  const failures: string[] = [];
  let pendingChallenge = "";
  const rp: { origin: string; rpId: string } = { origin: "", rpId: "localhost" };
  const state = { user: { name: "ana", id: new Uint8Array(randomBytes(16)) } };

  const verifyRegistration = (body: Record<string, unknown>): Registered => {
    const clientData = unb64(String(body.clientDataJSON));
    checkClientData(clientData, "webauthn.create", pendingChallenge, rp.origin);
    const { value } = decodeCbor(unb64(String(body.attestationObject)));
    if (!(value instanceof Map)) throw new Error("attestationObject is not a map");
    const fmt = value.get("fmt");
    const authBytes = value.get("authData");
    const stmt = value.get("attStmt");
    if (typeof fmt !== "string" || !(authBytes instanceof Uint8Array) || !(stmt instanceof Map)) throw new Error("bad attestationObject");
    if (fmt === "none" && stmt.size !== 0) throw new Error("none with a statement");
    const auth = parseAuthData(authBytes);
    if (!equal(auth.rpIdHash, sha256(new TextEncoder().encode(rp.rpId)))) throw new Error("rpIdHash");
    if ((auth.flags & 0x01) === 0 || (auth.flags & 0x04) === 0) throw new Error("UP and UV required");
    if (!auth.credentialId || !auth.coseKey || !auth.aaguid) throw new Error("no attested credential");
    if (b64(auth.credentialId) !== body.rawId || body.rawId !== body.id) throw new Error("credential ID mismatch");
    return {
      credentialId: b64(auth.credentialId),
      userHandle: b64(state.user.id),
      userName: state.user.name,
      aaguid: auth.aaguid,
      flags: auth.flags,
      fmt,
      key: es256Key(auth.coseKey),
    };
  };

  const verifySignIn = (body: Record<string, unknown>): SignedIn => {
    const clientData = unb64(String(body.clientDataJSON));
    checkClientData(clientData, "webauthn.get", pendingChallenge, rp.origin);
    const authBytes = unb64(String(body.authenticatorData));
    const auth = parseAuthData(authBytes);
    if (!equal(auth.rpIdHash, sha256(new TextEncoder().encode(rp.rpId)))) throw new Error("rpIdHash");
    if ((auth.flags & 0x01) === 0 || (auth.flags & 0x04) === 0) throw new Error("UP and UV required");
    const cred = registered.find((r) => r.credentialId === body.rawId);
    if (!cred) throw new Error("unknown credential");
    if (body.userHandle !== null && body.userHandle !== cred.userHandle) throw new Error("user handle");
    const signed = Buffer.concat([authBytes, sha256(clientData)]);
    if (!verify("sha256", signed, cred.key, unb64(String(body.signature)))) throw new Error("bad signature");
    return { credentialId: cred.credentialId, userName: cred.userName, flags: auth.flags, signCount: auth.signCount };
  };

  const server: Server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const json = (status: number, value: unknown): void => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    };
    if (req.method === "GET" && path === "/passkeys") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(PAGE(rpName));
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(404);
      res.end();
      return;
    }
    let raw = "";
    req.on("data", (chunk: Buffer) => (raw += chunk.toString()));
    req.on("end", () => {
      try {
        const body = JSON.parse(raw || "{}") as Record<string, unknown>;
        if (path === "/options/register") {
          pendingChallenge = b64(randomBytes(32));
          json(200, {
            rpId: rp.rpId,
            rpName,
            userId: b64(state.user.id),
            userName: state.user.name,
            displayName: state.user.name,
            challenge: pendingChallenge,
            exclude: registered.filter((r) => r.userHandle === b64(state.user.id)).map((r) => r.credentialId),
          });
        } else if (path === "/options/sign-in") {
          pendingChallenge = b64(randomBytes(32));
          const last = registered[registered.length - 1];
          json(200, { rpId: rp.rpId, challenge: pendingChallenge, allow: body.allowLast === true && last ? [last.credentialId] : [] });
        } else if (path === "/verify/register") {
          const r = verifyRegistration(body);
          registered.push(r);
          json(200, { aaguid: r.aaguid });
        } else if (path === "/verify/sign-in") {
          const s = verifySignIn(body);
          signedIn.push(s);
          json(200, { userName: s.userName });
        } else {
          json(404, {});
        }
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        failures.push(`${path}: ${message}`);
        json(400, { error: message });
      }
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  rp.origin = `http://localhost:${String(port)}`;
  return {
    url: (path) => `${rp.origin}${path}`,
    origin: rp.origin,
    registered,
    signedIn,
    failures,
    get user() {
      return state.user;
    },
    set user(u) {
      state.user = u;
    },
    close: () =>
      new Promise((done) => {
        server.closeAllConnections();
        server.close(() => {
          done();
        });
      }),
  };
}
