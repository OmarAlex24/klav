/**
 * In the page's own world (`world: "MAIN"`, at `document_start`): wraps
 * `navigator.credentials.create` and `.get` so that Klav can answer
 * WebAuthn calls with its passkeys (ADR 0020). It holds nothing secret:
 * it turns the page's options into a plain request for Klav's bridge (the
 * isolated content script), and Klav's answer into the objects WebAuthn
 * defines. Whatever Klav does not take (another algorithm, a security key,
 * silent mediation, a frame without the bridge, the person choosing «Use
 * another device») goes to the browser's own authenticator with the page's
 * original options. Conditional mediation goes to Klav too: the site's
 * passkeys show in Klav's field menu.
 *
 * The page sees its own request and answer here, which is fine: it is the
 * relying party. Klav's decisions (which origin, which passkey, the
 * person's consent) happen outside the page, in the background and in
 * Klav's frame.
 */
import { type CreateCall, fromB64, type GetCall, type PageWire, type PasskeyCall, type PasskeyOutcome, toB64 } from "../shared/passkey";

/** How long to wait for the bridge to say it heard a call (a frame without it gets the browser). */
const ACK_MS = 800;

type CredentialsFn = (this: CredentialsContainer, options?: CredentialRequestOptions | CredentialCreationOptions) => Promise<Credential | null>;

const proto = (globalThis as { CredentialsContainer?: { prototype: CredentialsContainer } }).CredentialsContainer?.prototype;

type Loose = Partial<Record<string, unknown>>;

function obj(value: unknown): Loose | undefined {
  return typeof value === "object" && value !== null ? value : undefined;
}

/** A BufferSource as base64url; `undefined` if it is not one. */
function b64(source: unknown): string | undefined {
  if (source instanceof ArrayBuffer) return toB64(new Uint8Array(source));
  if (ArrayBuffer.isView(source)) return toB64(new Uint8Array(source.buffer, source.byteOffset, source.byteLength));
  return undefined;
}

/** Optional text: absent is "", anything but a string is not Klav's. */
function text(value: unknown): string | undefined {
  if (value === undefined) return "";
  return typeof value === "string" ? value : undefined;
}

function idList(value: unknown): string[] | undefined {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return undefined;
  const out: string[] = [];
  for (const c of value) {
    const id = b64(obj(c)?.id);
    if (id === undefined) return undefined;
    out.push(id);
  }
  return out;
}

/**
 * The page's create options as a request for Klav; `undefined` leaves the
 * call to the browser (which also reports the page's own mistakes).
 */
export function createCall(options: unknown): CreateCall | undefined {
  const o = obj(options);
  const rp = obj(o?.rp);
  const user = obj(o?.user);
  if (!o || !rp || !user) return undefined;
  const challenge = b64(o.challenge);
  const userId = b64(user.id);
  const rpName = text(rp.name);
  const userName = text(user.name);
  const displayName = text(user.displayName);
  const exclude = idList(o.excludeCredentials);
  if (!challenge || !userId || rpName === undefined || userName === undefined || displayName === undefined || !exclude) return undefined;
  if (rp.id !== undefined && typeof rp.id !== "string") return undefined;
  const params = o.pubKeyCredParams === undefined ? [] : o.pubKeyCredParams;
  if (!Array.isArray(params)) return undefined;
  const algs: number[] = [];
  for (const p of params) {
    const alg = obj(p)?.alg;
    if (typeof alg !== "number") return undefined;
    algs.push(alg);
  }
  const attachment = obj(o.authenticatorSelection)?.authenticatorAttachment;
  return {
    kind: "create",
    ...(typeof rp.id === "string" ? { rp_id: rp.id } : {}),
    rp_name: rpName,
    user_id: userId,
    user_name: userName,
    user_display_name: displayName,
    challenge,
    algs,
    exclude,
    ...(attachment === "platform" || attachment === "cross-platform" ? { attachment } : {}),
    cred_props: obj(o.extensions)?.credProps === true,
  };
}

/** `mediation` of the page's get: `conditional` marks the call, `silent` (no UI at all) stays the browser's. */
export function getCall(options: unknown, mediation?: unknown): GetCall | undefined {
  if (mediation === "silent") return undefined;
  const o = obj(options);
  const challenge = b64(o?.challenge);
  const allow = idList(o?.allowCredentials);
  if (!o || !challenge || !allow) return undefined;
  if (o.rpId !== undefined && typeof o.rpId !== "string") return undefined;
  return {
    kind: "get",
    ...(typeof o.rpId === "string" ? { rp_id: o.rpId } : {}),
    challenge,
    allow,
    ...(mediation === "conditional" ? { conditional: true } : {}),
  };
}

function buffer(text: string): ArrayBuffer {
  const b = fromB64(text);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

/** An object with `prototype` (so `instanceof` holds) and these own read-only values. */
function shaped(prototype: object | undefined, values: Record<string, unknown>): object {
  const out = Object.create(prototype ?? Object.prototype) as object;
  for (const [key, value] of Object.entries(values)) {
    Object.defineProperty(out, key, { value, enumerable: true, configurable: true });
  }
  return out;
}

function prototypeOf(name: string): object | undefined {
  return (globalThis as unknown as Record<string, { prototype?: object } | undefined>)[name]?.prototype;
}

/** A `PublicKeyCredential` for a passkey Klav created. */
export function created(outcome: Extract<PasskeyOutcome, { status: "created" }>): Credential {
  const c = outcome.credential;
  const extensions = outcome.cred_props ? { credProps: { rk: true } } : {};
  const response = shaped(prototypeOf("AuthenticatorAttestationResponse"), {
    clientDataJSON: buffer(c.client_data_json),
    attestationObject: buffer(c.attestation_object),
    getAuthenticatorData: () => buffer(c.authenticator_data),
    getPublicKey: () => buffer(c.public_key),
    getPublicKeyAlgorithm: () => c.public_key_algorithm,
    getTransports: () => [...c.transports],
  });
  return shaped(prototypeOf("PublicKeyCredential"), {
    id: c.credential_id,
    rawId: buffer(c.credential_id),
    type: "public-key",
    authenticatorAttachment: "platform",
    response,
    getClientExtensionResults: () => structuredClone(extensions),
    toJSON: () => ({
      id: c.credential_id,
      rawId: c.credential_id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: structuredClone(extensions),
      response: {
        clientDataJSON: c.client_data_json,
        attestationObject: c.attestation_object,
        authenticatorData: c.authenticator_data,
        publicKey: c.public_key,
        publicKeyAlgorithm: c.public_key_algorithm,
        transports: [...c.transports],
      },
    }),
  }) as Credential;
}

/** A `PublicKeyCredential` for an assertion Klav signed. */
export function asserted(outcome: Extract<PasskeyOutcome, { status: "asserted" }>): Credential {
  const c = outcome.credential;
  const response = shaped(prototypeOf("AuthenticatorAssertionResponse"), {
    clientDataJSON: buffer(c.client_data_json),
    authenticatorData: buffer(c.authenticator_data),
    signature: buffer(c.signature),
    userHandle: buffer(c.user_handle),
  });
  return shaped(prototypeOf("PublicKeyCredential"), {
    id: c.credential_id,
    rawId: buffer(c.credential_id),
    type: "public-key",
    authenticatorAttachment: "platform",
    response,
    getClientExtensionResults: () => ({}),
    toJSON: () => ({
      id: c.credential_id,
      rawId: c.credential_id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: c.client_data_json,
        authenticatorData: c.authenticator_data,
        signature: c.signature,
        userHandle: c.user_handle,
      },
    }),
  }) as Credential;
}

function post(message: PageWire): void {
  window.postMessage(message, "*");
}

/**
 * Asks Klav. Resolves with the outcome, or with `browser` when nobody
 * answered (no bridge in this frame).
 */
function askKlav(call: PasskeyCall, signal: AbortSignal | undefined): Promise<PasskeyOutcome> {
  const id = crypto.randomUUID();
  return new Promise((resolve) => {
    let acked = false;
    const listen = (event: MessageEvent): void => {
      // Only Klav's bridge in this same window (never another frame).
      if (event.source !== window) return;
      const m = obj(event.data);
      if (m?.id !== id) return;
      if (m.klav === "webauthn-ack") acked = true;
      else if (m.klav === "webauthn-done") done(m.outcome as PasskeyOutcome);
    };
    const abort = (): void => {
      post({ klav: "webauthn-abort", id });
      done({ status: "error", name: "AbortError", message: "The operation was aborted." });
    };
    const timer = setTimeout(() => {
      if (!acked) done({ status: "browser" });
    }, ACK_MS);
    function done(outcome: PasskeyOutcome): void {
      removeEventListener("message", listen);
      signal?.removeEventListener("abort", abort);
      clearTimeout(timer);
      resolve(outcome);
    }
    addEventListener("message", listen);
    signal?.addEventListener("abort", abort, { once: true });
    post({ klav: "webauthn-call", id, call });
  });
}

function abortError(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
}

async function answer(
  original: CredentialsFn,
  self: CredentialsContainer,
  options: CredentialCreationOptions | CredentialRequestOptions,
  call: PasskeyCall,
): Promise<Credential | null> {
  const signal = options.signal ?? undefined;
  if (signal?.aborted) throw abortError(signal);
  const outcome = await askKlav(call, signal);
  switch (outcome.status) {
    case "browser":
      return original.call(self, options);
    case "error":
      if (outcome.name === "AbortError" && signal?.aborted) throw abortError(signal);
      throw new DOMException(outcome.message, outcome.name);
    case "created":
      return created(outcome);
    case "asserted":
      return asserted(outcome);
  }
}

/** Installs the hook (once, in a secure context with WebAuthn). */
export function install(): void {
  if (!proto || !window.isSecureContext) return;
  const originalCreate = Reflect.get<CredentialsContainer, "create">(proto, "create") as CredentialsFn;
  const originalGet = Reflect.get<CredentialsContainer, "get">(proto, "get");
  const create = function (this: CredentialsContainer, options?: CredentialCreationOptions): Promise<Credential | null> {
    let call: CreateCall | undefined;
    try {
      call = createCall(options?.publicKey);
    } catch {
      call = undefined;
    }
    if (!options || !call) return originalCreate.call(this, options);
    return answer(originalCreate, this, options, call);
  };
  const get = function (this: CredentialsContainer, options?: CredentialRequestOptions): Promise<Credential | null> {
    let call: GetCall | undefined;
    try {
      call = getCall(options?.publicKey, options?.mediation);
    } catch {
      call = undefined;
    }
    if (!options || !call) return originalGet.call(this, options);
    return answer(originalGet, this, options, call);
  };
  Object.defineProperty(proto, "create", { value: create, configurable: true, writable: true });
  Object.defineProperty(proto, "get", { value: get, configurable: true, writable: true });
}
