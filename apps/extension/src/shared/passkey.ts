/**
 * Passkeys in the browser (ADR 0020): what the page-world hook
 * (`page/webauthn.ts`), the isolated bridge (`content/webauthn.ts`) and the
 * background (`background/passkeys.ts`) pass each other. Every binary
 * value is base64url without padding, as klavd takes and gives them.
 *
 * The page writes these requests, so the bridge and the background both
 * keep only well-formed ones ([`cleanCall`]); anything else goes to the
 * browser's own authenticator, as if Klav were not there.
 */

/** Longest challenge, user ID and credential ID klavd accepts (bytes). */
export const MAX_CHALLENGE = 1024;
export const MAX_USER_ID = 64;
export const MAX_CREDENTIAL_ID = 1023;
/** Most credential IDs in `allowCredentials` / `excludeCredentials`. */
export const MAX_CREDENTIALS = 256;
/** Longest text the page may send (rp.name, user.name…). */
export const MAX_TEXT = 256;
/** ES256, the only algorithm Klav creates (ADR 0020 §5). */
export const ES256 = -7;

/** `navigator.credentials.create({publicKey})`, reduced to what Klav uses. */
export interface CreateCall {
  kind: "create";
  /** `rp.id`; the origin's host when absent. */
  rp_id?: string;
  rp_name: string;
  user_id: string;
  user_name: string;
  user_display_name: string;
  challenge: string;
  /** `pubKeyCredParams[].alg`. */
  algs: number[];
  exclude: string[];
  /** `authenticatorSelection.authenticatorAttachment`. */
  attachment?: "platform" | "cross-platform";
  /** The page asked for `extensions.credProps`. */
  cred_props: boolean;
}

/** `navigator.credentials.get({publicKey})`, reduced to what Klav uses. */
export interface GetCall {
  kind: "get";
  rp_id?: string;
  challenge: string;
  allow: string[];
  /**
   * `mediation: "conditional"`: the site's passkeys go in the field's menu
   * and the call waits, with no frame, until the person picks one there.
   */
  conditional?: boolean;
}

export type PasskeyCall = CreateCall | GetCall;

/** What klavd answers to `passkey_create` with `status: "created"`. */
export interface Registration {
  credential_id: string;
  client_data_json: string;
  attestation_object: string;
  authenticator_data: string;
  public_key: string;
  public_key_algorithm: number;
  transports: string[];
  item: string;
  title: string;
}

/** What klavd answers to `passkey_get`. */
export interface Assertion {
  credential_id: string;
  client_data_json: string;
  authenticator_data: string;
  signature: string;
  user_handle: string;
  item: string;
}

/** The page's errors (DOMException names WebAuthn uses). */
export type PasskeyErrorName = "NotAllowedError" | "InvalidStateError" | "AbortError";

/** How a call ends for the page. */
export type PasskeyOutcome =
  /** Hand it to the browser's own authenticator (the original call). */
  | { status: "browser" }
  | { status: "error"; name: PasskeyErrorName; message: string }
  /** `item`/`title` stay in the extension: the page gets only WebAuthn's fields. */
  | { status: "created"; credential: Omit<Registration, "item" | "title">; cred_props: boolean }
  | { status: "asserted"; credential: Omit<Assertion, "item"> };

/** Messages between the page-world hook and the bridge, through `window.postMessage`. */
export type PageWire =
  | { klav: "webauthn-call"; id: string; call: PasskeyCall }
  | { klav: "webauthn-abort"; id: string }
  | { klav: "webauthn-ack"; id: string }
  | { klav: "webauthn-done"; id: string; outcome: PasskeyOutcome };

/** A candidate as the surface shows it (klavd's `passkey_candidates`). */
export interface PasskeyCandidate {
  item: string;
  title: string;
  user_name: string;
  credential_id: string;
  vault: string;
}

export interface PasskeyCandidates {
  rp_id?: string;
  candidates: PasskeyCandidate[];
}

const B64URL = /^[A-Za-z0-9_-]*$/;

/** Bytes to base64url without padding. */
export function toB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url (padding optional) to bytes; throws on anything else. */
export function fromB64(text: string): Uint8Array {
  const clean = text.replace(/=+$/, "");
  if (!B64URL.test(clean) || clean.length % 4 === 1) throw new Error("not base64url");
  const binary = atob(clean.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Length in bytes of a base64url text, or undefined if it is not one. */
function b64Len(value: unknown): number | undefined {
  if (typeof value !== "string" || value.length > 4 * MAX_CREDENTIAL_ID) return undefined;
  try {
    return fromB64(value).length;
  } catch {
    return undefined;
  }
}

function b64(value: unknown, min: number, max: number): string | undefined {
  const n = b64Len(value);
  return n !== undefined && n >= min && n <= max ? (value as string).replace(/=+$/, "") : undefined;
}

function text(value: unknown, required: boolean): string | undefined {
  if (value === undefined && !required) return "";
  if (typeof value !== "string" || value.length > MAX_TEXT) return undefined;
  return value;
}

function ids(value: unknown): string[] | undefined {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_CREDENTIALS) return undefined;
  const out: string[] = [];
  for (const v of value) {
    const id = b64(v, 1, MAX_CREDENTIAL_ID);
    if (id === undefined) return undefined;
    out.push(id);
  }
  return out;
}

function rpId(value: unknown): string | undefined | null {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 253) return null;
  return value;
}

/**
 * A call as the page sent it, kept only if every field has the right shape
 * (klavd checks the rest: the rpId against the origin, the lengths again).
 * `undefined`: not one Klav takes; the browser handles it.
 */
export function cleanCall(raw: unknown): PasskeyCall | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const r = raw as Record<string, unknown>;
  const rp = rpId(r.rp_id);
  if (rp === null) return undefined;
  const challenge = b64(r.challenge, 16, MAX_CHALLENGE);
  if (challenge === undefined) return undefined;
  if (r.kind === "get") {
    const allow = ids(r.allow);
    if (!allow) return undefined;
    if (r.conditional !== undefined && typeof r.conditional !== "boolean") return undefined;
    return { kind: "get", ...(rp ? { rp_id: rp } : {}), challenge, allow, ...(r.conditional === true ? { conditional: true } : {}) };
  }
  if (r.kind !== "create") return undefined;
  const user_id = b64(r.user_id, 1, MAX_USER_ID);
  const rp_name = text(r.rp_name, false);
  const user_name = text(r.user_name, true);
  const user_display_name = text(r.user_display_name, false);
  const exclude = ids(r.exclude);
  const algs = Array.isArray(r.algs) && r.algs.length <= 32 && r.algs.every((a) => Number.isInteger(a)) ? (r.algs as number[]) : undefined;
  const attachment = r.attachment === "platform" || r.attachment === "cross-platform" ? r.attachment : undefined;
  if (r.attachment !== undefined && attachment === undefined) return undefined;
  if (user_id === undefined || rp_name === undefined || user_name === undefined || user_display_name === undefined || !exclude || !algs) {
    return undefined;
  }
  return {
    kind: "create",
    ...(rp ? { rp_id: rp } : {}),
    rp_name,
    user_id,
    user_name,
    user_display_name,
    challenge,
    algs,
    exclude,
    ...(attachment ? { attachment } : {}),
    cred_props: r.cred_props === true,
  };
}

/**
 * Whether Klav can answer a create at all: ES256 among the algorithms (or
 * none given, which WebAuthn reads as ES256 and RS256) and not a request
 * for a security key.
 */
export function klavCanCreate(call: CreateCall): boolean {
  if (call.attachment === "cross-platform") return false;
  return call.algs.length === 0 || call.algs.includes(ES256);
}
