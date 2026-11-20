// Passkeys (ADR 0020): what the page-world hook reads from the page's
// options, what the bridge and the background keep, and the objects the
// page gets back.
import { describe, expect, it } from "vitest";
import { asserted, createCall, created, getCall } from "../src/page/webauthn";
import { cleanCall, fromB64, klavCanCreate, MAX_CHALLENGE, toB64 } from "../src/shared/passkey";

const bytes = (n: number, fill = 1): Uint8Array => new Uint8Array(n).fill(fill);

function createOptions(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    rp: { id: "example.com", name: "Example" },
    user: { id: bytes(16, 7), name: "ana", displayName: "Ana" },
    challenge: bytes(32).buffer,
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ],
    excludeCredentials: [{ type: "public-key", id: bytes(16, 9) }],
    authenticatorSelection: { residentKey: "required" },
    extensions: { credProps: true },
    ...extra,
  };
}

describe("base64url", () => {
  it("round-trips bytes without padding", () => {
    for (const n of [0, 1, 2, 3, 16, 33, 70_000]) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37) & 0xff);
      const text = toB64(b);
      expect(text).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(fromB64(text)).toEqual(b);
    }
  });

  it("takes padding but nothing that is not base64url", () => {
    expect(fromB64("AQ==")).toEqual(Uint8Array.of(1));
    expect(() => fromB64("A+/=")).toThrow();
    expect(() => fromB64("AAAAA")).toThrow();
    expect(() => fromB64("a b")).toThrow();
  });
});

describe("the page's options", () => {
  it("reads a create call", () => {
    expect(createCall(createOptions())).toEqual({
      kind: "create",
      rp_id: "example.com",
      rp_name: "Example",
      user_id: toB64(bytes(16, 7)),
      user_name: "ana",
      user_display_name: "Ana",
      challenge: toB64(bytes(32)),
      algs: [-7, -257],
      exclude: [toB64(bytes(16, 9))],
      cred_props: true,
    });
  });

  it("keeps a security key request as one (the background hands it to the browser)", () => {
    const call = createCall(createOptions({ authenticatorSelection: { authenticatorAttachment: "cross-platform" } }));
    expect(call?.attachment).toBe("cross-platform");
  });

  it("leaves malformed options to the browser, which reports the page's mistake", () => {
    expect(createCall(undefined)).toBeUndefined();
    expect(createCall(createOptions({ challenge: "not bytes" }))).toBeUndefined();
    expect(createCall(createOptions({ user: { id: bytes(4), name: 7 } }))).toBeUndefined();
    expect(createCall(createOptions({ pubKeyCredParams: [{ alg: "ES256" }] }))).toBeUndefined();
    expect(createCall(createOptions({ excludeCredentials: [{ id: "x" }] }))).toBeUndefined();
    expect(createCall(createOptions({ rp: { id: 5 } }))).toBeUndefined();
  });

  it("reads a get call, with and without an rpId or allowCredentials", () => {
    expect(getCall({ challenge: bytes(16), rpId: "example.com", allowCredentials: [{ type: "public-key", id: bytes(8, 3) }] })).toEqual({
      kind: "get",
      rp_id: "example.com",
      challenge: toB64(bytes(16)),
      allow: [toB64(bytes(8, 3))],
    });
    expect(getCall({ challenge: new DataView(bytes(20).buffer) })).toEqual({ kind: "get", challenge: toB64(bytes(20)), allow: [] });
    expect(getCall({ challenge: bytes(16), allowCredentials: "x" })).toBeUndefined();
    expect(getCall({})).toBeUndefined();
  });

  it("marks conditional mediation and leaves silent mediation to the browser", () => {
    expect(getCall({ challenge: bytes(16) }, "conditional")).toEqual({ kind: "get", challenge: toB64(bytes(16)), allow: [], conditional: true });
    expect(getCall({ challenge: bytes(16) }, "optional")).toEqual({ kind: "get", challenge: toB64(bytes(16)), allow: [] });
    expect(getCall({ challenge: bytes(16) }, "silent")).toBeUndefined();
  });
});

describe("what the bridge and the background keep", () => {
  const create = createCall(createOptions());

  it("keeps well-formed calls as they are", () => {
    expect(cleanCall(create)).toEqual(create);
    const get = getCall({ challenge: bytes(16) });
    expect(cleanCall(get)).toEqual(get);
  });

  it("keeps the conditional mark only as a boolean", () => {
    const call = { kind: "get", challenge: toB64(bytes(16)), allow: [] };
    expect(cleanCall({ ...call, conditional: true })).toEqual({ ...call, conditional: true });
    expect(cleanCall({ ...call, conditional: false })).toEqual(call);
    expect(cleanCall({ ...call, conditional: "yes" })).toBeUndefined();
  });

  it("drops a challenge too short or too long", () => {
    expect(cleanCall({ kind: "get", challenge: toB64(bytes(15)), allow: [] })).toBeUndefined();
    expect(cleanCall({ kind: "get", challenge: toB64(bytes(MAX_CHALLENGE)), allow: [] })).toBeDefined();
    expect(cleanCall({ kind: "get", challenge: toB64(bytes(MAX_CHALLENGE + 1)), allow: [] })).toBeUndefined();
  });

  it("drops anything with the wrong shape", () => {
    expect(cleanCall(null)).toBeUndefined();
    expect(cleanCall({ ...create, kind: "delete" })).toBeUndefined();
    expect(cleanCall({ ...create, rp_id: "" })).toBeUndefined();
    expect(cleanCall({ ...create, user_id: toB64(bytes(65)) })).toBeUndefined();
    expect(cleanCall({ ...create, user_name: undefined })).toBeUndefined();
    expect(cleanCall({ ...create, user_name: "x".repeat(257) })).toBeUndefined();
    expect(cleanCall({ ...create, algs: [-7.5] })).toBeUndefined();
    expect(cleanCall({ ...create, attachment: "usb" })).toBeUndefined();
    expect(cleanCall({ ...create, exclude: ["a+b"] })).toBeUndefined();
    expect(cleanCall({ kind: "get", challenge: toB64(bytes(16)), allow: Array.from({ length: 257 }, () => "AA") })).toBeUndefined();
  });

  it("drops fields Klav does not use", () => {
    const kept = cleanCall({ kind: "get", challenge: toB64(bytes(16)), allow: [], origin: "https://evil.example" });
    expect(kept).toEqual({ kind: "get", challenge: toB64(bytes(16)), allow: [] });
  });

  it("creates only ES256 and never for a security key", () => {
    if (!create) throw new Error("no call");
    expect(klavCanCreate(create)).toBe(true);
    expect(klavCanCreate({ ...create, algs: [] })).toBe(true);
    expect(klavCanCreate({ ...create, algs: [-8, -257] })).toBe(false);
    expect(klavCanCreate({ ...create, attachment: "cross-platform" })).toBe(false);
    expect(klavCanCreate({ ...create, attachment: "platform" })).toBe(true);
  });
});

describe("what the page gets back", () => {
  const b = (n: number, fill: number): string => toB64(bytes(n, fill));

  it("a registration, with credProps only when asked", () => {
    const credential = {
      credential_id: b(16, 1),
      client_data_json: b(40, 2),
      attestation_object: b(80, 3),
      authenticator_data: b(37, 4),
      public_key: b(91, 5),
      public_key_algorithm: -7,
      transports: ["internal", "hybrid"],
    };
    const c = created({ status: "created", credential, cred_props: true }) as unknown as Record<string, unknown>;
    expect(c.id).toBe(credential.credential_id);
    expect(new Uint8Array(c.rawId as ArrayBuffer)).toEqual(bytes(16, 1));
    expect(c.type).toBe("public-key");
    expect(c.authenticatorAttachment).toBe("platform");
    expect((c.getClientExtensionResults as () => unknown)()).toEqual({ credProps: { rk: true } });
    const response = c.response as Record<string, unknown>;
    expect(new Uint8Array(response.attestationObject as ArrayBuffer)).toEqual(bytes(80, 3));
    expect((response.getPublicKeyAlgorithm as () => number)()).toBe(-7);
    expect((response.getTransports as () => string[])()).toEqual(["internal", "hybrid"]);
    expect(JSON.parse(JSON.stringify(c))).toMatchObject({ id: credential.credential_id, response: { attestationObject: credential.attestation_object } });
    const plain = created({ status: "created", credential, cred_props: false }) as unknown as Record<string, unknown>;
    expect((plain.getClientExtensionResults as () => unknown)()).toEqual({});
  });

  it("an assertion", () => {
    const credential = { credential_id: b(16, 1), client_data_json: b(40, 2), authenticator_data: b(37, 4), signature: b(70, 6), user_handle: b(16, 7) };
    const c = asserted({ status: "asserted", credential }) as unknown as Record<string, unknown>;
    const response = c.response as Record<string, unknown>;
    expect(new Uint8Array(response.signature as ArrayBuffer)).toEqual(bytes(70, 6));
    expect(new Uint8Array(response.userHandle as ArrayBuffer)).toEqual(bytes(16, 7));
    expect(JSON.parse(JSON.stringify(c))).toMatchObject({ rawId: credential.credential_id, response: { signature: credential.signature } });
  });
});
