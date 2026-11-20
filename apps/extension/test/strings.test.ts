import { afterEach, describe, expect, it } from "vitest";
import { fieldName, kindName } from "../src/ui/strings";
import { useLocale } from "./setup";

afterEach(() => {
  useLocale("en");
});

describe("fieldName", () => {
  it("names template fields in English", () => {
    expect(fieldName({ name: "password", label: "Password" })).toBe("Password");
    expect(fieldName({ name: "totp", label: "One-time password" })).toBe("One-time code");
    expect(fieldName({ name: "cvv", label: "" })).toBe("Security code");
    expect(fieldName({ name: "username", label: "username" })).toBe("Username");
  });

  it("names template fields in Spanish", () => {
    useLocale("es");
    expect(fieldName({ name: "password", label: "Password" })).toBe("Contraseña");
    expect(fieldName({ name: "totp", label: "One-time password" })).toBe("Código de un solo uso");
    expect(fieldName({ name: "cvv", label: "" })).toBe("Código de seguridad");
    expect(fieldName({ name: "username", label: "username" })).toBe("Usuario");
  });

  it("keeps labels the person chose, and unknown fields", () => {
    useLocale("es");
    expect(fieldName({ name: "password", label: "Clave del banco" })).toBe("Clave del banco");
    expect(fieldName({ name: "recovery", label: "Recovery codes" })).toBe("Recovery codes");
    expect(fieldName({ name: "recovery", label: "" })).toBe("recovery");
  });
});

describe("kindName", () => {
  it("names kinds in both catalogs, and passes unknown kinds through", () => {
    expect(kindName("identity")).toBe("Address");
    expect(kindName("ssh_key", true)).toBe("ssh key");
    useLocale("es");
    expect(kindName("identity")).toBe("Dirección");
    expect(kindName("card", true)).toBe("tarjeta");
    expect(kindName("passkey")).toBe("passkey");
  });
});
