import { type MessageKey, t } from "../shared/i18n";
import type { StopReason } from "../shared/messages";
import type { ErrorCode } from "../shared/protocol";

/** What the field menu says when Klav stopped a sign-in in several steps. */
export function stopText(reason: StopReason): string {
  const keys: Record<StopReason, MessageKey> = { no_password: "stop_no_password", captcha: "stop_captcha", other_site: "stop_other_site" };
  return t(keys[reason]);
}

/** What to tell the person for each error, in plain words. */
export function errorText(code: ErrorCode, message: string): string {
  switch (code) {
    case "host_missing":
      return t("error_host_missing");
    case "not_logged_in":
      return t("error_not_logged_in");
    case "wrong_credentials":
      return t("error_wrong_credentials");
    case "biometry_failed":
      return t("error_biometry_failed");
    case "biometry_unavailable":
      return t("error_biometry_unavailable");
    case "locked":
      return t("error_locked");
    case "network":
      return t("error_network");
    case "rollback":
    case "security":
      return t("error_security", message);
    case "denied":
      return message;
    case "timeout":
      return t("error_timeout");
    case "disconnected":
      return t("error_disconnected");
    case "covered":
      return t("covered");
    case "presence_busy":
      return t("error_presence_busy");
    case "browser_ambiguous":
      return t("error_browser_ambiguous");
    default:
      return message;
  }
}

/**
 * `klav://Vault/Project/Item title[/field]` as the item's title and where it
 * lives. Names come as written (`Banco Azul`) or percent-encoded
 * (`Banco%20Azul`, what older versions showed); both read the same.
 */
export function describeTarget(target: string): { title: string; where?: string } {
  if (!target.startsWith("klav://")) return { title: target };
  const parts = target
    .slice("klav://".length)
    .split("/")
    .map((p) => {
      try {
        return decodeURIComponent(p);
      } catch {
        return p;
      }
    });
  const [vault, project, title, field] = parts;
  if (!title) return { title: parts.join(" / ") };
  return { title: field ? `${title} (${field})` : title, where: [vault, project].filter(Boolean).join(" / ") };
}

/**
 * Names for the fields of klav-core's templates, keyed by `name`, with the
 * template's English label (a label the person changed is shown as is).
 */
const FIELD_NAMES: Record<string, [string, MessageKey]> = {
  username: ["Username", "field_username"],
  password: ["Password", "field_password"],
  totp: ["One-time password", "field_totp"],
  cardholder: ["Cardholder name", "field_cardholder"],
  number: ["Number", "field_number"],
  expiry: ["Expiry date", "field_expiry"],
  cvv: ["Verification code", "field_cvv"],
  pin: ["PIN", "field_pin"],
  first_name: ["First name", "field_first_name"],
  last_name: ["Last name", "field_last_name"],
  email: ["E-mail", "field_email"],
  phone: ["Phone", "field_phone"],
  address: ["Address", "field_address"],
  city: ["City", "field_city"],
  region: ["State / region", "field_region"],
  postal_code: ["Postal code", "field_postal_code"],
  country: ["Country", "field_country"],
  birth_date: ["Birth date", "field_birth_date"],
  private_key: ["Private key", "field_private_key"],
  public_key: ["Public key", "field_public_key"],
  fingerprint: ["Fingerprint", "field_fingerprint"],
  passphrase: ["Passphrase", "field_passphrase"],
  api_key: ["API key", "field_api_key"],
  key_id: ["Key ID", "field_key_id"],
  base_url: ["Base URL", "field_base_url"],
  expires: ["Expires", "field_expires"],
};

export function fieldName(f: { name: string; label: string }): string {
  const known = FIELD_NAMES[f.name];
  if (known && (!f.label || f.label === known[0] || f.label === f.name)) return t(known[1]);
  return f.label || f.name;
}

const KINDS: Record<string, [MessageKey, MessageKey]> = {
  login: ["kind_login", "kind_short_login"],
  card: ["kind_card", "kind_short_card"],
  identity: ["kind_identity", "kind_short_identity"],
  ssh_key: ["kind_ssh_key", "kind_short_ssh_key"],
  file: ["kind_file", "kind_short_file"],
  totp: ["kind_totp", "kind_short_totp"],
  note: ["kind_note", "kind_short_note"],
  api_key: ["kind_api_key", "kind_short_api_key"],
  environment: ["kind_environment", "kind_short_environment"],
};

/** An item's kind: «Card» under its title, «card» (`short`) at the end of a row. */
export function kindName(kind: string, short = false): string {
  const keys = KINDS[kind];
  return keys ? t(keys[short ? 1 : 0]) : kind;
}
