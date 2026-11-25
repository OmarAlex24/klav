/**
 * The presence gate's words in the extension (ADR 0041 §2.4, §3.1, §3.2):
 * what Klav's frame says when klavd asks for the master password, and what
 * a password unlock says it opens. Only with the gate on: with it off,
 * klavd never asks and `status` has no `presence`, so none of this shows.
 *
 * The frame says what klavd's own Touch ID dialog would say (`prompt.rs`):
 * the same event, agent, title and site, which klavd sends as data
 * (`BrowserAsk`), worded here in the browser's language. Names come cleaned
 * from klavd; they are quoted here again and only ever go in as text.
 */
import { t } from "./i18n";
import type { BrowserAsk, DaemonStatus, PasskeyUv, PresenceAsk } from "./protocol";

/** A name from klavd (an agent's, a title, a site), quoted; quote marks inside it can't close the quote. */
export function quoted(name: string): string {
  return t("quote", name.replace(/[“”«»"]/g, "'"));
}

/**
 * For an agent's values (the `presence` event): the same clause as klavd's
 * dialog, after «Klav wants to» (`prompt.rs`, `Prompt::Browser`).
 */
export function browserReason(ask: BrowserAsk, untilLock: boolean): string {
  const agent = quoted(ask.agent);
  const title = ask.title !== undefined ? quoted(ask.title) : undefined;
  const site = ask.site !== undefined ? quoted(ask.site) : undefined;
  let text: string;
  if (untilLock) {
    const start =
      ask.event === "fill"
        ? title !== undefined
          ? t("presence_start_fill", agent, title)
          : t("presence_start_fill_any", agent)
        : ask.event === "password_change"
          ? title !== undefined
            ? t("presence_start_change", agent, title)
            : t("presence_start_change_any", agent)
          : site !== undefined
            ? t("presence_start_passkey", agent, site)
            : t("presence_start_passkey_any", agent);
    const place = ask.connection === true ? t("presence_place_connection") : t("presence_place_browser");
    text = t("presence_until_lock", place, start);
  } else {
    text = title !== undefined ? t("presence_once", agent, title) : t("presence_once_any", agent);
  }
  const attached = ask.attached ?? 0;
  return attached > 1 ? t("presence_attached", text, attached) : text;
}

/** For one of the extension's own values (`presence_required`): what the password opens or hands out. */
export function valueReason(ask: PresenceAsk): string {
  if (ask.lasts === "5m") return t("presence_lasts_5m");
  if (ask.lasts === "until_lock") return t("presence_lasts_until_lock");
  const value = ask.value;
  const title = value?.title !== undefined ? quoted(value.title) : undefined;
  if (title !== undefined) {
    switch (value?.kind) {
      case "fill":
        return t("presence_value_fill", title);
      case "show":
        return t("presence_value_show", title);
      case "code":
        return t("presence_value_code", title);
      case "previous":
        return t("presence_value_previous", title);
      default:
        break;
    }
  }
  if (value?.kind === "generated") return t("presence_value_generated");
  return t("presence_value_any");
}

/** The frame's question: «Klav wants to …». */
export function presenceQuestion(ask: PresenceAsk): string {
  const reason = ask.browser ? browserReason(ask.browser, ask.lasts === "until_lock") : valueReason(ask);
  return t("presence_klav_wants", reason);
}

/**
 * What a password unlock from the extension opens, as its question says it
 * (ADR 0041, own choice 34): `shown` for the request, and the line the
 * form shows. Nothing without the gate (no `presence` in `status`): an
 * older klavd, or the gate off, gets the unlock it always got.
 */
export function unlockOpens(status: DaemonStatus | undefined): { shown?: PasskeyUv; line?: string } {
  const presence = status?.presence;
  if (!presence) return {};
  if (presence.lasts === "5m") return { shown: "5m", line: t("unlock_opens_5m") };
  if (presence.lasts === "until_lock") return { shown: "unlocked", line: t("unlock_opens_until_lock") };
  return { shown: "always" };
}
