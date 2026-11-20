/**
 * The agent notice: when an agent filled this page (with the person's
 * approval), a bar at the bottom says so: «Klav rellenó esta página para
 * claude-code» and the agent's reason. Blue, because it is about an agent.
 */
import { localizePage, t } from "../shared/i18n";
import { ask } from "../shared/messages";
import { band, ditherCanvas } from "../shared/dither";
import { h } from "./dom";
import { framePage } from "./frame";
import { iconButton } from "./kit";

localizePage("frame_notice");
const root = document.getElementById("notice") as HTMLElement;
const page = framePage("notice", root);

async function load(): Promise<void> {
  let said: { agent: string; reason?: string; rotated?: boolean; passkey?: string };
  try {
    said = await ask<{ agent: string; reason?: string; rotated?: boolean; passkey?: string }>({ type: "notice_load", noticeId: page.id });
  } catch {
    page.close();
    return;
  }
  const stripe = ditherCanvas(document, band(), { palette: "blue", pixel: 2 });
  root.replaceChildren(
    h(
      "div",
      { class: "notice-bar", role: "status" },
      h("span", { class: "notice-band" }, stripe.canvas),
      h(
        "div",
        { class: "notice-main" },
        h(
          "p",
          { class: "agent-mark" },
          said.passkey !== undefined
            ? t("agent_passkey", said.passkey, said.agent)
            : t(said.rotated ? "agent_rotated" : "agent_filled", said.agent),
        ),
        said.reason ? h("p", { class: "notice-reason" }, t("quote", said.reason)) : null,
      ),
      iconButton("close", t("close_notice"), page.close),
    ),
  );
  page.resize();
  requestAnimationFrame(() => {
    stripe.repaint();
  });
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") page.close();
});

void load();
