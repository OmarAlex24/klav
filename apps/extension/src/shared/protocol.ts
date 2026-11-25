/**
 * `klavd` protocol, version 1, as the extension sees it through
 * `klav-native-host` (docs/klavd.md §3, docs/extension.md §3). Types
 * mirror `klav-daemon::protocol` and `klav-client`.
 */

import type { Registration } from "./passkey";

export const PROTOCOL_VERSION = 1;
/** Name of the native messaging host. */
export const HOST_NAME = "dev.klav.host";

export type ItemKind = "login" | "card" | "identity" | "ssh_key" | "file" | "totp" | "note" | "api_key";

export type FieldKind =
  | "username"
  | "password"
  | "totp"
  | "file"
  | "text"
  | "concealed"
  | "url"
  | "email"
  | "phone"
  | "date"
  | "month_year";

export type ErrorCode =
  | "locked"
  | "not_logged_in"
  | "wrong_credentials"
  | "rollback"
  | "not_found"
  | "invalid"
  | "conflict"
  | "network"
  | "session_expired"
  | "biometry_unavailable"
  | "biometry_failed"
  | "bad_request"
  | "security"
  | "denied"
  // From klav-native-host: its wrapper does not allow this build. The
  // bridge turns it into `host_missing`.
  | "extension_not_allowed"
  | "internal"
  // Extension-side: the host is not installed or the port closed.
  | "host_missing"
  | "disconnected"
  | "timeout"
  // The page covers, hides or moves the frame where the choice was made (T62).
  | "covered"
  // The presence gate (ADR 0041, on since layer 6): the master password
  // is needed (`presence` says what it grants), another check is running,
  // or more than one browser is attached and not exactly one is in front.
  | "presence_required"
  | "presence_busy"
  | "browser_ambiguous";

export interface ErrorBody {
  code: ErrorCode;
  message: string;
  /** With `presence_required`: what the password would grant. */
  presence?: PresenceAsk;
}

/** Whose verification a window belongs to (ADR 0041 §1). */
export type PresenceKey = "session" | "parent" | "connection" | "none";

/**
 * What klavd asks the master password for (`presence_required`, and the
 * `presence` event for an agent's values): the frame words its question
 * from it, never from `window` alone.
 */
export interface PresenceAsk {
  key: PresenceKey;
  window: PasskeyUv;
  terminal?: string;
  declared?: boolean;
  /** What the password grants: a window lasting this; missing: only this one value. */
  lasts?: "5m" | "until_lock";
  /** The one value it hands out, when `lasts` is missing. */
  value?: { kind: "show" | "previous" | "code" | "fill" | "generated" | "resolve"; title?: string; count?: number };
  /** An agent's values for a browser connection (the `presence` event). */
  browser?: BrowserAsk;
}

/** The event that made klavd ask for a browser connection (ADR 0041 §3.1). */
export interface BrowserAsk {
  event: "fill" | "password_change" | "passkey_sign_in";
  /** The agent's name, cleaned by klavd. */
  agent: string;
  /** The item's title from the vault. */
  title?: string;
  /** The passkey's rpId from the vault (never the agent's claim, T140). */
  site?: string;
  /** How many browser connections are attached, when more than one. */
  attached?: number;
  /** `true`: worded for this connection (no window per browser). */
  connection?: boolean;
}

/** With the gate on, what an `unlock` from this connection would open (`status`). */
export interface StatusPresence {
  elsewhere?: boolean;
  key: PresenceKey;
  terminal?: string;
  declared?: boolean;
  lasts?: "5m" | "until_lock";
}

export interface DaemonStatus {
  version: string;
  protocol: number;
  pid: number;
  logged_in: boolean;
  unlocked: boolean;
  email?: string;
  unlocked_with?: "password" | "touch_id";
  idle_lock_secs: number;
  locks_in_secs?: number;
  touch_id: { available: boolean; enrolled: boolean; password_required?: string };
  /** Moves when what reads answer may have changed (ADR 0026): read again when it does. */
  revision?: number;
  /** A background sync is in flight. */
  syncing?: boolean;
  /** The passkey verification window (ADR 0020 §8). */
  passkey_uv?: PasskeyUv;
  /** A passkey use now needs no new verification (still within the window). */
  passkey_verified?: boolean;
  /** Browsers whose extension attached since klavd started (the Mac app, ADR 0027 §4). */
  browsers?: { browser: string; connected: boolean; at_ms: number }[];
  /** An `unlock` with the gate on found klavd already unlocked by another key. */
  already_unlocked?: boolean;
  /** Only with the presence gate on (ADR 0041): what a password unlock opens. */
  presence?: StatusPresence;
}

/** When a passkey use needs Touch ID or the master password again (ADR 0020 §8). */
export type PasskeyUv = "always" | "5m" | "unlocked";

export interface ItemSummary {
  id: string;
  reference: string;
  vault_id: string;
  vault: string;
  project_id: string;
  project: string;
  kind: ItemKind;
  title: string;
  username?: string;
  urls: string[];
  tags: string[];
  version: number;
  updated_at: number;
  trashed: boolean;
  /** The URLs whose site the person confirmed: the only ones Klav fills (ADR 0030 §7). */
  confirmed_urls?: string[];
  /** URLs an agent added that the person has not confirmed (never suggested nor filled). */
  pending_urls?: string[];
  /** The agent that wrote the current version, if one did. */
  author_agent_id?: string;
}

export interface FieldView {
  id: string;
  name: string;
  label: string;
  kind: FieldKind;
  secret: boolean;
  filled: boolean;
  value?: string;
}

export interface ItemView extends ItemSummary {
  fields: FieldView[];
  has_notes: boolean;
  notes?: string;
  attachments: { id: string; name: string; size: number }[];
  revealed: boolean;
}

export interface Suggestion {
  id: string;
  kind: ItemKind;
  title: string;
  username?: string;
  hint?: string;
  location: string;
  totp?: boolean;
  /** An assisted change left a new password pending (ADR 0022 §5): the menu offers both. */
  pending?: boolean;
  /** How a login's URLs relate to the page (ADR 0025 §3): logins come in this order. */
  relation?: HostRelation;
  /** For a login of the `parent` group: the host it was saved for (`my.example.com`). */
  site?: string;
}

/** Exact host, a subdomain of the item's, or the parent of the item's (ADR 0025). */
export type HostRelation = "exact" | "subdomain" | "parent";

export interface Suggestions {
  host?: string;
  /** Exact host first, then subdomain: what may fill without the person picking it. */
  logins: Suggestion[];
  /**
   * Logins saved for a subdomain of the page (ADR 0025): their own group,
   * «Saved for a subdomain», with the host in view. Filled only when the
   * person picks one (`autofill` with `chosen`), never by itself or for agents.
   */
  parent?: Suggestion[];
  /**
   * One-time codes saved on their own (kind `totp`) whose issuer, title or
   * URLs name the page: the top of the popup's «Codes», to copy, never to
   * fill. An older klavd leaves it out: none.
   */
  codes?: Suggestion[];
  cards: Suggestion[];
  identities: Suggestion[];
}

export interface FillValue {
  name: string;
  kind: FieldKind;
  value: string;
}

export interface AutofillValues {
  id: string;
  kind: ItemKind;
  title: string;
  fields: FillValue[];
}

export interface VaultSummary {
  id: string;
  name: string;
  deleted: boolean;
  items: number;
}

export interface ProjectSummary {
  id: string;
  vault_id: string;
  vault: string;
  name: string;
}

export type Permission =
  | "list"
  | "fill"
  | "inject"
  | "totp"
  | "reveal"
  | "create"
  | "update"
  | "delete"
  | "passkey"
  | "rotate";

/** The agent's running task an approval request falls outside of (ADR 0021 §6). */
export interface OutsideTask {
  id: string;
  task: string;
  expires_at: number;
  /** «Add to the task» is offered (never for reveal or delete). */
  can_add: boolean;
}

export type TaskStatus = "pending" | "approved" | "denied" | "expired" | "ended";

export interface TaskCardPermission {
  permission: Permission;
  checked: boolean;
  asked: boolean;
  added_by_klav: boolean;
  denied_by_policy: boolean;
  /** Checks the site and the item has none (ADR 0030 §6): cannot be checked. */
  no_site?: boolean;
}

export interface TaskCardRow {
  vault_id: string;
  project_id: string;
  item_id: string;
  reference: string;
  title?: string;
  username?: string;
  missing: boolean;
  asked_domain?: string;
  domain_mismatch: boolean;
  /** No site, and a permission on the row needs one (ADR 0030 §6). */
  no_site?: boolean;
  /** `domains` is the agent's host on a card or an identity: its claim. */
  domain_claimed?: boolean;
  domains: string[];
  permissions: TaskCardPermission[];
}

/** A task as the person's client completes it (ADR 0021 §3). */
export interface TaskCard {
  id: string;
  status: TaskStatus;
  agent_id: string;
  agent: string;
  task: string;
  reason: string;
  duration_secs: number;
  created_at: number;
  decide_by: number;
  decided_at?: number;
  revision: number;
  expires_at?: number;
  ended_at?: number;
  ended_by?: "person" | "agent" | "expiry" | "revocation";
  rows: TaskCardRow[];
  /** Offered by the person, without a request from the agent (ADR 0022 §6). */
  offered?: boolean;
  /** SHA-256 of the request this card was built from: deciding sends it back (ADR 0030 §5). */
  request_digest: string;
}

/** What the person changed on the card: `[item_id, permission | null]` pairs. */
export interface TaskChoice {
  without: [string, Permission | null][];
  with: [string, Permission | null][];
  for_secs?: number;
}

export interface ApprovalView {
  id: string;
  status: "pending" | "approved" | "denied" | "expired";
  agent_id: string;
  agent: string;
  permission: Permission;
  target: string;
  reason: string;
  domain?: string;
  created_at: number;
  expires_at: number;
  lease_until?: number;
  task?: OutsideTask;
  /** SHA-256 of the request this card was built from: deciding sends it back (ADR 0030 §5). */
  request_digest: string;
}

export interface FieldInput {
  name: string;
  value: string;
  kind?: FieldKind;
  secret: boolean;
}

export interface NewItem {
  kind: ItemKind;
  title: string;
  vault?: string;
  project?: string;
  fields: FieldInput[];
  urls: string[];
  tags: string[];
  /** A secure note's text (or any item's notes). */
  notes?: string;
}

export interface ItemPatch {
  title?: string;
  set: FieldInput[];
  remove: string[];
  add_urls: string[];
  add_tags: string[];
  /** URLs to remove, exactly as stored (a site an agent added). */
  remove_urls?: string[];
}

/** One generator history entry, without its value (ADR 0022 §2). */
export interface GeneratedView {
  created_at: number;
  host?: string;
  saved_in?: string;
  saved_in_title?: string;
  /** Still only in this computer's outbox. */
  pending: boolean;
}

/** One previous password of an item, without its value (ADR 0022 §3). */
export interface PreviousPasswordView {
  index: number;
  field: string;
  label: string;
  from_ms?: number;
  to_ms: number;
  /** Generated for an assisted change and never confirmed. */
  unconfirmed?: boolean;
}

export interface PasswordHistoryView {
  entries: PreviousPasswordView[];
  /** An assisted change left a new password pending (ADR 0022 §5). */
  pending: boolean;
  pending_since?: number;
}

/** Where an export comes from (ADR 0024): `klav import --from`. */
export type ImportSource = "bitwarden" | "1password" | "google" | "chrome" | "firefox" | "safari" | "csv";

export type ImportFormat =
  | "bitwarden"
  | "bitwarden_csv"
  | "one_password"
  | "one_password_csv"
  | "google_authenticator"
  | "chrome"
  | "firefox"
  | "safari"
  | "csv";

export interface ImportRemark {
  at: string;
  reason: string;
}

/** What one file (or QR code) contributed. */
export interface ImportSourceReport {
  name: string;
  format: ImportFormat;
  items: number;
  skipped: ImportRemark[];
  notes: ImportRemark[];
  more_remarks?: number;
  passkeys: number;
  batches?: { id: number; index: number; size: number }[];
}

/** Google Authenticator codes still missing from an export in several. */
export interface ImportMissing {
  id: number;
  size: number;
  /** Positions not read yet, from 1. */
  missing: number[];
}

export interface ImportAdded {
  session: string;
  partial?: boolean;
  sources: ImportSourceReport[];
  entries: number;
  passkeys: number;
  missing: ImportMissing[];
}

export type ImportAction = "new" | "merge" | "duplicate";

export type ImportChange =
  | "password_added"
  | "password_replaced"
  | "password_kept"
  | "history_added"
  | "totp_added"
  | "totp_second"
  | "urls_added"
  | "notes_added"
  | "fields_added"
  | "tags_added"
  | "renamed"
  | "totp_item"
  | "passkey_added"
  | "passkey_kept"
  | "passkey_other_site";

/** One line of the preview: no values. */
export interface ImportRow {
  at: string;
  title: string;
  kind: ItemKind;
  username?: string;
  host?: string;
  action: ImportAction;
  target: string;
  changes: ImportChange[];
  /** The sites a merge adds (with "urls_added"), by host: always named (T119). */
  sites_added?: string[];
}

export interface ImportTotals {
  new: number;
  merged: number;
  duplicates: number;
}

export interface ImportPreview {
  vault: string;
  project: string;
  sources: ImportSourceReport[];
  totals: ImportTotals;
  rows: ImportRow[];
  rows_total: number;
  passkeys: number;
  missing: ImportMissing[];
}

export interface ImportResult {
  vault: string;
  project: string;
  created: number;
  updated: number;
  totals: ImportTotals;
  passkeys: number;
  /** Passkeys that could not be saved, as "<title>: <why>"; their login was imported without them. */
  passkeys_failed?: string[];
}

/** An item in the vault health report (ADR 0022 §4): never a value. */
export interface HealthItem {
  id: string;
  vault_id: string;
  project_id: string;
  reference: string;
  kind: ItemKind;
  title: string;
  username?: string;
  hosts: string[];
  field: string;
  field_label: string;
}

export type BreachReport =
  | { status: "off" }
  | { status: "checked"; found: { item: HealthItem; count: number }[]; queries: number }
  | { status: "failed"; message: string };

/** `vault_health`: reused, weak, old and (if the check is on) breached passwords. */
export interface VaultHealth {
  checked_at: number;
  items: number;
  passwords: number;
  skipped?: number;
  reused: { items: HealthItem[] }[];
  weak: { item: HealthItem; score: number; generated_bits?: number }[];
  old: { item: HealthItem; since_ms: number; days: number; source: "record" | "created" }[];
  breaches: BreachReport;
}

/** `health_settings`: the breach check of this device. */
export interface HealthSettingsView {
  breach_check: boolean;
  notice: string;
}

export interface ChangePasswordUrl {
  url: string;
  host: string;
  source: "bundled" | "well_known";
  domain?: string;
}

export type OfferBlock = "not_granted" | "no_site" | "not_login" | "other_field";

/** One login on «Fix my reused passwords» (ADR 0022 §6). */
export interface OfferRow {
  item_id: string;
  vault_id: string;
  project_id: string;
  reference: string;
  title: string;
  username?: string;
  hosts: string[];
  change_url?: ChangePasswordUrl;
  /** For the person only: which logins share one password. */
  group?: number;
  permissions: Permission[];
  blocked?: OfferBlock;
}

export interface OfferAgent {
  id: string;
  name: string;
}

/** `reused_offer`: the agents that can take the task and the logins. */
export interface ReusedOffer {
  agents: OfferAgent[];
  agent?: OfferAgent;
  rows: OfferRow[];
  task: string;
  reason: string;
  duration_secs: number;
}

export interface OfferRequest {
  agent: string;
  items: string[];
  task?: string;
  reason?: string;
  duration_secs?: number;
}

export type SiteState = "changed" | "pending" | "failed";

/** One site of a task with `rotate`, from its `rotate.*` events. */
export interface SiteProgress {
  item_id: string;
  reference?: string;
  title?: string;
  hosts: string[];
  state: SiteState;
  started?: boolean;
  at?: number;
}

export interface TaskProgress {
  task_id: string;
  card?: TaskCard;
  sites: SiteProgress[];
}

export interface SecretRequestSetupUrl {
  url: string;
  host: string;
  has_punycode: boolean;
}

export interface SecretRequestProxyProposal {
  preset?: string | null;
  profile: string;
  upstream: string;
  header: string;
  prefix: string;
  methods: string[];
  ask_methods: string[];
  path_prefixes: string[];
  rate_per_minute?: number | null;
}

export interface SecretRequestProposal {
  v: number;
  mode: "create" | "update";
  kind?: ItemKind | null;
  title?: string | null;
  vault_id?: string | null;
  project_id?: string | null;
  target_item_id?: string | null;
  field: string;
  placeholder?: string | null;
  setup_url?: string | null;
  base_url?: string | null;
  urls?: string[];
  notes?: string | null;
  proxy_proposal?: SecretRequestProxyProposal | null;
}

export interface SecretRequestCard {
  id: string;
  status: "pending" | "fulfilled" | "denied" | "expired";
  agent_id: string;
  agent: string;
  mode: "create" | "update";
  target_item_id?: string | null;
  target_reference?: string | null;
  target_title?: string | null;
  target_kind?: ItemKind | null;
  reason: string;
  created_at: number;
  expires_at: number;
  decided_at?: number | null;
  proposal_digest: string;
  proposal?: SecretRequestProposal | null;
  proposal_error?: string | null;
  setup_url?: SecretRequestSetupUrl | null;
  agent_projects?: [string, string][];
}

export interface FulfillSecretRequestInput {
  digest: string;
  secret: string;
  vault?: string;
  project?: string;
  title?: string;
  field?: string;
  urls?: string[];
  notes?: string;
  allow_duplicate?: boolean;
  grant_proxy?: boolean;
}

export interface FulfillSecretResult {
  card: SecretRequestCard;
  item: ItemSummary;
  in_grant: boolean;
  proxy_profile?: string | null;
  proxy_warnings?: string[];
}

/** Requests the extension may send (the host refuses the others). */
export type Request =
  | { op: "status" }
  /** `passkey_flow`: set only by the background, for Klav's passkey frame (ADR 0020 §8). */
  /**
   * `shown`: the window this unlock's own question said it opens (ADR 0041,
   * own choice 34). It goes in the request envelope, not the request: the
   * bridge moves it there.
   */
  | { op: "unlock"; password?: string; passkey_flow?: boolean; shown?: PasskeyUv }
  | { op: "lock" }
  | { op: "sync" }
  | { op: "vaults" }
  | { op: "projects"; vault?: string }
  | { op: "list"; filter: { vault?: string; project?: string; kind?: ItemKind; kinds?: ItemKind[]; codes?: boolean; tag?: string; query?: string; trash: boolean } }
  /** `password`: the presence gate's (ADR 0041), after a `presence_required`; ignored without the gate. */
  | { op: "view"; query: string; reveal: boolean; password?: string }
  | { op: "suggest"; url: string }
  /** `chosen`: the person picked a login of the `parent` group (ADR 0025 §2). */
  | { op: "autofill"; item: string; url: string; part?: "all" | "totp" | "pending"; chosen?: boolean; password?: string }
  | { op: "totp"; query: string; field?: string; password?: string }
  | { op: "create"; item: NewItem }
  | { op: "edit"; query: string; patch: ItemPatch }
  | { op: "generator_record"; value: string; host?: string }
  | { op: "generator_history" }
  | { op: "generated_value"; created_at: number; password?: string }
  | { op: "generator_delete"; which: { some: number[] } | "all" }
  | { op: "password_history"; query: string }
  | { op: "previous_password"; query: string; index: number; password?: string }
  /** «Usar la nueva» (`accept`) or «Mantener la actual» on a pending password (ADR 0022 §5). */
  | { op: "resolve_pending"; query: string; accept: boolean }
  | { op: "import_add"; session?: string; name: string; from?: ImportSource; data: string; more?: boolean }
  | { op: "import_preview"; session: string; vault?: string; project?: string }
  | { op: "import_apply"; session: string; vault?: string; project?: string }
  | { op: "import_cancel"; session: string }
  | { op: "approvals"; all: boolean }
  | { op: "decide_approval"; approval: string; approve: boolean; digest: string; lease_secs?: number; password?: string }
  | { op: "tasks"; all: boolean }
  | { op: "decide_task"; task: string; approve: boolean; digest: string; choice?: TaskChoice; password?: string }
  | { op: "add_to_task"; approval: string; digest: string; password?: string }
  | { op: "end_task"; task: string }
  | { op: "secret_requests"; all: boolean }
  | { op: "fulfill_secret_request"; request: string; input: FulfillSecretRequestInput; password?: string }
  | { op: "deny_secret_request"; request: string; digest: string }
  | { op: "extension_attach"; browser: string }
  | { op: "extension_reply"; event: number; ok?: unknown; error?: { code: string; message: string } }
  /** The master password for klavd's `presence` event `event`, on this connection (ADR 0041 §3.2). */
  | { op: "extension_presence"; event: number; password: string }
  /** The vault health report and its breach check setting (ADR 0022 §4). */
  | { op: "vault_health" }
  | { op: "health_settings"; breach_check?: boolean }
  /** The passkey verification window; loosening it asks for Touch ID or `password` (ADR 0020 §8). */
  | { op: "passkey_uv"; window?: PasskeyUv; password?: string }
  /** «Arreglar mis contraseñas repetidas» (ADR 0022 §6): the card, the offer and its progress. */
  | { op: "reused_offer"; agent?: string }
  | { op: "offer_task"; offer: OfferRequest; password?: string }
  | { op: "task_progress"; task: string }
  /** Passkeys (ADR 0020): `origin` is the sender's, as the browser reported it. */
  | { op: "passkey_candidates"; origin: string; rp_id?: string; allow_credentials: string[] }
  | { op: "passkey_get"; origin: string; rp_id?: string; challenge: string; item: string; password?: string }
  /** An agent's armed use in tab `tab_id` (ADR 0020 §9): only with klavd's token for it, once. */
  | { op: "agent_passkey_use"; tab_id: number; origin: string; rp_id?: string; challenge: string; token: string }
  | { op: "passkey_create"; request: PasskeyCreateRequest; password?: string };

/** What a page asks to create, for klavd (`klav_client::passkeys::PasskeyCreateRequest`). */
export interface PasskeyCreateRequest {
  origin: string;
  rp_id?: string;
  rp_name?: string;
  user_id: string;
  user_name: string;
  user_display_name?: string;
  challenge: string;
  exclude_credentials?: string[];
  item?: string;
  replace?: boolean;
}

/** klavd's answer to `passkey_create`. */
export type PasskeyCreateOutcome =
  | ({ status: "created" } & Registration)
  | { status: "browser" }
  | { status: "excluded" }
  | { status: "exists"; item: string; title: string };

export interface ResponseEnvelope {
  v: number;
  id: number;
  ok?: unknown;
  error?: ErrorBody;
  warnings?: string[];
}

/** An error from klavd, the host or the port. */
export class DaemonError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    /** With `presence_required`: what the password would grant. */
    readonly presence?: PresenceAsk,
  ) {
    super(message);
    this.name = "DaemonError";
  }
}
