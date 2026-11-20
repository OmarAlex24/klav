/** The part of a Playwright (Chromium) page the SDK uses. */
export interface Page {
  context(): {
    newCDPSession(page: Page): Promise<{
      send(method: string, params?: object): Promise<any>;
      detach(): Promise<void>;
    }>;
  };
}

export declare const EXIT: Readonly<{
  SECURITY: 3;
  PENDING: 4;
  DENIED: 5;
  EXPIRED: 6;
  PAUSED: 7;
  ACCOUNT_DELETING: 8;
  NO_TERMINAL: 9;
}>;

export declare class KlavError extends Error {
  /** `klav`'s exit code: 4 waits for the person, 5 denied, 6 expired, 3 security, 7 paused, 8 the account is being deleted. */
  code: number;
  stderr: string;
}

export interface Common {
  /** Why the agent needs it (mandatory; logged and shown to the person). */
  reason: string;
  /** Agent name (default: `$KLAV_AGENT` or the only one). */
  agent?: string;
  /** Wait for the person's approval, e.g. "2m". */
  wait?: string;
  /** Use this approval (a request the person approved); refused for another action. */
  approvalId?: string;
  /** Working directory (its `klav.toml` applies). */
  cwd?: string;
}

export interface FillOptions extends Common {
  /** The browser's CDP address (default: `$KLAV_CDP`). */
  cdp?: string;
  /** CSS selectors by field name, e.g. `{ password: "#pass" }`. */
  selectors?: Record<string, string>;
  /** Submit the form after filling (default false). */
  submit?: boolean;
}

/** What `fill` did: field names and addresses, never values. */
export interface FillReport {
  url: string;
  filled: string[];
  submitted?: boolean;
  /** After `submit`: whether a new page loaded. */
  navigated?: boolean;
  /** After `submit`: the page's address. */
  url_after?: string;
}

export declare function targetId(page: Page): Promise<string>;
export declare function fill(
  page: Page,
  reference: string,
  options: FillOptions,
): Promise<FillReport>;
export declare function registerSession(
  name: string,
  page?: Page,
  options?: { cdp?: string },
): Promise<void>;
export declare function run(
  command: string,
  args: string[],
  options: Common & { env?: Record<string, string>; timeout?: string },
): Promise<{ code: number; stdout: string; stderr: string }>;
/** `out` must be inside `cwd` (the working directory by default). */
export declare function inject(
  options: Common & { out: string; reference?: string; template?: string; force?: boolean },
): Promise<void>;
export declare function totp(reference: string, options: Common & { field?: string }): Promise<string>;

export interface ApprovalDecision {
  approval_id: string;
  status: "approved" | "pending" | "denied" | "expired";
  lease_until?: number | null;
  used: boolean;
  expires_at: number;
}
export declare function waitApproval(
  id: string,
  options?: { timeout?: string; agent?: string; cwd?: string },
): Promise<ApprovalDecision>;

export type TaskPermission = "fill" | "totp" | "inject" | "update" | "passkey" | "rotate";

/** A task request (ADR 0021): what `tarea.toml` holds. */
export interface TaskSpec {
  /** Short title (max 120 characters; the person sees it). */
  task: string;
  /** Why (max 500 characters; mandatory). */
  reason: string;
  /** From approval: "30m", "2h", "1h30m" (5m to 24h). */
  duration: string;
  /** 1 to 50 items, each once. `reveal` and `delete` never go in a task. */
  access: { ref: string; permissions: TaskPermission[]; domain?: string }[];
}

/** A task as the agent sees it, with the person's decision verified. */
export interface Task {
  task_id: string;
  status: "pending" | "approved" | "denied" | "expired" | "ended";
  task: string;
  /** Pending: until when the person can decide; approved: when it ends (Unix ms). */
  expires_at: number;
  revision?: number;
  ended_by?: "person" | "agent" | "expiry" | "revocation";
  /** What was approved: use only this. */
  access?: { ref: string; permissions: TaskPermission[]; domains?: string[]; added_by_klav?: TaskPermission[] }[];
  /** What the person left out. */
  removed?: { ref: string; permissions: TaskPermission[] }[];
}

export interface TaskOptions {
  agent?: string;
  cwd?: string;
}

export declare function requestTask(spec: TaskSpec, options?: TaskOptions & { wait?: string }): Promise<Task>;
export declare function waitTask(id: string, options?: TaskOptions & { timeout?: string }): Promise<Task>;
export declare function getTask(id: string, options?: TaskOptions): Promise<Task>;
export declare function endTask(id: string, options: TaskOptions & { reason: string }): Promise<Task>;
