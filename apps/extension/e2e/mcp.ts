/**
 * A minimal MCP client for the tests: `klav mcp` as an agent, over its
 * stdio (one JSON-RPC message per line). Keeps every line it saw, and its
 * stderr, to check that no secret ever reached the agent.
 */
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { createInterface } from "node:readline";

export interface ToolResult {
  text: string;
  isError: boolean;
}

export class McpClient {
  readonly seen: string[] = [];
  /** Everything `klav mcp` wrote to stderr (its log). */
  readonly errors: string[] = [];
  private readonly child: ChildProcessWithoutNullStreams;
  private next = 1;
  private readonly waiting = new Map<number, (value: Record<string, unknown>) => void>();

  constructor(bin: string, cwd: string, env: Record<string, string>) {
    this.child = spawn(bin, ["mcp"], { cwd, env: { ...process.env, ...env } });
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => this.errors.push(chunk));
    createInterface({ input: this.child.stdout }).on("line", (line) => {
      this.seen.push(line);
      const message = JSON.parse(line) as Record<string, unknown>;
      const id = typeof message.id === "number" ? message.id : undefined;
      if (id === undefined) return;
      this.waiting.get(id)?.(message);
      this.waiting.delete(id);
    });
  }

  request(method: string, params: unknown): Promise<Record<string, unknown>> {
    const id = this.next++;
    return new Promise((resolve) => {
      this.waiting.set(id, resolve);
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  async initialize(): Promise<void> {
    await this.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "0" } });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  }

  async tool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const reply = await this.request("tools/call", { name, arguments: args });
    const result = reply.result as { content: { text: string }[]; isError: boolean };
    return { text: result.content[0]?.text ?? "", isError: result.isError };
  }

  close(): void {
    this.child.stdin.end();
    this.child.kill();
  }
}
