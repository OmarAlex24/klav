/**
 * A TCP proxy that delays every chunk in each direction, to stand a local
 * klav-server where a far one would be (perf.spec.ts). It runs in its own
 * Node process: the harness runs `klav` with `spawnSync`, which would
 * stall a proxy living in the test's event loop.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

export interface Latency {
  url: string;
  /** Sets the delay each way, in milliseconds (half the round trip). */
  set(ms: number): Promise<void>;
  close(): void;
}

/** The proxy itself, run as `node -e`. argv: target port. Prints `<proxy port> <control port>`. */
const PROXY = `
const net = require("node:net");
const http = require("node:http");
const target = Number(process.argv[1]);
let ms = 0;
const pipe = (from, to) => {
  from.on("data", (chunk) => {
    const send = () => { if (!to.destroyed) to.write(chunk); };
    if (ms > 0) setTimeout(send, ms); else send();
  });
  from.on("end", () => setTimeout(() => to.end(), ms));
  from.on("error", () => to.destroy());
  from.on("close", () => setTimeout(() => to.destroy(), ms));
};
const proxy = net.createServer((client) => {
  const upstream = net.createConnection(target, "127.0.0.1");
  pipe(client, upstream);
  pipe(upstream, client);
});
const control = http.createServer((req, res) => {
  ms = Number(req.url.slice(1)) || 0;
  res.end("ok");
});
proxy.listen(0, "127.0.0.1", () => control.listen(0, "127.0.0.1", () => {
  console.log(proxy.address().port + " " + control.address().port);
}));
process.stdin.on("end", () => process.exit(0));
process.stdin.resume();
`;

export async function startLatency(target: number): Promise<Latency> {
  // stdin stays open: the proxy exits when the test process goes away.
  const child = spawn(process.execPath, ["-e", PROXY, String(target)], { stdio: ["pipe", "pipe", "inherit"] });
  const line = await new Promise<string>((done, fail) => {
    const lines = createInterface({ input: child.stdout });
    lines.once("line", done);
    child.once("exit", () => {
      fail(new Error("the latency proxy exited"));
    });
  });
  const [proxyPort, controlPort] = line.split(" ");
  return {
    url: `http://127.0.0.1:${proxyPort ?? ""}`,
    async set(ms: number) {
      await fetch(`http://127.0.0.1:${controlPort ?? ""}/${String(Math.round(ms))}`);
    },
    close() {
      child.kill();
    },
  };
}
