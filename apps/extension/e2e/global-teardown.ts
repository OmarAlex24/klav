/** Removes the run's temporary directory (see global-setup.ts). */
import { rmSync } from "node:fs";

export default function globalTeardown(): void {
  const dir = process.env.KLAV_E2E_ROOT;
  if (dir?.includes("klav-e2e-run-")) rmSync(dir, { recursive: true, force: true });
}
