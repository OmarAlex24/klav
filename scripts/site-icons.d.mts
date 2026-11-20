/** Types for the tests of scripts/site-icons.mjs. */
export type Command = [string, ...number[]];
export function normalize(d: string): Command[];
export function serialize(cmds: Command[]): string;
export function licenseProblem(slug: string, entry: { title: string; license?: unknown } | undefined): string | undefined;
