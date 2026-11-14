/**
 * Contract test: every `vault.secrets.*` / `vault.zkDeks.*` call of `@k9o/kibo`, sent through a recording client, must hit a
 * route the gateway serves, send a body that route reads, and use only query parameters it declares (or that the entry names
 * as read by the handler). The gateway's emitted OpenAPI is the source of truth; the checker is shared with `@k9o/core`.
 */
import { describe, expect, it } from "bun:test";
import { checkBody, findOperation, methodsFor } from "../../../core/test/contract/openapi.ts";
import { CALLS, type KiboCall } from "./calls.ts";
import { recordingKibo } from "./recorder.ts";

/** JSON with object keys sorted, so key order never matters. */
function canon(v: unknown): string {
  return JSON.stringify(v, (_k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => a.localeCompare(b))) : x));
}

async function verdict(entry: KiboCall): Promise<string[]> {
  const { client, sent } = recordingKibo();
  try {
    await entry.call(client);
  } catch (e) {
    if (sent.length === 0) return [`the call threw before sending: ${e instanceof Error ? e.message : String(e)}`];
  }
  if (sent.length === 0) return ["the call sent no request"];
  const problems: string[] = [];
  for (const req of sent) {
    const op = findOperation(req.method, req.path);
    if (!op) {
      const other = methodsFor(req.path);
      problems.push(other.length > 0 ? `${req.method} ${req.path}: the route exists for ${other.join("/")} only` : `${req.method} ${req.path}: no such route`);
      continue;
    }
    if (op.body) problems.push(...checkBody(op.body, req.body).map((m) => `${req.method} ${op.template}: ${m}`));
    else if (req.body !== undefined) problems.push(`${req.method} ${op.template}: the route declares no body and the call sends one`);
    if (op.query.length > 0) for (const q of req.query) if (!op.query.includes(q) && !(entry.extraQuery ?? []).includes(q)) problems.push(`${req.method} ${op.template}: query '${q}' is not declared by the route`);
  }
  // What the OpenAPI cannot say: the exact route, op, challenge header and body.
  const first = sent.slice(0, entry.expectRoutes.length);
  entry.expectRoutes.forEach((want, i) => {
    const got = first[i];
    if (!got) return void problems.push(`expected request ${i + 1} (${want.route}) was not sent`);
    if (`${got.method} ${got.path}` !== want.route) problems.push(`request ${i + 1}: sent ${got.method} ${got.path}, expected ${want.route}`);
    if (got.queryValues["op"] !== want.op) problems.push(`request ${i + 1}: op=${got.queryValues["op"]}, expected ${want.op}`);
    if ((got.headers["x-k9o-reveal-challenge"] ?? undefined) !== want.header) problems.push(`request ${i + 1}: X-K9O-Reveal-Challenge=${got.headers["x-k9o-reveal-challenge"]}, expected ${want.header}`);
    if ("body" in want && canon(got.body) !== canon(want.body)) problems.push(`request ${i + 1}: body ${JSON.stringify(got.body)}, expected ${JSON.stringify(want.body)}`);
  });
  return problems;
}

describe("@k9o/kibo vault client against the gateway OpenAPI", () => {
  for (const entry of CALLS) {
    it(entry.id, async () => {
      expect(await verdict(entry), `${entry.id} disagrees with the gateway`).toEqual([]);
    });
  }

  it("covers every vault.secrets.* and vault.zkDeks.* method", () => {
    const { client } = recordingKibo();
    const methods = [
      ...Object.keys(client.vault.secrets).map((m) => `secrets.${m}`),
      ...Object.keys(client.vault.zkDeks).map((m) => `zkDeks.${m}`),
    ];
    const covered = new Set(CALLS.map((c) => c.id.split(" ")[0]));
    expect(methods.filter((m) => !covered.has(m))).toEqual([]);
  });
});
