/**
 * A Kibo vault client whose network is a recorder: every request is captured (method, path, query, headers, JSON body) and
 * answered with a generic success envelope.
 */
import { createKiboClient, type KiboClient } from "../../src/index.ts";

export type Sent = { method: string; path: string; query: string[]; queryValues: Record<string, string>; headers: Record<string, string>; body: unknown };

export function recordingKibo(): { client: KiboClient; sent: Sent[] } {
  const sent: Sent[] = [];
  const fetchImpl = (async (input: string | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    let body: unknown;
    if (typeof init?.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    if ((init?.method ?? "GET") === "HEAD" && url.pathname === "/") return new Response(null, { status: 200 });
    sent.push({
      method: String(init?.method ?? "GET"),
      path: url.pathname,
      query: [...url.searchParams.keys()],
      queryValues: Object.fromEntries(url.searchParams.entries()),
      headers: Object.fromEntries(Object.entries((init?.headers as Record<string, string>) ?? {}).map(([k, v]) => [k.toLowerCase(), v])),
      body,
    });
    if (init?.method === "DELETE") return new Response(null, { status: 204 });
    return new Response(JSON.stringify({ data: { secrets: [], nextCursor: null, value: "" }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof globalThis.fetch;
  const client = createKiboClient({
    baseUrl: "https://acme.api.k9o.io",
    projectSlug: "demo-app",
    apiKey: "k9o_test",
    fetch: fetchImpl,
    retryConfig: { maxRetries: 0 },
  } as never);
  return { client, sent };
}
