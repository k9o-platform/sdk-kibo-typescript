/**
 * Wire-shape tests for `client.kibo.vault.secrets.*` — the full family: list / get / create /
 * revealChallenge / reveal / update / rotate / move / delete.
 *
 * Verifies URL/query/method/body, including:
 *  - `region` optional (the gateway sets its own), sent only when given
 *  - `value` base64-encoded on write, base64-decoded on reveal
 *  - the `X-K9O-Reveal-Challenge` header on `reveal`
 */

import { describe, expect, it } from "bun:test";
import { createKiboClient } from "../src/index.ts";
import type { HttpClientConfig } from "@k9o/core/http";

type CapturedRequest = { url: string; method: string; body?: string; headers?: Record<string, string> };

function captureFetch(captured: CapturedRequest, responseBody: unknown, status = 200): typeof globalThis.fetch {
  return (async (input: string | URL, init?: RequestInit) => {
    captured.url = typeof input === "string" ? input : input.toString();
    captured.method = init?.method as string;
    captured.headers = (init?.headers as Record<string, string>) ?? {};
    if (init?.body !== undefined) captured.body = String(init.body);
    if (status === 204) return new Response(null, { status: 204 });
    return new Response(JSON.stringify(responseBody), { status, headers: { "content-type": "application/json" } });
  }) as unknown as typeof globalThis.fetch;
}

function config(cap: CapturedRequest, responseBody: unknown, status = 200): HttpClientConfig {
  return { baseUrl: "https://acme.api.k9o.io", projectSlug: "member-portal", fetch: captureFetch(cap, responseBody, status) };
}

const SUMMARY = {
  id: "sec_abc", name: "db/pw", ownerId: "usr_1", visibility: { kind: "private" }, version: 1,
  kid: "vkey_1", createdAt: "t", createdBy: "usr_1", updatedAt: "t", updatedBy: "usr_1",
  rotatedAt: null, retiredAt: null, metadata: {},
};

describe("kibo vault.secrets", () => {
  it("list() GETs /@<slug>/vault/secrets with prefix/cursor/limit, no region", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, { data: { secrets: [SUMMARY], nextCursor: null }, meta: {} }));
    const env = await client.vault.secrets.list({ prefix: "db/", limit: 10 });
    expect(cap.method).toBe("GET");
    expect(cap.url).toBe("https://acme.api.k9o.io/@member-portal/vault/secrets?prefix=db%2F&limit=10");
    expect(env.data.secrets[0]!.id).toBe("sec_abc");
  });

  it("get() reads metadata through the list route (a plain GET on the secret is a reveal and 401s without a challenge)", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const other = { ...SUMMARY, id: "sec_other", name: "db/pw2" };
    const client = createKiboClient(config(cap, { data: { secrets: [other, SUMMARY], nextCursor: null }, meta: {} }));
    const env = await client.vault.secrets.get("db/pw");
    expect(cap.method).toBe("GET");
    expect(cap.url).toBe("https://acme.api.k9o.io/@member-portal/vault/secrets?prefix=db%2Fpw&limit=100");
    expect(cap.headers?.["X-K9O-Reveal-Challenge"]).toBeUndefined();
    expect(env.data.id).toBe("sec_abc");
  });

  it("get() follows the cursor until it finds the exact name, then throws K9O_NOT_FOUND when absent", async () => {
    const urls: string[] = [];
    const pages = [
      { data: { secrets: [{ ...SUMMARY, name: "db/pw2" }], nextCursor: "c1" }, meta: {} },
      { data: { secrets: [], nextCursor: null }, meta: {} },
    ];
    const fetchImpl = (async (input: string | URL, init?: RequestInit) => {
      if (init?.method === "HEAD") return new Response(null, { status: 200 }); // origin probe, not an API call
      urls.push(String(input));
      return new Response(JSON.stringify(pages.shift()), { status: 200, headers: { "content-type": "application/json" } });
    }) as unknown as typeof globalThis.fetch;
    const client = createKiboClient({ baseUrl: "https://acme.api.k9o.io", projectSlug: "member-portal", fetch: fetchImpl });
    const err = await client.vault.secrets.get("db/pw").then(() => null, (e: unknown) => e);
    expect((err as { code?: string }).code).toBe("K9O_NOT_FOUND");
    expect(urls.length).toBe(2);
    expect(urls[0]).not.toContain("cursor=");
    expect(urls[1]).toContain("cursor=c1");
  });

  it("create() POSTs with region query + base64-encoded value", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, { data: SUMMARY, meta: {} }));
    await client.vault.secrets.create({ name: "db/pw", value: "hunter2", region: "us01", visibility: { kind: "private" } });
    expect(cap.method).toBe("POST");
    expect(cap.url).toBe("https://acme.api.k9o.io/@member-portal/vault/secrets/db%2Fpw?region=us01");
    const body = JSON.parse(cap.body!);
    expect(body.value).toBe(Buffer.from("hunter2", "utf8").toString("base64"));
    expect(body.value).not.toBe("hunter2");
  });

  it("revealChallenge() POSTs ?op=reveal-challenge and sends region only when given", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, { data: { challenge: "rvc_1", expiresAt: "t" }, meta: {} }));
    const env = await client.vault.secrets.revealChallenge("db/pw", { region: "us01" });
    expect(cap.method).toBe("POST");
    expect(cap.url).toContain("op=reveal-challenge");
    expect(cap.url).toContain("region=us01");
    expect(env.data.challenge).toBe("rvc_1");
  });

  it("reveal() GETs with the X-K9O-Reveal-Challenge header and decodes base64 value to plaintext", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const wireValue = Buffer.from("hunter2", "utf8").toString("base64");
    const client = createKiboClient(config(cap, {
      data: { id: "sec_abc", name: "db/pw", version: 1, value: wireValue, revealedAt: "t", attestationTier: { urn: "u", operator: "platform", verified: true } },
      meta: {},
    }));
    const env = await client.vault.secrets.reveal("db/pw", { region: "us01", challenge: "rvc_1" });
    expect(cap.method).toBe("GET");
    expect(cap.headers?.["X-K9O-Reveal-Challenge"]).toBe("rvc_1");
    expect(env.data.value).toBe("hunter2");
    expect(env.data.attestationTier.operator).toBe("platform");
  });

  it("update() PUTs with region query + base64-encoded value, returns the narrow {id,name,version} shape", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, { data: { id: "sec_abc", name: "db/pw", version: 2 }, meta: {} }));
    const env = await client.vault.secrets.update("db/pw", { region: "us01", value: "newpw" });
    expect(cap.method).toBe("PUT");
    expect(cap.url).toBe("https://acme.api.k9o.io/@member-portal/vault/secrets/db%2Fpw?region=us01");
    expect(JSON.parse(cap.body!).value).toBe(Buffer.from("newpw", "utf8").toString("base64"));
    expect(env.data.version).toBe(2);
  });

  it("rotate() POSTs ?op=rotate&region=<region>, no body", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, { data: { id: "sec_abc", name: "db/pw", version: 2, rotatedAt: "t", ledgerSequenceNumber: 2 }, meta: {} }));
    const env = await client.vault.secrets.rotate("db/pw", { region: "us01" });
    expect(cap.method).toBe("POST");
    expect(cap.url).toContain("op=rotate");
    expect(env.data.ledgerSequenceNumber).toBe(2);
  });

  it("move() POSTs ?op=move&region=<region> with {newPath}", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, { data: { id: "sec_abc", name: "db/pw2", event: "SECRET_PATH_CHANGED" }, meta: {} }));
    const env = await client.vault.secrets.move("db/pw", { region: "us01", newPath: "db/pw2" });
    expect(cap.method).toBe("POST");
    expect(cap.url).toContain("op=move");
    expect(JSON.parse(cap.body!)).toEqual({ newPath: "db/pw2" });
    expect(env.data.event).toBe("SECRET_PATH_CHANGED");
  });

  it("delete() DELETEs with region query and handles a 204 empty body", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, undefined, 204));
    const env = await client.vault.secrets.delete("db/pw", { region: "us01" });
    expect(cap.method).toBe("DELETE");
    expect(cap.url).toBe("https://acme.api.k9o.io/@member-portal/vault/secrets/db%2Fpw?region=us01");
    expect(env.data).toBeUndefined();
  });
});
