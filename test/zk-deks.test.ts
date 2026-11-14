/**
 * Wire-shape tests for `client.kibo.vault.zkDeks`.
 *
 * Verifies URL construction (member-plane slug grammar `/@<slug>/vault/zk-deks`),
 * HTTP method, request body, and the response envelope shape against the
 * gateway contract. (Live integration is exercised by the conformance gate
 * against staging once the gateway endpoint is reachable.)
 */

import { describe, expect, it } from "bun:test";
import { createKiboClient } from "../src/index.ts";
import type { HttpClientConfig } from "@k9o/core/http";

type CapturedRequest = { url: string; method: string; body?: string };

function captureFetch(captured: CapturedRequest, responseBody: unknown, status = 200): typeof globalThis.fetch {
  return (async (input: string | URL, init?: RequestInit) => {
    captured.url = typeof input === "string" ? input : input.toString();
    captured.method = init?.method as string;
    if (init?.body !== undefined) captured.body = String(init.body);
    return new Response(JSON.stringify(responseBody), { status, headers: { "content-type": "application/json" } });
  }) as unknown as typeof globalThis.fetch;
}

function config(cap: CapturedRequest, responseBody: unknown, projectSlug?: string): HttpClientConfig {
  return {
    baseUrl: "https://acme.api.k9o.io",
    projectSlug,
    fetch: captureFetch(cap, responseBody),
  };
}

describe("kibo vault.zkDeks", () => {
  it("store POSTs /@<slug>/vault/zk-deks with {envelope,provider,keyVersionRef}", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, { data: { id: "zkdek_abc", createdAt: "t" }, meta: {} }, "member-portal"));
    const env = await client.vault.zkDeks.store({ envelope: "b64envelope", provider: "aws-kms", keyVersionRef: "arn:aws:kms:..." });
    expect(cap.method).toBe("POST");
    expect(cap.url).toBe("https://acme.api.k9o.io/@member-portal/vault/zk-deks");
    expect(cap.body).toContain("b64envelope");
    expect(cap.body).toContain("aws-kms");
    expect(env.data.id).toBe("zkdek_abc");
  });

  it("fetch GETs /@<slug>/vault/zk-deks/<id> and returns the opaque record", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, { data: { id: "zkdek_abc", envelope: "b64envelope", provider: "aws-kms", keyVersionRef: "arn", createdAt: "t" }, meta: {} }, "member-portal"));
    const env = await client.vault.zkDeks.fetch("zkdek_abc");
    expect(cap.method).toBe("GET");
    expect(cap.url).toBe("https://acme.api.k9o.io/@member-portal/vault/zk-deks/zkdek_abc");
    expect(env.data.envelope).toBe("b64envelope");
    expect(env.data.provider).toBe("aws-kms");
  });

  it("throws K9O_MISSING_PROJECT_CONTEXT without a bound project", async () => {
    const cap: CapturedRequest = { url: "", method: "" };
    const client = createKiboClient(config(cap, { data: null, meta: {} }));
    await expect(
      client.vault.zkDeks.store({ envelope: "x", provider: "aws-kms", keyVersionRef: "y" }),
    ).rejects.toThrow(/project/i);
  });
});
