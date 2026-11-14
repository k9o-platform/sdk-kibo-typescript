import { describe, expect, test } from "bun:test";
import { createKiboClientCore, type KiboAppWasm, type KiboClientCoreConfig } from "../src/client-core.ts";

const KEY = "arn:aws:kms:eu-central-1:111122223333:key/mine";
const tok = (over: Record<string, unknown> = {}) => ({
  data: { token: "jwt-secret", expiresAt: "x", issuer: "i", subject: "proj_1:crypt:c:op:encrypt", audience: "a", kid: "k", projectId: "proj_1", provider: "aws", ...over },
});

function fakeWasm(log: string[], over: Partial<KiboAppWasm> = {}): KiboAppWasm {
  return {
    core_capabilities: () => ["expected_key_refs"],
    async acquire_kms_credential(input: any) {
      log.push(`exchange:${input.identity_token}`);
      return { secret: "cred-1", expires_at_unix_secs: 10_000 };
    },
    async app_crypto_seal(input: any) {
      log.push(`seal:${input.crypt}:${input.project_id}:${input.expected_key_refs.join(",")}`);
      return { container: [1, 2, 3, ...input.plaintext] };
    },
    async app_crypto_open(input: any) {
      log.push(`open:${input.crypt}:${input.expected_key_refs.join(",")}`);
      if (input.container[0] !== 1) throw new Error("K9O_CRYPTO_UNEXPECTED_KEY: no");
      return { plaintext: input.container.slice(3) };
    },
    ...over,
  };
}

function cfg(log: string[], over: Partial<KiboClientCoreConfig> = {}): KiboClientCoreConfig {
  return {
    provider: "aws",
    posture: "byok",
    projectId: "proj_1",
    keyRef: { version: 1, externalRef: KEY },
    federation: { provider: "aws", role_arn: "arn:aws:iam::1:role/r", session_name: "s", region: "eu-central-1", key_arn: KEY, duration_secs: 900 },
    expectedKeyRefs: [KEY],
    federatedToken: async (req) => {
      log.push(`token:${req.crypt}:${req.op}`);
      return tok() as never;
    },
    wasm: fakeWasm(log),
    now: () => 1000,
    ...over,
  };
}

describe("kibo client core", () => {
  test("encrypt: token, then exchange, then seal; round trips through decrypt", async () => {
    const log: string[] = [];
    const core = createKiboClientCore(cfg(log));
    const enc = await core.encrypt("c", [{ plaintext: new TextEncoder().encode("hi") }]);
    expect(log).toEqual(["token:c:encrypt", "exchange:jwt-secret", `seal:c:proj_1:${KEY}`]);
    const ct = (enc.items[0] as { ciphertext: string }).ciphertext;
    const dec = await core.decrypt("c", [{ ciphertext: ct }]);
    expect((dec.items[0] as { text: string }).text).toBe("hi");
  });

  test("vault: the JWT auth mount is handed to the core under the core's own name `mount`", async () => {
    let seen: any;
    const wasm = fakeWasm([], {
      async acquire_kms_credential(input: any) {
        seen = input.spec;
        return { secret: "cred-1", expires_at_unix_secs: 10_000 };
      },
    });
    const vaultKey = "transit/mykey:1";
    const core = createKiboClientCore(
      cfg([], {
        provider: "vault",
        keyRef: { version: 1, externalRef: vaultKey },
        expectedKeyRefs: [vaultKey],
        federation: { provider: "vault", vault_addr: "https://vault.example:8200", jwt_auth_mount: "jwt", role: "app" },
        federatedToken: async () => tok({ provider: "vault" }) as never,
        wasm,
      }),
    );
    await core.encrypt("c", [{ plaintext: new TextEncoder().encode("hi") }]);
    expect(seen).toEqual({ provider: "vault", vault_addr: "https://vault.example:8200", mount: "jwt", role: "app" });
  });

  test("declares it enforces the pin", () => {
    expect(createKiboClientCore(cfg([])).enforcesExpectedKeyRefs).toBe(true);
  });

  test("refuses to be built without a pin, with an empty pin, or with a key outside the pin", () => {
    expect(() => createKiboClientCore(cfg([], { expectedKeyRefs: undefined as never }))).toThrow();
    expect(() => createKiboClientCore(cfg([], { expectedKeyRefs: [] }))).toThrow();
    expect(() => createKiboClientCore(cfg([], { expectedKeyRefs: ["arn:aws:kms:eu-central-1:111122223333:key/other"] }))).toThrow(/keyRef/);
  });

  test("an empty pin from the router reaches no network and no KMS", async () => {
    const log: string[] = [];
    const core = createKiboClientCore(cfg(log));
    await expect(core.decrypt("c", [{ ciphertext: "AQID" }], { expectedKeyRefs: [] })).rejects.toThrow(/key pin/);
    expect(log).toEqual([]);
  });

  test("a core that does not list expected_key_refs is refused before any token is fetched", async () => {
    const log: string[] = [];
    const core = createKiboClientCore(cfg(log, { wasm: fakeWasm(log, { core_capabilities: () => [] }) }));
    await expect(core.encrypt("c", [{ plaintext: new Uint8Array([1]) }])).rejects.toMatchObject({ code: "K9O_CRYPTO_KEY_PIN_UNENFORCED" });
    expect(log).toEqual([]);
  });

  test("an older core without the new exports is refused", async () => {
    const log: string[] = [];
    const old = { core_capabilities: () => ["expected_key_refs"] } as unknown as KiboAppWasm;
    const core = createKiboClientCore(cfg(log, { wasm: old }));
    await expect(core.encrypt("c", [{ plaintext: new Uint8Array([1]) }])).rejects.toMatchObject({ code: "KIBO_WASM_ERROR" });
  });

  test("a response naming another provider or project is refused and nothing is exchanged", async () => {
    for (const over of [{ provider: "gcp" }, { projectId: "proj_other" }]) {
      const log: string[] = [];
      const core = createKiboClientCore(cfg(log, { federatedToken: async () => tok(over) as never }));
      await expect(core.encrypt("c", [{ plaintext: new Uint8Array([1]) }])).rejects.toMatchObject({ code: "K9O_INVALID_FIELD_VALUE" });
      expect(log).toEqual([]);
    }
  });

  test("projectId comes from the response only when not configured", async () => {
    const log: string[] = [];
    const core = createKiboClientCore(cfg(log, { projectId: undefined }));
    await core.encrypt("c", [{ plaintext: new Uint8Array([1]) }]);
    expect(log.at(-1)).toBe(`seal:c:proj_1:${KEY}`);
    const none = createKiboClientCore(cfg([], { projectId: undefined, federatedToken: async () => tok({ projectId: undefined }) as never }));
    await expect(none.encrypt("c", [{ plaintext: new Uint8Array([1]) }])).rejects.toMatchObject({ code: "K9O_INVALID_FIELD_VALUE" });
  });

  test("the exchanged credential is reused until near expiry, then exchanged again", async () => {
    const log: string[] = [];
    let t = 1000;
    const core = createKiboClientCore(cfg(log, { now: () => t }));
    await core.encrypt("c", [{ plaintext: new Uint8Array([1]) }]);
    await core.encrypt("c", [{ plaintext: new Uint8Array([1]) }]);
    expect(log.filter((l) => l.startsWith("exchange")).length).toBe(1);
    t = 9_950; // inside the 60 s skew of 10_000
    await core.encrypt("c", [{ plaintext: new Uint8Array([1]) }]);
    expect(log.filter((l) => l.startsWith("exchange")).length).toBe(2);
  });

  test("a stalled exchange is abandoned at the deadline", async () => {
    const log: string[] = [];
    const stalled = fakeWasm(log, { acquire_kms_credential: () => new Promise(() => {}) });
    const core = createKiboClientCore(cfg(log, { wasm: stalled, exchangeDeadlineMs: 20 }));
    await expect(core.encrypt("c", [{ plaintext: new Uint8Array([1]) }])).rejects.toMatchObject({ code: "KIBO_EXCHANGE_TIMEOUT" });
  });

  test("one bad item fails on its own and carries the core's code; the others succeed", async () => {
    const log: string[] = [];
    const core = createKiboClientCore(cfg(log));
    const good = (await core.encrypt("c", [{ plaintext: new Uint8Array([9]) }])).items[0] as { ciphertext: string };
    const r = await core.decrypt("c", [{ ciphertext: "AAAA" }, good]);
    expect(r.items[0]).toMatchObject({ ok: false, code: "K9O_CRYPTO_UNEXPECTED_KEY" });
    expect(r.items[1]).toMatchObject({ ok: true });
  });

  test("rewrap opens and seals under the configured key with the rewrap token", async () => {
    const log: string[] = [];
    const core = createKiboClientCore(cfg(log));
    const ct = ((await core.encrypt("c", [{ plaintext: new Uint8Array([7]) }])).items[0] as { ciphertext: string }).ciphertext;
    log.length = 0;
    const r = await core.rewrap("c", [{ ciphertext: ct }]);
    expect(r.items[0]).toMatchObject({ ok: true });
    expect(log[0]).toBe("token:c:rewrap");
    expect(log.slice(-2).map((l) => l.split(":")[0])).toEqual(["open", "seal"]);
  });

  test("neither the token nor the credential appears in an error", async () => {
    const log: string[] = [];
    const leaky = fakeWasm(log, { async app_crypto_seal() { throw new Error("UPSTREAM_KMS_ERROR: denied"); } });
    const core = createKiboClientCore(cfg(log, { wasm: leaky }));
    const r = await core.encrypt("c", [{ plaintext: new Uint8Array([1]) }]);
    const s = JSON.stringify(r);
    expect(s).not.toContain("jwt-secret");
    expect(s).not.toContain("cred-1");
  });

  test("a per-call pin that excludes the key refuses every item before any token or exchange", async () => {
    const log: string[] = [];
    const core = createKiboClientCore(cfg(log));
    const other = { expectedKeyRefs: ["arn:aws:kms:eu-central-1:111122223333:key/other"] };
    for (const r of [
      await core.encrypt("c", [{ plaintext: new Uint8Array([1]) }], other),
      await core.decrypt("c", [{ ciphertext: "AQID" }], other),
      await core.rewrap("c", [{ ciphertext: "AQID" }], other),
    ]) {
      expect(r.items).toMatchObject([{ ok: false, code: "K9O_CRYPTO_UNEXPECTED_KEY" }]);
    }
    expect(log).toEqual([]);
    const ok = await core.encrypt("c", [{ plaintext: new Uint8Array([1]) }], { expectedKeyRefs: [KEY] });
    expect(ok.items[0]).toMatchObject({ ok: true });
    expect(log.map((e) => e.split(":")[0])).toEqual(["token", "exchange", "seal"]);
  });
});
