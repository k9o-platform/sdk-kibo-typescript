/**
 * A build of @k9o/kibo published without its native core (no bundle at publish time) must say so, with a typed error,
 * and must not be a bare module-resolution failure. Skipped where a core IS vendored under wasm/.
 */
import { describe, expect, it } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { decrypt, encrypt } from "../src/crypto.ts";
import { KError } from "@k9o/core/errors";

const HAS_CORE = existsSync(join(import.meta.dir, "..", "wasm", "kibo_kms_rest_ffi.js"));
const maybe = HAS_CORE ? describe.skip : describe;

maybe("no wasm core bundled", () => {
  const input = {
    provider: "aws-kms" as const,
    kms_cred: { secret: "dummy-token", expires_at_unix_secs: 9_999_999_999 },
    key_ref: { version: 1, external_ref: "arn:aws:kms:us-east-1:000000000000:key/abc-123" },
    provider_config: { aws_region: "us-east-1" },
    attestation_tier: "software" as const,
    encryption_context: [],
    plaintext: new Uint8Array([104, 105]),
  };

  it("encrypt rejects with a KError that names the missing core", async () => {
    const err = await encrypt(input as never).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(KError);
    expect((err as KError).code).toBe("KIBO_WASM_ERROR");
    expect((err as KError).message).toContain("not bundled");
  });

  it("decrypt does too, and the failure is not cached", async () => {
    const dec = { ...input, envelope: new Uint8Array([1]), strategy: "direct" } as never;
    for (let i = 0; i < 2; i++) {
      const err = await decrypt(dec).then(() => null, (e: unknown) => e);
      expect((err as KError).code).toBe("KIBO_WASM_ERROR");
    }
  });
});
