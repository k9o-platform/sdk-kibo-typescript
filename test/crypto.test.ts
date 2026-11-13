/**
 * Wiring tests for the ZK encrypt/decrypt surface against the REAL bound core
 * wasm (`kibo-kms-rest-ffi`, vendored under wasm/). These exercise the wasm
 * boundary + input marshaling + error mapping WITHOUT a live customer KMS, by
 * using the posture-floor path (rejected pre-KMS). The full crypto round-trip
 * needs real KMS creds + is exercised by the staging conformance ZK step.
 */

import { describe, expect, it } from "bun:test";
import { encrypt, setZkWasm, type ZkWasm } from "../src/crypto.ts";
import { KError } from "@k9o/core/errors";
// The bound core, compiled to wasm (nodejs target). Generated/gitignored.
import * as core from "../wasm/kibo_kms_rest_ffi.js";

setZkWasm(core as unknown as ZkWasm);

const BASE = {
  provider: "aws-kms" as const,
  kms_cred: { secret: "dummy-token", expires_at_unix_secs: 9_999_999_999 },
  key_ref: { version: 1, external_ref: "arn:aws:kms:us-east-1:000000000000:key/abc-123" },
  provider_config: { aws_region: "us-east-1" },
  attestation_tier: "software" as const,
  encryption_context: [],
  plaintext: new Uint8Array([104, 105]),
};

describe("kibo crypto — bound core wasm", () => {
  it("the core wasm loads + exports zk_encrypt / zk_decrypt", () => {
    expect(typeof (core as { zk_encrypt?: unknown }).zk_encrypt).toBe("function");
    expect(typeof (core as { zk_decrypt?: unknown }).zk_decrypt).toBe("function");
  });

  it("posture-floor violation → K9O_CRYPTO_POSTURE_FLOOR_VIOLATION (rejected pre-KMS, dimension-tagged)", async () => {
    let caught: unknown;
    try {
      // byok requested, but the project floor requires hyok → byok < hyok.
      await encrypt({ ...BASE, posture: "byok", posture_policy: { min_custody_posture: "hyok" } });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(KError);
    const k = caught as KError;
    expect(k.code).toBe("K9O_CRYPTO_POSTURE_FLOOR_VIOLATION");
    expect((k.context as { dimension?: string }).dimension).toBe("custody_posture");
  });
});
