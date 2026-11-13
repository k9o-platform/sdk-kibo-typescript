/**
 * ZK encrypt/decrypt — the thin TS wrapper over the bound crypto core
 * (`kibo-kms-rest-ffi`) compiled to wasm. ZERO crypto here: every
 * wrap/unwrap, envelope framing, posture-floor enforcement, and KMS round-trip
 * lives in the audited Rust core. This layer only marshals the typed input
 * across the wasm boundary and maps the core's error string → `KError`.
 *
 * The core exposes `zk_encrypt`/`zk_decrypt` (async) taking/returning plain JS
 * objects via serde-wasm-bindgen, and rejecting with the `ZkFfiError` display
 * string (`"<K9O_CODE>: <message>"`, optionally with a posture-violation tail).
 *
 * These are standalone exports (`import { encrypt, decrypt } from "@k9o/kibo"`), not methods of the client: they run
 * locally against the customer's own KMS and make no platform call. The `vault.zkDeks.{store,fetch}` surface
 * (envelope persistence) is separate and decoupled (the core never sees the store).
 */

import { KError } from "@k9o/core/errors";
import { loadZkGlue, nodeDeps } from "./wasm-loader.ts";
import type {
  KiboEncryptInput,
  KiboEncryptOutput,
  KiboDecryptInput,
  KiboDecryptOutput,
} from "./crypto-types.ts";

/** The minimal surface the bound ZK-core wasm exposes. */
export interface ZkWasm {
  zk_encrypt(input: unknown): Promise<unknown>;
  zk_decrypt(input: unknown): Promise<unknown>;
}

let cachedWasm: ZkWasm | undefined;

/**
 * Inject a pre-loaded core wasm module. Hosts that bundle the wasm themselves
 * (browser/RN, or a test) call this; otherwise `encrypt`/`decrypt` lazy-load
 * the vendored per-provider artifact.
 */
export function setZkWasm(mod: ZkWasm): void {
  cachedWasm = mod;
}

/**
 * Lazily load the bound core wasm. ONE all-provider artifact is generated from `kibo-kms-rest-ffi` (the core compiles
 * every KMS provider in; the `provider` input field selects at call time) and vendored under `wasm/` by the publish
 * pipeline. See `wasm-loader.ts` for how the CommonJS glue is loaded from this ESM package and for the failure modes.
 */
async function loadWasm(): Promise<ZkWasm> {
  if (cachedWasm) return cachedWasm;
  // A failure is not cached: the next call tries again.
  cachedWasm = await loadZkGlue(nodeDeps(import.meta.url));
  return cachedWasm;
}

/** The loaded core, for the client core (`client-core.ts`), which needs the exports beyond `zk_encrypt`/`zk_decrypt`. */
export async function loadBundledWasm(): Promise<ZkWasm> {
  return loadWasm();
}

/**
 * Encrypt `input.plaintext` via the customer KMS, client-side. Returns the
 * opaque ZKFE envelope — store it via `vault.zkDeks.store`  or keep it
 * yourself; it is meaningless to the platform.
 */
export async function encrypt(input: KiboEncryptInput): Promise<KiboEncryptOutput> {
  const wasm = await loadWasm();
  let out: unknown;
  try {
    out = await wasm.zk_encrypt(input);
  } catch (e) {
    throw mapZkError(e);
  }
  return { envelope: toBytes((out as { envelope?: unknown }).envelope) };
}

/**
 * Decrypt a ZKFE `input.envelope`. `strategy`, `attestation_tier`, and
 * `encryption_context` MUST match the values used at encrypt — they are AAD-bound
 * and never recovered from the envelope (anti-substitution discipline).
 */
export async function decrypt(input: KiboDecryptInput): Promise<KiboDecryptOutput> {
  const wasm = await loadWasm();
  let out: unknown;
  try {
    out = await wasm.zk_decrypt(input);
  } catch (e) {
    throw mapZkError(e);
  }
  return { plaintext: toBytes((out as { plaintext?: unknown }).plaintext) };
}

/** Normalise wasm byte output (serde-wasm-bindgen emits `Vec<u8>` as a number
 *  array; some hosts return a `Uint8Array`) to `Uint8Array`. */
function toBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return Uint8Array.from(v as number[]);
  throw new KError({
    code: "KIBO_WASM_DECODE_ERROR",
    message: "ZK core returned a non-byte value where bytes were expected",
    context: {},
  });
}

/**
 * Map the core's rejected error → `KError`. The wasm path flattens `ZkFfiError`
 * to its display string: `"<CODE>: <message>"` where `<CODE>` is a `K9O_*` wire
 * code (or `UPSTREAM_KMS_ERROR` for the customer's own KMS failures), optionally
 * followed by `"(dimension: …, requested: …, declared: …)"` for a posture-floor
 * violation. Codes are passed through (never hardcoded), per the KError discipline.
 */
function mapZkError(e: unknown): KError {
  if (e instanceof KError) return e;
  const raw = e instanceof Error ? e.message : String(e);
  const head = /^([A-Z][A-Z0-9_]*):\s*([\s\S]*)$/.exec(raw);
  const code = head?.[1] ?? "KIBO_WASM_ERROR";
  let message = head?.[2] ?? raw;

  let context: Record<string, unknown> = {};
  const pv = /\(dimension:\s*([^,]+),\s*requested:\s*([^,]+),\s*declared:\s*([^)]+)\)\s*$/.exec(message);
  if (pv) {
    context = { dimension: pv[1]!.trim(), requested: pv[2]!.trim(), declared: pv[3]!.trim() };
    message = message.slice(0, pv.index).trim();
  }
  return new KError({ code, message, context });
}
