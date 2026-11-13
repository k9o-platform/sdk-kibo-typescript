/**
 * The client core for `client.crypto` on a BYOK or HYOK project: opens and seals data on this machine, against your own KMS or
 * HSM, so the platform never sees plaintext or the key. ZERO crypto here: sealing, opening, the key pin and the token exchange
 * all run in the audited Rust core (`kibo-kms-rest-ffi`, wasm). This file only sequences them:
 *
 *   federated token (platform) -> `acquire_kms_credential` (your cloud) -> `app_crypto_seal` / `app_crypto_open` (your KMS)
 *
 * Everything that picks a key, a provider, a role, a region or an endpoint comes from the configuration you pass here. Nothing
 * comes from the platform's answer: the token response's `provider` and `projectId` are checked against your configuration,
 * and a mismatch is refused, never followed.
 */

import {
  CRYPTO_ERR_KEY_PIN_UNENFORCED,
  checkExpectedKeyRefs,
  keyRefMatches,
  type CiphertextItem,
  type ClientCoreEncryptItem,
  type ClientCoreOptions,
  type ClientCryptoCore,
  type CryptoItemFailure,
  type DecryptResult,
  type EncryptResult,
  type FederatedToken,
  type FederatedTokenRequest,
  type KeyRefProvider,
  type RewrapResult,
} from "@k9o/core";
import { KError } from "@k9o/core/errors";

/** Where your key lives and how to reach it. All of it is yours: the platform never supplies any of these. */
export type KiboFederationSpec =
  | { provider: "aws"; role_arn: string; session_name: string; region: string; key_arn: string; duration_secs: number }
  | { provider: "gcp"; audience: string }
  | { provider: "azure"; tenant_id: string; client_id: string; scope: string }
  | {
      provider: "vault";
      vault_addr: string;
      /** The JWT auth mount: the name Vault serves the JWT login under, `jwt` for `auth/jwt` (not the transit mount, which comes from the key reference). */
      jwt_auth_mount: string;
      role: string;
    };

/** The core's own name for the Vault JWT auth mount is `mount`; this is the one place the spec is handed to it. */
function coreSpec(spec: KiboFederationSpec): unknown {
  if (spec.provider !== "vault") return spec;
  const { jwt_auth_mount, ...rest } = spec;
  return { ...rest, mount: jwt_auth_mount };
}

export type KiboClientCoreConfig = {
  /** Your cloud. Must equal `federation.provider`. */
  provider: KeyRefProvider;
  posture: "byok" | "hyok";
  /** The project id (`proj_...`). Bound into what is sealed. Leave out only if you want the token response's value; a value given here is never overridden. */
  projectId?: string | undefined;
  /** The exact key this application uses. */
  keyRef: { version: number; externalRef: string };
  /** Region for AWS, address for Vault. */
  providerConfig?: { aws_region?: string; vault_address?: string };
  /** How to exchange the platform's identity token for a credential on your cloud. */
  federation: KiboFederationSpec;
  /**
   * The keys this application allows. Required and non-empty: a core with no pin opens whatever key a stored container names, so
   * this client never calls without one.
   */
  expectedKeyRefs: ReadonlyArray<string>;
  /** `(req) => client.crypto.federatedToken(req)`. */
  federatedToken: (req: FederatedTokenRequest) => Promise<{ data: FederatedToken }>;
  /** The loaded core. Defaults to the bundled one. */
  wasm?: KiboAppWasm;
  /** How long the exchange may take before it is abandoned, in milliseconds. Default 30000. The browser build has no deadline of its own. */
  exchangeDeadlineMs?: number;
  /** The host clock, Unix seconds. Default `Date.now() / 1000`. */
  now?: () => number;
};

/** What the bound core exports beyond `zk_encrypt` and `zk_decrypt`. */
export interface KiboAppWasm {
  app_crypto_seal(input: unknown): Promise<unknown>;
  app_crypto_open(input: unknown): Promise<unknown>;
  acquire_kms_credential(input: unknown): Promise<unknown>;
  core_capabilities(): string[];
}

/** Raised by this client when the exchange runs past its deadline. */
export const KIBO_ERR_EXCHANGE_TIMEOUT = "KIBO_EXCHANGE_TIMEOUT";

const PROVIDER_WIRE: Record<KeyRefProvider, string> = {
  aws: "aws-kms",
  gcp: "gcp-kms",
  azure: "azure-kv",
  vault: "hashicorp-vault",
};

/** Refresh a credential this long before it expires. */
const SKEW_SECS = 60;

type Cred = { secret: string; expires_at_unix_secs: number };
type Op = FederatedTokenRequest["op"];

function bad(message: string, context: Record<string, unknown> = {}): KError {
  return new KError({ code: "K9O_INVALID_FIELD_VALUE", message, context, recommendation: null });
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return Uint8Array.from(v as number[]);
  throw new KError({ code: "KIBO_WASM_DECODE_ERROR", message: "the core returned a non-byte value where bytes were expected", context: {} });
}

/** The core rejects with `"<CODE>: <message>"`; `UPSTREAM_KMS_ERROR` is your own KMS failing. */
function mapCoreError(e: unknown): KError {
  if (e instanceof KError) return e;
  const raw = e instanceof Error ? e.message : String(e);
  const head = /^([A-Z][A-Z0-9_]*):\s*([\s\S]*)$/.exec(raw);
  return new KError({ code: head?.[1] ?? "KIBO_WASM_ERROR", message: head?.[2] ?? raw, context: {} });
}

function failure(e: unknown): CryptoItemFailure {
  const k = mapCoreError(e);
  return { ok: false, code: k.code, message: k.message };
}

async function withDeadline<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new KError({
            code: KIBO_ERR_EXCHANGE_TIMEOUT,
            message: `the token exchange with your cloud did not finish within ${ms} ms`,
            context: { deadlineMs: ms },
            recommendation: "Check that your cloud's token endpoint is reachable from this host.",
          }),
        ),
      ms,
    );
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Build the client core. Register it with `client.crypto.useClientCore(core)`. */
export function createKiboClientCore(config: KiboClientCoreConfig): ClientCryptoCore {
  if (config.provider !== config.federation.provider) {
    throw bad("provider and federation.provider must be the same cloud", { field: "provider" });
  }
  if (!(config.provider in PROVIDER_WIRE)) throw bad('provider must be "aws", "gcp", "azure" or "vault"', { field: "provider" });
  if (config.posture !== "byok" && config.posture !== "hyok") throw bad('posture must be "byok" or "hyok"', { field: "posture" });
  const pin = checkExpectedKeyRefs(config.expectedKeyRefs);
  if (pin === undefined) throw bad("expectedKeyRefs is required: this client never seals or opens without a key pin", { field: "expectedKeyRefs" });
  if (!keyRefMatches(config.keyRef.externalRef, pin, config.provider)) {
    throw bad("keyRef is not in expectedKeyRefs", { field: "keyRef" });
  }
  const deadlineMs = config.exchangeDeadlineMs ?? 30_000;
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  const creds = new Map<string, Cred>();
  let capsChecked = false;

  const effectivePin = (options?: ClientCoreOptions): ReadonlyArray<string> => {
    const p = options?.expectedKeyRefs ?? pin;
    if (p.length === 0) throw bad("expectedKeyRefs is empty: refusing to call without a key pin", { field: "expectedKeyRefs" });
    return p;
  };

  /** Per-item refusals when the configured key is not in this call's pin; checked before any token or exchange. */
  const refuseIfKeyNotPinned = (pinList: ReadonlyArray<string>, n: number): CryptoItemFailure[] | undefined => {
    if (keyRefMatches(config.keyRef.externalRef, pinList, config.provider)) return undefined;
    return Array.from({ length: n }, () => ({
      ok: false as const,
      code: "K9O_CRYPTO_UNEXPECTED_KEY",
      message: "the configured key is not in this call's expectedKeyRefs; nothing was sent",
    }));
  };

  const wasm = async (): Promise<KiboAppWasm> => {
    const w = config.wasm ?? ((await loadBundled()) as KiboAppWasm);
    for (const fn of ["app_crypto_seal", "app_crypto_open", "acquire_kms_credential", "core_capabilities"] as const) {
      if (typeof w[fn] !== "function") {
        throw new KError({
          code: "KIBO_WASM_ERROR",
          message: `the Kibo core does not export ${fn}; it is older than zk-bundle-v2.16.3`,
          context: { missing: fn },
          recommendation: "Use a build of @k9o/kibo that ships zk-bundle-v2.16.3 or later.",
        });
      }
    }
    if (!capsChecked) {
      if (!w.core_capabilities().includes("expected_key_refs")) {
        throw new KError({
          code: CRYPTO_ERR_KEY_PIN_UNENFORCED,
          message: "the Kibo core does not declare that it enforces expected_key_refs; nothing was sent",
          context: {},
          recommendation: "Use a build of @k9o/kibo that ships zk-bundle-v2.16.3 or later.",
        });
      }
      capsChecked = true;
    }
    return w;
  };

  const credential = async (w: KiboAppWasm, crypt: string, op: Op): Promise<{ cred: Cred; projectId: string }> => {
    const t = (await config.federatedToken({ crypt, op })).data;
    const named_provider = (t as { provider?: unknown }).provider;
    if (named_provider !== undefined && named_provider !== config.provider) {
      throw bad(`the platform named provider "${String(named_provider)}"; this client is configured for "${config.provider}"`, { field: "provider" });
    }
    const named = (t as { projectId?: unknown }).projectId;
    if (named !== undefined && config.projectId !== undefined && named !== config.projectId) {
      throw bad("the platform named a different project than the one configured", { field: "projectId" });
    }
    const projectId = config.projectId ?? (typeof named === "string" ? named : undefined);
    if (projectId === undefined) throw bad("projectId is not configured and the platform did not name one", { field: "projectId" });

    const cacheKey = `${crypt}\u0000${op}\u0000${t.subject}`;
    const cached = creds.get(cacheKey);
    // A token is fetched on every call (it is bound to the call's crypt and op); the credential from the exchange is reused until it is close to expiring.
    if (cached !== undefined && cached.expires_at_unix_secs - SKEW_SECS > now()) return { cred: cached, projectId };
    let out: unknown;
    try {
      out = await withDeadline(
        w.acquire_kms_credential({ spec: coreSpec(config.federation), identity_token: t.token, now_unix_secs: now() }),
        deadlineMs,
      );
    } catch (e) {
      throw mapCoreError(e);
    }
    const c = out as Partial<Cred>;
    if (typeof c?.secret !== "string" || typeof c.expires_at_unix_secs !== "number") {
      throw new KError({ code: "KIBO_WASM_DECODE_ERROR", message: "the core returned a credential without secret or expiry", context: {} });
    }
    const cred = { secret: c.secret, expires_at_unix_secs: c.expires_at_unix_secs };
    creds.set(cacheKey, cred);
    return { cred, projectId };
  };

  const common = (cred: Cred, projectId: string, crypt: string, context: string | undefined, pinList: ReadonlyArray<string>, options?: ClientCoreOptions) => ({
    kms_cred: cred,
    provider_config: {
      aws_region: config.providerConfig?.aws_region ?? null,
      vault_address: config.providerConfig?.vault_address ?? null,
    },
    project_id: projectId,
    crypt,
    context: context ?? null,
    expected_key_refs: [...pinList],
  });

  const seal = async (w: KiboAppWasm, cred: Cred, projectId: string, crypt: string, plaintext: Uint8Array, context: string | undefined, pinList: ReadonlyArray<string>, options?: ClientCoreOptions): Promise<string> => {
    const out = await w.app_crypto_seal({
      provider: PROVIDER_WIRE[config.provider],
      posture: config.posture,
      key_ref: { version: config.keyRef.version, external_ref: config.keyRef.externalRef },
      plaintext: Array.from(plaintext),
      ...common(cred, projectId, crypt, context, pinList, options),
    });
    return toBase64(toBytes((out as { container?: unknown }).container));
  };

  const open = async (w: KiboAppWasm, cred: Cred, projectId: string, crypt: string, ciphertext: string, context: string | undefined, pinList: ReadonlyArray<string>, options?: ClientCoreOptions): Promise<Uint8Array> => {
    const out = await w.app_crypto_open({
      container: Array.from(fromBase64(ciphertext)),
      ...common(cred, projectId, crypt, context, pinList, options),
    });
    return toBytes((out as { plaintext?: unknown }).plaintext);
  };

  const text = (b: Uint8Array): string | undefined => {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(b);
    } catch {
      return undefined;
    }
  };

  return {
    enforcesExpectedKeyRefs: true,

    async encrypt(crypt: string, items: ReadonlyArray<ClientCoreEncryptItem>, options?: ClientCoreOptions): Promise<EncryptResult> {
      const pinList = effectivePin(options);
      const refused = refuseIfKeyNotPinned(pinList, items.length);
      if (refused) return { items: refused };
      const w = await wasm();
      const { cred, projectId } = await credential(w, crypt, "encrypt");
      const out: EncryptResult["items"] = [];
      for (const it of items) {
        try {
          out.push({ ok: true, ciphertext: await seal(w, cred, projectId, crypt, it.plaintext, it.context, pinList, options) });
        } catch (e) {
          out.push(failure(e));
        }
      }
      return { items: out };
    },

    async decrypt(crypt: string, items: ReadonlyArray<CiphertextItem>, options?: ClientCoreOptions): Promise<DecryptResult> {
      const pinList = effectivePin(options);
      const refused = refuseIfKeyNotPinned(pinList, items.length);
      if (refused) return { items: refused };
      const w = await wasm();
      const { cred, projectId } = await credential(w, crypt, "decrypt");
      const out: DecryptResult["items"] = [];
      for (const it of items) {
        try {
          const plaintext = await open(w, cred, projectId, crypt, it.ciphertext, it.context, pinList, options);
          const t = text(plaintext);
          out.push({ ok: true, plaintext, ...(t === undefined ? {} : { text: t }) });
        } catch (e) {
          out.push(failure(e));
        }
      }
      return { items: out };
    },

    async rewrap(crypt: string, items: ReadonlyArray<CiphertextItem>, options?: ClientCoreOptions): Promise<RewrapResult> {
      const pinList = effectivePin(options);
      const refused = refuseIfKeyNotPinned(pinList, items.length);
      if (refused) return { items: refused };
      const w = await wasm();
      const { cred, projectId } = await credential(w, crypt, "rewrap");
      const out: RewrapResult["items"] = [];
      for (const it of items) {
        try {
          const plaintext = await open(w, cred, projectId, crypt, it.ciphertext, it.context, pinList, options);
          out.push({ ok: true, ciphertext: await seal(w, cred, projectId, crypt, plaintext, it.context, pinList, options) });
        } catch (e) {
          out.push(failure(e));
        }
      }
      return { items: out };
    },
  };
}

async function loadBundled(): Promise<unknown> {
  const { loadBundledWasm } = await import("./crypto.ts");
  return loadBundledWasm();
}
