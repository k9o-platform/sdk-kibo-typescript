/**
 * TS contract for the ZK encrypt/decrypt FFI surface — mirrors the Rust
 * `kibo-kms-rest-ffi::types` (the bound core) field-for-field.
 *
 * These types cross the wasm boundary as plain JS objects (serde-wasm-bindgen),
 * so the field names + enum wire-tokens must match the Rust serde exactly:
 *   - `KmsProvider`        kebab-case   (`aws-kms`, `gcp-kms`, `azure-kv`, `hashicorp-vault`)
 *   - all other enums      snake_case   (`byok`, `local_envelope`, `hardware_backed`, …)
 *   - bytes (`Vec<u8>`)    `Uint8Array` at the boundary
 *
 * Strict-ZK invariant: the `secret` in `KiboCredential` is a customer-issued
 * short-lived federated token — never a platform KEK; it is zeroized in the core
 * after use and never logged or returned. The platform never sees plaintext.
 */

// The customer KMS provider — the same routing selector as the ZK-DEK store
// surface. Reuse the canonical definition (no duplication).
import type { KmsProvider } from "./types.ts";
export type { KmsProvider };

/** Custody posture for an encrypt call. `platform-managed` is structurally absent
 *  here — `kibo-kms-rest` is the KEK-free customer-KMS layer (ZK is never PM). */
export type KiboPosture = "byok" | "hyok";

/** Explicit strategy pin. Omit → `local_envelope` (the posture default). */
export type KiboStrategy = "local_envelope" | "customer_kms_oracle";

/** Oracle routing mode. Omit → `brokered` (default). */
export type KiboOracleMode = "brokered" | "direct";

/** Device attestation tier bound into the AAD for every operation. */
export type KiboAttestationTier = "software" | "hardware_backed" | "confidential";

/** The min-custody-posture floor ladder (3-mode; `platform_managed` = no floor).
 *  Ordering: `PLATFORM_MANAGED < BYOK < HYOK`. */
export type KiboMinPosture = "platform_managed" | "byok" | "hyok";

/** Acceptable oracle-mode set (the `allowed_oracle_modes` policy dial). */
export interface KiboAllowedOracleModes {
  brokered: boolean;
  direct: boolean;
}

/** Project-declared crypto-posture floor . Omit fields for the
 *  most-permissive default (`platform_managed` floor + both oracle modes). */
export interface KiboPosturePolicy {
  min_custody_posture?: KiboMinPosture;
  allowed_oracle_modes?: KiboAllowedOracleModes;
}

/** Short-lived customer KMS credential — the edge device's federated token.
 *  `secret` is treated as secret material (zeroized in-core; never returned). */
export interface KiboCredential {
  secret: string;
  expires_at_unix_secs: number;
}

/** Key version reference identifying the customer KMS key. `external_ref` is
 *  provider-specific (AWS key ARN / GCP resource name / Azure key URL / Vault
 *  `<mount>/<key>:<ver>`). `version` is the monotone KEK-rotation counter. */
export interface KiboKeyRef {
  version: number;
  external_ref: string;
}

/** Provider-specific init params. Only the compiled-in provider's field is read. */
export interface KiboProviderConfig {
  aws_region?: string;
  vault_address?: string;
}

/** A single encryption-context key/value pair. Bound into the AAD at encrypt and
 *  re-supplied byte-for-byte at decrypt. (Record shape — uniffi can't cross
 *  tuples; the wasm JSON is `[{"key":"…","value":"…"}]`.) `kibo:` is reserved. */
export interface KiboKvPair {
  key: string;
  value: string;
}

/** All inputs to `encrypt` — mirrors Rust `EncryptInput`. */
export interface KiboEncryptInput {
  provider: KmsProvider;
  posture: KiboPosture;
  strategy?: KiboStrategy;
  oracle_mode?: KiboOracleMode;
  kms_cred: KiboCredential;
  key_ref: KiboKeyRef;
  provider_config: KiboProviderConfig;
  attestation_tier: KiboAttestationTier;
  encryption_context: KiboKvPair[];
  /** Plaintext bytes to encrypt. */
  plaintext: Uint8Array;
  posture_policy?: KiboPosturePolicy;
}

/** All inputs to `decrypt` — mirrors Rust `DecryptInput`. `strategy`,
 *  `attestation_tier`, and `encryption_context` MUST be re-supplied (never read
 *  from the envelope — anti-envelope-substitution discipline). */
export interface KiboDecryptInput {
  kms_cred: KiboCredential;
  provider_config: KiboProviderConfig;
  /** The canonical (`b"KIBO"`) envelope from a prior `encrypt`. */
  envelope: Uint8Array;
  strategy: KiboStrategy;
  attestation_tier: KiboAttestationTier;
  encryption_context: KiboKvPair[];
}

/** Output of `encrypt` — the opaque ZKFE envelope (pass straight to `decrypt`). */
export interface KiboEncryptOutput {
  envelope: Uint8Array;
}

/** Output of `decrypt` — the recovered plaintext. */
export interface KiboDecryptOutput {
  plaintext: Uint8Array;
}
