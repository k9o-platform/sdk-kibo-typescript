/**
 * `@k9o/kibo` - Zero-Knowledge BYOK/HYOK vault SDK.
 *
 * Two surfaces:
 *   - the vault client (`createKiboClient`; composed into `@k9o/core` as `client.kibo`): `vault.secrets.*` and
 *     `vault.zkDeks.{store,fetch}`, plain REST calls to the platform.
 *   - standalone `encrypt` / `decrypt`: local envelope encryption against the customer's own KMS, in WASM, with no
 *     platform call. They are not methods of the client. `setZkWasm` supplies the WASM core yourself.
 *
 * No cryptography lives in this package: wrapping, envelope framing and posture-floor enforcement are in the compiled core.
 */

export { createKiboClient, type KiboClient } from "./client-factory.ts";
export type {
  KmsProvider, StoreZkDekInput, ZkDekHandle, ZkDekRecord,
  SecretVisibility, CreateSecretInput, SecretSummary,
  ListSecretsInput, ListSecretsResult, AttestationTier, RevealChallenge, RevealSecretResult,
  UpdateSecretInput, UpdateSecretResult, RotateSecretResult, MoveSecretResult,
} from "./types.ts";

// Standalone zero-knowledge encrypt/decrypt (bound-core wasm).
export { encrypt, decrypt, setZkWasm, type ZkWasm } from "./crypto.ts";
export type {
  KiboPosture, KiboStrategy, KiboOracleMode, KiboAttestationTier, KiboMinPosture,
  KiboAllowedOracleModes, KiboPosturePolicy, KiboCredential, KiboKeyRef,
  KiboProviderConfig, KiboKvPair, KiboEncryptInput, KiboEncryptOutput,
  KiboDecryptInput, KiboDecryptOutput,
} from "./crypto-types.ts";

// The client core for `client.crypto` on a BYOK or HYOK project (`client.crypto.useClientCore(createKiboClientCore({...}))`).
export {
  createKiboClientCore, KIBO_ERR_EXCHANGE_TIMEOUT,
  type KiboClientCoreConfig, type KiboFederationSpec, type KiboAppWasm,
} from "./client-core.ts";
