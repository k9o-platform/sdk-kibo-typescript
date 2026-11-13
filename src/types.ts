/**
 * `@k9o/kibo` — Zero-Knowledge BYOK/HYOK vault SDK types.
 *
 * Surface: the ZK-DEK store/fetch and the secrets family. The wrapped
 * envelope is produced client-side by the ZK core (compiled to wasm); this SDK ships it
 * **verbatim and opaque** and never reads its interior.
 */

/** Customer KMS/HSM provider — non-secret routing metadata (mirrors the ZK FFI provider selector). */
export type KmsProvider = "aws-kms" | "gcp-kms" | "azure-kv" | "hashicorp-vault";

/**
 * Input to store an opaque customer-wrapped DEK.
 * `provider` + `keyVersionRef` are explicit non-secret fields the SDK supplies
 * (vault-ops never parses the envelope to derive them).
 */
export type StoreZkDekInput = {
  /** base64 opaque `WrappedDek` envelope (AEAD-sealed under the customer KEK). */
  envelope: string;
  /** Which customer KMS/HSM holds the wrapping KEK. */
  provider: KmsProvider;
  /** Customer key reference (KMS ARN / GCP resource / AKV id / Vault path). */
  keyVersionRef: string;
};

/** Store response — the opaque `zkdek_<base62>` handle + creation timestamp. */
export type ZkDekHandle = {
  /** `zkdek_<base62>` handle. */
  id: string;
  createdAt: string;
};

/** Fetch response — the stored record: opaque envelope + non-secret metadata. */
export type ZkDekRecord = {
  id: string;
  /** base64 opaque `WrappedDek` envelope, returned verbatim for the customer to unwrap. */
  envelope: string;
  provider: KmsProvider;
  keyVersionRef: string;
  createdAt: string;
};

/** Secret visibility. Write operations (create/update) stay owner-only regardless of this tag. */
export type SecretVisibility =
  | { kind: "private" }
  | { kind: "shared"; principals?: string[]; roles?: string[] };

/** Input to create a vault secret: `POST /@<projectSlug>/vault/secrets/<name>`. */
export type CreateSecretInput = {
  /** Hierarchical path the secret is addressed under, e.g. `byos/s3-prod` (also the `:name` URL segment). */
  name: string;
  /** The plaintext to seal, as a regular (non-base64) string; `vault.secrets.create` base64-encodes it for the wire. */
  value: string;
  /** Optional. The gateway sets the residency region of the write itself and discards this; it is sent only when given. */
  region?: string;
  visibility?: SecretVisibility;
  metadata?: Record<string, string>;
};

/** A secret WITHOUT its sealed ciphertext — the create/list/read metadata shape. */
export type SecretSummary = {
  /** `sec_<base62>`. */
  id: string;
  name: string;
  ownerId: string;
  visibility: SecretVisibility;
  version: number;
  /** The wrapping-key id at this version. */
  kid: string;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
  rotatedAt: string | null;
  retiredAt: string | null;
  metadata: Record<string, string>;
};

/** `client.kibo.vault.secrets.list()` input. */
export type ListSecretsInput = {
  /** Filter to a path prefix. */
  prefix?: string;
  cursor?: string;
  limit?: number;
};

export type ListSecretsResult = {
  secrets: readonly SecretSummary[];
  nextCursor: string | null;
};

/** The releasing node's observed attestation tier; present on every reveal. */
export type AttestationTier = {
  /** `attestation:destination:region` trust-tier URN. */
  urn: string;
  /** Node provenance: `platform` (Kibo-operated) or `client` (Private Perimeter). */
  operator: string;
  /** Whether node attestation was verified against the vendor PKI on the URN's attestation segment. */
  verified: boolean;
};

/** `revealChallenge()` result — a single-use challenge to present on the immediately-following `reveal()`. */
export type RevealChallenge = {
  challenge: string;
  expiresAt: string;
};

/** `reveal()` result. `value` is the decoded plaintext (the SDK base64-decodes the wire value, the
 *  inverse of `create`'s encode) — never the raw base64. */
export type RevealSecretResult = {
  id: string;
  name: string;
  version: number;
  value: string;
  revealedAt: string;
  attestationTier: AttestationTier;
};

/** `update()` input. */
export type UpdateSecretInput = {
  /** Optional. The gateway sets the residency region of the write itself and discards this; it is sent only when given. */
  region?: string;
  /** New plaintext — bumps `version`. The SDK base64-encodes it for the wire. */
  value: string;
  metadata?: Record<string, string>;
};

/**
 * `update()` result: the gateway returns only `{id, name, version}`, narrower than the OpenAPI `SecretSummary`.
 * Call `get()` afterward if the full summary is needed.
 */
export type UpdateSecretResult = {
  id: string;
  name: string;
  version: number;
};

/**
 * `rotate()` result: not described by the OpenAPI schema (which declares a summary or a reveal challenge for the
 * route); typed to what the gateway returns. `ledgerSequenceNumber` is undocumented.
 */
export type RotateSecretResult = {
  id: string;
  name: string;
  version: number;
  rotatedAt: string;
  ledgerSequenceNumber: number;
};

/**
 * `move()` result: not the OpenAPI `SecretSummary`; it has no `version` and carries an undocumented `event`
 * field (`"SECRET_PATH_CHANGED"` observed; typed as `string`).
 */
export type MoveSecretResult = {
  id: string;
  name: string;
  event: string;
};
