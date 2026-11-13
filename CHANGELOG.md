# Changelog

## 1.5.0 (unreleased)

### Added

- `createKiboClientCore` matches the configured key against the call's `expectedKeyRefs` before it fetches a federated token or exchanges a credential; a key outside the call's pin gets `K9O_CRYPTO_UNEXPECTED_KEY` on every item, with no token fetch and no seal or open.
- `createKiboClientCore(config)`: the client core for `client.crypto` on a BYOK or HYOK project. Register it with `client.crypto.useClientCore(...)`. It fetches the federated token, exchanges it with your cloud (`acquire_kms_credential`, with a deadline, 30 s by default), then seals or opens with your own KMS. Needs `zk-bundle-v2.15.0` or later.
- A key pin is required: it refuses to be built without a non-empty `expectedKeyRefs`, refuses a core that does not list `expected_key_refs`, and never takes the key, provider or project from the platform's answer. A response naming another provider or project is refused.

### Changed

- README description.
- The Vault federation field is `jwt_auth_mount` (the JWT auth mount, `jwt` for `auth/jwt`), not `mount`.

## 1.3.0 — 2026-10-26

### Changed

- `vault.secrets.get(name)` looks the secret up by exact name through the list route and returns its metadata.
- `region` is optional on every named-secret method.
- `vault.secrets.revealChallenge` takes an optional `reason`.
- `KIBO_WASM_ERROR` now says whether the core is missing or present but failed to load.
- README: `encrypt` and `decrypt` are standalone exports, not methods on the client. The vault is `client.kibo.vault`.

### Removed

- Nothing.

### Added

- Nothing. `setZkWasm(core)` remains the way to supply your own core.

## 1.0.0

First public release.
