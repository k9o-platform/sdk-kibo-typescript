# @k9o/kibo

Official Kibo client for [Kilimanjaro](#105-about-kilimanjaro).
Encrypt and decrypt on the client with keys held in your own KMS, so the platform never sees plaintext. Store and reveal secrets in the Kibo vault.

## Contents

**A. Get started**

1. [Links](#1-links)
2. [Install](#2-install)
3. [Choose the right package](#3-choose-the-right-package)
4. [Quick start](#4-quick-start)

**B. Use Kibo**

5. [Reveal a secret](#5-reveal-a-secret)
6. [Store a wrapped data key](#6-store-a-wrapped-data-key)
7. [Encrypt and decrypt](#7-encrypt-and-decrypt)
8. [Encrypt through `k9o.crypto` on a BYOK or HYOK project](#8-encrypt-through-k9ocrypto-on-a-byok-or-hyok-project)

**C. Troubleshoot**

9. [Handle errors](#9-handle-errors)

**D. Reference**

10. [Appendix](#10-appendix)
    - 10.1 [Client options](#101-client-options)
    - 10.2 [Methods](#102-methods)
    - 10.3 [Encrypt and decrypt fields](#103-encrypt-and-decrypt-fields)
    - 10.4 [Error codes](#104-error-codes)
    - 10.5 [About Kilimanjaro](#105-about-kilimanjaro)
11. [License](#11-license)

## A. Get started

### 1. Links

- Website: <https://kilimanjaro.dev>
- Documentation / Developer Hub: <https://docs.kilimanjaro.dev>
- Open source
  - Platform: <https://github.com/k9o-platform>
  - Community: <https://github.com/k9o-community>

### 2. Install

```bash
npm install @k9o/kibo @k9o/core
```

Bun works too: `bun add @k9o/kibo @k9o/core`.

- Needs a runtime with global `fetch`: Node 18+, Bun 1.1+, or a modern browser.
- Needs `@k9o/core`, which provides the client. The vault is `k9o.kibo.vault`.
- `encrypt` and `decrypt` are standalone exports of `@k9o/kibo`, not methods on the client.
- They use the Kibo core (WebAssembly), which the package ships. See [encrypt and decrypt](#7-encrypt-and-decrypt).

### 3. Choose the right package

| Package | Use it when you are… | Registry | Source |
| --- | --- | --- | --- |
| `@k9o/core` | Building a backend service that uses the platform's data, compute, governance and control features. | [npm](https://www.npmjs.com/package/@k9o/core) | [sdk-typescript](https://github.com/k9o-platform/sdk-typescript) |
| `@k9o/gate` | Implementing sign-up, sign-in, sessions, federation and end-user identity, or verifying a Gate token. | [npm](https://www.npmjs.com/package/@k9o/gate) | [sdk-gate-typescript](https://github.com/k9o-platform/sdk-gate-typescript) |
| `@k9o/kibo` | Keeping secrets in the vault, or encrypting and decrypting with a key you hold. | [npm](https://www.npmjs.com/package/@k9o/kibo) | [sdk-kibo-typescript](https://github.com/k9o-platform/sdk-kibo-typescript) |
| `@k9o/barbican` | Checking model input and redacting model output on your own machine, with no account. | [npm](https://www.npmjs.com/package/@k9o/barbican) | [sdk-barbican-typescript](https://github.com/k9o-platform/sdk-barbican-typescript) |
| `@k9o/cli` | Operating projects from a terminal or CI: migrations, functions, sign-in providers and secrets. | [npm](https://www.npmjs.com/package/@k9o/cli) | [k9o-cli](https://github.com/k9o-platform/k9o-cli) |

`@k9o/core` also exposes Gate as `k9o.gate` and the vault as `k9o.kibo.vault`.

### 4. Quick start

The examples use a `tasks` project that keeps a webhook signing key in the vault. Create the client once, as `k9o`. Run this code on a server. The vault and your KMS credential never belong in browser or mobile code.

```ts
import { createClient } from "@k9o/core";

const k9o = createClient({
  apiKey: process.env.K9O_API_KEY,
  orgSlug: "acme",
  projectSlug: "member-portal",
});
```

For a custom host, pass the full organization host as `baseUrl` and `projectSlug`, and leave out `orgSlug`. See [client options](#101-client-options).

Create a secret. `region` is optional on every secret method. Pass it to pin a region, such as `region: "de01"`.

```ts
const created = await k9o.kibo.vault.secrets.create({
  name: "tasks/webhook-signing-key",
  value: "whsec_example",
});
const secret = created.data;

console.log(`${secret.name} ${secret.version}`);
```

```text
tasks/webhook-signing-key 1
```

A secret name can contain `/`, as in `tasks/webhook-signing-key`; it is a literal part of the name. The SDK sends the name URL-encoded and the gateway reads an encoded `/` back as one `/`. A name with an empty segment (`a//b`) or a `.` or `..` segment is refused with a 400 on every vault route, and so is an encoded `.`.

List secrets under a prefix. Listing returns metadata, never values.

```ts
const listed = await k9o.kibo.vault.secrets.list({ prefix: "tasks/" });
const secrets = listed.data.secrets;

for (const item of secrets) {
  console.log(`${item.name} ${item.version}`);
}
```

```text
tasks/webhook-signing-key 1
```

Read one secret's metadata by its exact name. This does not reveal the value.

```ts
const found = await k9o.kibo.vault.secrets.get("tasks/webhook-signing-key");

console.log(`${found.data.name} ${found.data.version}`);
```

```text
tasks/webhook-signing-key 1
```

Every method resolves to `{ data, meta }`. See [methods](#102-methods) for the full list.

[↑ Back to Contents](#contents)

## B. Use Kibo

### 5. Reveal a secret

Revealing takes two calls: ask for a single-use challenge, then present it.
A plain read of a secret is a reveal, so it is refused without the challenge.

```ts
const challenge = await k9o.kibo.vault.secrets.revealChallenge("tasks/webhook-signing-key", {
  reason: "rotate the webhook endpoint",
});
const revealed = await k9o.kibo.vault.secrets.reveal("tasks/webhook-signing-key", {
  challenge: challenge.data.challenge,
});

console.log(`${revealed.data.value}`);
```

```text
whsec_example
```

### 6. Store a wrapped data key

`zkDeks.store` saves an envelope you produced yourself. The platform keeps it as opaque bytes and never reads it.

```ts
const stored = await k9o.kibo.vault.zkDeks.store({
  envelope: "BASE64_ENVELOPE",
  provider: "aws-kms",
  keyVersionRef: "arn:aws:kms:eu-central-1:111122223333:key/example",
});
const handle = stored.data.id;

const fetched = await k9o.kibo.vault.zkDeks.fetch(handle);
console.log(`${fetched.data.provider}`);
```

```text
aws-kms
```

### 7. Encrypt and decrypt

`encrypt` and `decrypt` run on your machine against your own KMS. They make no call to the platform.
They wrap the Kibo core, a WebAssembly module. This package has no cryptography of its own.

![Client-side encryption: your application seals and opens data on your machine against your own KMS or HSM. Only ciphertext reaches the platform, which never sees plaintext or your key.](https://raw.githubusercontent.com/k9o-platform/docs/main/static/img/readme/client-side-encryption.svg)

Pin your key. Set `expectedKeyRefs` to the identifiers of your own KMS keys, taken from your own cloud configuration and never from the platform, and scope the cloud role to those keys alone. The core then refuses any other key before it uses a token or makes a network call. See [Encrypt through `k9o.crypto`](#8-encrypt-through-k9ocrypto-on-a-byok-or-hyok-project) for the exact rules.

- The package ships the core under `wasm/` and loads it on first use.
- To use your own build, load it and pass it to `setZkWasm(core)`.
- A missing or unloadable core fails with `KIBO_WASM_ERROR`. The message says which. See [handle errors](#9-handle-errors).
- The vault methods above work without the core.

```ts
import { encrypt, decrypt } from "@k9o/kibo";
import type { KiboEncryptInput } from "@k9o/kibo";

const kmsToken = process.env.KMS_FEDERATED_TOKEN ?? "";
const context = [{ key: "collection", value: "tasks" }];
const title = new TextEncoder().encode("Write the README");

const input: KiboEncryptInput = {
  provider: "aws-kms",
  posture: "byok",
  kms_cred: { secret: kmsToken, expires_at_unix_secs: 1_800_000_000 },
  key_ref: { version: 1, external_ref: "arn:aws:kms:eu-central-1:111122223333:key/example" },
  provider_config: { aws_region: "eu-central-1" },
  attestation_tier: "software",
  encryption_context: context,
  plaintext: title,
};

const sealed = await encrypt(input);

const opened = await decrypt({
  kms_cred: { secret: kmsToken, expires_at_unix_secs: 1_800_000_000 },
  provider_config: { aws_region: "eu-central-1" },
  envelope: sealed.envelope,
  strategy: "local_envelope",
  attestation_tier: "software",
  encryption_context: context,
});

console.log(`${new TextDecoder().decode(opened.plaintext)}`);
```

```text
Write the README
```

- Give `decrypt` the same `strategy`, `attestation_tier` and `encryption_context` you used to encrypt.
- Keep the returned `envelope` yourself, or save it with `zkDeks.store`.
- All fields are described in [encrypt and decrypt fields](#103-encrypt-and-decrypt-fields).

### 8. Encrypt through `k9o.crypto` on a BYOK or HYOK project

The platform never sees the plaintext or the key. The key, your cloud and the exchange are all set here, from your own configuration:

```ts
k9o.crypto.useClientCore(
  createKiboClientCore({
    provider: "aws",
    posture: "byok",
    keyRef: { version: 1, externalRef: "arn:aws:kms:eu-central-1:111122223333:key/abc" },
    providerConfig: { aws_region: "eu-central-1" },
    federation: { provider: "aws", role_arn, session_name: "app", region: "eu-central-1", key_arn, duration_secs: 900 },
    expectedKeyRefs: ["arn:aws:kms:eu-central-1:111122223333:key/abc"], // required
    federatedToken: (req) => k9o.crypto.federatedToken(req),
  }),
);
```

- `expectedKeyRefs` is required. Without it the core would open whatever key a stored container names.
- A federated-token response that names another `provider` or `projectId` is refused, never followed.
- In a browser the token exchange has no redirect refusal, so point `vault_addr` at the address itself; the call is abandoned after `exchangeDeadlineMs` (30 s).
- For Vault, the federation is `{ provider: "vault", vault_addr, jwt_auth_mount, role }`. `jwt_auth_mount` is the JWT auth mount: the name Vault serves the JWT login under, `jwt` for `auth/jwt` (not the transit mount, which comes from the key reference).
- A Vault standby node's redirect fails on native builds: point at the active node or a load balancer.

[↑ Back to Contents](#contents)

## C. Troubleshoot

### 9. Handle errors

Every failure is a `KError` from `@k9o/core`. Check `code`. The `input` is the one from the previous section.

```ts
import { KError } from "@k9o/core";
import { encrypt } from "@k9o/kibo";

try {
  await encrypt(input);
} catch (error) {
  if (error instanceof KError && error.code === "KIBO_WASM_ERROR") {
    console.log(`${error.code}`);
  }
}
```

```text
KIBO_WASM_ERROR
```

The `message` says whether the core is missing or is present but failed to load.

See [error codes](#104-error-codes).

[↑ Back to Contents](#contents)

## D. Reference

### 10. Appendix

#### 10.1 Client options

The vault is reached through `createClient` from `@k9o/core`. Pass only what you need.

| Form | Options | Use |
|---|---|---|
| Default | `apiKey`, `orgSlug`, `projectSlug` | Platform at `https://api.k9o.io` |
| Custom host | `apiKey`, `baseUrl`, `projectSlug` | Self-hosted or custom host |

Without a project, vault methods throw `K9O_MISSING_PROJECT_CONTEXT`.

#### 10.2 Methods

All are under `k9o.kibo.vault`.

| Method | What it does |
|---|---|
| `secrets.list({ prefix?, cursor?, limit? })` | List secret metadata |
| `secrets.get(name)` | Find one secret by exact name through the list route; returns its metadata |
| `secrets.create({ name, value, region?, visibility?, metadata? })` | Seal a new secret |
| `secrets.revealChallenge(name, { region?, reason? })` | Mint a single-use reveal challenge |
| `secrets.reveal(name, { challenge, region? })` | Return the plaintext value |
| `secrets.update(name, { value, region?, metadata? })` | Set a new value and bump the version |
| `secrets.rotate(name, { region? })` | Re-wrap the secret under a fresh key |
| `secrets.move(name, { newPath, region? })` | Rename the secret's path |
| `secrets.delete(name, { region? })` | Retire the secret |
| `zkDeks.store({ envelope, provider, keyVersionRef })` | Store a wrapped data key envelope |
| `zkDeks.fetch(id)` | Fetch a stored envelope by its handle |

Exported from `@k9o/kibo` directly:

| Function | What it does |
|---|---|
| `encrypt(input)` | Encrypt bytes with your KMS; returns `{ envelope }` |
| `decrypt(input)` | Decrypt an envelope; returns `{ plaintext }` |
| `setZkWasm(core)` | Supply your own Kibo core instead of the shipped one |
| `createKiboClient(config)` | Build a vault client from a core HTTP config |

`visibility` is `{ kind: "private" }` (default) or `{ kind: "shared", principals?, roles? }`.

#### 10.3 Encrypt and decrypt fields

| Field | Used by | Meaning |
|---|---|---|
| `provider` | encrypt | `aws-kms`, `gcp-kms`, `azure-kv` or `hashicorp-vault` |
| `posture` | encrypt | `byok` or `hyok` |
| `kms_cred` | both | `{ secret, expires_at_unix_secs }`, a short-lived federated token you issue |
| `key_ref` | encrypt | `{ version, external_ref }` identifying your KMS key |
| `provider_config` | both | `{ aws_region?, vault_address? }` |
| `attestation_tier` | both | `software`, `hardware_backed` or `confidential` |
| `encryption_context` | both | List of `{ key, value }` pairs; `kibo:` keys are reserved |
| `strategy` | decrypt (optional on encrypt) | `local_envelope` or `customer_kms_oracle` |
| `oracle_mode` | encrypt, optional | `brokered` or `direct` |
| `posture_policy` | encrypt, optional | Minimum custody posture and allowed oracle modes |
| `plaintext` | encrypt | Bytes to encrypt |
| `envelope` | decrypt | Bytes returned by `encrypt` |

#### 10.4 Error codes

| Code | When |
|---|---|
| `KIBO_WASM_ERROR` | The Kibo core is missing, or is present but failed to load; the message says which |
| `KIBO_WASM_DECODE_ERROR` | The core returned something other than bytes |
| `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION` | `posture` is below the floor in `posture_policy`; `context` has `dimension`, `requested`, `declared` |
| `UPSTREAM_KMS_ERROR` | Your own KMS failed the call |
| `K9O_MISSING_PROJECT_CONTEXT` | A vault method was called without a bound project |

Other codes from the core are passed through unchanged.


#### 10.5 About Kilimanjaro

Kilimanjaro is a modular developer platform for building secure enterprise applications. You define AI agents, functions and data pipelines
on the platform. The SDKs let you deploy and invoke them, read and write your data, publish to and subscribe to streams, sign users in, and
encrypt with keys you hold.

It provides four building blocks:

- **Keep**: AI security and governance. Guardrails and policy for the agents you run.
- **Pulse**: data intelligence and real-time stream processing. Streams, analytics and live feeds.
- **Gate**: customer identity and access management. Sign-in and sessions, and automatic data scoping so a signed-in user reaches only their own data.
- **Kibo**: cryptographic keys and secrets management. Client-side encryption with keys you hold, and a secrets vault.

### 11. License

Apache-2.0 © Formelo Inc. See `LICENSE` and `NOTICE`.

[↑ Back to Contents](#contents)
