/**
 * `client.kibo.vault.*` - the Kibo vault surface.
 *
 * `vault.zkDeks.{store,fetch}` store and fetch the opaque customer-wrapped DEK envelope, project-scoped. There is
 * no cryptography in this client: it is a plain authenticated REST round-trip carrying an opaque blob (the
 * wrapping happens in the standalone `encrypt`/`decrypt`, which never call the platform).
 * `vault.secrets.*` is the typed secrets family.
 */

import { request, type HttpClientConfig } from "@k9o/core/http";
import { projectPath } from "@k9o/core/url-grammar";
import { KError } from "@k9o/core/errors";
import type { Envelope } from "@k9o/core/envelope";
import type {
  StoreZkDekInput, ZkDekHandle, ZkDekRecord,
  CreateSecretInput, SecretSummary, ListSecretsInput, ListSecretsResult,
  RevealChallenge, RevealSecretResult, UpdateSecretInput, UpdateSecretResult,
  RotateSecretResult, MoveSecretResult,
} from "./types.ts";

/** UTF-8-safe base64 encode, usable across browser/Node/Bun (unlike `Buffer`). The wire `value` field is base64. */
function encodeBase64Utf8(plaintext: string): string {
  return btoa(unescape(encodeURIComponent(plaintext)));
}

/** Inverse of {@link encodeBase64Utf8} — decodes a revealed wire `value` back to plaintext. */
function decodeBase64Utf8(b64: string): string {
  return decodeURIComponent(escape(atob(b64)));
}

/** Both `vault.zkDeks` and `vault.secrets` require a project context (member-plane). */
function requireProjectSlug(config: HttpClientConfig): string {
  if (config.projectSlug === undefined || config.projectSlug.length === 0) {
    throw new KError({
      code: "K9O_MISSING_PROJECT_CONTEXT",
      message: "client.kibo.vault requires a bound projectSlug (member-plane resource)",
      context: {},
      recommendation: "Pass projectSlug when constructing the client.",
    });
  }
  return config.projectSlug;
}

/** Bound on the pages `secrets.get` scans for an exact name. */
const MAX_GET_PAGES = 20;

/** @internal */
export function makeVaultNamespace(config: HttpClientConfig) {
  const listSecrets = async (input?: ListSecretsInput): Promise<Envelope<ListSecretsResult>> =>
    request<ListSecretsResult>(config, {
      method: "GET",
      path: projectPath(requireProjectSlug(config), "vault/secrets"),
      query: { prefix: input?.prefix, cursor: input?.cursor, limit: input?.limit },
    });

  return {
    /** Opaque store/fetch of a customer-wrapped DEK envelope. */
    zkDeks: {
      /**
       * Store an opaque customer-wrapped DEK envelope.
       * `POST /@<projectSlug>/vault/zk-deks` → the `zkdek_<base62>` handle.
       * The SDK ships the envelope verbatim; it is never parsed here.
       */
      async store(input: StoreZkDekInput): Promise<Envelope<ZkDekHandle>> {
        return request<ZkDekHandle>(config, {
          method: "POST",
          path: projectPath(requireProjectSlug(config), "vault/zk-deks"),
          body: input,
        });
      },

      /**
       * Fetch a stored `WrappedDek` by its handle.
       * `GET /@<projectSlug>/vault/zk-deks/<id>` → the opaque envelope + the
       * non-secret `provider`/`keyVersionRef` the caller needs to unwrap it.
       */
      async fetch(id: string): Promise<Envelope<ZkDekRecord>> {
        return request<ZkDekRecord>(config, {
          method: "GET",
          path: projectPath(requireProjectSlug(config), `vault/zk-deks/${encodeURIComponent(id)}`),
        });
      },
    },

    /**
     * Typed secrets surface (`/@<projectSlug>/vault/secrets`): list / get / create / revealChallenge / reveal /
     * update / rotate / move / delete.
     *
     * `region`: the gateway sets the residency region of every vault call itself and discards a caller-supplied
     * `region` query parameter, so it is optional on every method. When given, it is still sent (older gateways
     * required it).
     *
     * Response shapes for `update`/`rotate`/`move` are typed to what the gateway returns, not the OpenAPI's
     * `SecretSummary` (see `UpdateSecretResult`/`RotateSecretResult`/`MoveSecretResult` in `types.ts`).
     */
    secrets: {
      /** List secrets (metadata only, never ciphertext). `GET /@<projectSlug>/vault/secrets`. */
      list: listSecrets,

      /**
       * Read one secret's metadata (never its value; use `revealChallenge` + `reveal` for that).
       *
       * Vault answers a `GET /@<projectSlug>/vault/secrets/<name>` only as a reveal: with no
       * `X-K9O-Reveal-Challenge` header it refuses with 401 `K9O_REVEAL_CHALLENGE_REQUIRED`, whatever the caller's
       * rights. There is no plain metadata read on that route, so `get` reads the metadata the route that exists
       * for it returns: it lists by the exact name as prefix and picks the exact match. It throws `K9O_NOT_FOUND`
       * (status 404) when no secret has that name.
       */
      async get(name: string, _opts?: { region?: string }): Promise<Envelope<SecretSummary>> {
        let cursor: string | undefined;
        for (let page = 0; page < MAX_GET_PAGES; page++) {
          const env = await listSecrets({ prefix: name, ...(cursor !== undefined ? { cursor } : {}), limit: 100 });
          const hit = env.data.secrets.find((s) => s.name === name);
          if (hit !== undefined) return { ...env, data: hit };
          if (env.data.nextCursor === null || env.data.nextCursor === undefined) break;
          cursor = env.data.nextCursor;
        }
        throw new KError({
          code: "K9O_NOT_FOUND",
          message: `No secret named '${name}' in this project.`,
          context: { name },
          status: 404,
        });
      },

      /**
       * Create a secret under the caller's own auth.
       * `POST /@<projectSlug>/vault/secrets/<name>` -> the `sec_<base62>` summary.
       */
      async create(input: CreateSecretInput): Promise<Envelope<SecretSummary>> {
        const { name, region, value, ...rest } = input;
        return request<SecretSummary>(config, {
          method: "POST",
          path: projectPath(requireProjectSlug(config), `vault/secrets/${encodeURIComponent(name)}`),
          query: { region },
          // The wire `value` is base64 (a raw string is rejected as unparseable). `input.value` stays the
          // caller-facing plaintext; base64 is purely a wire detail handled here.
          body: { ...rest, value: encodeBase64Utf8(value) },
        });
      },

      /** Mint a single-use reveal challenge; pass it to the immediately-following `reveal()`.
       *  `POST .../<name>?op=reveal-challenge`. The optional `reason` is accepted by the gateway and not forwarded. */
      async revealChallenge(name: string, opts?: { region?: string; reason?: string }): Promise<Envelope<RevealChallenge>> {
        return request<RevealChallenge>(config, {
          method: "POST",
          path: projectPath(requireProjectSlug(config), `vault/secrets/${encodeURIComponent(name)}`),
          query: { op: "reveal-challenge", region: opts?.region },
          ...(opts?.reason !== undefined ? { body: { reason: opts.reason } } : {}),
        });
      },

      /** Reveal a secret's plaintext value using a single-use challenge from `revealChallenge()`.
       *  `GET .../<name>` with `X-K9O-Reveal-Challenge`. Decodes the wire's base64 `value` back to plaintext
       *  (symmetric with `create`'s encode). */
      async reveal(name: string, opts: { region?: string; challenge: string }): Promise<Envelope<RevealSecretResult>> {
        const envelope = await request<RevealSecretResult>(config, {
          method: "GET",
          path: projectPath(requireProjectSlug(config), `vault/secrets/${encodeURIComponent(name)}`),
          query: { region: opts.region },
          headers: { "X-K9O-Reveal-Challenge": opts.challenge },
        });
        return { ...envelope, data: { ...envelope.data, value: decodeBase64Utf8(envelope.data.value) } };
      },

      /** Update a secret's value (bumps version), owner-only. `PUT .../<name>`.
       *  Returns only `{id, name, version}` (see `UpdateSecretResult`); call `get()` after for the rest. */
      async update(name: string, input: UpdateSecretInput): Promise<Envelope<UpdateSecretResult>> {
        return request<UpdateSecretResult>(config, {
          method: "PUT",
          path: projectPath(requireProjectSlug(config), `vault/secrets/${encodeURIComponent(name)}`),
          query: { region: input.region },
          body: { value: encodeBase64Utf8(input.value), ...(input.metadata !== undefined ? { metadata: input.metadata } : {}) },
        });
      },

      /** Rotate a secret's wrapping key (re-wraps under a fresh `kid`; content unchanged), owner-only.
       *  `POST .../<name>?op=rotate`. */
      async rotate(name: string, opts?: { region?: string }): Promise<Envelope<RotateSecretResult>> {
        return request<RotateSecretResult>(config, {
          method: "POST",
          path: projectPath(requireProjectSlug(config), `vault/secrets/${encodeURIComponent(name)}`),
          query: { op: "rotate", region: opts?.region },
        });
      },

      /** Move (rename) a secret's hierarchical path, owner-only. `POST .../<name>?op=move`. */
      async move(name: string, opts: { region?: string; newPath: string }): Promise<Envelope<MoveSecretResult>> {
        return request<MoveSecretResult>(config, {
          method: "POST",
          path: projectPath(requireProjectSlug(config), `vault/secrets/${encodeURIComponent(name)}`),
          query: { op: "move", region: opts.region },
          body: { newPath: opts.newPath },
        });
      },

      /** Retire a secret, owner-only. `DELETE .../<name>`. */
      async delete(name: string, opts?: { region?: string }): Promise<Envelope<void>> {
        return request<void>(config, {
          method: "DELETE",
          path: projectPath(requireProjectSlug(config), `vault/secrets/${encodeURIComponent(name)}`),
          query: { region: opts?.region },
        });
      },
    },
  };
}
