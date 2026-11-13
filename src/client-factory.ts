/**
 * `createKiboClient(config)` — per-instance Kibo (ZK vault) SDK factory.
 *
 * Composes into `@k9o/core` as `client.kibo` (re-export, available when a
 * project is bound — the same composition pattern as `@k9o/gate`). Reuses the
 * core HTTP layer (`@k9o/core/http`) so the bearer/header/retry contract is
 * identical to the rest of the SDK pool.
 */

import { type HttpClientConfig } from "@k9o/core/http";
import { makeVaultNamespace } from "./vault.ts";

/** Shape of the per-instance client returned by `createKiboClient`. */
export type KiboClient = {
  /** Vault surface: `vault.secrets.*` and `vault.zkDeks.{store,fetch}`. */
  vault: ReturnType<typeof makeVaultNamespace>;
};

/** Construct a Kibo client bound to the supplied (core) HTTP config. */
export function createKiboClient(config: HttpClientConfig): KiboClient {
  return {
    vault: makeVaultNamespace(config),
  };
}
